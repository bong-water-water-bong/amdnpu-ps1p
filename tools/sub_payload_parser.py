#!/usr/bin/env python3
"""Sub-Payload String Table Parser for $PS1p firmware containers.

This tool parses the ``sub_payload`` section of a $PS1p firmware container,
extracting null-terminated ASCII strings, grouping them by bracketed prefix,
finding the string table extent, and detecting binary blobs in the remainder
of the section.

Typical usage::

    from tools.sub_payload_parser import SubPayloadParser
    from ps1p import open_ps1p

    fw = open_ps1p('/tmp/orig_decomp.sbin')
    payload = fw.get_section('sub_payload')
    parser = SubPayloadParser(payload.data)
    summary = parser.summarize()
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Any

from ps1p.blob import BlobAnalyzer

# Minimum string length (characters) to report
_MIN_STRING_LEN = 4

# Threshold for string table detection: a 64-byte window is considered
# "string content" if at least this fraction of bytes are printable ASCII.
_STRING_TABLE_PRINTABLE_THRESHOLD = 0.10

# Window size for string table extent scanning
_SCAN_WINDOW = 64


def _extract_c_strings(data: bytes, min_len: int = _MIN_STRING_LEN) -> dict[int, str]:
    """Extract null-terminated ASCII strings from *data*.

    Walks through the data looking for sequences of printable ASCII
    bytes terminated by ``\\x00`` (or end-of-data).  Only strings with
    at least *min_len* characters are returned.

    Parameters
    ----------
    data : bytes
        Raw data to scan.
    min_len : int
        Minimum number of printable characters for a string to be
        included.

    Returns
    -------
    dict[int, str]
        ``{offset: string}`` mapping.
    """
    strings: dict[int, str] = {}
    i = 0
    n = len(data)
    while i < n:
        # Skip non-printable bytes and nulls
        if data[i] == 0 or not (32 <= data[i] < 127):
            i += 1
            continue

        start = i
        while i < n and 32 <= data[i] < 127:
            i += 1

        length = i - start
        if length >= min_len:
            s = data[start:i].decode("ascii", errors="replace")
            strings[start] = s

        # Skip the null terminator if present
        if i < n and data[i] == 0:
            i += 1

    return strings


def _group_by_prefix(
    strings: dict[int, str],
) -> dict[str, list[tuple[int, str]]]:
    """Group *strings* by their bracketed prefix.

    Strings starting with ``[PREFIX]`` are grouped under that prefix.
    Strings without a bracketed prefix go under ``'_default_'``.
    """
    grouped: dict[str, list[tuple[int, str]]] = {}
    prefix_re = re.compile(r"^\[([^\]]+)\]")

    for offset, s in strings.items():
        m = prefix_re.match(s)
        if m:
            key = f"[{m.group(1)}]"
        else:
            key = "_default_"
        grouped.setdefault(key, []).append((offset, s))

    return grouped


def _find_string_table_extent(
    data: bytes,
    threshold: float = _STRING_TABLE_PRINTABLE_THRESHOLD,
    window: int = _SCAN_WINDOW,
) -> tuple[int, int]:
    """Find the contiguous string region at the start of *data*.

    Scans 64-byte windows from the beginning of the data.  The string
    table is the leading region where the proportion of printable ASCII
    bytes exceeds *threshold*.  Returns ``(start, end)`` where *start*
    is always 0 (strings always begin at offset 0 in sub_payload).

    Parameters
    ----------
    data : bytes
        Raw sub-payload data.
    threshold : float
        Fraction of printable bytes required in a window to consider
        it part of the string table (default 0.10).
    window : int
        Window size in bytes (default 64).

    Returns
    -------
    tuple[int, int]
        ``(start_offset, end_offset)``.
    """
    start = 0
    end = 0
    for i in range(0, len(data), window):
        chunk = data[i : i + window]
        if not chunk:
            break
        printable = sum(1 for b in chunk if 32 <= b < 127)
        ratio = printable / len(chunk)
        if ratio > threshold:
            end = i + len(chunk)
        else:
            # First window below threshold ends the string region
            break
    return (start, end)


def _hexdump(data: bytes, width: int = 16) -> str:
    """Return a hexdump string of *data*."""
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hex_part:<{width*3 - 1}}  |{ascii_part}|")
    return "\n".join(lines)


class SubPayloadParser:
    """Parse the ``sub_payload`` section of a $PS1p firmware container.

    Parameters
    ----------
    data : bytes
        Raw bytes of the ``sub_payload`` section.
    """

    def __init__(self, data: bytes):
        self._data = data

    # ── public API ────────────────────────────────────────────────

    def extract_strings(self) -> dict[int, str]:
        """Return ``{offset: string}`` for all null-terminated ASCII
        strings >= 4 characters found in the sub_payload data."""
        return _extract_c_strings(self._data)

    def group_strings_by_prefix(self) -> dict[str, list[tuple[int, str]]]:
        """Group strings by their bracketed prefix.

        Returns a dict like::

            {
                '[MGT]': [(offset, '...'), ...],
                '[SHIM_DMA TEST]': [(offset, '...'), ...],
                '_default_': [(offset, '...'), ...],
            }
        """
        strings = self.extract_strings()
        return _group_by_prefix(strings)

    def find_string_table_extent(self) -> tuple[int, int]:
        """Return ``(start_offset, end_offset)`` of the contiguous
        printable string region.

        The string table is the leading region of sub_payload where
        printable ASCII content dominates (>10% of bytes per 64-byte
        window).
        """
        return _find_string_table_extent(self._data)

    def extract_binary_blobs(self, min_size: int = 64) -> list[dict[str, Any]]:
        """Find contiguous binary blobs in the sub_payload data.

        Uses ``BlobAnalyzer`` from the ps1p package to detect blobs
        in the entire data region (the string table will naturally
        produce no significant binary blobs).

        Parameters
        ----------
        min_size : int
            Minimum blob size to report (default 64).

        Returns
        -------
        list[dict]
            Each entry::

                {
                    'offset': int,
                    'size': int,
                    'entropy': float,
                    'classification': str,
                }
        """
        blobs = BlobAnalyzer.find_blobs(self._data, min_size=min_size)
        return [
            {
                "offset": b.start_offset,
                "size": b.size,
                "entropy": b.entropy,
                "classification": b.classification,
            }
            for b in blobs
        ]

    def summarize(self) -> dict[str, Any]:
        """Return a summary dict of the sub_payload section.

        Keys:
        - ``total_size``
        - ``string_table_offset``
        - ``string_table_size``
        - ``num_strings``
        - ``num_binary_blobs``
        - ``binary_regions``: ``[(offset, size, classification), ...]``
        """
        total_size = len(self._data)
        st_start, st_end = self.find_string_table_extent()
        string_table_size = st_end - st_start
        strings = self.extract_strings()
        num_strings = len(strings)
        blobs = self.extract_binary_blobs()
        num_binary_blobs = len(blobs)
        binary_regions = [
            (b["offset"], b["size"], b["classification"]) for b in blobs
        ]
        return {
            "total_size": total_size,
            "string_table_offset": st_start,
            "string_table_size": string_table_size,
            "num_strings": num_strings,
            "num_binary_blobs": num_binary_blobs,
            "binary_regions": binary_regions,
        }


# ── CLI ─────────────────────────────────────────────────────────


def _run_cli(args: list[str] | None = None) -> int:
    """Run the command-line interface.  Returns exit code."""
    parser = argparse.ArgumentParser(
        description="Parse the sub_payload section of a $PS1p firmware container."
    )
    parser.add_argument(
        "firmware",
        help="Path to the $PS1p firmware file (.sbin)",
    )
    parser.add_argument(
        "--hexdump",
        action="store_true",
        help="Show hexdump of the first 256 bytes",
    )
    opts = parser.parse_args(args)

    try:
        from ps1p import open_ps1p

        fw = open_ps1p(opts.firmware)
    except Exception as e:
        print(f"Error opening firmware: {e}", file=sys.stderr)
        return 1

    payload = fw.get_section("sub_payload")
    if payload is None:
        print("Error: no sub_payload section found", file=sys.stderr)
        return 1

    parser_obj = SubPayloadParser(payload.data)
    summary = parser_obj.summarize()
    grouped = parser_obj.group_strings_by_prefix()

    print(f"Sub-Payload Analysis: {opts.firmware}")
    print(f"{'=' * 60}")
    print(f"  Total size:         {summary['total_size']} bytes "
          f"(0x{summary['total_size']:05X})")
    print(f"  String table:       offset=0x{summary['string_table_offset']:05X}, "
          f"size={summary['string_table_size']} bytes "
          f"(0x{summary['string_table_size']:04X})")
    print(f"  Number of strings:  {summary['num_strings']}")
    print(f"  Number of prefixes: {len(grouped)}")
    print(f"  Binary blobs:       {summary['num_binary_blobs']}")
    print()

    # Print string groups
    print("Strings by prefix:")
    print("-" * 60)
    for prefix in sorted(grouped.keys()):
        entries = grouped[prefix]
        print(f"  {prefix}: {len(entries)} strings")
        for offset, s in entries[:3]:
            display = s[:80] + "..." if len(s) > 80 else s
            print(f"     0x{offset:05X}: {display}")
        if len(entries) > 3:
            print(f"     ... and {len(entries) - 3} more")
    print()

    # Print binary blob summary
    if summary["binary_regions"]:
        print("Binary blobs:")
        print("-" * 60)
        for offset, size, classification in summary["binary_regions"][:20]:
            print(f"  0x{offset:05X}: {size:6d} bytes  {classification}")
        if len(summary["binary_regions"]) > 20:
            print(f"  ... and {len(summary['binary_regions']) - 20} more")
    else:
        print("No binary blobs detected.")
    print()

    if opts.hexdump:
        print("Hexdump of first 256 bytes:")
        print("-" * 60)
        print(_hexdump(payload.data[:256]))
        print()

    return 0


def main() -> None:
    """Entry point for ``python3 -m tools.sub_payload_parser``."""
    sys.exit(_run_cli())


if __name__ == "__main__":
    main()
