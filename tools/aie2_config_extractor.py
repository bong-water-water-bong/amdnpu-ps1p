#!/usr/bin/env python3
"""AIE2 Column Configuration Extractor.

Extracts and analyzes AIE2 column configuration data from the ``sub_payload``
section of a $PS1p firmware container.  The sub_payload section contains:

1. **String table** (~0-0x1280) — null-terminated ASCII strings
2. **Padding region** (~0x1280-0x2d0ff) — mostly zeros with sparse content
3. **Data table region** (~0x2d100-0x42e2b) — high-entropy AIE2 control/configuration
4. **Final sparse region** (~0x42e2c-end) — zeros

The data table region contains Xilinx AA99 sync words, 64-byte aligned
structures, control packets with opcode bytes 0x01/0x02/0x03, and
high-entropy blobs classified as ``data_table`` or ``binary_code``.

Typical usage::

    from tools.aie2_config_extractor import Aie2ConfigExtractor
    from ps1p import open_ps1p

    fw = open_ps1p('/tmp/orig_decomp.sbin')
    payload = fw.get_section('sub_payload')
    extractor = Aie2ConfigExtractor(payload.data)
    summary = extractor.summarize()
"""

from __future__ import annotations

import argparse
import math
import sys
from typing import Any

from ps1p.blob import BlobAnalyzer

# Xilinx bitstream sync word
_XILINX_SYNC = b"\xaa\x99"

# Region boundary estimates for offset-to-region classification.
_STRING_TABLE_END = 0x1280
_DATA_TABLE_START = 0x2D100
_DATA_TABLE_END = 0x42E2C


def _entropy(data: bytes) -> float:
    """Compute Shannon entropy of *data*.

    Returns float in [0.0, 8.0].
    """
    if len(data) == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def _classify_offset(offset: int) -> str:
    """Determine the named region for an offset within sub_payload."""
    if offset < _STRING_TABLE_END:
        return "string_table"
    elif offset < _DATA_TABLE_START:
        return "padding"
    elif offset < _DATA_TABLE_END:
        return "data_table"
    else:
        return "sparse"


def _hex(data: bytes, max_len: int = 16) -> str:
    """Return hex string of *data*, at most *max_len* bytes."""
    return data[:max_len].hex()


def _control_opcodes(data: bytes, search_limit: int = 256) -> list[int]:
    """Extract candidate control opcodes at 4-aligned offsets.

    AIE2 control packets typically start with opcode bytes 0x01, 0x02,
    or 0x03 at 4-byte aligned boundaries.  Returns only byte values
    that are valid opcode candidates (0x01-0x1f) to avoid noise from
    data fields that happen to fall at aligned positions.

    Parameters
    ----------
    data : bytes
        Binary data to scan.
    search_limit : int
        Maximum number of bytes to examine.

    Returns
    -------
    list[int]
        Candidate opcode byte values found at 4-aligned positions.
    """
    opcodes: list[int] = []
    limit = min(search_limit, len(data))
    for i in range(0, limit, 4):
        b = data[i]
        if 0x01 <= b <= 0x1f:
            opcodes.append(b)
    return opcodes


def _find_data_region_start_end(data: bytes) -> tuple[int, int]:
    """Find start and end offsets of the non-zero data region.

    Scans forward from after the string table to find the first
    significant entropy window (entropy > 3.0 in a 256-byte window).
    Scans from the end to find the last such window.

    Returns
    -------
    tuple[int, int]
        ``(start_offset, end_offset)``.
    """
    n = len(data)

    # Find data start: first window with entropy > 3.0 after string table
    data_start = _DATA_TABLE_START  # fallback
    for i in range(_STRING_TABLE_END, n, 64):
        chunk = data[i : i + 256]
        if len(chunk) < 64:
            break
        ent = _entropy(chunk)
        if ent > 3.0:
            data_start = i
            break

    # Find data end: last window with entropy > 3.0, scanning from end
    data_end = n
    for i in range(n - 256, _STRING_TABLE_END - 1, -64):
        if i < 0:
            break
        chunk = data[i : i + 256]
        if len(chunk) < 64:
            continue
        ent = _entropy(chunk)
        if ent > 3.0:
            data_end = i + 256
            break

    return (data_start, data_end)


class Aie2ConfigExtractor:
    """Extract and analyze AIE2 column configuration from sub_payload.

    Parameters
    ----------
    data : bytes
        Raw bytes of the ``sub_payload`` section.
    """

    def __init__(self, data: bytes):
        self._data = data

    # ── Public API ───────────────────────────────────────────────

    def find_xilinx_sync_words(self) -> list[dict]:
        """Find all AA99 (Xilinx bitstream sync) occurrences.

        Returns list of dict entries::

            {
                'offset': int,
                'context': str,   # 8 bytes surrounding the sync word
                'region': str,    # one of 'string_table', 'padding',
                                  # 'data_table', 'sparse'
            }
        """
        results: list[dict] = []
        data = self._data
        pos = 0
        while True:
            idx = data.find(_XILINX_SYNC, pos)
            if idx == -1:
                break
            ctx_start = max(0, idx - 3)
            ctx_end = min(len(data), idx + 6)
            context = _hex(data[ctx_start:ctx_end], max_len=9)
            results.append(
                {
                    "offset": idx,
                    "context": context,
                    "region": _classify_offset(idx),
                }
            )
            pos = idx + 2  # advance past the 2-byte sync
        return results

    def find_data_table_blobs(
        self, min_entropy: float = 4.5, min_size: int = 32
    ) -> list[dict]:
        """Find all high-entropy data blobs beyond the string table.

        Scans the data table region (the high-entropy area starting
        past the padding) for contiguous binary blobs.  Each blob is
        analyzed for entropy, Xilinx sync words, and control opcodes.

        Parameters
        ----------
        min_entropy : float
            Minimum entropy to report (default 4.5).
        min_size : int
            Minimum blob size to report (default 32).

        Returns
        -------
        list[dict]
            Sorted by offset ascending.  Each entry::

                {
                    'offset': int,
                    'size': int,
                    'entropy': float,
                    'first_bytes_hex': str,
                    'has_xilinx_sync': bool,
                    'control_opcodes': list[int],
                }
        """
        data = self._data

        # Find blobs in the full data using BlobAnalyzer
        raw_blobs = BlobAnalyzer.find_blobs(data, min_size=min_size)

        # Filter to only data_table region and high enough entropy
        data_table_blobs: list[dict] = []
        for b in raw_blobs:
            if b.start_offset < _DATA_TABLE_START:
                continue
            if b.start_offset >= _DATA_TABLE_END:
                continue
            if b.entropy < min_entropy:
                continue

            blob_data = data[b.start_offset : b.start_offset + b.size]
            has_sync = _XILINX_SYNC in blob_data

            data_table_blobs.append(
                {
                    "offset": b.start_offset,
                    "size": b.size,
                    "entropy": b.entropy,
                    "first_bytes_hex": _hex(blob_data, 16),
                    "has_xilinx_sync": has_sync,
                    "control_opcodes": _control_opcodes(blob_data),
                }
            )

        return sorted(data_table_blobs, key=lambda x: x["offset"])

    def find_aligned_structures(self, alignment: int = 64) -> list[dict]:
        """Find non-zero *alignment*-byte aligned blocks in the data region.

        The AIE2 configuration data appears to be organized in
        64-byte aligned blocks.  Uses dynamically detected region
        boundaries from ``_find_data_region_start_end()`` to avoid
        scanning the padding and sparse regions.

        Parameters
        ----------
        alignment : int
            Alignment boundary (default 64).

        Returns
        -------
        list[dict]
            Each entry::

                {
                    'block_index': int,
                    'offset': int,
                    'size': int,
                    'first_bytes': str,
                }
        """
        data = self._data
        results: list[dict] = []

        data_start, data_end = _find_data_region_start_end(data)

        # Align start to the nearest alignment boundary
        start = ((data_start + alignment - 1) // alignment) * alignment
        end = data_end
        block_index = 0

        for offset in range(start, end, alignment):
            chunk = data[offset : offset + alignment]
            if len(chunk) < alignment:
                continue
            # Skip entirely zero blocks
            if all(b == 0 for b in chunk):
                continue
            results.append(
                {
                    "block_index": block_index,
                    "offset": offset,
                    "size": alignment,
                    "first_bytes": _hex(chunk, 16),
                }
            )
            block_index += 1

        return results

    def classify_config_region(self, offset: int, size: int = 256) -> dict:
        """Classify a region of sub_payload data.

        Uses the ps1p ``BlobAnalyzer`` to classify the content type.

        Parameters
        ----------
        offset : int
            Starting offset within sub_payload.
        size : int
            Number of bytes to analyze (default 256).

        Returns
        -------
        dict
            ``{'offset': int, 'size': int, 'classification': str,
            'entropy': float, 'thumbnail_hex': str}``
        """
        chunk = self._data[offset : offset + size]
        if not chunk:
            return {
                "offset": offset,
                "size": 0,
                "classification": "empty",
                "entropy": 0.0,
                "thumbnail_hex": "",
            }

        analysis = BlobAnalyzer.analyze(chunk, start_offset=offset)
        return {
            "offset": analysis.start_offset,
            "size": analysis.size,
            "classification": analysis.classification,
            "entropy": analysis.entropy,
            "thumbnail_hex": _hex(chunk, 32),
        }

    def compute_entropy_profile(self, window_size: int = 256) -> list[dict]:
        """Compute entropy across the sub_payload in sliding windows.

        Returns a list of dictionaries for every *window_size* stride
        position in the data, giving entropy and BlobAnalyzer
        classification.

        Returns
        -------
        list[dict]
            Each entry::

                {
                    'offset': int,
                    'entropy': float,
                    'classification': str,
                }
        """
        data = self._data
        profile: list[dict] = []
        n = len(data)

        for i in range(0, n, window_size):
            chunk = data[i : i + window_size]
            if len(chunk) < 16:
                break
            ent = _entropy(chunk)
            analysis = BlobAnalyzer.analyze(chunk, start_offset=i)
            profile.append(
                {
                    "offset": i,
                    "entropy": round(ent, 4),
                    "classification": analysis.classification,
                }
            )

        return profile

    def summarize(self) -> dict[str, Any]:
        """Return a summary dict of the AIE2 configuration.

        Keys:

        - ``total_size`` — total sub_payload size
        - ``num_xilinx_sync_words`` — count of AA99 pairs
        - ``num_data_table_blobs`` — high-entropy blobs in data region
        - ``num_aligned_structures`` — non-zero 64-byte aligned blocks
        - ``data_region_start`` — offset where non-zero data begins
        - ``data_region_end`` — offset where non-zero data ends
        """
        total_size = len(self._data)
        data_start, data_end = _find_data_region_start_end(self._data)

        # Cache inner results so CLI doesn't recompute
        self._sync_words = self.find_xilinx_sync_words()
        self._data_blobs = self.find_data_table_blobs()
        self._aligned = self.find_aligned_structures()

        return {
            "total_size": total_size,
            "num_xilinx_sync_words": len(self._sync_words),
            "num_data_table_blobs": len(self._data_blobs),
            "num_aligned_structures": len(self._aligned),
            "data_region_start": data_start,
            "data_region_end": data_end,
        }


# ── CLI ─────────────────────────────────────────────────────────


def _run_cli(args: list[str] | None = None) -> int:
    """Run the command-line interface.  Returns exit code."""
    parser = argparse.ArgumentParser(
        description="Extract and analyze AIE2 column configuration "
        "from $PS1p firmware sub_payload."
    )
    parser.add_argument(
        "firmware",
        help="Path to the $PS1p firmware file (.sbin)",
    )
    parser.add_argument(
        "--detail",
        action="store_true",
        help="Show detailed information about data table blobs",
    )
    parser.add_argument(
        "--region",
        nargs=2,
        metavar=("START", "SIZE"),
        help="Analyze a specific region: --region <start_hex> <size_dec>",
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

    extractor = Aie2ConfigExtractor(payload.data)
    summary = extractor.summarize()

    # ── Handle --region mode ──────────────────────────────────
    if opts.region:
        try:
            start_str = opts.region[0]
            if start_str.startswith("0x") or start_str.startswith("0X"):
                start = int(start_str, 16)
            else:
                start = int(start_str)
            size = int(opts.region[1])
        except ValueError:
            print("Error: --region requires numeric start and size", file=sys.stderr)
            return 1

        if start < 0 or start >= len(payload.data):
            print(f"Error: start offset 0x{start:x} out of range "
                  f"(0-0x{len(payload.data):x})", file=sys.stderr)
            return 1

        region = extractor.classify_config_region(start, size)
        print(f"Region Analysis: 0x{region['offset']:05X} ({region['size']} bytes)")
        print(f"{'=' * 50}")
        print(f"  Classification:  {region['classification']}")
        print(f"  Entropy:         {region['entropy']:.4f}")
        print(f"  Thumbnail (hex): {region['thumbnail_hex']}")
        print()
        return 0

    # ── Normal mode ───────────────────────────────────────────
    # Use cached results from summarize() call above
    sync_words = getattr(extractor, '_sync_words', extractor.find_xilinx_sync_words())
    data_blobs = getattr(extractor, '_data_blobs', extractor.find_data_table_blobs())
    aligned = getattr(extractor, '_aligned', extractor.find_aligned_structures())
    profile = extractor.compute_entropy_profile()

    print(f"AIE2 Configuration Analysis: {opts.firmware}")
    print(f"{'=' * 60}")
    print(f"  Total sub_payload size:  {summary['total_size']} bytes "
          f"(0x{summary['total_size']:05X})")
    print(f"  Data region:             0x{summary['data_region_start']:05X} - "
          f"0x{summary['data_region_end']:05X}")
    print(f"  Xilinx sync words:       {summary['num_xilinx_sync_words']}")
    print(f"  Data table blobs:        {summary['num_data_table_blobs']}")
    print(f"  Aligned structures:      {summary['num_aligned_structures']}")
    print()

    # ── Xilinx Sync Words ─────────────────────────────────────
    print("Xilinx Sync Word Locations:")
    print("-" * 60)
    if sync_words:
        for sw in sync_words:
            print(f"  0x{sw['offset']:05X}  context={sw['context']}  "
                  f"region={sw['region']}")
    else:
        print("  (none found)")
    print()

    # ── Data Table Blobs ──────────────────────────────────────
    print(f"Data Table Blobs ({len(data_blobs)} total):")
    print("-" * 60)
    if data_blobs:
        for blob in data_blobs:
            sync_mark = " [SYNC]" if blob["has_xilinx_sync"] else ""
            print(f"  0x{blob['offset']:05X}: size={blob['size']:5d}  "
                  f"entropy={blob['entropy']:.2f}{sync_mark}")
            if opts.detail:
                first_16 = blob["first_bytes_hex"]
                print(f"         first 16 bytes: {first_16}")
                opcodes = blob["control_opcodes"][:16]
                op_str = ", ".join(f"0x{b:02x}" for b in opcodes)
                print(f"         control opcodes: [{op_str}]")
    else:
        print("  (none found)")
    print()

    # ── Entropy Profile Overview ──────────────────────────────
    print("Entropy Profile Overview:")
    print("-" * 60)
    # Show region boundaries where classification changes
    prev_class: str | None = None
    for entry in profile:
        if entry["classification"] != prev_class:
            print(f"  0x{entry['offset']:05X}: entropy={entry['entropy']:.2f}  "
                  f"class={entry['classification']}")
            prev_class = entry["classification"]
    print()

    # ── Aligned Structures ────────────────────────────────────
    print(f"Aligned Structures (non-zero 64-byte blocks): {len(aligned)}")
    print("-" * 60)
    if aligned:
        # Show first and last few
        show: list[dict] = aligned[:5]
        if len(aligned) > 10:
            show.append({"block_index": "...", "offset": 0, "size": 0, "first_bytes": ""})
            show.extend(aligned[-5:])
        for a in show:
            if a["block_index"] == "...":
                print("  ...")
                continue
            print(f"  block #{a['block_index']:5d}  @ 0x{a['offset']:05X}  "
                  f"first bytes: {a['first_bytes']}")
    else:
        print("  (none found)")
    print()

    return 0


def main() -> None:
    """Entry point for ``python3 -m tools.aie2_config_extractor``."""
    sys.exit(_run_cli())


if __name__ == "__main__":
    main()
