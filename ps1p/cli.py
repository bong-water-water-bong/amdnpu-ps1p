"""Command-line interface for PS1p firmware container analysis.

Subcommands:
  info    — Show container info (version, size, sections with entropy)
  extract — Extract all sections to files
  dump    — Dump section details, optional blob analysis
  repack  — Repack with byte-level patches
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from ps1p.container import open_ps1p
from ps1p.blob import BlobAnalyzer


def cmd_info(args: argparse.Namespace) -> int:
    """Show container info (version, size, sections with entropy)."""
    try:
        container = open_ps1p(args.input)
    except FileNotFoundError:
        print(f"error: file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    summary = container.summarize()

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"PS1p Container: {os.path.basename(args.input)}")
    print(f"  Magic:         {summary['magic']}")
    print(f"  Version:       {summary['version']}")
    print(f"  Claimed Size:  {summary['claimed_size']}")
    print(f"  Actual Size:   {summary['actual_size']}")
    print(f"  Old Format:    {summary['is_old_format']}")
    print(f"  Header SHA256: {summary['sha256_header']}")
    print(f"  Data SHA256:   {summary['sha256_data']}")
    print()
    print(f"  Sections ({len(summary['sections'])}):")
    for name, info in summary['sections'].items():
        print(f"    {name:20s} offset={info['offset']}  "
              f"size={info['size']:>6}  entropy={info['entropy']:.4f}  "
              f"sha256={info['sha256']}")

    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """Extract all sections to files."""
    try:
        container = open_ps1p(args.input)
    except FileNotFoundError:
        print(f"error: file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    output_dir = args.output
    if output_dir is None:
        base = os.path.splitext(os.path.basename(args.input))[0]
        output_dir = f"{base}_sections"

    paths = container.extract_all(output_dir)
    print(f"Extracted {len(paths)} sections to: {output_dir}")
    for name, path in paths.items():
        size = container.get_section(name).size if container.get_section(name) else 0
        print(f"  {name:20s}  {size:>8} bytes  ->  {path}")

    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    """Dump section details, optional blob analysis."""
    try:
        container = open_ps1p(args.input)
    except FileNotFoundError:
        print(f"error: file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    section = container.get_section(args.section)
    if section is None:
        print(f"error: section '{args.section}' not found", file=sys.stderr)
        available = ", ".join(container.sections.keys())
        print(f"  available sections: {available}", file=sys.stderr)
        return 1

    print(f"Section: {section.name}")
    print(f"  Offset:      0x{section.offset:05X}")
    print(f"  Size:        {section.size} bytes")
    print(f"  End:         0x{section.end:05X}")
    print(f"  Entropy:     {section.entropy_value:.4f}")
    print(f"  SHA256:      {section.sha256}")
    print(f"  Description: {section.description}")

    if args.v:
        analysis = BlobAnalyzer.analyze(section.data, section.offset)
        print(f"\n  Blob Analysis:")
        print(f"    Classification:    {analysis.classification}")
        print(f"    Printable Ratio:   {analysis.printable_ratio:.4f}")
        print(f"    Null Ratio:        {analysis.null_ratio:.4f}")
        print(f"    ARM Thumb:         {analysis.is_arm_thumb}")
        print(f"    Xilinx Sync:       {analysis.has_xilinx_sync}")
        print(f"    ELF Header:        {analysis.has_elf_header}")
        if analysis.potential_code_types:
            print(f"    Code Types:        {', '.join(analysis.potential_code_types)}")

    if args.blobs:
        min_blob_size = args.min_blob_size
        blobs = BlobAnalyzer.find_blobs(section.data, min_size=min_blob_size)
        if not blobs:
            print(f"\n  No blobs found (min_size={min_blob_size})")
        else:
            print(f"\n  Blobs ({len(blobs)} found, min_size={min_blob_size}):")
            for blob in blobs:
                print(f"    [{blob.start_offset:>7}..{blob.start_offset + blob.size:>7}] "
                      f"size={blob.size:>6}  entropy={blob.entropy:.4f}  "
                      f"{blob.classification}")
                if args.v:
                    code = ", ".join(blob.potential_code_types) if blob.potential_code_types else "-"
                    print(f"      printable={blob.printable_ratio:.4f}  "
                          f"nulls={blob.null_ratio:.4f}  "
                          f"types=[{code}]")

    return 0


def cmd_repack(args: argparse.Namespace) -> int:
    """Repack with byte-level patches.

    The --replace argument format: offset,file_path
    (e.g., --replace 0x220,/tmp/new_ipu.bin)
    """
    try:
        container = open_ps1p(args.input)
    except FileNotFoundError:
        print(f"error: file not found: {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        offset_str, file_path = args.replace.split(",", 1)
        if offset_str.startswith("0x"):
            offset = int(offset_str, 16)
        else:
            offset = int(offset_str)
    except ValueError:
        print(f"error: invalid replace format '{args.replace}'. "
              f"Use: offset,file_path (e.g., 0x220,/tmp/new_ipu.bin)",
              file=sys.stderr)
        return 1

    if not os.path.exists(file_path):
        print(f"error: patch file not found: {file_path}", file=sys.stderr)
        return 1

    try:
        with open(file_path, "rb") as f:
            patch_data = f.read()
    except Exception as e:
        print(f"error: reading patch file: {e}", file=sys.stderr)
        return 1

    if offset + len(patch_data) > len(container.raw_data):
        print(f"error: patch at 0x{offset:X} (size {len(patch_data)}) "
              f"exceeds container size {len(container.raw_data)}",
              file=sys.stderr)
        return 1

    patched = container.patch(offset, patch_data)

    try:
        with open(args.output, "wb") as f:
            f.write(patched.raw_data)
    except Exception as e:
        print(f"error: writing output: {e}", file=sys.stderr)
        return 1

    print(f"Repacked to: {args.output}")
    print(f"  Patched {len(patch_data)} bytes at offset 0x{offset:X}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for ps1p CLI."""
    parser = argparse.ArgumentParser(
        prog="ps1p",
        description="PS1p firmware container analysis and extraction tool",
    )
    subparsers = parser.add_subparsers(dest="command", help="subcommand help")

    # info
    p_info = subparsers.add_parser("info", help="Show container info")
    p_info.add_argument("input", help="Path to PS1p firmware file")
    p_info.add_argument("--json", action="store_true", help="Output as JSON")
    p_info.set_defaults(func=cmd_info)

    # extract
    p_extract = subparsers.add_parser("extract", help="Extract all sections to files")
    p_extract.add_argument("input", help="Path to PS1p firmware file")
    p_extract.add_argument("-o", "--output", help="Output directory (default: <basename>_sections)")
    p_extract.set_defaults(func=cmd_extract)

    # dump
    p_dump = subparsers.add_parser("dump", help="Dump section details")
    p_dump.add_argument("input", help="Path to PS1p firmware file")
    p_dump.add_argument("section", help="Section name to dump")
    p_dump.add_argument("-v", action="store_true", help="Verbose: show blob analysis")
    p_dump.add_argument("--blobs", action="store_true", help="Find and list blobs")
    p_dump.add_argument("--min-blob-size", type=int, default=64, help="Minimum blob size (default: 64)")
    p_dump.set_defaults(func=cmd_dump)

    # repack
    p_repack = subparsers.add_parser("repack", help="Repack with byte-level patches")
    p_repack.add_argument("input", help="Path to PS1p firmware file")
    p_repack.add_argument("-o", "--output", required=True, help="Output file path")
    p_repack.add_argument("--replace", required=True,
                          help="Patch in format: offset,file_path (e.g., 0x220,/tmp/new.bin)")
    p_repack.set_defaults(func=cmd_repack)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point for ps1p CLI.

    Returns 0 on success, 1 on error.
    """
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1

    if args.command is None:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
