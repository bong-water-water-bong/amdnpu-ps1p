# AMD NPU $PS1p — Firmware Container Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**ps1p** is a Python library for parsing, extracting, modifying, and analyzing
AMD NPU (Neural Processing Unit) firmware images in the **$PS1p container format**.

The $PS1p format is the firmware packaging used by AMD XDNA™ 2 NPUs
(Strix Halo / Ryzen AI 300 series) to wrap the IPU (Intelligent Processing Unit)
microcontroller firmware and its associated AI Engine (AIE2) control data.

## Features

- **Parse** $PS1p firmware containers and extract all sections
- **Identify** firmware version, SHA256 checksums, partition tables
- **Extract** IPU microcontroller code, string tables, AIE2 control payloads
- **Analyze** binary blobs with entropy metrics and content classification
- **Dump** section details including ARM Thumb code detection and Xilinx bitstream markers
- **Repack** modified containers with byte-level patching
- **CLI** with `info`, `extract`, `dump`, `repack` commands
- **API** clean Python interface for programmatic use

## Installation

```bash
pip install git+https://github.com/bong-water-water-bong/amdnpu-ps1p.git

# Or install from source:
git clone https://github.com/bong-water-water-bong/amdnpu-ps1p.git
cd amdnpu-ps1p
pip install -e .
```

## Quick Start

```bash
# Show container info
ps1p info firmware.sbin

# Extract all sections
ps1p extract firmware.sbin -o extracted/

# Dump section details with blob analysis
ps1p dump firmware.sbin sub_payload --blobs

# Extract IPU code and analyze it
ps1p extract firmware.sbin
python3 -c "
from ps1p import open_ps1p
fw = open_ps1p('firmware.sbin')
fw.extract_all('out')
print(fw.summarize())
"
```

## Commands

| Command            | Description                                   |
|--------------------|-----------------------------------------------|
| `ps1p info <file>` | Display container metadata and section table  |
| `ps1p extract <file>` | Extract all sections to individual files   |
| `ps1p dump <file> <section>` | Show detailed analysis of a section    |
| `ps1p repack <file> -o <out>` | Repack with byte-level patches         |

### Examples

```bash
# Show info as JSON
ps1p info firmware.sbin --json

# Extract to a specific directory
ps1p extract firmware.sbin -o /tmp/extracted

# Dump IPU code section details
ps1p dump firmware.sbin ipu_code --verbose

# Find sub-blobs in the AIE2 payload
ps1p dump firmware.sbin sub_payload --blobs --min-blob-size 128

# Repack with a patched byte at offset 0x220
ps1p repack firmware.sbin -o patched.sbin --replace 0x220,patched_code.bin
```

## Python API

```python
from ps1p import open_ps1p, BlobAnalyzer

# Open a firmware file
fw = open_ps1p('/path/to/firmware.sbin')

# Access sections
code = fw.get_section('ipu_code')
payload = fw.get_section('sub_payload')

# Section properties
print(f"IPU Code: {code.offset:#06x}-{code.end:#06x} ({code.size} bytes)")
print(f"Entropy: {code.entropy_value:.3f}")
print(f"SHA256: {code.sha256}")

# Extract everything
paths = fw.extract_all('/tmp/output/')

# Blob analysis
analysis = BlobAnalyzer.analyze(payload.data)
print(f"Classification: {analysis.classification}")
```

## Container Structure

The $PS1p container packages the NPU firmware in this layout:

| Section         | Offset (v1.1.x)     | Description                                   |
|-----------------|---------------------|-----------------------------------------------|
| Header          | 0x00-0x21F          | Magic ($PS1p), version, SHA256, RSA signature |
| IPU Code        | 0x220-0x1C000       | VE2 VLIW microcontroller firmware             |
| String Table    | 0x1C000-0x20000     | Log messages and debug strings                |
| Sub-Payload     | 0x20000-0x68C70     | AIE2 kernels, SOC config, bitstream           |
| Partition Table | 0x68A00-0x68C70     | AIE column partition mapping                  |
| RSA Signature   | 0x68D70-0x68E70     | RSA-2048 signature (256 bytes)                |

## Firmware Source

The `.sbin` firmware files are found on AMD Linux systems at:

```
/lib/firmware/amdnpu/<vendor_device>/npu.sbin.zst
```

Decompress with `zstd` before using:

```bash
zstd -dc /lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst > firmware.sbin
```

## Requirements

- Python 3.10+
- No external dependencies (standard library only)
- `zstd` command-line tool for firmware decompression (system utility)

## License

MIT
