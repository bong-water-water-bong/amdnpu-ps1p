#!/usr/bin/env python3
"""
NPU IPU Firmware Binary Extractor
==================================
Extracts sub-components from AMD NPU VE2 IPU firmware ($PS1p container format).

The firmware contains:
  1. IPU Firmware Code (VE2 custom VLIW ISA) - 0x220-0x1C000
  2. String/Data Table - 0x1C000-0x1FFFF
  3. Sub-payload with Kernel/SOC Headers/Xilinx blobs
  4. Partition table
  5. RSA-2048 signature

Usage:
  python3 extract_ipu_fw.py <firmware.sbin>
  python3 extract_ipu_fw.py /tmp/orig_decomp.sbin
"""

import struct
import hashlib
import sys
import os
import math
from collections import Counter


def block_entropy(data):
    if len(data) == 0:
        return 0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c > 0)


def analyze_firmware(path):
    with open(path, 'rb') as f:
        data = f.read()

    print(f"File: {path}")
    print(f"Size: {len(data)} bytes ({len(data) / 1024:.1f} KB)")
    print()

    # Validate magic
    magic = data[0x10:0x15]
    assert magic == b'$PS1p', f"Not a $PS1p container: magic={magic}"

    # Parse header
    ver_bytes = data[0x15:0x18]
    ver = struct.unpack('<I', ver_bytes + b'\x00')[0]
    ver_str = data[0x1d0:0x1e5].split(b'\x00')[0].decode()
    claimed_size = struct.unpack('<Q', data[0x50:0x58])[0]

    print(f"Version: {ver_str} (header: 0x{ver:06x})")
    print(f"Claimed data size: {claimed_size} (0x{claimed_size:x})")
    print(f"Actual size: {len(data)}")
    print()

    # Section 1: IPU Code
    code = data[0x220:0x1c000]
    print(f"1. IPU Firmware Code: 0x220-0x1C000")
    print(f"   Size: {len(code)} bytes ({len(code) / 1024:.1f} KB)")
    print(f"   SHA256: {hashlib.sha256(code).hexdigest()}")
    print(f"   Entropy: {block_entropy(code):.4f}")

    # Section 2: String Table
    strings = data[0x1c000:0x20000]
    print(f"\n2. String/Data Table: 0x1C000-0x20000")
    print(f"   Size: {len(strings)} bytes ({len(strings) / 1024:.1f} KB)")

    # Section 3: Sub-payload
    payload_start = 0x20000
    for i in range(0x20000, min(0x40000, len(data))):
        if data[i] != 0:
            payload_start = i
            break

    payload_end = 0x68C70
    payload = data[payload_start:payload_end]
    print(f"\n3. Sub-payload Region: 0x{payload_start:05X}-0x{payload_end:05X}")
    print(f"   Size: {len(payload)} bytes ({len(payload) / 1024:.1f} KB)")
    print(f"   Entropy: {block_entropy(payload):.4f}")

    # Find sub-blobs by scanning for transitions between ASCII/data and binary code
    current_start = None
    code_regions = []
    stride = 4
    for i in range(payload_start, payload_end - 64, stride):
        chunk = data[i:i + 64]
        ascii_bytes = sum(1 for b in chunk if 32 <= b < 127)
        if ascii_bytes < 10:  # Less than ~15% ASCII = likely binary code
            if current_start is None:
                current_start = i
        else:
            if current_start is not None and i - current_start > 256:
                blob = data[current_start:i]
                ent = block_entropy(blob)
                code_regions.append((current_start, i, i - current_start, ent))
            current_start = None

    if code_regions:
        print(f"\n   Found {len(code_regions)} binary sub-blobs:")
        for start, end, size, ent in sorted(code_regions, key=lambda x: -x[2])[:10]:
            # Classify blob
            ascii_count = sum(1 for b in data[start:end] if 32 <= b < 127)
            ascii_pct = ascii_count / size * 100 if size > 0 else 0
            if ent > 7.8:
                label = "ENCRYPTED/HIGH ENTROPY"
            elif ascii_pct > 60:
                label = "text/strings"
            elif ent > 6.0:
                label = "code (ARM/RISC-V?)"
            elif ent > 4.0:
                label = "data/table"
            else:
                label = "sparse data"
            print(f"     0x{start:05X}-0x{end:05X}: {size:>7} bytes  "
                  f"entropy={ent:.3f}  ascii={ascii_pct:.0f}%  [{label}]")

    # Check for specific code types
    print(f"\n   ARM/Thumb detection in sub-payload:")
    arm_count = 0
    for i in range(payload_start, payload_end - 4, 2):
        hw = struct.unpack('<H', data[i:i + 2])[0]
        # Thumb2 common patterns
        if hw in [0xb580, 0xb510, 0xb570, 0xb530]:  # PUSH {lr} variants
            arm_count += 1
            if arm_count <= 3:
                print(f"     Thumb prologue at 0x{i:05X}: 0x{hw:04x}")
    if arm_count == 0:
        print(f"     No ARM Thumb prologues found (not ARM code)")

    # Section 4: Partition Table
    pt_start = 0x68A00
    pt_end = 0x68C70
    pt = data[pt_start:pt_end]
    print(f"\n4. Partition Table: 0x{pt_start:05X}-0x{pt_end:05X}")
    print(f"   Size: {len(pt)} bytes")

    magic = struct.unpack('<I', data[pt_start:pt_start + 4])[0]
    print(f"   Magic: 0x{magic:08x}")
    if magic == 0x00abcdef:
        count = struct.unpack('<I', data[pt_start + 4:pt_start + 8])[0]
        print(f"   Section count: {count}")

    for i in range(pt_start + 8, min(pt_end, len(data)), 32):
        fields = struct.unpack('<IIIIIIII', data[i:i + 32])
        if any(f != 0 for f in fields):
            addrs = []
            for f in fields:
                if f >= 0x20000000:
                    addrs.append(f"VA=0x{f:08x}")
                elif f <= 0x100:
                    addrs.append(str(f))
                elif f == 0xffffffff:
                    addrs.append("-1")
                else:
                    addrs.append(f"0x{f:08x}")
            print(f"     0x{i:05X}: {', '.join(addrs)}")

    # Section 5: RSA Signature
    sig_start = 0x68D70
    sig = data[sig_start:sig_start + 256]
    print(f"\n5. RSA-2048 Signature: 0x{sig_start:05X}-0x{sig_start + 256:05X}")
    print(f"   First 16 bytes: {sig[:16].hex()}")
    print(f"   Last 16 bytes: {sig[-16:].hex()}")
    print(f"   SHA256 of signature: {hashlib.sha256(sig).hexdigest()}")

    # Header data
    sha_header = data[0x130:0x170].decode().strip('\x00')
    print(f"\n6. Header Data:")
    print(f"   SHA256 hex at 0x130: {sha_header}")
    print(f"   Binary hash at 0xD0: {data[0xD0:0xF0].hex()}")

    # Save extracted components
    base = os.path.splitext(path)[0]
    out_dir = f"{base}_extracted"
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n--- Extracting to {out_dir}/ ---")

    with open(f"{out_dir}/ipu_code.bin", 'wb') as f:
        f.write(code)
    print(f"  ipu_code.bin: {len(code)} bytes")

    with open(f"{out_dir}/string_table.bin", 'wb') as f:
        f.write(strings)
    print(f"  string_table.bin: {len(strings)} bytes")

    with open(f"{out_dir}/sub_payload.bin", 'wb') as f:
        f.write(payload)
    print(f"  sub_payload.bin: {len(payload)} bytes")

    with open(f"{out_dir}/rsa_signature.bin", 'wb') as f:
        f.write(sig)
    print(f"  rsa_signature.bin: {len(sig)} bytes")

    with open(f"{out_dir}/partition_table.bin", 'wb') as f:
        f.write(pt)
    print(f"  partition_table.bin: {len(pt)} bytes")

    # Extract individual sub-blobs
    print(f"\n   Extracting individual sub-blobs:")
    for idx, (start, end, size, ent) in enumerate(
        sorted(code_regions, key=lambda x: -x[2])[:8]):
        blob = data[start:end]
        label = f"blob_{idx}"
        fn = f"{out_dir}/{label}.bin"
        with open(fn, 'wb') as f:
            f.write(blob)
        print(f"     {label}.bin: 0x{start:05X}-0x{end:05X} ({size} bytes, "
              f"entropy={ent:.3f})")

    print(f"\nDone! Files extracted to {out_dir}/")
    return data


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/orig_decomp.sbin"
    analyze_firmware(path)
