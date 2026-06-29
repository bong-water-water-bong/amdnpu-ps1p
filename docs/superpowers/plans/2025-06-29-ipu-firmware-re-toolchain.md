# IPU Firmware Reverse Engineering Toolchain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the disassembly and analysis toolchain for the Strix Halo NPU's VE2 IPU firmware, identify the "not the last scheduled" serialization gate, and produce a patched firmware that allows concurrent NPU access.

**Architecture:** The IPU (Image Processor Unit) uses a custom 32-bit VLIW ISA. We'll reverse-engineer the encoding by: (1) building an aiebu-toolchain-based cross-reference between known test programs and their compiled output, (2) using Ghidra's processor module framework for disassembly, (3) locating the serialization gate string reference in the firmware binary, and (4) producing a patched binary with the gate removed.

**Tech Stack:** Python 3 (analysis scripts), Ghidra (if we can install), aiebu-asm/dump (installed), custom Python disassembler, xxd/hexdump, binwalk, zstd, git

## Global Constraints

- All tools must run on Ubuntu 26.04 (kernel 7.0.0-27-generic)
- All output goes to /home/bcloud/npu_re_workspace/
- The firmware binary is /lib/firmware/amdnpu/17f0_11/npu_7.sbin (v1.1.2.65)
- The decompressed binary is at /tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin
- Code section: 0x220 to 0x1c000 (113,120 bytes, ~28,280 instructions)
- String table: at ~0x1c000 to ~0x1d800 (boundaries to be confirmed)
- Key string at offset 0x1e655: "Application %u is not the last scheduled. The last scheduled was %d."
- aiebu-asm is at /usr/bin/aiebu-asm (supports targets: aie2ps, aie2asm, aie2txn, aie2dpu, aie2_config, aie4, aie2ps_config, aie4_config)
- aiebu-dump is at /usr/bin/aiebu-dump (disassembler for aiebu-format ELFs)
- Ghidra installation is optional; custom Python disassembler is the primary path

---

### Task 1: Discover the IPU ISA Encoding Through aiebu-toolchain Analysis

**Files:**
- Create: `tools/decode_isa.py` — Python script to analyze instruction patterns
- Create: `tools/compile_test_programs.py` — Script to generate test AIE2PS programs
- Read: `/usr/bin/aiebu-asm` (check --help for all targets)
- Read: `/usr/bin/aiebu-dump` (check --help for disassembly capabilities)

**Interfaces:**
- Consumes: None (first task)
- Produces: `tools/opcode_map.json` — mapping of instruction patterns to their encodings
- Produces: `tools/known_instructions.txt` — list of identified instruction encodings

**Approach:**
The aiebu-asm assembler supports the "aie2ps" target which compiles to IPU binary format.
We'll compile a series of minimal test programs (NOP, ADD, SUB, branch, load, store)
and use the output to build an opcode map. AIE2PS is the processor type inside the IPU.

- [ ] **Step 1: Check aiebu-asm capabilities**

```bash
aiebu-asm --help 2>&1 | tee /tmp/aietools_help.txt
aiebu-dump --help 2>&1 | tee /tmp/aietools_dump_help.txt
```

Expected: List of assembler options, available targets, and disassembler options.

- [ ] **Step 2: Create minimal AIE2PS assembly test program: NOP-only**

```bash
cat > /tmp/test_nop.S << 'ASM'
# Minimal AIE2PS test: just NOPs
.text
nop
nop
nop
nop
ASM
aiebu-asm -t aie2ps -o /tmp/test_nop.o /tmp/test_nop.S 2>&1
xxd /tmp/test_nop.o | head -30
```

Expected: Assembler output file, hexdump showing instruction encoding.

- [ ] **Step 3: Create add/immediate test programs**

```bash
# For each: compile, dump, analyze
cat > /tmp/test_add.S << 'ASM'
.text
add r1, r2, r3
ASM
aiebu-asm -t aie2ps -o /tmp/test_add.o /tmp/test_add.S 2>&1

cat > /tmp/test_addi.S << 'ASM'
.text
addi r1, r2, 42
ASM
aiebu-asm -t aie2ps -o /tmp/test_addi.o /tmp/test_addi.S 2>&1
```

- [ ] **Step 4: Create branch/compare test programs**

```bash
cat > /tmp/test_branch.S << 'ASM'
.text
beq r1, r2, target
nop
target:
nop
ASM
aiebu-asm -t aie2ps -o /tmp/test_branch.o /tmp/test_branch.S 2>&1
```

- [ ] **Step 5: Create load/store test programs**

```bash
cat > /tmp/test_load.S << 'ASM'
.text
lw r1, 0(r2)
ASM
aiebu-asm -t aie2ps -o /tmp/test_load.o /tmp/test_load.S 2>&1
```

- [ ] **Step 6: Write decode_isa.py to analyze instruction patterns**

```python
#!/usr/bin/env python3
"""
IPU ISA Decoder - analyzes aiebu-asm compiled output to build opcode mappings.
Takes an ELF file produced by aiebu-asm, extracts the code section,
and dumps raw instruction bytes with annotations.
"""
import struct, sys, os

def parse_aiebu_elf(path):
    """Parse aiebu-format ELF to extract code section."""
    # AIEBU produces a specific ELF format - read and parse
    # The code section may be .text or custom section
    # Use aiebu-dump -d to disassemble if available
    pass

def extract_instructions(data, offset=0, count=None):
    """Extract N 32-bit instructions from raw data, return as list of hex."""
    if count is None:
        count = (len(data) - offset) // 4
    instrs = []
    for i in range(count):
        addr = offset + i * 4
        if addr + 4 <= len(data):
            instrs.append(struct.unpack('<I', data[addr:addr+4])[0])
    return instrs

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <elf_file>")
        return 1
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = f.read()
    print(f"File: {path} ({len(data)} bytes)")
    instrs = extract_instructions(data, 0, 16)
    for i, instr in enumerate(instrs):
        print(f"  [{i:3d}] 0x{instr:08x}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
```

- [ ] **Step 7: Run decode_isa.py on ALL test binaries, cross-reference encodings**

```bash
for f in /tmp/test_*.o; do
    echo "=== $f ==="
    python3 tools/decode_isa.py "$f"
done | tee tools/opcode_analysis.txt
```

Expected: Different instruction patterns produce different encodings, allowing us to build the opcode map.

- [ ] **Step 8: Compare compiled encodings against firmware binary**

```bash
python3 tools/decode_isa.py /tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin 0x220 100
```

Expected: Firmware binary at entry point should contain instructions that partially match our known patterns.

- [ ] **Step 9: Commit all tools and analysis**

```bash
git add tools/decode_isa.py tools/compile_test_programs.py tools/opcode_map.json
git commit -m "feat: initial IPU ISA opcode analysis via aiebu-toolchain"
```

---

### Task 2: Cross-Reference the Serialization String in Firmware Binary

**Files:**
- Modify: `tools/decode_isa.py` — Add string reference scanning
- Create: `tools/find_string_ref.py` — Locate cross-references to the serialization string
- Read: `/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin`

**Interfaces:**
- Consumes: Task 1's opcode_map.json and firmware binary
- Produces: `data/string_ref_locations.json` — addresses where the serialization string is referenced

- [ ] **Step 1: Locate the exact string in the firmware binary**

```python
#!/usr/bin/env python3
import struct

with open('/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin', 'rb') as f:
    data = f.read()

target = b"Application %u is not the last scheduled. The last scheduled was %d."
idx = data.find(target)
print(f"String found at offset: 0x{idx:05x}")
# Also search for partial matches and nearby strings
nearby_start = max(0, idx - 0x100)
nearby_end = min(len(data), idx + len(target) + 0x100)
print(f"Context ({nearby_end - nearby_start} bytes around string):")
print(data[nearby_start:nearby_end].hex())
```

- [ ] **Step 2: Scan the entire code section for references to the string address**

The IPU processor likely uses PC-relative addressing (like RISC-V). The string is at offset ~0x1e655. Instructions that reference this address will contain the offset encoded as an immediate field.

```python
def find_pc_relative_refs(data, code_start, code_end, target_addr):
    """Find all instructions that reference target_addr via PC-relative encoding."""
    refs = []
    for addr in range(code_start, code_end, 4):
        instr = struct.unpack('<I', data[addr:addr+4])[0]
        # Try common PC-relative patterns
        # Pattern 1: AUIPC-like (upper immediate + JALR-like lower)
        # Pattern 2: Direct branch with offset
        # Look for instructions where bits match target offset encoding
        # This requires understanding the ISA - for now, try both
        # big-immediate (like LUI/AUIPC) and PC-relative (like JAL)
        pass
    return refs
```

- [ ] **Step 3: Identify the conditional branch after the string comparison**

Once we find the reference to the serialization string, the disassembly around it should show:
1. Load the string address into a register
2. Call a print function (or pass to error handler)
3. A conditional branch (BEQ/BNE) that controls whether execution continues or jumps to the serialization gate

- [ ] **Step 4: Commit string reference analysis**

```bash
git add tools/find_string_ref.py data/string_ref_locations.json
git commit -m "feat: located serialization gate string references in firmware"
```

---

### Task 3: Build Custom Python Disassembler for IPU ISA

**Files:**
- Create: `tools/ipu_disasm.py` — Full disassembler for the custom IPU VLIW ISA
- Create: `tools/ipu_disasm_test.py` — Tests using known encodings from Task 1

**Interfaces:**
- Consumes: opcode map from Task 1, string reference data from Task 2
- Produces: `data/firmware_disassembly.txt` — Full disassembly of the firmware around the serialization gate

- [ ] **Step 1: Design the disassembler class structure**

The disassembler needs to:
1. Parse the custom VLIW packet format (likely 4 instructions per packet, or 5 slots)
2. Decode each instruction slot based on opcode position (bits [4:0] seem to encode the operation class)
3. Handle immediate encoding patterns (immediates may be in fixed bit positions)
4. Handle register encoding (5-bit register fields are likely)

- [ ] **Step 2: Implement instruction classification based on observed patterns**

From our analysis, the top nibble distribution shows ~40% zeros, and bit positions have distinct distributions. Implement a classifier that groups instructions by their bit patterns.

- [ ] **Step 3: Implement register and immediate extraction**

The RISC-V-like patterns (0x13=OP-IMM, 0x33=OP) might indicate the ALU/move operations use similar encoding. Extract register fields at positions [7:11], [15:19], [20:24].

- [ ] **Step 4: Add VLIW bundle parsing (5 slots per packet)**

The xdna-emu docs mention AIE2 VLIW has 8 slots. The IPU (AIE2PS) likely has 5-8 slots per VLIW packet. Implement packet parsing.

- [ ] **Step 5: Run disassembler on the serialization gate region**

```bash
python3 tools/ipu_disasm.py -s 0x1e600 -e 0x1e700 /tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin
```

- [ ] **Step 6: Commit disassembler**

```bash
git add tools/ipu_disasm.py tools/ipu_disasm_test.py
git commit -m "feat: custom IPU VLIW disassembler with serialization gate analysis"
```

---

### Task 4: Analyze Serialization Gate Logic

**Files:**
- Create: `tools/analyze_gate.py` — Trace the serialization branch logic
- Create: `tools/patched_firmware.py` — Patch the firmware binary

**Interfaces:**
- Consumes: firmware binary, disassembled gate region from Task 3
- Produces: `data/gate_analysis.txt` — Full analysis of the serialization gate logic
- Produces: `data/npu_7_patched.sbin` — Patched firmware binary

- [ ] **Step 1: Disassemble the code around the string reference**

The code 50-100 instructions before and after the string reference should show:
- The comparison logic (which application ID vs last scheduled ID)
- The conditional branch (BNE/BEQ) that gates execution
- The context switch path vs the continuation path

- [ ] **Step 2: Identify the two paths**

- **Serialization path**: Logs the error, returns without executing, possibly polls
- **Execution path**: Continues with power-on-sequence, AIE execution, power-off

- [ ] **Step 3: Design the patch**

The simplest patch is to change the conditional branch (BNE → NOP or BNE → unconditional branch) so execution always takes the success path.

- [ ] **Step 4: Create the patched binary**

```bash
python3 tools/patched_firmware.py /tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin \
    --patch-at 0xXXXXX --change-bytes 00000000
```

- [ ] **Step 5: Verify the patch doesn't corrupt the binary**

```bash
# Check the binary still has valid structure
python3 -c "
import struct
with open('data/npu_7_patched.sbin', 'rb') as f:
    d = f.read()
# Check header magic
print('Magic:', d[:4])
# Check size
print(f'Patched size: {len(d)} bytes')
# Compare with original
with open('/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin', 'rb') as f2:
    orig = f2.read()
print(f'Same size: {len(d) == len(orig)}')
changed = sum(1 for a,b in zip(d, orig) if a != b)
print(f'Changed bytes: {changed}')
"
```

- [ ] **Step 6: Commit patched firmware analysis**

```bash
git add tools/analyze_gate.py tools/patched_firmware.py data/gate_analysis.txt
git commit -m "feat: serialization gate analysis and firmware patch"
```

---

### Task 5: Set Up Firmware Modification Pipeline

**Files:**
- Create: `tools/firmware_packager.py` — Full pipeline for unpacking, modifying, repacking firmware
- Create: `tools/verify_checksum.py` — Checksum verification tool
- Create: `Makefile` — Build automation

**Interfaces:**
- Consumes: Original firmware, patched binary
- Produces: `tools/firmware_packager.py`, verified patched output

- [ ] **Step 1: Understand the firmware container format**

The firmware uses the `$PS1p` container format with SHA256-like hash at offset 0x10 and code at 0x220. We need to understand:
1. Is the hash verified by the XPU/PSP before loading?
2. Is there a signature that would reject our patched firmware?
3. Can we recalculate the hash after patching?

- [ ] **Step 2: Build unpack/repack pipeline**

```python
#!/usr/bin/env python3
"""
Firmware packager for Strix Halo NPU.
Handles the $PS1p container format.
"""
import struct, hashlib

def unpack_firmware(path):
    """Unpack $PS1p firmware container."""
    with open(path, 'rb') as f:
        data = f.read()
    
    # Parse header
    magic = data[0:4]
    version_major = data[4]
    version_minor = data[5]
    version_patch = data[6]
    version_build = data[7]
    
    # Hash at offset 0x10 (32 bytes = 256 bits)
    stored_hash = data[0x10:0x30]
    code = data[0x220:]
    
    print(f"Firmware: {magic} v{version_major}.{version_minor}.{version_patch}.{version_build}")
    print(f"Code at 0x220, {len(code)} bytes")
    print(f"Hash: {stored_hash.hex()}")
    
    return data

def repack_firmware(header, patched_code, update_hash=True):
    """Repack firmware with optional hash update."""
    result = header + patched_code
    if update_hash:
        new_hash = hashlib.sha256(patched_code).digest()
        result = result[:0x10] + new_hash + result[0x30:]
    return result
```

- [ ] **Step 3: Test loading patched firmware (dry run)**

The question is: can we actually load a patched firmware on the live system?
We need to investigate:
1. Does the kernel driver support loading firmware from a custom path?
2. Can we use modprobe parameters to specify a custom firmware file?
3. What happens if we directly overwrite /lib/firmware/amdnpu/17f0_11/npu_7.sbin?

- [ ] **Step 4: Commit firmware packager**

```bash
git add tools/firmware_packager.py tools/verify_checksum.py Makefile
git commit -m "feat: complete firmware modification pipeline"
```

---

### Task 6: End-to-End Verification and Testing

**Files:**
- Read: All previously created tools and analysis
- Create: `tools/npu_stress_test.py` — Script to run concurrent NPU workloads

**Interfaces:**
- Consumes: Patched firmware binary from Task 4, verified by Task 5
- Produces: Serialization test results showing concurrent access working

- [ ] **Step 1: Load patched firmware onto NPU**

Investigate firmware loading mechanism:
- Check `/sys/bus/pci/drivers/amdxdna/` for unload/load capability
- Check kernel module parameters for firmware path override
- Check if aie2_control_flags module parameter allows bypassing firmware load

```bash
# Check modinfo for firmware loading parameters
modinfo amdxdna | grep -i firmware
# Check current parameters
cat /sys/module/amdxdna/parameters/* 2>/dev/null
```

- [ ] **Step 2: Test concurrent workload with patched firmware**

Use the C test programs from earlier work, or the XRT SHIM test.

- [ ] **Step 3: Measure performance**

Compare serial (before patch) vs concurrent (after patch) throughput.

- [ ] **Step 4: Document everything**

```bash
git add tools/npu_stress_test.py
git commit -m "feat: end-to-end firmware patch verification"
```
