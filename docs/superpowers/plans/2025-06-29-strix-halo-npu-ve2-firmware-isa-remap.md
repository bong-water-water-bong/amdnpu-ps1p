# Strix Halo NPU VE2 Firmware ISA Reverse Engineering & Serialization Gate Analysis

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Map the VE2 IPU firmware processor ISA, locate the "one-call-at-a-time" serialization gate in the firmware binary, identify the exact branch instruction to modify, and validate against the kernel driver's scheduling FIFO.

**Architecture:** The Strix Halo NPU uses AMD's VE2 platform with a custom IPU (Image Processor Unit) control processor running firmware at `/lib/firmware/amdnpu/17f0_11/npu_7.sbin` (v1.1.2.65). The firmware binary is a flat binary loaded into IPU SRAM. The serialization gate is enforced at two levels: (1) the firmware's scheduler enforces `"Application %u is not the last scheduled"` checks, and (2) the kernel driver's `ve2_mgmt_schedule_cmd()` -> `notify_fw_cmd_ready()` path serializes via an event-generation register (`VE2_EVENT_GENERATE_REG = 0x00034008`) with the `VE2_USER_EVENT_ID=0xB6` doorbell.

**Tech Stack:** Python3, xxd, binwalk, firmware binary from `/lib/firmware/amdnpu/`, kernel driver source from `github.com/amd/xdna-driver`, npu7_regs.h, ve2_mgmt.c/ve2_hwctx.c/ve2_fw.c

---

## What We Know Already

From the kernel driver source code:

### Mailbox Protocol
- **HSA Queue mechanism**: Host writes packets to the write_index ring; firmware reads via read_index
- **Doorbell/completion**: Writing `0xB6` to `0x00034008` (VE2_EVENT_GENERATE_REG) wakes the IPU
- **Completion detection**: Driver polls `HSA_QUEUE_READ_INDEX_OFFSET` via `check_read_index()`
- **Handshake init**: `ve2_partition_initialize()` + `ve2_partition_uc_wakeup()`

### FIFO Scheduling (kernel side)
- `ve2_mgmt_schedule_cmd()` enqueues into `mgmtctx->ctx_command_fifo_head`
- If no active context, does handshake init. If different context, marks for context switch.
- **Key bottleneck**: Only ONE active context per partition (`mgmtctx->active_ctx`)
- The `notify_fw_cmd_ready()` doorbell fires per submitted command

### Firmware Side
- Strings confirm: `"Application %u is not the last scheduled. The last scheduled was %d."`
- String at offset `0x1e655` with format specifiers `%u` (app_id) and `%d` (last_scheduled)
- Related strings: `"Failed to get last executed app_id"`, `"Application %u is not allocated"`, `"context_priority:%u"`
- IPU ISA: 32-bit RISC-like, heavy opcode 0x00 (1497/1832 = 81.6%), no RISC-V opcode match

### The Serialization Stack
```
Userspace  →  DRM_IOCTL_AMDXDNA_EXEC_CMD  →  driver amdxdna_ctx.c
Driver     →  amdxdna_cmd_submit()         →  ve2_cmd_submit()
           →  ve2_mgmt_schedule_cmd()      →  notify_fw_cmd_ready()
Firmware   →  Event 0xB6 handler           →  "not the last scheduled" check
           →  Power gate DLDO/ONO sequence  →  AIE execution
```

---

## Task 1: Create Firmware Research Toolkit

**Files:**
- Create: `/home/bcloud/npu_re_workspace/tools/ipu_isa_analyzer.py`
- Create: `/home/bcloud/npu_re_workspace/tools/fw_string_extractor.py`
- Create: `/home/bcloud/npu_re_workspace/tools/code_block_finder.py`
- Data: `/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin`

- [ ] **Step 1: Create the IPU ISA analyzer that identifies instruction boundaries**

```python
#!/usr/bin/env python3
"""
ipu_isa_analyzer.py - Analyze VE2 IPU firmware to identify instruction formats.
The IPU uses a custom 32-bit RISC-like ISA. We analyze opcode distributions,
identify instruction boundaries, and find patterns matching known control flow.
"""
import struct
import sys

FW_PATH = '/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin'
CODE_START = 0x220
CODE_END_CANDIDATES = [0x1c000, 0x1d000]  # Before string tables

def load_fw(path=FW_PATH):
    with open(path, 'rb') as f:
        return f.read()

def analyze_opcodes(data, start, end):
    """Analyze 32-bit instruction opcode distribution."""
    opcodes_4bit = {}
    opcodes_7bit = {}
    opcodes_5bit = {}
    func3_map = {}
    
    for addr in range(start, min(end, len(data)), 4):
        instr = struct.unpack('<I', data[addr:addr+4])[0]
        op4 = instr & 0xf
        op5 = instr & 0x1f
        op7 = instr & 0x7f
        
        opcodes_4bit[op4] = opcodes_4bit.get(op4, 0) + 1
        opcodes_5bit[op5] = opcodes_5bit.get(op5, 0) + 1
        opcodes_7bit[op7] = opcodes_7bit.get(op7, 0) + 1
        
        # Check for I-type like: [imm12][rs1][func3][rd][opcode]
        func3 = (instr >> 12) & 0x7
        if op7 == 0x13:  # typical RISC-V OP-IMM
            func3_map[func3] = func3_map.get(func3, 0) + 1
    
    print(f"=== Opcode Analysis ({start:#x}-{end:#x}) ===")
    print(f"\n4-bit opcodes (16 total):")
    for k in sorted(opcodes_4bit.keys()):
        pct = opcodes_4bit[k] / sum(opcodes_4bit.values()) * 100
        print(f"  0x{k:x}: {opcodes_4bit[k]:5d} ({pct:.1f}%)")
    
    print(f"\n5-bit opcodes (32 total):")
    for k in sorted(opcodes_5bit.keys()):
        pct = opcodes_5bit[k] / sum(opcodes_5bit.values()) * 100
        print(f"  0x{k:02x}: {opcodes_5bit[k]:5d} ({pct:.1f}%)")
    
    print(f"\n7-bit opcodes (128 total):")
    for k in sorted(opcodes_7bit.keys()):
        pct = opcodes_7bit[k] / sum(opcodes_7bit.values()) * 100
        print(f"  0x{k:02x}: {opcodes_7bit[k]:5d} ({pct:.1f}%)")
    
    print(f"\nTotal instructions: {sum(opcodes_7bit.values())}")
    
    # Heatmap: find regions dominated by specific opcodes
    print(f"\n=== Opcode heatmap (0x220-0x1c000, 256B blocks) ===")
    block_size = 256
    for block_start in range(start, min(end, start + 0x4000), block_size):
        block_end = min(block_start + block_size, end)
        counts = {}
        for addr in range(block_start, block_end, 4):
            instr = struct.unpack('<I', data[addr:addr+4])[0]
            op4 = instr & 0xf
            counts[op4] = counts.get(op4, 0) + 1
        dominant = max(counts, key=counts.get)
        total = sum(counts.values())
        if total > 0:
            print(f"  0x{block_start:05x}: dominant op4=0x{dominant:x} ({counts[dominant]}/{total})")
    
    return opcodes_7bit

def find_instruction_boundaries(data, start, end):
    """
    Search for patterns suggesting multi-byte instruction bundles.
    VE2 IPU likely has a VLIW-like format. Looking for patterns where
    instruction density changes, suggesting different slot widths.
    """
    print(f"\n=== Instruction Boundary Analysis ===")
    
    # Look for patterns where every Nth byte has a similar value
    # (suggests a fixed-width instruction)
    for width in [2, 4, 6, 8]:
        aligned = 0
        misaligned = 0
        for addr in range(start, min(end - width, start + 0x10000), 1):
            # Check if addr is aligned to width
            if addr % width == 0:
                aligned += 1
            else:
                misaligned += 1
        # Actually check if opcode bits follow alignment
        zero_op = 0
        nonzero_op = 0
        for addr in range(start, min(end - 4, start + 0x10000), width if width <= 4 else 4):
            instr = struct.unpack('<I', data[addr:addr+4])[0]
            if (instr & 0x7f) == 0:
                zero_op += 1
            else:
                nonzero_op += 1
        if zero_op > 0:
            print(f"  Width {width}: {nonzero_op} non-zero / {zero_op} zero opcodes")
    
    return

def identify_functions(data, start, end):
    """
    Identify function boundaries by looking for common prologue patterns
    and branch target alignment. RISC prologues often include:
    - addi sp, sp, -N  (stack frame)
    - sw ra, offset(sp) (save return address)
    - sw s0, offset(sp)
    """
    print(f"\n=== Function Prologue Search ===")
    
    # In the VE2 IPU ISA, look for patterns that look like CALL/RET sequences
    # CALL instructions reference nearby addresses
    # RET instructions are often a single instruction
    
    # Search for RET-like patterns (instructions with opcode that might be JALR zero, ra, 0)
    ret_count = 0
    call_count = 0
    
    for addr in range(start, min(end - 4, start + 0x20000), 4):
        instr = struct.unpack('<I', data[addr:addr+4])[0]
        # RISC-V JALR rd, rs1, imm has opcode 0x67
        # A return is JALR x0, x1, 0 which is 0x00008067
        # Let's check for similar patterns
        
        # Branch-like: check if bits indicate control flow
        op7 = instr & 0x7f
        if op7 in [0x63, 0x67, 0x6F]:  # BRANCH, JALR, JAL
            call_count += 1
    
    print(f"  Potential call/branch instructions: {call_count}")
    
    # Now let's find control flow graph edges
    # Look for branches to nearby addresses
    for addr in range(start, min(end - 4, start + 0x20000), 4):
        instr = struct.unpack('<I', data[addr:addr+4])[0]
        op7 = instr & 0x7f
        
        if op7 == 0x6F:  # JAL (jump and link)
            # RISC-V JAL format: [imm20|rd|opcode]
            # imm[20|10:1|11|19:12]
            imm20 = ((instr >> 12) & 0xff) << 12  # simplified
            target = addr + 4 + imm20
            if start <= target < end:
                pass  # potential call target
    
    return

if __name__ == '__main__':
    data = load_fw()
    analyze_opcodes(data, CODE_START, 0x10000)
    find_instruction_boundaries(data, CODE_START, 0x10000)
    identify_functions(data, CODE_START, 0x10000)
```

- [ ] **Step 2: Test run the analyzer**

```bash
cd /home/bcloud/npu_re_workspace && python3 tools/ipu_isa_analyzer.py 2>&1 | head -60
```

Expected output: Opcode distribution showing whether the ISA is 4-bit, 5-bit, or 7-bit opcode based, and heatmap showing code vs. data regions.

- [ ] **Step 3: Create string reference tracker that maps format strings to code addresses**

```python
#!/usr/bin/env python3
"""
fw_string_extractor.py - Extract all debug/format strings from NPU firmware
and map string addresses to code locations for Ghidra/RE import.
"""
import struct
import os

FW_PATH = '/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin'

def extract_strings(data):
    """Find all printable strings > 4 chars in length."""
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            start = i
            while i < len(data) and 32 <= data[i] < 127:
                i += 1
            s = data[start:i].decode('ascii', errors='replace')
            if len(s) >= 6:
                strings.append((start, s))
        else:
            i += 1
    return strings

def find_string_references(data, strings, code_start=0x220, code_end=0x1c000):
    """Find all 32-bit references to each string address within the code section."""
    print("=== String Reference Map ===")
    print(f"{'Address':<10} {'String':<60} {'Code References'}")
    print("-" * 100)
    
    for addr, s in strings:
        # Skip very short strings and non-semantic strings
        if len(s) < 8 or s.startswith(('.', '@', '/', '*', '=')):
            continue
        
        # Search for this string's address as a 32-bit value in code
        refs = []
        for code_addr in range(code_start, min(code_end, len(data) - 4), 4):
            val = struct.unpack('<I', data[code_addr:code_addr+4])[0]
            if val == addr:
                refs.append(code_addr)
        
        if refs:
            ref_str = ', '.join(f'0x{r:x}' for r in refs[:5])
            if len(refs) > 5:
                ref_str += f'... (+{len(refs)-5})'
            print(f"0x{addr:<06x} {s[:58]:<60} {ref_str}")

    # Also search for partial references (PC-relative offsets)
    print(f"\n=== PC-Relative Reference Candidates ===")
    # Some firmware uses PC-relative addressing where the instruction
    # encodes the offset from the current PC to the string
    for code_addr in range(code_start, min(code_end, len(data) - 4), 4):
        instr = struct.unpack('<I', data[code_addr:code_addr+4])[0]
        op7 = instr & 0x7f
        
        # Check for LUI/ADDI-like instructions that might form a string address
        # RISC-V LUI rd, imm20 has opcode 0x37
        if op7 == 0x37:  # LUI
            imm20 = instr >> 12
            target = imm20 << 12
            for str_addr, s in strings:
                if abs(target - str_addr) < 0x1000 and len(s) >= 8:
                    print(f"  LUI at 0x{code_addr:05x} -> possible string at 0x{str_addr:05x}: '{s[:50]}'")
                    break

if __name__ == '__main__':
    with open(FW_PATH, 'rb') as f:
        data = f.read()
    
    strings = extract_strings(data)
    find_string_references(data, strings)
```

- [ ] **Step 4: Create code block finder for the scheduler region**

```python
#!/usr/bin/env python3
"""
code_block_finder.py - Disassemble the region around the scheduler check
code that uses the "not the last scheduled" string.
"""
import struct

FW_PATH = '/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin"

def find_region_around_string(data, str_addr, radius=0x800):
    """Find and dump the code region surrounding a string reference."""
    start = max(0x220, str_addr - radius)
    end = min(len(data), str_addr + radius)
    
    print(f"=== Region around string at 0x{str_addr:x} ===")
    print(f"Code range: 0x{start:x} - 0x{end:x} ({end-start} bytes)\n")
    
    # Dump raw hex with alignment
    for addr in range(start, end, 16):
        chunk = data[addr:addr+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        marker = "  ← STR" if addr == str_addr else ""
        if any(32 <= b < 127 for b in chunk[:4]) and len(chunk) == 16:
            printable_count = sum(1 for b in chunk if 32 <= b < 127)
            if printable_count > 8:
                marker = "  ← STR+"
        print(f"0x{addr:05x}: {hex_part}  {ascii_part}{marker}")

def find_adjacent_code_patterns(data, str_addr):
    """
    The scheduler code calls a function that checks app_id vs last_scheduled.
    Find:
    1. The format string reference (LUI + ADDI or similar)
    2. The function call near the reference
    3. The branch condition that skips the error
    4. The error logging function
    
    The region around 0x1e5f0-0x1e6b0 has the scheduler strings. Code
    referencing them should be at most 0x1000-0x2000 bytes before (since
    firmware uses LUI+ADDI or similar to compute string addresses).
    """
    print(f"\n=== Searching for branch/compare near scheduler strings ===")
    
    # Search in the code region (0x220 to 0x1c000) for patterns that
    # reference the "not the last scheduled" string address
    target = str_addr
    
    for code_addr in range(0x220, 0x1c000, 4):
        instr = struct.unpack('<I', data[code_addr:code_addr+4])[0]
        
        # Check if this instruction loads a value close to the string address
        op7 = instr & 0x7f
        rd = (instr >> 7) & 0x1f
        rs1 = (instr >> 15) & 0x1f
        imm12 = (instr >> 20) & 0xfff
        
        # ADDI rd, rs1, imm12 (opcode 0x13, func3=0)
        if op7 == 0x13 and ((instr >> 12) & 0x7) == 0:
            # Check if rd + imm might be our string address
            # We'd need to track register values, but for now:
            pass
    
    # Alternative: search for the file-offset reference pattern
    # In flat binaries without relocations, strings may be referenced by
    # their raw file offset if the binary is loaded at base addr 0x0
    print(f"\nSearching for hardcoded offset 0x{target:x} in code...")
    for code_addr in range(0x220, 0x1c000, 4):
        val = struct.unpack('<I', data[code_addr:code_addr+4])[0]
        if 0x1e000 <= val <= 0x1f000 and val < len(data):
            # This might be a reference to the string table
            pass

if __name__ == '__main__':
    with open(FW_PATH, 'rb') as f:
        data = f.read()
    
    # The scheduler strings are in the 0x1e600-0x1e750 range
    # Dump the entire scheduler region
    find_region_around_string(data, 0x1e600, 0x100)
    
    print("\n")
    find_region_around_string(data, 0x1e655, 0x20)
```

- [ ] **Step 5: Commit analysis tools**

```bash
cd /home/bcloud/npu_re_workspace
git add tools/
git commit -m "feat: add firmware RE analysis toolkit (ISA analyzer, string extractor, code finder)"
```

---

## Task 2: Map the IPU Instruction Set Architecture

**Files:**
- Create: `/home/bcloud/npu_re_workspace/data/isa_map.md`
- Data: `/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin`

- [ ] **Step 1: Run comprehensive opcode analysis**

```bash
cd /home/bcloud/npu_re_workspace && python3 tools/ipu_isa_analyzer.py > data/opcode_analysis.txt 2>&1
cat data/opcode_analysis.txt
```

Analyze the output to determine:
- Is the ISA 32-bit fixed-width? (dominant opcode patterns)
- Is it VLIW with slots? (variation in instruction encoding)
- What are the opcode groups? (ALU, memory, branch, CSR)

- [ ] **Step 2: Identify R-type, I-type, S-type, B-type, U-type, J-type formats**

Based on the opcode analysis, test each format against real instruction sequences:

```python
#!/usr/bin/env python3
"""Test different instruction format hypotheses against the firmware binary."""
import struct

PROBES = [
    (0x220, "First 4 instructions - likely entry point"),
    (0x2a0, "After entry point - initialization"),
    (0x10000, "Mid-section - likely scheduler code"),
    (0x1c000, "Near end of code section"),
]

def try_riscv_decode(data, addr):
    """Try decoding instruction as RISC-V-like format."""
    instr = struct.unpack('<I', data[addr:addr+4])[0]
    opcode = instr & 0x7f
    
    # RISC-V opcode map
    op_names = {
        0x13: "OP-IMM", 0x33: "OP", 0x03: "LOAD",
        0x23: "STORE", 0x63: "BRANCH", 0x67: "JALR",
        0x6F: "JAL", 0x37: "LUI", 0x17: "AUIPC", 0x73: "SYSTEM"
    }
    
    # Decode I-type: [imm12][rs1][func3][rd][opcode]
    opname = op_names.get(opcode, f"UNK(0x{opcode:02x})")
    rd = (instr >> 7) & 0x1f
    func3 = (instr >> 12) & 0x7
    rs1 = (instr >> 15) & 0x1f
    imm = (instr >> 20) & 0xfff
    
    return f"0x{addr:05x}: [{opname:8s}] rd=x{rd:02d} rs1=x{rs1:02d} func3={func3:d} imm12=0x{imm:03x} (raw=0x{instr:08x})"

for addr, desc in PROBES:
    print(f"\n=== {desc} (0x{addr:x}) ===")
    for offset in range(0, 32, 4):
        print(try_riscv_decode(data, addr + offset))
```

- [ ] **Step 3: Document the ISA format**

```markdown
# VE2 IPU ISA Map

## Observations

[Fill in from analysis output]

## Instruction Formats

### R-type (Register)
[Format description]

### I-type (Immediate)
[Format description]

### B-type (Branch)
[Format description with displacement encoding]

## Register File
[Identified registers]

## Control Flow Instructions
- Branch conditions
- Call/Return mechanism
- PC-relative jumps
```

- [ ] **Step 4: Commit ISA documentation**

```bash
cd /home/bcloud/npu_re_workspace
git add data/
git commit -m "feat: initial VE2 IPU ISA mapping complete"
```

---

## Task 3: Locate the Serialization Gate in Firmware

**Files:**
- Modify: `/home/bcloud/npu_re_workspace/tools/code_block_finder.py`
- Create: `/home/bcloud/npu_re_workspace/tools/scheduler_analyzer.py`

- [ ] **Step 1: Find cross-references to the "not the last scheduled" string**

```bash
cd /home/bcloud/npu_re_workspace && python3 tools/fw_string_extractor.py 2>&1 | grep -i "not the last\|last scheduled\|last executed\|last_app\|last_app_id\|app_id"
```

If no direct references found (expected for PC-relative encoding), search for the string address in instruction immediates.

- [ ] **Step 2: Build the scheduler analyzer**

```python
#!/usr/bin/env python3
"""
scheduler_analyzer.py - Decode the scheduler logic around the
"not the last scheduled" string to find the branch we need to patch.
"""
import struct

FW_PATH = '/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin'

# Known scheduler string addresses (from firmware dump)
SCHEDULER_STRINGS = {
    0x1e5f1: "Application %u is not allocated",
    0x1e616: "Failed to get last executed app_id",
    0x1e63f: "Application %u is not the last scheduled. The last scheduled was %d.",
    0x1e689: "create_context",
    0x1e699: "numcol:%u",
    0x1e6a4: "unused start col:%u",
    0x1e6b9: "num command queue pairs requested:%u",
    0x1e6df: "num pdi ids:%u",
    0x1e6ef: "pasid:%u",
    0x1e6f9: "sec comm target type:%u",
    0x1e712: "context_priority:%u",
}

def scan_scheduler_code(data):
    """Scan the code section for references to scheduler strings."""
    code_start = 0x220
    code_end = 0x1c000
    
    print("=== Scheduler Code Scan ===")
    
    # For each string address, search for it in LUI instructions
    # LUI format: [imm20][rd][opcode=0x37]
    # imm20 = upper 20 bits of the address
    
    for str_addr, str_name in sorted(SCHEDULER_STRINGS.items()):
        # The LUI would load the upper 20 bits of the string address
        upper = (str_addr >> 12) & 0xfffff
        
        print(f"\n--- String: 0x{str_addr:05x} '{str_name}' ---")
        print(f"  LUI imm20 target: 0x{upper:05x}")
        
        # Search for LUI or similar instruction loading this value
        found_once = False
        for code_addr in range(code_start, code_end, 4):
            instr = struct.unpack('<I', data[code_addr:code_addr+4])[0]
            
            # Test various opcode patterns
            op7 = instr & 0x7f
            op5 = instr & 0x1f
            
            # Pattern 1: Direct 32-bit reference (no fixups in flat binary)
            if (instr >> 12) == upper or instr == str_addr:
                if not found_once:
                    print(f"  [DIRECT] Found reference at 0x{code_addr:05x}: 0x{instr:08x}")
                    found_once = True
            
            # Pattern 2: LUI-like (opcode 0x37 in RISC-V)
            if op7 == 0x37:
                imm20 = instr >> 12
                if imm20 == upper or abs(imm20 - upper) <= 1:
                    rd = (instr >> 7) & 0x1f
                    print(f"  [LUI-like] At 0x{code_addr:05x}: rd=x{rd:02d} imm20=0x{imm20:05x}")
                    # Show next instruction (should be ADDI for low bits)
                    if code_addr + 4 < code_end:
                        next_instr = struct.unpack('<I', data[code_addr+4:code_addr+8])[0]
                        print(f"    Next instr: 0x{next_instr:08x}")
                    found_once = True

def find_compare_sequence(data):
    """
    Find the comparison sequence: app_id != last_app_id → branch to error.
    Pattern: LUI (load string addr) + ADDI + CALL or BNE/BEQ + error
    """
    print("\n\n=== Find Comparison + Branch Pattern ===")
    code_start = 0x220
    code_end = 0x1c000
    
    # The comparison instruction will compare two registers
    # Branch-if-not-equal would go to error handling code
    
    for addr in range(code_start, code_end, 4):
        instr = struct.unpack('<I', data[addr:addr+4])[0]
        op7 = instr & 0x7f
        func3 = (instr >> 12) & 0x7
        
        # B-type branches: opcode 0x63
        if op7 == 0x63:
            rs2 = (instr >> 20) & 0x1f
            rs1 = (instr >> 15) & 0x1f
            
            # BEQ (func3=0) or BNE (func3=1)
            if func3 == 0:
                btype = "BEQ"
            elif func3 == 1:
                btype = "BNE"
            else:
                continue
            
            # Extract B-immediate (RISC-V format)
            b_imm = ((instr >> 7) & 0x1) << 11  # bit 11
            b_imm |= ((instr >> 8) & 0xf) << 1   # bits 4:1
            b_imm |= ((instr >> 25) & 0x3f) << 5 # bits 10:5
            b_imm |= ((instr >> 31) & 0x1) << 12 # bit 12
            
            # Sign extend
            if b_imm & 0x1000:
                b_imm -= 0x2000
            
            target = addr + 4 + b_imm
            
            # Check if this branch targets near the scheduler error strings
            # The error handler should be within -0x100 to +0x100 of a
            # LUI reference to the scheduler strings
            if 0x1e000 <= target <= 0x1f000 or target < code_start or target >= code_end:
                continue
            
            # Check if nearby code references scheduler strings
            for check in range(max(code_start, target - 64), min(code_end, target + 64), 4):
                check_instr = struct.unpack('<I', data[check:check+4])[0]
                for str_addr in SCHEDULER_STRINGS:
                    upper = (str_addr >> 12) & 0xfffff
                    if (check_instr >> 12) == upper or check_instr == str_addr:
                        print(f"  {btype} at 0x{addr:05x}: rs1=x{rs1:02d} rs2=x{rs2:02d} target=0x{target:05x}")
                        print(f"    -> References string 0x{str_addr:05x} nearby")
                        break
    
    return

if __name__ == '__main__':
    with open(FW_PATH, 'rb') as f:
        data = f.read()
    
    scan_scheduler_code(data)
    find_compare_sequence(data)
```

- [ ] **Step 3: Run the scheduler analyzer and identify the exact branch**

```bash
cd /home/bcloud/npu_re_workspace && python3 tools/scheduler_analyzer.py 2>&1
```

- [ ] **Step 4: Commit scheduling gate findings**

```bash
cd /home/bcloud/npu_re_workspace
git add tools/scheduler_analyzer.py data/
git commit -m "feat: located serialization branch in firmware scheduler"
```

---

## Task 4: Validate Against Kernel Driver FIFO + Doorbell Path

**Files:**
- Create: `/home/bcloud/npu_re_workspace/tools/doorbell_tracer.py`
- Create: `/home/bcloud/npu_re_workspace/docs/full_stack_path.md`

- [ ] **Step 1: Trace the complete submission path end-to-end and document**

Read and document the full path from userspace IOCTL → kernel FIFO → doorbell → firmware scheduler:

```bash
# The path is:
# 1. userspace: xrt::run::start() → hwqueue::submit() → DRM_IOCTL_AMDXDNA_EXEC_CMD
# 2. kernel: amdxdna_drm_submit_cmd_ioctl() → amdxdna_drm_submit_execbuf() → amdxdna_cmd_submit() → ve2_cmd_submit() → ve2_mgmt_schedule_cmd()
# 3. kernel FIFO: ve2_fifo_enqueue() on mgmtctx->ctx_command_fifo_head
# 4. kernel doorbell: notify_fw_cmd_ready() → write VE2_USER_EVENT_ID (0xB6) to VE2_EVENT_GENERATE_REG (0x00034008)
# 5. firmware: event 0xB6 handler → read HSA queue → "not the last scheduled" gate → column power gates (DLDO/ONO) → AIE execution
# 6. firmware completion: write read_index → IRQ → driver check_read_index() → WAIT_CMD returns
#
# The FIRMWARE GATE is at step 5: the IPU firmware checks 
# last_executed_app_id against the current app's ID before proceeding.
```

- [ ] **Step 2: Document the full serialization stack**

```markdown
# Full-Stack NPU Serialization Path

## Userspace (XRT SHIM)
- File: `/opt/xilinx/xrt/lib64/libxrt_driver_xdna.so.2.23.0`
- Class: `shim_xdna::hwctx` / `