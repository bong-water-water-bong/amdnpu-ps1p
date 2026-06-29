#!/usr/bin/env python3
"""
Serialization Gate Analyzer for Strix Halo NPU Firmware.

This tool:
1. Locates the scheduling string references in the firmware
2. Traces backward to find the comparison/branch logic
3. Disassembles the region around the gate
4. Identifies the specific branch that enforces serialization
5. Suggests patch locations
"""

import struct
import sys
from ipu_disasm import decode_16bit, disassemble_range

# The key scheduling strings in the firmware
SCHED_STRINGS = {
    0x1e5f0: "%s: Application %u is not allocated.",
    0x1e616: "%s: Failed to get last executed app_id.",
    0x1e63f: "%s: Application %u is not the last scheduled. The last scheduled was %d.",
    0x1e689: "create_context",
    0x1e6b9: "num command queue pairs requested:%u",
    0x1e6df: "num pdi ids:%u",
    0x1e6f9: "sec comm target type:%u",
    0x1e712: "context_priority:%u",
    0x1e769: "delete_context",
    0x1e7dc: "Failed to retrieve last executed app id",
    0x1e5ef: "",
    0x1e5f9: "cation %u is not allocated.",
    0x1e612: "d.",
    0x1e627: " last executed app_id.",
    0x1e633: "ed app_id.",
    0x1e669: "ed. The last scheduled was %d.",
    0x1e679: "eduled was %d.",
}

def find_string_references(data):
    """Find all literal pool entries that reference scheduling strings."""
    code = data[0x220:0x1c000]
    refs = {}
    
    for addr in range(0x220, 0x1c000, 4):
        val = struct.unpack('<I', data[addr:addr+4])[0]
        if val in SCHED_STRINGS:
            refs[addr] = (val, SCHED_STRINGS[val])
    
    return refs

def find_gate_region(data):
    """Find the region containing serialization gate logic."""
    code = data[0x220:0x1c000]
    
    # Find where the "not the last scheduled" string refs are
    refs = find_string_references(data)
    
    # Group references by proximity to find function boundaries
    ref_addrs = sorted(refs.keys())
    
    if not ref_addrs:
        print("No scheduling string references found!")
        return None
    
    print(f"Found {len(ref_addrs)} scheduling string references:")
    for addr in ref_addrs:
        val, s = refs[addr]
        print(f"  0x{addr:05x}: refs string at 0x{val:05x} -> \"{s}\"")
    
    # The refs cluster around the error logging function
    # Find the tightest cluster
    min_addr = min(ref_addrs)
    max_addr = max(ref_addrs)
    
    return (min_addr - 0x200, max_addr + 0x200)  # buffer around the cluster

def disassemble_gate(data, output_file="data/gate_disassembly.txt"):
    """Disassemble the serialization gate region."""
    region = find_gate_region(data)
    if not region:
        return
    
    start, end = region
    start = max(0x220, start)
    end = min(0x1c000, end)
    
    print(f"\nDisassembling gate region: 0x{start:05x} - 0x{end:05x}")
    lines = disassemble_range(data, start, end)
    
    with open(output_file, 'w') as f:
        f.write(f"; VE2 IPU Firmware - Serialization Gate Disassembly\n")
        f.write(f"; Region: 0x{start:05x} - 0x{end:05x}\n")
        f.write(f"; Target string references:\n")
        for addr, (val, s) in sorted(find_string_references(data).items()):
            f.write(f";   0x{addr:05x} -> 0x{val:05x}: {s}\n")
        f.write(f"; Decoded as dual-issue 16-bit VLIW ISA\n")
        f.write(f"; Format: addr: 32bit_hex  lo_mnem | hi_mnem\n\n")
        
        for line in lines:
            f.write(line + "\n")
    
    print(f"Disassembly written to {output_file}")
    return output_file

def find_conditional_branch(data, gate_start, gate_end):
    """
    Locate the conditional branch that gates serialization.
    
    The serialization logic should look like:
      1. Load last_executed_app_id from memory
      2. Load current app_id
      3. Compare (sub/cmp) 
      4. Conditional branch to error handler if mismatch
      5. Otherwise continue with command processing
    
    Search for branch-like instructions (op4=7 or op4=8) that 
    jump to the error logging function (where the string refs are).
    """
    code = data[0x220:0x1c000]
    
    candidates = []
    for addr in range(max(0x220, gate_start - 0x400), gate_start, 4):
        instr = struct.unpack('<I', code[addr-0x220:addr-0x220+4])[0]
        lo = instr & 0xffff
        hi = (instr >> 16) & 0xffff
        
        # Look for branch instructions in both slots
        for hw, slot_name in [(lo, "lo"), (hi, "hi")]:
            op4 = (hw >> 12) & 0xf
            sub4 = (hw >> 8) & 0xf
            
            # Conditional branches are likely op4=7 (bne) or op4=8 (beq)
            if op4 in [7, 8]:
                target = hw & 0xff  # potential offset
                # Check if target is within reasonable branch range
                if 0x30 <= target <= 0x100:
                    candidates.append({
                        'addr': addr,
                        'slot': slot_name,
                        'op4': op4,
                        'target_offset': target,
                        'instr': instr,
                        'hw': hw,
                    })
    
    return candidates

def suggest_patch(data, branch_candidates):
    """Suggest which instruction to patch and with what value."""
    if not branch_candidates:
        print("No branch candidates found.")
        return
    
    print(f"\n=== Branch Candidates ===")
    for bc in branch_candidates:
        print(f"  0x{bc['addr']:05x} ({bc['slot']}): "
              f"op4={bc['op4']} target_offset=0x{bc['target_offset']:02x} "
              f"0x{bc['instr']:08x}")

def main():
    firmware_path = "/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin"
    
    with open(firmware_path, 'rb') as f:
        data = f.read()
    
    print(f"Firmware: {firmware_path} ({len(data)} bytes)")
    
    # Step 1: Find string references
    region = find_gate_region(data)
    
    # Step 2: Disassemble the gate region
    if region:
        disassemble_gate(data)
        
        # Step 3: Find conditional branches
        candidates = find_conditional_branch(data, *region)
        suggest_patch(data, candidates)

if __name__ == '__main__':
    main()
