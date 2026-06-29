#!/usr/bin/env python3
"""
VE2 IPU Firmware Serialization Gate Patcher
============================================
Patches the "not the last scheduled application" check in the NPU firmware
to allow concurrent access.

Strategy:
---------
The firmware contains a check that rejects command execution if the
requesting application is not the "last scheduled application". The error
message is: "%s: Application %%u is not the last scheduled. The last
scheduled was %%d."

We cannot NOP out the error message directly - it's embedded in a VLIW
instruction packet with hardware dependency tracking. Instead, we patch
the CONDITIONAL BRANCH that triggers the error path so it ALWAYS falls
through to the success path.

PATCHING STRATEGY (VLIW-aware):
-------------------------------
The error condition is: if (current_app_id != last_scheduled_app_id)
                             branch to error_handler

We need to either:
A) Invert the branch condition (BNE -> BEQ or vice versa)
B) Replace the branch with NOP (always fall through)
C) Change the branch target to skip the error log (jump past it)

The safest approach: identify the BNE/BNE instruction that branches
to the error path and replace it with NOP (0x0000 in the relevant slot).

FINDING THE BRANCH:
-------------------
The error string references are in the literal pool.
The function that CALLS the error log will have:
- A LOAD of the app_id registers
- A CMP/SUB of the two values
- A conditional branch preceding the error log call

FIRMWARE LOAD ADDRESS:
---------------------
The firmware is loaded at address 0 (file offset = virtual address).
The code section is at file offset 0x220, corresponding to address 0x220.
"""

import struct
import os

def load_firmware(path="/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin"):
    with open(path, 'rb') as f:
        return f.read()

def save_firmware(data, path):
    with open(path, 'wb') as f:
        f.write(data)

def find_string_references(data):
    """Find all code locations that reference scheduling strings."""
    sched_strings = {
        0x1e5ef: "%s: Application %u is not allocated.",
        0x1e5f0: "s: Application %u is not allocated.",
        0x1e616: "%s: Failed to get last executed app_id.",
        0x1e63f: "%s: Application %u is not the last scheduled. The last scheduled was %d.",
    }
    refs = []
    for addr in range(0x220, 0x1c000, 4):
        val = struct.unpack('<I', data[addr:addr+4])[0]
        if val in sched_strings:
            refs.append((addr, val, sched_strings[val]))
    return refs

def find_error_log_function(data, verbose=True):
    """Find the error logging function by locating string literal references."""
    refs = find_string_references(data)
    
    if verbose:
        print(f"Found {len(refs)} scheduling string literal references:")
        for addr, val, s in sorted(refs):
            print(f"  0x{addr:05x}: 0x{val:05x} -> \"{s[:60]}...\"")
    
    if not refs:
        print("ERROR: No scheduling string references found!")
        return None
    
    # Find the function boundaries around the main literal block
    # The scheduling strings at 0x1e5f0-0x1e6xx are referenced from code
    # at addresses 0x3280-0x33a0
    
    # Find min and max reference addresses to define the function region
    ref_addrs = sorted([r[0] for r in refs])
    min_ref = min(ref_addrs)
    max_ref = max(ref_addrs)
    
    if verbose:
        print(f"\nLiteral pool region: 0x{min_ref:05x} - 0x{max_ref:05x}")
        print(f"Searching for callers of this function...")
    
    # Find CALL instructions that target this region
    # CALL format: hi16 has pattern 0x0cXX (or lo16)
    callers = []
    for addr in range(0x220, min_ref - 0x10, 4):
        instr = struct.unpack('<I', data[addr:addr+4])[0]
        lo = instr & 0xffff
        hi = (instr >> 16) & 0xffff
        
        for hw, name in [(lo, "lo"), (hi, "hi")]:
            op4 = hw >> 12
            sub4 = (hw >> 8) & 0xf
            if op4 == 0 and sub4 == 0xc:
                # CALL instruction encoding: 0x0cXX where the target is computed
                # The full target = 0x3000 + (hw & 0xff) * 32  ??
                # Or simpler: the low byte encodes page/offset within page
                low_bits = hw & 0xff
                # Check if this calls INTO our literal pool region
                # Estimate target from low_bits
                estimated_target = 0x3000 + low_bits * 0x40  # rough
                if 0x3000 <= estimated_target <= 0x3a00:
                    callers.append((addr, name, hw, estimated_target))
    
    if verbose:
        if callers:
            print(f"\nPotential callers of error log function:")
            for addr, name, hw, target in callers:
                print(f"  0x{addr:05x} ({name}): 0x{hw:04x} -> ~0x{target:04x}")
        else:
            print(f"  No clear callers found (expected for VLIW)")
    
    return (min_ref, max_ref)

def find_patch_candidates(data, lit_pool_start, lit_pool_end, verbose=True):
    """
    Find conditional branches that lead to the error path.
    
    In a VLIW architecture, the pattern would be:
    [instruction sequence]
    cmp rX, rY           ; compare current_app_id vs last_executed
    beq label_success     ; branch if EQUAL (skip error)
    [error logging code]  ; CALL to error function
    label_success:
    [normal execution]
    
    OR the inverse:
    cmp rX, rY
    bne label_error       ; branch if NOT EQUAL (go to error)
    [normal execution]
    ...
    label_error:
    [error logging code]
    """
    
    # Since CALL patterns aren't standard, let me search differently.
    # The ERROR path includes LOADING the string constants.
    # The CALL to error function loads string addresses as LDI.
    # The conditional branch BEFORE the error path is what we want.
    
    # Search for code just before the literal pool that references
    # string constants and looks like error handling
    
    if verbose:
        print(f"\nSearching for patch candidates near literal pool...")
    
    data_array = data
    
    # Look for conditional branch instructions (op4=7 or op4=8) that
    # target addresses BEFORE where the error strings are loaded
    candidates = []
    
    for addr in range(lit_pool_start - 0x400, lit_pool_start, 4):
        instr = struct.unpack('<I', data_array[addr:addr+4])[0]
        lo = instr & 0xffff
        hi = (instr >> 16) & 0xffff
        
        for hw, name in [(lo, "lo"), (hi, "hi")]:
            op4 = hw >> 12
            
            # Conditional branch instructions (beq/bne)
            if op4 in [7, 8]:
                branch_offset = hw & 0x0f  # low 4 bits = offset
                sub4 = (hw >> 8) & 0xf
                r1 = (hw >> 4) & 0xf
                r2 = hw & 0xf
                
                candidates.append({
                    'addr': addr,
                    'slot': name,
                    'hw': hw,
                    'op4': op4,
                    'sub4': sub4,
                    'r1': r1,
                    'r2': r2,
                    'offset_low': branch_offset,
                    'instr': instr,
                    'type': 'beq' if op4 == 8 else 'bne',
                })
    
    if verbose:
        print(f"Found {len(candidates)} branch candidates before error function:")
        for c in candidates[:20]:
            print(f"  0x{c['addr']:05x} ({c['slot']}): 0x{c['hw']:04x} "
                  f"op4={c['op4']} sub4={c['sub4']} r1={c['r1']} r2={c['r2']}")
    
    return candidates

def suggest_patch(data, lit_pool, candidates):
    """
    Suggest the best branch to patch based on context analysis.
    """
    if not candidates:
        print("\nNO CANDIDATES FOUND - Need more ISA analysis")
        return None, None
    
    # Strategy: look at the first few candidates before the literal pool
    # The most likely candidate is a branch that:
    # 1. Is close to the literal pool (within 100 instructions)
    # 2. Has op4=7 (bne) - branch on NOT EQUAL -> error handler
    # 3. Is preceded by a compare instruction
    
    print(f"\n{'='*60}")
    print("PATCH RECOMMENDATION")
    print(f"{'='*60}")
    
    # Show the context around the top candidates
    for c in candidates[:5]:
        addr = c['addr']
        print(f"\nPotential patch at 0x{addr:05x} ({c['slot']}):")
        print(f"  Instruction: 0x{c['hw']:04x} (op4={c['op4']}, type={c['type']})")
        
        # Show 4 instructions before and after
        ctx_start = max(0x220, addr - 16)
        ctx_end = min(0x1c000, addr + 20)
        
        for a in range(ctx_start, ctx_end, 4):
            instr = struct.unpack('<I', data[a:a+4])[0]
            marker = " <-- CANDIDATE" if a == addr else ""
            print(f"   0x{a:05x}: 0x{instr:08x}{marker}")
    
    # For the PATCH: we want to NOP the conditional branch in the FIRMWARE
    # If it's a BNE (branch if NOT equal to error), we want to NOP it
    # so execution falls through to the success path
    
    # The actual patch value depends on the slot:
    # If candidate is in "lo" slot, set lo half to 0x0000 (NOP)
    # If candidate is in "hi" slot, set hi half to 0x0000 (NOP)
    
    print(f"\n{'='*60}")
    print("RECOMMENDED PATCH")
    print(f"{'='*60}")
    print("To disable the serialization gate, locate the conditional branch")
    print("that jumps to the error handler and replace it with NOP.")
    print("The branch will be similar to:")
    print("  bne rX, rY  ->  ERROR (not the last scheduled)")
    print("Replace with:")
    print("  nop               (always continue)")
    print()
    print("Search pattern: find 'bne' instruction (op4=7, sub4=3)")
    print("or 'beq' instruction (op4=8, sub4=0) near offset 0x2DD0-0x2E50")
    
    return candidates[0] if candidates else None


def apply_patch(data, target_addr, slot, new_lo=None, new_hi=None):
    """
    Apply a patch to the firmware at the given address.
    """
    offset = target_addr - 0x220
    instr = struct.unpack('<I', data[offset:offset+4])[0]
    lo = instr & 0xffff
    hi = (instr >> 16) & 0xffff
    
    if slot == "lo" and new_lo is not None:
        lo = new_lo
    elif slot == "hi" and new_hi is not None:
        hi = new_hi
    
    new_instr = (hi << 16) | lo
    data_array = bytearray(data)
    struct.pack_into('<I', data_array, offset, new_instr)
    
    return bytes(data_array)


def main():
    firmware_path = "/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin"
    
    print("VE2 IPU Firmware - Serialization Gate Patcher")
    print("=" * 60)
    print(f"Firmware: {firmware_path}")
    
    data = load_firmware(firmware_path)
    
    # Step 1: Find the error logging function
    print("\n[1] Locating scheduling string references...")
    lit_pool = find_error_log_function(data)
    
    if not lit_pool:
        return
    
    # Step 2: Find branch candidates
    print(f"\n[2] Finding conditional branches before error function...")
    candidates = find_patch_candidates(data, lit_pool[0] - 0x200, lit_pool[0] + 0x200)
    
    # Step 3: Suggest patch
    suggestion = suggest_patch(data, lit_pool, candidates)
    
    # Step 4: Generate patched firmware
    print(f"\n{'='*60}")
    print("GENERATING PATCH REPORT")
    print(f"{'='*60}")
    
    # Save a report of what we found
    report = f"""VE2 IPU Firmware Serialization Gate - Analysis Report
=======================================================
Firmware: {firmware_path}
Size: {len(data)} bytes

Scheduling string literal pool: 0x{lit_pool[0]:05x} - 0x{lit_pool[1]:05x}
Number of string references: {len(find_string_references(data))}

Key error message at file offset:
  0x1e5f0: "%s: Application %u is not allocated."
  0x1e616: "%s: Failed to get last executed app_id."
  0x1e63f: "%s: Application %%u is not the last scheduled. The last scheduled was %%d."

Patch Location (hypothesized):
  Conditional branch at ~0x2DD0-0x2E50 that gates the error path
  Replace the BNE/BEQ with NOP to bypass serialization check

PATCH INSTRUCTIONS:
1. Find the conditional branch instruction in the scheduler function
2. For 'bne rX, rY' -> nop: change hi or lo 16-bit half to 0x0000
3. For 'beq rX, rY' -> nop: change hi or lo 16-bit half to 0x0000
4. Save the patched firmware
5. Compute SHA256 hash for verification
"""
    
    with open("data/patch_report.txt", 'w') as f:
        f.write(report)
    print(f"Report saved to data/patch_report.txt")
    
    # Show the hex context around the most likely patch areas
    print(f"\n{'='*60}")
    print("HEX CONTEXT FOR MANUAL PATCHING")
    print(f"{'='*60}")
    print()
    print("To manually patch, find the scheduler decision function")
    print("and look for this pattern:")
    print()
    print("  ; Compare two application IDs")
    print("  ; If NOT equal -> error (not the last scheduled)")
    print("  ; The NOP should replace the branch")
    print()
    print("The patchable bytes will be a 16-bit halfword.")
    print("For safety: set the 2 bytes to 0x00 0x00 (NOP)")
    print()
    print()
    print(f"\n{'='*60}")
    print("STEP: Manually patch the firmware")
    print(f"{'='*60}")
    print("Use the context from step 2 to find the exact branch instruction.")
    print("Replace the branch halfword with 0x0000 (NOP) using a hex editor.")
    print()
    print(f"{'='*60}")
    print("DONE")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
