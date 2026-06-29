#!/usr/bin/env python3
"""
FINAL: Find the exact serialization gate in the VE2 IPU firmware.

Based on the struct handshake kernel documentation, the firmware:
1. Receives a doorbell (0xB6 written to 0x34008)
2. Sets doorbell_pending=1 (offset 0x6c in handshake)
3. Checks if it's the "last scheduled application"
4. Processes or rejects the command

The serialization check involves:
- Reading current_app_id from somewhere
- Comparing with the application requesting the command
- Branching to error handler if mismatch -> "%s: Application %u is not the last scheduled"
"""

import struct
import sys

def load_firmware(path="/tmp/npu_re/npu_17f0_11_fw_1.1.2.65.sbin"):
    with open(path, 'rb') as f:
        return f.read()

def disasm_16(hw, addr=0):
    """Better 16-bit instruction decoder."""
    if hw == 0:
        return "nop"
    
    op4 = (hw >> 12) & 0xf
    sub4 = (hw >> 8) & 0xf
    r1 = (hw >> 4) & 0xf
    r2 = hw & 0xf
    
    # ISA based on observed patterns:
    # op4=0: NOP/MOV/addressing (39%)
    if op4 == 0:
        if sub4 == 0:
            if r1 == 0: return f"clr r{r2}" if r2 else "nop"
            return f"nop r{r1},r{r2}"  # unknown
        elif sub4 == 1: return f"add r{r1}, r{r2}"
        elif sub4 == 2: return f"ldi r{r2}, 0x{hw:03x}"
        elif sub4 == 3: return f"subi r{r2}, {r1}"  # subtract immediate
        elif sub4 == 4: return f"li r{r2}, 0x{hw&0xff:02x}"  # load byte immediate
        elif sub4 == 5: return f"lw r{r2}, [r{r1}]"  # load word
        elif sub4 == 6: return f"sw r{r1}, [r{r2}]"  # store word
        elif sub4 == 7: return f"call 0x{hw:04x}"  # call function
        elif sub4 == 8: return f"mv r{r2}, r{r1}"  # move register
        elif sub4 == 9: return f"addi r{r1}, {r2}"
        elif sub4 == 0xa: return f"mul r{r1}, r{r2}"
        elif sub4 == 0xb: return f"div r{r1}, r{r2}"
        elif sub4 == 0xc: return f"call 0x{((hw&0x0f)<<8)|r1:03x}"  # full call target
        elif sub4 == 0xd: return f"sub r{r1}, r{r2}"
        elif sub4 == 0xe: return f"and r{r1}, r{r2}"
        elif sub4 == 0xf: return f"or r{r1}, r{r2}"
        return f"op0.{sub4} r{r1},r{r2}"
    
    # op4=1: ADDI (4.3%)
    if op4 == 1: return f"addi r{r1}, {r2}"
    
    # op4=2: ALU/Logic (7.1%)
    if sub4 == 0: return f"ldi r{r1}, 0x{hw&0xff:02x}"
    if sub4 == 8: return f"lsh r{r2}, {r1}"
    if sub4 == 1: return f"subi r{r1}, {r2}"
    return f"op2.{sub4} r{r1},r{r2}"
    
    # op4=3: COMPARE (3.6%)
    if op4 == 3:
        if sub4 == 0: return f"cmp r{r1}, r{r2}"
        if sub4 == 1: return f"cmpi r{r1}, {r2}"
        if sub4 >= 0xe: return f"cmp r{r2}, [{r1}]"
        return f"cmp r{r1}, r{r2}"
    
    # op4=4: LOAD (4.5%)
    if op4 == 4:
        if sub4 == 0: return f"ld r{r2}, [r{r1}+0]"
        if sub4 == 1: return f"ld r{r2}, [r{r1}+{r2}]"
        return f"ld r{r2}, [r{r1}+{sub4}]"
        return f"op4.{sub4} r{r1},r{r2}"
    
    # op4=5: STORE (3.0%)
    if op4 == 5: return f"st [r{r2}], r{r1}"
    
    # op4=6: (4.0%)
    if op4 == 6: return f"op6.{sub4} r{r1},r{r2}"
    
    # op4=7: BRANCH (2.4%)
    if op4 == 7:
        if sub4 == 0: return f"bne r{r1}, r{r2}"
        if sub4 == 2: return f"bra 0x{hw:03x}"
        if sub4 == 3: return f"bne r{r1}, {r2}"
        return f"bne r{r1}, r{r2}"
    
    # op4=8: RET/BEQ (6.2%)
    if op4 == 8:
        if sub4 == 0 and r1 == 0 and r2 == 0: return "ret"
        if sub4 == 0: return f"beq r{r1}, r{r2}"
        return f"beq r{r1}, r{r2}"
    
    # op4=9: MOVE (4.3%)
    if op4 == 9: return f"mv r{r2}, r{r1}"
    
    # op4=0xa: ALU (3.8%)
    if op4 == 0xa: return f"opA.{sub4} r{r1},r{r2}"
    
    # op4=0xb: (2.6%)
    if op4 == 0xb: return f"opB.{sub4} r{r1},r{r2}"
    
    # op4=0xc: LOAD MEM (5.6%)
    if op4 == 0xc:
        if sub4 == 0: return f"ld r{r1}, [{r2}]"
        if sub4 >= 0xf: return f"ld r{r1}, [{r2}+0x{sub4:01x}]"
        return f"ld r{r1}, [{r2}+0x{sub4:01x}]"
    
    # op4=0xd: (2.3%)
    if op4 == 0xd: return f"opD.{sub4} r{r1},r{r2}"
    
    # op4=0xe: (3.0%)
    if op4 == 0xe: return f"opE.{sub4} r{r1},r{r2}"
    
    # op4=0xf: IMMEDIATE (4.2%)
    if op4 == 0xf: return f"imm 0x{hw:03x}"
    
    return f"op{op4}.{sub4} r{r1},r{r2}"


def disassemble(data, start, end):
    """Disassemble a range."""
    lines = []
    for addr in range(start, end, 4):
        if addr - 0x220 + 4 > len(data):
            break
        instr = struct.unpack('<I', data[addr-0x220:addr-0x220+4])[0]
        lo = instr & 0xffff
        hi = (instr >> 16) & 0xffff
        lo_mnem = disasm_16(lo, addr)
        hi_mnem = disasm_16(hi, addr + 2)
        
        if lo_mnem == "nop" and hi_mnem == "nop":
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  nop")
        elif hi_mnem == "nop":
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  {lo_mnem:30s}")
        elif lo_mnem == "nop":
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  {hi_mnem:30s}")
        else:
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  {lo_mnem:30s} | {hi_mnem}")
    return lines


def main():
    data = load_firmware()
    
    # Step 1: Find the main scheduling function
    # The kernel writes doorbell at 0x34008 with value 0xB6
    # Let me look at code that handles doorbell_pending (offset 0x6c in handshake)
    
    # Based on the struct handshake:
    # doorbell_pending at offset 0x6c
    # fw_state at offset 0xa0
    # completion_status at offset 0x74
    
    # Let me look at the context around the doorbell write instruction (0x3b38-0x3b3c)
    # to find the scheduler function
    
    print("=" * 70)
    print("VE2 IPU FIRMWARE - SCHEDULER FUNCTION ANALYSIS")
    print("=" * 70)
    
    # The code at 0x3b34-0x3b40 references 0x34008 (VE2_EVENT_GENERATE_REG)
    # This is likely a COMMAND COMPLETION handler, not doorbell receive
    # (The FW writes completion events)
    
    print("\n[1] Analyzing code referencing VE2_EVENT_GENERATE_REG (0x34008)")
    print("-" * 50)
    
    # Function at 0x3b00-0x3c00 seems to be the interrupt handler
    # Let me check if there's a function prologue nearby
    print("\nFunction context around doorbell references:")
    for line in disassemble(data, 0x3aa0, 0x3c80):
        print(line)
    
    # Step 2: Find the scheduling decision logic
    # The "not the last scheduled" error implies comparing two application IDs
    # Let me search for comparisons between two loaded values
    
    print("\n\n[2] Searching for scheduling comparison logic")
    print("-" * 50)
    print("Looking in code that references CMP instructions near error strings...")
    
    # The scheduling strings are at file offsets 0x1e5f0-0x1e6xx
    # References to these in code indicate error handling path
    
    print("\n\n[3] Key finding: doorbell_pending check")
    print("-" * 50)
    print("Based on handshake struct, doorbell_pending at offset 0x6c")
    print("The firmware sets this to 1 when it receives a doorbell")
    print("This is the entry point into the scheduling decision")
    
    # Show the scheduler workqueue context from kernel
    print("\n\n[4] Kernel-side scheduler (ve2_mgmt.c):")
    print("-" * 50)
    print("The kernel has ve2_scheduler_work() that:")
    print("  1. Checks FIFO for pending contexts")
    print("  2. Does context switch if needed")
    print("  3. Calls ve2_mgmt_handshake_init() for new context")
    print("  4. Writes doorbell 0xB6 to 0x34008")
    print("\nThe FIRMWARE-side check is INDEPENDENT:")
    print("  - Firmware stores 'last scheduled application' ID internally")
    print("  - On new command, compares against stored ID")
    print("  - If mismatch: rejects with '%s: Application %u is not the last scheduled'")
    print("  - This is the gate we need to patch")
    
    # Step 5: Find the actual comparison
    # The comparison would be: load current_app_id, compare with requested_app_id
    # The error strings reference shows which code path leads to the error
    # The conditional branch that SKIPS the error is the gate
    
    # The string references 0x1e5ef/0x1e5f0 are at specific literal pool addresses
    # In the code section, these are the literals loaded by LDI instructions
    # The function that error-logs is called by CALL instructions
    
    # Let me check the code at the push region for doorbell handling
    print("\n\n[5] Detailed doorbell handler analysis")
    print("-" * 50)
    print("Looking for function that handles doorbell_pending flag...")
    
    # The region 0x3a00-0x3e00 contains code with register calculation
    # patterns. Let me look for the pattern:
    #   ldi rx, handshake_base  (load partition base addr)
    #   ld ry, [rx + 0x6c]     (load doorbell_pending)
    #   cmp ry, #1              (check if doorbell received)
    #   beq doorbell_handler     (branch to handler)
    
    # First check: what does handshake struct look like in firmware?
    # The firmware gets partition_base_address from the handshake
    # to find the memory region, then accesses offsets from there
    
    print("\nFull doorbell handler region (0x3a00-0x3e00):")
    for line in disassemble(data, 0x3a00, 0x3e00):
        print(line)

if __name__ == '__main__':
    main()
