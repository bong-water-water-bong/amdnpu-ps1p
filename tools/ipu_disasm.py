#!/usr/bin/env python3
"""
VE2 IPU Firmware Disassembler
==============================
The IPU (Image Processor Unit) in AMD's XDNA2 NPU uses a custom 
dual-issue 16-bit VLIW ISA. Each 32-bit word contains two 16-bit 
instructions that execute in parallel.

16-bit instruction format (hypothesized):
  [15:12] = opcode (4 bits = 16 opcodes)
  [11:8]  = sub-opcode or dest register (4 bits) 
  [7:4]   = operand 1 or register 1 (4 bits)
  [3:0]   = operand 2 or register 2 / immediate (4 bits)

Known instruction patterns:
  op4=0x0 (~39%): Most common - NOP, MOV, basic ALU, or data
    sub4=0x0: NOP (0x0000 is 20.7% of all halfwords)
    sub4=0x1: Register move / arithmetic
    sub4=0x2: Load immediate low
    sub4=0x8: Memory access / register load
    sub4=0xc: Branch/call target
  
  op4=0xc (~5.6%): Memory/load operations
    0xc090 is most common (823x) - likely a specific load
  
  op4=0x2 (~7.1%): Arithmetic/logic
    0x2890 is common (120x) - sub4=0x8, r1=9, r2=0

  op4=0x8 (~6.2%): Conditional operations? 
    0x8000 (344x) and 0x8001 (180x) common

  op4=0x9 (~4.3%): Move/transfer?
    0x9080 (203x) and 0x9091 (166x)

  op4=0xf (~4.2%): Immediate/constant loading
    0xf01d (317x) common - likely a large immediate or offset
"""

import struct
import sys

def decode_16bit(hw, addr=0):
    """Decode a 16-bit instruction to a mnemonic."""
    if hw == 0:
        return "nop"
    
    op4 = (hw >> 12) & 0xf
    sub4 = (hw >> 8) & 0xf
    r1 = (hw >> 4) & 0xf
    r2 = hw & 0xf
    
    # Try to identify instruction classes
    
    # If sub4 == r1 == 0 and r2 != 0: immediate/data load
    if sub4 == 0 and r1 == 0 and r2 != 0 and op4 not in [0, 8, 9, 0xf]:
        return f"ldi r{r2}, 0x{hw:04x}"
    
    # If op4 == 0: the most common case
    if op4 == 0:
        if sub4 == 0:
            if r1 == 0:
                if r2 == 0:
                    return "nop"
                else:
                    return f"mov r{r2}, #0"  # or clr
            elif sub4 == 0:
                if r2 == 0:
                    return f"str r{r1}"  # store
                return f"mov r1=r{r1}, r2=r{r2}"
        elif sub4 == 2:
            return f"ldi r{r2}, 0x{hw:03x}"  # load immediate
        elif sub4 == 8:
            return f"ldw r{r2}, [r{r1}]"  # load from register
        elif sub4 == 0xc:
            return f"call 0x{hw:04x}"  # call target
        else:
            return f"op0.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 1: arithmetic?
    if op4 == 1:
        return f"add r{r1}, r{r2}"
    
    # op4 = 2: logic/arith
    if op4 == 2:
        if sub4 == 0 and r1 == 0 and r2 == 0:
            return f"ext 0x{hw:04x}"  # extended instruction
        elif sub4 == 0:
            return f"alu r{r1}, 0x{r2:x}"
        elif sub4 == 1:
            return f"sub r{r1}, r{r2}"
        elif sub4 == 8:
            return f"lsh r{r1}, r{r2}"  # load/shift
        else:
            return f"op2.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 3: compare/branch?
    if op4 == 3:
        return f"cmp r{r1}, r{r2}"
    
    # op4 = 4: move?
    if op4 == 4:
        if sub4 == 1:
            return f"mv r{r1}, r{r2}"
        elif sub4 == 0:
            return f"lda 0x{hw:04x}"
        else:
            return f"op4.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 5: store?
    if op4 == 5:
        return f"st r{r1}, [r{r2}]"
    
    # op4 = 6: vector?
    if op4 == 6:
        return f"op6.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 7: ??? 
    if op4 == 7:
        if sub4 == 2:
            return f"bra 0x{hw:03x}"  # branch?
        elif sub4 == 3:
            return f"bne r{r1}, r{r2}"  # branch if not equal?
        else:
            return f"op7.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 8: conditional
    if op4 == 8:
        if sub4 == 0:
            if r1 == 0 and r2 == 0:
                return "ret"  # return?
            return f"beq r{r1}, r{r2}"  # branch if equal?
        return f"op8.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 9: transfer
    if op4 == 9:
        return f"op9.sub{sub4} r{r1}, r{r2}"  # likely move
    
    # op4 = 0xa: ???
    if op4 == 0xa:
        return f"opa.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 0xb: ???
    if op4 == 0xb:
        return f"opb.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 0xc: load
    if op4 == 0xc:
        if sub4 == 0:
            return f"ld r{r1}, [r{r2}]"
        return f"opc.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 0xd: ???
    if op4 == 0xd:
        return f"opd.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 0xe: ??? 
    if op4 == 0xe:
        return f"ope.sub{sub4} r{r1}, r{r2}"
    
    # op4 = 0xf: immediate
    if op4 == 0xf:
        if sub4 == 0:
            return f"imm 0x{hw:03x}"
        return f"opf.sub{sub4} r{r1}, r{r2}"
    
    return f"op{op4}.sub{sub4} r{r1}, r{r2}"


def disassemble_range(data, start_addr, end_addr):
    """Disassemble a range of addresses."""
    lines = []
    for addr in range(start_addr, end_addr, 4):
        if addr - 0x220 + 4 > len(data):
            break
        try:
            instr = struct.unpack('<I', data[addr-0x220:addr-0x220+4])[0]
        except:
            break
        
        lo = instr & 0xffff
        hi = (instr >> 16) & 0xffff
        
        lo_mnem = decode_16bit(lo, addr)
        hi_mnem = decode_16bit(hi, addr + 2)
        
        if lo_mnem == "nop" and hi_mnem == "nop":
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  nop")
        elif hi_mnem == "nop":
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  {lo_mnem:30s}  ; (hi=nop)")
        elif lo_mnem == "nop":
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  {hi_mnem:30s}  ; (lo=nop)")
        else:
            lines.append(f"  0x{addr:05x}: 0x{instr:08x}  {lo_mnem:30s} | {hi_mnem}")
    
    return lines


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <firmware.sbin> [start_addr] [end_addr]")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    start = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x220
    end = int(sys.argv[3], 16) if len(sys.argv) > 3 else min(start + 0x200, 0x1c000)
    
    lines = disassemble_range(data, start, end)
    for line in lines:
        print(line)
