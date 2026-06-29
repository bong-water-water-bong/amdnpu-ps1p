#!/usr/bin/env python3
"""
VE2 IPU Verified Disassembler (v2)
====================================
A verified disassembler for the VE2 IPU's dual-issue 16-bit VLIW ISA,
based on the opcode map built in Task B1.

ISA format per 16-bit halfword:
  [15:12] = op4  (primary opcode / group)
  [11:8]  = sub4 (sub-opcode / modifier)
  [7:4]   = r1   (first register / operand)
  [3:0]   = r2   (second register / operand / low immediate)

Each 32-bit word = two 16-bit instructions (lo=slot0, hi=slot1).

Usage:
    python3 -m tools.ipu_disasm_v2 /tmp/orig_decomp.sbin [--start ADDR] [--end ADDR] [--gate]
"""

import struct
import sys
import argparse


# Known code section bounds
CODE_START = 0x220
CODE_END = 0x1c000


# ---------------------------------------------------------------------------
# Opcode map — derived from statistical analysis of the firmware (Task B1)
# ---------------------------------------------------------------------------

OPCODE_MAP = {
    '0x0': {
        'name': 'NOP/CLR/MOV/LOADI/BRANCH',
        'subcodes': {
            0x0: {'name': 'nop/clr/mov', 'match': lambda op4, sub4, r1, r2: sub4 == 0},
            0x1: {'name': 'add', 'match': lambda op4, sub4, r1, r2: sub4 == 1},
            0x2: {'name': 'ldi', 'match': lambda op4, sub4, r1, r2: sub4 == 2},
            0x3: {'name': 'sub', 'match': lambda op4, sub4, r1, r2: sub4 == 3},
            0x4: {'name': 'li', 'match': lambda op4, sub4, r1, r2: sub4 == 4},
            0x5: {'name': 'lw', 'match': lambda op4, sub4, r1, r2: sub4 == 5},
            0x6: {'name': 'sw', 'match': lambda op4, sub4, r1, r2: sub4 == 6},
            0x7: {'name': 'call', 'match': lambda op4, sub4, r1, r2: sub4 == 7},
            0x8: {'name': 'mv', 'match': lambda op4, sub4, r1, r2: sub4 == 8},
            0xc: {'name': 'call', 'match': lambda op4, sub4, r1, r2: sub4 == 0xc},
        },
        'confidence': 'high',
    },
    '0x1': {'name': 'ADDI (add immediate)', 'subcodes': {}, 'confidence': 'medium'},
    '0x2': {'name': 'ALU/LOGIC (arithmetic/logic/shift)', 'subcodes': {}, 'confidence': 'medium'},
    '0x3': {'name': 'CMP (compare)', 'subcodes': {}, 'confidence': 'medium'},
    '0x4': {'name': 'LOAD (memory load with offset)', 'subcodes': {}, 'confidence': 'medium'},
    '0x5': {'name': 'STORE (memory store)', 'subcodes': {}, 'confidence': 'medium'},
    '0x6': {'name': 'VEC/ALU (misc arithmetic)', 'subcodes': {}, 'confidence': 'low'},
    '0x7': {'name': 'BRANCH (conditional branch)', 'subcodes': {}, 'confidence': 'medium'},
    '0x8': {'name': 'RET/BEQ (return/conditional)', 'subcodes': {}, 'confidence': 'medium'},
    '0x9': {'name': 'MV (register move)', 'subcodes': {}, 'confidence': 'medium'},
    '0xa': {'name': 'ALU (misc arithmetic)', 'subcodes': {}, 'confidence': 'low'},
    '0xb': {'name': 'MISC (miscellaneous)', 'subcodes': {}, 'confidence': 'low'},
    '0xc': {'name': 'LOAD_MEM (load from [reg])', 'subcodes': {}, 'confidence': 'medium'},
    '0xd': {'name': 'PERIPH (peripheral access)', 'subcodes': {}, 'confidence': 'low'},
    '0xe': {'name': 'SYNC (synchronization/barrier)', 'subcodes': {}, 'confidence': 'low'},
    '0xf': {'name': 'IMM (immediate load)', 'subcodes': {}, 'confidence': 'medium'},
}


# ---------------------------------------------------------------------------
# Instruction field extractors
# ---------------------------------------------------------------------------

def _op4(hw: int) -> int:
    return (hw >> 12) & 0xF


def _sub4(hw: int) -> int:
    return (hw >> 8) & 0xF


def _r1(hw: int) -> int:
    return (hw >> 4) & 0xF


def _r2(hw: int) -> int:
    return hw & 0xF


# ---------------------------------------------------------------------------
# Disassembler class
# ---------------------------------------------------------------------------

class IpuDisassemblerV2:
    """Verified disassembler for VE2 IPU dual-issue 16-bit VLIW ISA."""

    def __init__(self, opcode_map: dict = None):
        """Initialize with optional opcode map from Task B1."""
        self._opcode_map = opcode_map if opcode_map is not None else OPCODE_MAP

    def get_opcode_map(self) -> dict:
        """Return the opcode map dictionary."""
        return self._opcode_map

    # ------------------------------------------------------------------
    # 16-bit instruction decoder
    # ------------------------------------------------------------------

    def decode_16bit(self, hw: int, addr: int = 0) -> str:
        """Decode one 16-bit instruction to mnemonic string."""
        if hw == 0:
            return "nop"

        op4 = _op4(hw)
        sub4 = _sub4(hw)
        r1 = _r1(hw)
        r2 = _r2(hw)

        # --- op4=0x0: NOP/CLR/MOV/LOADI/BRANCH (most common group) ---
        if op4 == 0:
            return self._decode_op0(sub4, r1, r2, hw)

        # --- op4=0x1: ADDI ---
        if op4 == 1:
            return f"addi r{r1}, 0x{r2:x}"

        # --- op4=0x2: ALU/SHIFT ---
        if op4 == 2:
            return self._decode_op2(sub4, r1, r2, hw)

        # --- op4=0x3: CMP ---
        if op4 == 3:
            return f"cmp r{r1}, r{r2}"

        # --- op4=0x4: LOAD (word with offset) ---
        if op4 == 4:
            if sub4 == 1:
                return f"ld [r{r1}+r{r2}], r{r2}"
            elif sub4 == 0:
                return f"ld [r{r1}+0], r{r2}"
            return f"ld r{r1}, [r{r2}+0x{sub4:x}]"

        # --- op4=0x5: STORE ---
        if op4 == 5:
            return f"st r{r1}, [r{r2}]"

        # --- op4=0x6: VEC/ALU ---
        if op4 == 6:
            return f"alu6 r{r1}, r{r2}"

        # --- op4=0x7: BRANCH ---
        if op4 == 7:
            return self._decode_op7(sub4, r1, r2, hw)

        # --- op4=0x8: RET/BEQ ---
        if op4 == 8:
            return self._decode_op8(sub4, r1, r2, hw)

        # --- op4=0x9: MV (register move) ---
        if op4 == 9:
            return f"mv r{r2}, r{r1}"

        # --- op4=0xa: ALU2 ---
        if op4 == 0xa:
            return f"alua r{r1}, r{r2}"

        # --- op4=0xb: MISC ---
        if op4 == 0xb:
            return f"misc r{r1}, r{r2}"

        # --- op4=0xc: LOAD_MEM ---
        if op4 == 0xc:
            return f"ld r{r1}, [r{r2}]"

        # --- op4=0xd: PERIPH ---
        if op4 == 0xd:
            return f"periph r{r1}, r{r2}"

        # --- op4=0xe: SYNC ---
        if op4 == 0xe:
            return f"sync r{r1}, r{r2}"

        # --- op4=0xf: IMM ---
        if op4 == 0xf:
            imm_val = ((sub4 << 8) | (r1 << 4) | r2)
            return f"imm 0x{imm_val:03x}"

        return f"op{op4}.sub{sub4} r{r1}, r{r2}"

    # ------------------------------------------------------------------
    # Sub-decoders for complex opcode groups
    # ------------------------------------------------------------------

    def _decode_op0(self, sub4: int, r1: int, r2: int, hw: int) -> str:
        """Decode op4=0 group: NOP/CLR/MOV/LOADI/BRANCH."""
        if sub4 == 0:
            if r1 == 0 and r2 == 0:
                return "nop"
            if r1 == 0 and r2 != 0:
                return f"clr r{r2}"
            if r1 != 0 and r2 == 0:
                return f"str r{r1}"
            return f"op0.sub0 r{r1}, r{r2}"

        if sub4 == 1:
            return f"add r{r1}, r{r2}"

        if sub4 == 2:
            imm_val = (r1 << 4) | r2
            return f"ldi r{r2}, 0x{imm_val:02x}"

        if sub4 == 3:
            return f"sub r{r1}, r{r2}"

        if sub4 == 4:
            imm_val = (r1 << 4) | r2
            return f"li r{r2}, 0x{imm_val:02x}"

        if sub4 == 5:
            return f"lw r{r2}, [r{r1}]"

        if sub4 == 6:
            return f"sw r{r1}, [r{r2}]"

        if sub4 == 7:
            target = (r1 << 8) | (r2 << 4)
            return f"call 0x{target:04x}"

        if sub4 == 8:
            return f"mv r{r2}, r{r1}"

        if sub4 == 0xc:
            target = (r1 << 4) | r2
            return f"call 0x{target:03x}"

        return f"op0.sub{sub4:x} r{r1}, r{r2}"

    def _decode_op2(self, sub4: int, r1: int, r2: int, hw: int) -> str:
        """Decode op4=2 group: ALU/SHIFT."""
        if sub4 == 0:
            return f"lsh r{r1}, r{r2}"
        if sub4 == 1:
            return f"subi r{r1}, 0x{r2:x}"
        if sub4 == 7:
            return f"alu2.7 r{r1}, r{r2}"
        if sub4 == 8:
            return f"lsh r{r1}, r{r2}"
        return f"op2.sub{sub4:x} r{r1}, r{r2}"

    def _decode_op7(self, sub4: int, r1: int, r2: int, hw: int) -> str:
        """Decode op4=7 group: BRANCH."""
        if sub4 == 0:
            return f"bne r{r1}, r{r2}"
        if sub4 == 2:
            return f"bra 0x{r1:x}{r2:x}"
        return f"bne r{r1}, r{r2}"

    def _decode_op8(self, sub4: int, r1: int, r2: int, hw: int) -> str:
        """Decode op4=8 group: RET/BEQ."""
        if sub4 == 0 and r1 == 0 and r2 == 0:
            return "ret"
        if sub4 == 0:
            return f"beq r{r1}, r{r2}"
        return f"op8.sub{sub4:x} r{r1}, r{r2}"

    # ------------------------------------------------------------------
    # 32-bit word disassembly
    # ------------------------------------------------------------------

    def disassemble_word(self, word: int, addr: int) -> tuple[str, str]:
        """Disassemble one 32-bit word -> (slot0_mnem, slot1_mnem)."""
        lo = word & 0xFFFF
        hi = (word >> 16) & 0xFFFF

        slot0 = self.decode_16bit(lo, addr)
        slot1 = self.decode_16bit(hi, addr + 2)

        return slot0, slot1

    # ------------------------------------------------------------------
    # Range disassembly
    # ------------------------------------------------------------------

    def disassemble_range(self, data: bytes, base_addr: int,
                          start: int, end: int) -> list[str]:
        """Disassemble a range of addresses.

        Args:
            data: Full firmware binary
            base_addr: Address of byte 0 in `data`. For full firmware
                       this is typically 0.
            start: Start address (absolute in the same address space as
                   base_addr). E.g., to show code-relative offset 0x2D80,
                   pass start=CODE_START+0x2D80.
            end: End address (exclusive).

        Returns:
            List of formatted disassembly strings
        """
        lines = []
        for addr in range(start, end, 4):
            offset = addr - base_addr
            if offset < 0 or offset + 4 > len(data):
                break

            word = struct.unpack('<I', data[offset:offset + 4])[0]
            slot0, slot1 = self.disassemble_word(word, addr)

            # Format the output
            if slot0 == "nop" and slot1 == "nop":
                lines.append(f"  0x{addr:05x}: 0x{word:08x}  nop")
            elif slot1 == "nop":
                lines.append(f"  0x{addr:05x}: 0x{word:08x}  {slot0}")
            elif slot0 == "nop":
                lines.append(f"  0x{addr:05x}: 0x{word:08x}  {slot1}  ; (slot0=nop)")
            else:
                lines.append(f"  0x{addr:05x}: 0x{word:08x}  {slot0}  |  {slot1}")

        return lines

    def print_disassembly(self, lines: list[str]) -> None:
        """Print formatted disassembly."""
        for line in lines:
            print(line)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='VE2 IPU Verified Disassembler (v2)')
    parser.add_argument('firmware', help='Path to firmware binary')
    parser.add_argument('--start', type=lambda s: int(s, 16),
                        default=None, help='Start address (hex)')
    parser.add_argument('--end', type=lambda s: int(s, 16),
                        default=None, help='End address (hex, exclusive)')
    parser.add_argument('--gate', action='store_true',
                        help='Disassemble the serialization gate region (code offsets 0x2D80-0x2E40)')
    parser.add_argument('--opcodes', action='store_true',
                        help='Show the opcode map used')

    args = parser.parse_args()

    with open(args.firmware, 'rb') as f:
        data = f.read()

    dis = IpuDisassemblerV2()

    if args.opcodes:
        print_opcode_map(dis)
        return

    # All offsets are file offsets. --gate uses known file offsets.
    if args.gate:
        # Gate region: file offsets 0x2D80-0x2E40 (includes jump table at 0x2DD8)
        start = 0x2D80
        end = 0x2E40
    elif args.start is not None:
        start = args.start
        end = args.end if args.end is not None else min(start + 0x200, len(data))
    else:
        # Default: first chunk of code section
        start = CODE_START
        end = CODE_START + 0x1E0

    lines = dis.disassemble_range(data, 0, start, end)
    dis.print_disassembly(lines)


def print_opcode_map(dis: IpuDisassemblerV2) -> None:
    """Print the opcode map table."""
    om = dis.get_opcode_map()
    print("=" * 70)
    print("VE2 IPU OPCODE MAP (from statistical analysis)")
    print("=" * 70)
    print()
    print(f"  {'Op4':<6} {'Name':<40} {'Confidence'}")
    print(f"  {'-'*4} {'-'*38} {'-'*10}")
    for op4 in range(16):
        key = f'0x{op4:x}'
        info = om.get(key, {})
        name = info.get('name', 'UNKNOWN')
        conf = info.get('confidence', 'low')
        print(f"  {key:<6} {name:<40} {conf}")

    print()
    print("  Subcode details:")
    print(f"  {'Op4':<6} {'Sub4':<6} {'Name':<30}")
    print(f"  {'-'*4} {'-'*4} {'-'*28}")
    for op4 in range(16):
        key = f'0x{op4:x}'
        info = om.get(key, {})
        subs = info.get('subcodes', {})
        if not subs:
            continue
        for sub4_val, sub_info in subs.items():
            if isinstance(sub_info, dict):
                sname = sub_info.get('name', f'sub{sub4_val}')
            else:
                sname = str(sub_info)
            print(f"  {key:<6} 0x{sub4_val:x}  {'':<6} {sname}")


if __name__ == '__main__':
    main()
