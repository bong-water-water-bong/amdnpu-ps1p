#!/usr/bin/env python3
"""
VE2 IPU ISA Opcode Map Builder
================================
Builds a verified opcode map for the VE2 IPU processor's custom
dual-issue 16-bit VLIW ISA through statistical analysis of the
firmware binary.

The ISA format per 16-bit halfword:
  [15:12] = op4  (primary opcode / group)
  [11:8]  = sub4 (sub-opcode / modifier)
  [7:4]   = r1   (first register / operand)
  [3:0]   = r2   (second register / operand / low immediate)

Each 32-bit word = two 16-bit instructions (lo=slot0, hi=slot1)
executing in parallel.

Usage:
    python3 -m tools.build_opcode_map /tmp/orig_decomp.sbin
"""

import struct
import sys
from collections import Counter, defaultdict


# Known code section bounds
CODE_START = 0x220
CODE_END = 0x1c000

# Known jump table location and targets (from manual analysis)
KNOWN_JUMP_TABLE_OFFSETS = list(range(0x2DD8, 0x2DF8, 4))
KNOWN_JUMP_TABLE_TARGETS = [0x8578, 0x85bc, 0x85f8, 0xfc98, 0x8664, 0x87ac, 0x87c8, 0x6264]


class OpcodeAnalyzer:
    """Statistical analyzer for the VE2 IPU firmware opcode structure."""

    def __init__(self, firmware_path: str):
        """Load firmware, extract ipu_code section."""
        with open(firmware_path, 'rb') as f:
            self._raw = f.read()

        self.code_offset = CODE_START
        self.code = self._raw[CODE_START:CODE_END]
        self.code_size = len(self.code)

    # ------------------------------------------------------------------
    # Statistics helpers
    # ------------------------------------------------------------------

    def _halfwords(self):
        """Iterate over all 16-bit halfwords in the code section."""
        for i in range(0, len(self.code), 2):
            yield struct.unpack('<H', self.code[i:i + 2])[0]

    def _words(self):
        """Iterate over all 32-bit words in the code section."""
        for i in range(0, len(self.code), 4):
            yield struct.unpack('<I', self.code[i:i + 4])[0]

    def _lo_hw(self, word: int) -> int:
        return word & 0xFFFF

    def _hi_hw(self, word: int) -> int:
        return (word >> 16) & 0xFFFF

    def _op4(self, hw: int) -> int:
        return (hw >> 12) & 0xF

    def _sub4(self, hw: int) -> int:
        return (hw >> 8) & 0xF

    def _r1(self, hw: int) -> int:
        return (hw >> 4) & 0xF

    def _r2(self, hw: int) -> int:
        return hw & 0xF

    def _file_offset(self, code_rel_offset: int) -> int:
        """Convert code-relative offset to absolute file offset."""
        return self.code_offset + code_rel_offset

    def _word_at(self, file_offset: int) -> int:
        """Read a 32-bit word at an absolute file offset."""
        return struct.unpack('<I', self._raw[file_offset:file_offset + 4])[0]

    # ------------------------------------------------------------------
    # Analysis methods
    # ------------------------------------------------------------------

    def compute_halfword_frequencies(self) -> dict:
        """Count all 16-bit halfword occurrences in ipu_code.
        Returns {halfword: count} sorted by count descending.
        """
        freq = Counter()
        for hw in self._halfwords():
            freq[hw] += 1
        return dict(freq.most_common())

    def compute_op4_frequencies(self) -> dict:
        """Group by op4 (high nibble) and sub4 (second nibble).
        Returns {op4: {sub4: count, ...}, ...}
        """
        op4_counts = Counter()
        op4_sub4: dict[int, Counter] = defaultdict(Counter)

        for hw in self._halfwords():
            op4 = self._op4(hw)
            sub4 = self._sub4(hw)
            op4_counts[op4] += 1
            op4_sub4[op4][sub4] += 1

        result: dict[int, dict] = {}
        for op4 in range(16):
            cnt = op4_counts.get(op4, 0)
            if cnt == 0:
                result[op4] = {}
                continue
            subs = dict(op4_sub4[op4].most_common())
            result[op4] = {
                'count': cnt,
                'subcodes': subs,
            }
        return result

    def _find_all_hi_nop_entries(self) -> list[dict]:
        """Find ALL 32-bit words with hi=NOP and lo in code range.
        Returns [{'offset': int, 'target': int}, ...] sorted by offset.
        """
        entries = []
        for i in range(0, len(self.code), 4):
            word = struct.unpack('<I', self.code[i:i + 4])[0]
            lo = self._lo_hw(word)
            hi = self._hi_hw(word)
            if hi == 0x0000 and lo >= 0x0220 and lo < 0x1C000:
                file_off = self._file_offset(i)
                entries.append({'offset': file_off, 'target': lo})

        # De-duplicate by offset
        seen: set[int] = set()
        unique: list[dict] = []
        for e in entries:
            if e['offset'] not in seen:
                seen.add(e['offset'])
                unique.append(e)
        unique.sort(key=lambda x: x['offset'])
        return unique

    def find_jump_table_entries(self) -> list[dict]:
        """Find jump tables using clustering: 3+ contiguous words with
        hi=NOP and lo pointing to valid code addresses.
        Real jump tables appear as contiguous blocks of such words.

        Returns [{'offset': int, 'target': int}, ...] sorted by offset,
        only including entries that are part of clusters of >= 3 words.
        """
        all_entries = self._find_all_hi_nop_entries()

        # Group into clusters: contiguous offsets (4 bytes apart)
        clusters: list[list[dict]] = []
        if not all_entries:
            return []
        current: list[dict] = [all_entries[0]]

        for e in all_entries[1:]:
            if e['offset'] == current[-1]['offset'] + 4:
                current.append(e)
            else:
                if len(current) >= 3:
                    clusters.append(current)
                current = [e]
        if len(current) >= 3:
            clusters.append(current)

        # Flatten clusters back to a single sorted list
        result: list[dict] = []
        for c in clusters:
            result.extend(c)
        return result

    def find_load_immediate_patterns(self) -> list[dict]:
        """Find LDI patterns: hi=NOP, lo matches load-immediate format.
        LDI likely has format: op4=0, sub4=2 (ldi r{r2}, 0x{low_12_bits}).
        Returns [{'offset': int, 'value': int, 'interpretation': str}, ...]
        """
        results = []
        for i in range(0, len(self.code), 4):
            word = struct.unpack('<I', self.code[i:i + 4])[0]
            lo = self._lo_hw(word)
            hi = self._hi_hw(word)
            if hi != 0x0000:
                continue
            op4 = self._op4(lo)
            sub4 = self._sub4(lo)
            if op4 == 0 and sub4 == 2:
                # LDI: r2 holds the dest register, low 12 bits (r1:r2 nibbles)
                # r1 and r2 together form the immediate value
                imm_val = (self._r1(lo) << 4) | self._r2(lo)
                r_dest = self._r2(lo)  # or r1? based on format analysis
                file_off = self._file_offset(i)
                results.append({
                    'offset': file_off,
                    'value': imm_val,
                    'interpretation': f"ldi r{r_dest}, 0x{imm_val:02x}",
                })
        return results

    def find_call_targets(self) -> list[dict]:
        """Find CALL instructions. Known CALL format:
        - op4=0, sub4=7 or sub4=0xc
        - Pattern 0x0001_xxxx is common where hi=0x0001, lo varies

        Returns [{'offset': int, 'instr': int, 'lo': int, 'hi': int}, ...]
        """
        results = []
        for i in range(0, len(self.code), 4):
            word = struct.unpack('<I', self.code[i:i + 4])[0]
            lo = self._lo_hw(word)
            hi = self._hi_hw(word)
            op4_lo = self._op4(lo)
            sub4_lo = self._sub4(lo)

            # CALL type A: op4=0, sub4=7 (call function)
            # CALL type B: op4=0, sub4=0xc (call with target)
            # Also pattern hi=0x0001 is often a call prefix
            is_call = False
            if op4_lo == 0 and sub4_lo == 7:
                is_call = True
            elif op4_lo == 0 and sub4_lo == 0xc:
                is_call = True
            elif hi == 0x0001:
                is_call = True  # call prefix pattern

            if is_call:
                file_off = self._file_offset(i)
                results.append({
                    'offset': file_off,
                    'instr': word,
                    'lo': lo,
                    'hi': hi,
                })
        return results

    def find_conditional_branches(self) -> list[dict]:
        """Find BEQ/BNE patterns near the serialization gate.
        Returns instructions in range 0x2D00-0x2DD8 that look like branch
        instructions (op4=7 or op4=8 with non-zero sub4).
        """
        results = []
        # Gate region: code offsets 0x2D00 to 0x2DD8 relative to 0x220
        gate_code_start = 0x2D00 - CODE_START  # 0x2AE0
        gate_code_end = 0x2DD8 - CODE_START     # 0x2BB8

        for i in range(gate_code_start, min(gate_code_end, len(self.code) - 3), 4):
            word = struct.unpack('<I', self.code[i:i + 4])[0]
            lo = self._lo_hw(word)
            hi = self._hi_hw(word)
            file_off = self._file_offset(i)

            for hw, slot in [(lo, 'lo'), (hi, 'hi')]:
                if hw == 0:
                    continue
                op4 = self._op4(hw)
                sub4 = self._sub4(hw)
                r1 = self._r1(hw)
                r2 = self._r2(hw)

                # op4=7: likely branch (bne/bra)
                # op4=8: likely conditional (beq/ret)
                if op4 in (7, 8):
                    results.append({
                        'offset': file_off,
                        'slot': slot,
                        'hw': hw,
                        'op4': op4,
                        'sub4': sub4,
                        'r1': r1,
                        'r2': r2,
                    })
        return results

    def build_opcode_map(self) -> dict:
        """Build comprehensive opcode map with confidence scores.

        Returns dict with structure:
            'opcodes': {hex_op4: {'name': str, 'subcodes': dict,
                                   'frequency': float, 'confidence': str}}
            'jump_table_entries': [...]
            'known_patterns': {...}
        """
        op4_freq = self.compute_op4_frequencies()
        total_hw = len(list(self._halfwords()))
        jump_table = self.find_jump_table_entries()

        opcodes: dict[str, dict] = {}

        # Opcode interpretations based on observed patterns and known ISA structures
        interpretations = {
            0x0: {
                'name': 'NOP/CLR/MOV/LOADI/BRANCH',
                'subcodes': {
                    0x0: 'nop/clr (0x0000=20.7% is NOP)',
                    0x1: 'add/sub (register arithmetic)',
                    0x2: 'ldi (load immediate low byte)',
                    0x3: 'subi/logic (subtract immediate)',
                    0x4: 'li (load byte immediate)',
                    0x5: 'lw (load word from memory)',
                    0x6: 'sw (store word to memory)',
                    0x7: 'call (function call)',
                    0x8: 'mv (register move)',
                    0x9: 'addi (add immediate)',
                    0xa: 'mul (multiply)',
                    0xb: 'div (divide)',
                    0xc: 'call (far call / full target)',
                    0xd: 'sub (register subtract)',
                    0xe: 'and (bitwise and)',
                    0xf: 'or (bitwise or)',
                },
                'confidence': 'high',
            },
            0x1: {
                'name': 'ADDI (add immediate)',
                'subcodes': {},
                'confidence': 'medium',
            },
            0x2: {
                'name': 'ALU/LOGIC (arithmetic/logic)',
                'subcodes': {
                    0x0: 'ldi (load immediate, r1=dest)',
                    0x1: 'subi (subtract immediate)',
                    0x8: 'lsh (load/shift)',
                },
                'confidence': 'medium',
            },
            0x3: {
                'name': 'CMP (compare)',
                'subcodes': {
                    0x0: 'cmp r1, r2',
                    0x1: 'cmpi (compare immediate)',
                    0xe: 'cmp r2, [r1] (compare with memory)',
                },
                'confidence': 'medium',
            },
            0x4: {
                'name': 'LOAD (memory load)',
                'subcodes': {
                    0x0: 'ld [r1+0], r2 (load with offset 0)',
                    0x1: 'ld [r1+r2] (load indexed)',
                },
                'confidence': 'medium',
            },
            0x5: {
                'name': 'STORE (memory store)',
                'subcodes': {},
                'confidence': 'medium',
            },
            0x6: {
                'name': 'VECTOR/ALU (misc arithmetic)',
                'subcodes': {},
                'confidence': 'low',
            },
            0x7: {
                'name': 'BRANCH (bne/bra)',
                'subcodes': {
                    0x0: 'bne r1, r2 (branch if not equal)',
                    0x2: 'bra (unconditional branch)',
                },
                'confidence': 'medium',
            },
            0x8: {
                'name': 'RET/BEQ (return / conditional)',
                'subcodes': {
                    0x0: 'ret (r1=0,r2=0) / beq r1,r2',
                },
                'confidence': 'medium',
            },
            0x9: {
                'name': 'MV (register move)',
                'subcodes': {},
                'confidence': 'medium',
            },
            0xa: {
                'name': 'ALU (misc arithmetic)',
                'subcodes': {},
                'confidence': 'low',
            },
            0xb: {
                'name': 'MISC (miscellaneous)',
                'subcodes': {},
                'confidence': 'low',
            },
            0xc: {
                'name': 'LOAD (memory load with offset)',
                'subcodes': {
                    0x0: 'ld r1, [r2]',
                },
                'confidence': 'medium',
            },
            0xd: {
                'name': 'MISC (miscellaneous)',
                'subcodes': {},
                'confidence': 'low',
            },
            0xe: {
                'name': 'MISC (miscellaneous)',
                'subcodes': {},
                'confidence': 'low',
            },
            0xf: {
                'name': 'IMM (immediate / constant)',
                'subcodes': {},
                'confidence': 'medium',
            },
        }

        for op4 in range(16):
            key = f'0x{op4:x}'
            data = op4_freq.get(op4, {})
            if not data:
                opcodes[key] = {
                    'name': 'UNUSED',
                    'subcodes': {},
                    'frequency': 0.0,
                    'confidence': 'low',
                }
                continue

            cnt = data['count']
            pct = round(100.0 * cnt / total_hw, 1)
            interp = interpretations.get(op4, {})
            name = interp.get('name', f'OP{op4}')
            subs = interp.get('subcodes', {})
            conf = interp.get('confidence', 'low')

            # Build subcode display including frequencies
            sub_freqs = {}
            for sub4, sub_cnt in data['subcodes'].items():
                sub_pct = round(100.0 * sub_cnt / total_hw, 2)
                sub_name = subs.get(sub4, f'sub{sub4}')
                sub_freqs[f'0x{sub4:x}'] = {
                    'count': sub_cnt,
                    'frequency': sub_pct,
                    'interpretation': sub_name,
                }

            opcodes[key] = {
                'name': name,
                'subcodes': sub_freqs,
                'frequency': pct,
                'confidence': conf,
            }

        # Find common instruction patterns
        hw_freq = self.compute_halfword_frequencies()
        top_instructions = []
        for hw, cnt in list(hw_freq.items())[:20]:
            top_instructions.append({
                'hex': f'0x{hw:04x}',
                'count': cnt,
                'frequency': round(100.0 * cnt / total_hw, 2),
            })

        # Analyze slot usage
        lo_only = 0
        hi_only = 0
        dual = 0
        both_nop = 0
        for word in self._words():
            lo = self._lo_hw(word)
            hi = self._hi_hw(word)
            lo_nop = lo == 0
            hi_nop = hi == 0
            if lo_nop and hi_nop:
                both_nop += 1
            elif lo_nop and not hi_nop:
                hi_only += 1
            elif not lo_nop and hi_nop:
                lo_only += 1
            else:
                dual += 1

        known_patterns = {
            'nop_value': 0x0000,
            'nop_frequency': round(100.0 * hw_freq.get(0x0000, 0) / total_hw, 2),
            'total_halfwords': total_hw,
            'total_words': len(list(self._words())),
            'code_size': self.code_size,
            'slot_usage': {
                'lo_only': lo_only,
                'hi_only': hi_only,
                'dual_issue': dual,
                'both_nop': both_nop,
            },
            'top_instructions': top_instructions,
        }

        return {
            'opcodes': opcodes,
            'jump_table_entries': jump_table,
            'known_patterns': known_patterns,
        }

    def print_report(self):
        """Print formatted analysis report."""
        total_hw = len(list(self._halfwords()))
        total_words = total_hw // 2

        print("=" * 70)
        print("VE2 IPU ISA OPCODE MAP ANALYSIS REPORT")
        print("=" * 70)
        print()

        # 1. Summary statistics
        print("1. SUMMARY STATISTICS")
        print("-" * 60)
        print(f"  Code section:      0x{CODE_START:05X} - 0x{CODE_END:05X}")
        print(f"  Code size:         {self.code_size} bytes ({self.code_size // 1024} KB)")
        print(f"  Total 32-bit words: {total_words}")
        print(f"  Total 16-bit halfwords: {total_hw}")
        print(f"  Unique halfwords:  {len(self.compute_halfword_frequencies())}")
        print()

        # 2. Op4 frequency table
        print("2. OP4 FREQUENCY TABLE")
        print("-" * 60)
        print(f"  {'Op4':<5} {'Count':<10} {'Freq%':<10} {'Name':<35} {'Confidence'}")
        print(f"  {'-'*4} {'-'*8} {'-'*8} {'-'*33} {'-'*10}")

        opcode_map = self.build_opcode_map()
        op4_freq_data = self.compute_op4_frequencies()
        for op4 in range(16):
            key = f'0x{op4:x}'
            info = opcode_map['opcodes'].get(key, {})
            data = op4_freq_data.get(op4, {})
            cnt = data.get('count', 0) if isinstance(data, dict) else 0
            pct = info.get('frequency', 0.0)
            name = info.get('name', 'UNKNOWN')
            conf = info.get('confidence', 'low')
            print(f"  0x{op4:x}   {cnt:<10} {pct:<10} {name:<35} {conf}")

        print()

        # 3. Op4/sub4 cross-tabulation
        print("3. OP4/SUB4 CROSS-TABULATION (subcodes with >0.5% frequency)")
        print("-" * 60)
        for op4 in range(16):
            data = op4_freq_data.get(op4, {})
            cnt = data.get('count', 0) if isinstance(data, dict) else 0
            if cnt == 0:
                continue
            subs = data.get('subcodes', {}) if isinstance(data, dict) else {}
            print(f"\n  0x{op4:x} (total={cnt}):")
            for sub4, sub_cnt in subs.items():
                sub_pct = round(100.0 * sub_cnt / total_hw, 2)
                if sub_pct >= 0.5:
                    interp = 'unknown'
                    if opcode_map['opcodes'].get(f'0x{op4:x}', {}).get('subcodes', {}):
                        si = opcode_map['opcodes'][f'0x{op4:x}']['subcodes'].get(f'0x{sub4:x}', {})
                        interp = si.get('interpretation', 'unknown')
                    bar = '#' * int(sub_pct)
                    print(f"    0x{sub4:x}: {sub_cnt:6d} ({sub_pct:5.2f}%) {bar:<20} {interp}")

        print()

        # 4. Jump table entries
        print("4. JUMP TABLE ENTRIES (clustered - 3+ contiguous)")
        print("-" * 60)
        jt_entries = opcode_map['jump_table_entries']
        if jt_entries:
            print(f"  Found {len(jt_entries)} potential jump table entries "
                  f"(across {self._count_clusters(jt_entries)} clusters):")
            current_off = -4
            for e in jt_entries:
                marker = "  <-- KNOWN" if e['offset'] in KNOWN_JUMP_TABLE_OFFSETS else ""
                gap = "" if e['offset'] == current_off + 4 else \
                    f"\n    ... gap at 0x{current_off+4:05x} ..."
                if gap:
                    print(gap)
                print(f"    0x{e['offset']:05x}: -> 0x{e['target']:05x}{marker}")
                current_off = e['offset']
        else:
            print("  No jump table entries found.")
        print()

        # 5. Conditional branch candidates near gate region
        print("5. BRANCH CANDIDATES NEAR GATE REGION (0x2D00-0x2DD8)")
        print("-" * 60)
        branches = self.find_conditional_branches()
        if branches:
            print(f"  Found {len(branches)} branch candidates:")
            for b in branches:
                print(f"    0x{b['offset']:05x} ({b['slot']}): "
                      f"0x{b['hw']:04x} op4=0x{b['op4']:x} sub4=0x{b['sub4']:x} "
                      f"r1={b['r1']} r2={b['r2']}")
        else:
            print("  No branch candidates found.")
        print()

        # 6. Top instructions
        print("6. TOP HALFWORD FREQUENCIES")
        print("-" * 60)
        print(f"  {'Rank':<5} {'Hex':<8} {'Count':<10} {'Freq%':<10}")
        print(f"  {'-'*4} {'-'*6} {'-'*8} {'-'*8}")
        for rank, instr in enumerate(opcode_map['known_patterns']['top_instructions'], 1):
            print(f"  {rank:<5} {instr['hex']:<8} {instr['count']:<10} "
                  f"{instr['frequency']:<10}")
        print()

        # 7. Slot usage analysis
        print("7. SLOT USAGE ANALYSIS")
        print("-" * 60)
        su = opcode_map['known_patterns']['slot_usage']
        total_words = su['lo_only'] + su['hi_only'] + su['dual_issue'] + su['both_nop']
        for label, key in [("Slot 0 only (hi=NOP)", 'lo_only'),
                            ("Slot 1 only (lo=NOP)", 'hi_only'),
                            ("Dual-issue (both active)", 'dual_issue'),
                            ("Both NOP", 'both_nop')]:
            val = su[key]
            pct = round(100.0 * val / total_words, 1) if total_words else 0
            print(f"  {label:<30}: {val:6d} ({pct:5.1f}%)")
        print()

        # 8. Opcode map
        print("8. OPCODE MAP WITH CONFIDENCE LEVELS")
        print("-" * 60)
        for op4 in range(16):
            key = f'0x{op4:x}'
            info = opcode_map['opcodes'].get(key, {})
            name = info.get('name', 'UNKNOWN')
            freq = info.get('frequency', 0.0)
            conf = info.get('confidence', 'low')

            if freq == 0:
                continue

            bar = '#' * max(1, int(freq / 2))
            print(f"  0x{op4:x} | {bar:<20} {freq:5.1f}% | {name:<35} [{conf}]")
            subs = info.get('subcodes', {})
            for sub_key, sub_info in subs.items():
                sub_freq = sub_info.get('frequency', 0.0)
                interp = sub_info.get('interpretation', '')
                if sub_freq >= 0.3:
                    print(f"       {sub_key}: {interp} ({sub_freq}%)")

        print()
        print("=" * 70)
        print("REPORT COMPLETE")
        print("=" * 70)

    @staticmethod
    def _count_clusters(entries: list[dict]) -> int:
        """Count the number of clusters in a sorted list of jump table entries."""
        if not entries:
            return 0
        count = 1
        for i in range(1, len(entries)):
            if entries[i]['offset'] != entries[i - 1]['offset'] + 4:
                count += 1
        return count


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 -m tools.build_opcode_map <firmware.sbin>")
        sys.exit(1)

    firmware_path = sys.argv[1]
    analyzer = OpcodeAnalyzer(firmware_path)
    analyzer.print_report()


if __name__ == '__main__':
    main()
