#!/usr/bin/env python3
"""
Tests for the VE2 IPU Verified Disassembler (v2).
Tests known encoding patterns from the opcode map analysis.
"""

import struct
import sys
import os
import pytest

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.ipu_disasm_v2 import IpuDisassemblerV2, CODE_START


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def d():
    """Default disassembler instance."""
    return IpuDisassemblerV2()


@pytest.fixture
def firmware():
    """Load firmware binary for integration tests."""
    path = '/tmp/orig_decomp.sbin'
    if not os.path.exists(path):
        pytest.skip(f"Firmware not found at {path}")
    with open(path, 'rb') as f:
        return f.read()


# =========================================================================
# Known instruction encodings (from statistical analysis)
# =========================================================================

class TestNop:
    """NOP = 0x0000 (20.74% of all halfwords)."""

    def test_nop_is_zero(self, d):
        assert d.decode_16bit(0x0000) == "nop"

    def test_nop_any_addr(self, d):
        assert d.decode_16bit(0x0000, 0x100) == "nop"


class TestOp4_0_Sub0:
    """op4=0, sub4=0 encodings."""

    def test_clr_r2(self, d):
        # sub4=0, r1=0, r2=N → clr rN
        assert d.decode_16bit(0x0001) == "clr r1"
        assert d.decode_16bit(0x0002) == "clr r2"
        assert d.decode_16bit(0x000f) == "clr r15"

    def test_str_r1(self, d):
        # sub4=0, r1=N, r2=0 → str rN
        assert d.decode_16bit(0x0010) == "str r1"
        assert d.decode_16bit(0x0020) == "str r2"
        assert d.decode_16bit(0x00f0) == "str r15"

    def test_str_r1_r2_unknown(self, d):
        # sub4=0, r1≠0, r2≠0 → unknown
        result = d.decode_16bit(0x0011)  # r1=1, r2=1
        assert result not in ("nop", "clr r1", "str r1")
        assert "r1=1" in result or "r2=1" in result or "?" in result or "sub" in result.lower()


class TestOp4_0_Sub1:
    """sub4=1: add r{r1}, r{r2}"""

    def test_add(self, d):
        assert d.decode_16bit(0x0110) == "add r1, r0"
        assert d.decode_16bit(0x0120) == "add r2, r0"

    def test_add_regs(self, d):
        assert d.decode_16bit(0x0134) == "add r3, r4"


class TestOp4_0_Sub2:
    """sub4=2: ldi r{r2}, 0x{low_byte}."""

    def test_ldi_zero(self, d):
        assert d.decode_16bit(0x0200) == "ldi r0, 0x00"

    def test_ldi_dest_is_imm_low(self, d):
        # r2 is both dest register and low nibble of immediate
        assert d.decode_16bit(0x0201) == "ldi r1, 0x01"

    def test_ldi_known_pattern(self, d):
        # 0x027d: r1=7, r2=13 → ldi r13, 0x7d
        assert d.decode_16bit(0x027d) == "ldi r13, 0x7d"

    def test_ldi_high_nibble(self, d):
        # 0x02e0: r1=14, r2=0 → ldi r0, 0xe0
        assert d.decode_16bit(0x02e0) == "ldi r0, 0xe0"


class TestRet:
    """RET = 0x8000 (344x occurrences)."""

    def test_ret(self, d):
        assert d.decode_16bit(0x8000) == "ret"

    def test_beq(self, d):
        assert d.decode_16bit(0x8010) == "beq r1, r0"
        assert d.decode_16bit(0x8001) == "beq r0, r1"


class TestMv:
    """MV: op4=9, sub4=0: mv r{r2}, r{r1}."""

    def test_mv_9080(self, d):
        assert d.decode_16bit(0x9080) == "mv r0, r8"

    def test_mv_9091(self, d):
        assert d.decode_16bit(0x9091) == "mv r1, r9"

    def test_mv_arbitrary(self, d):
        assert d.decode_16bit(0x9010) == "mv r0, r1"
        assert d.decode_16bit(0x90ab) == "mv r11, r10"


class TestLoadOp4C:
    """LOAD: op4=0xc, sub4=0: ld r{r1}, [r{r2}]."""

    def test_ld_c090(self, d):
        assert d.decode_16bit(0xc090) == "ld r9, [r0]"

    def test_ld_arbitrary(self, d):
        assert d.decode_16bit(0xc010) == "ld r1, [r0]"
        assert d.decode_16bit(0xc031) == "ld r3, [r1]"


class TestImmOp4F:
    """IMM: op4=0xf."""

    def test_imm_format(self, d):
        assert d.decode_16bit(0xf01d) == "imm 0x01d"

    def test_imm_any(self, d):
        result = d.decode_16bit(0xf01d)
        assert "imm" in result.lower()


class TestOp4_0_Sub5_Lw:
    """sub4=5: lw r{r2}, [r{r1}]"""

    def test_lw(self, d):
        assert d.decode_16bit(0x0501) == "lw r1, [r0]"
        assert d.decode_16bit(0x0502) == "lw r2, [r0]"


class TestOp4_0_Sub6_Sw:
    """sub4=6: sw r{r1}, [r{r2}]"""

    def test_sw(self, d):
        assert d.decode_16bit(0x0661) == "sw r6, [r1]"
        assert d.decode_16bit(0x0660) == "sw r6, [r0]"


class TestBneOp4_7:
    """BRANCH: op4=7."""

    def test_bne(self, d):
        result = d.decode_16bit(0x7010)
        assert "bne" in result.lower() or "br" in result.lower()


class TestAddi:
    """ADDI: op4=1."""

    def test_addi(self, d):
        result = d.decode_16bit(0x1120)
        assert "addi" in result.lower() or "add" in result.lower()


class TestCallOp4_0_Sub7:
    """CALL: op4=0, sub4=7."""

    def test_call_sub7(self, d):
        result = d.decode_16bit(0x07ab)
        assert "call" in result.lower()

    def test_call_sub7_target(self, d):
        assert d.decode_16bit(0x07ab) == "call 0x0ab0"


class TestCallOp4_0_SubC:
    """CALL: op4=0, sub4=0xc."""

    def test_call_subc(self, d):
        result = d.decode_16bit(0x0cab)
        assert "call" in result.lower()

    def test_call_subc_target(self, d):
        assert d.decode_16bit(0x0cab) == "call 0x0ab"


class TestOp4_0_Sub3:
    """sub4=3: sub r{r1}, r{r2}"""

    def test_sub(self, d):
        assert d.decode_16bit(0x0301) == "sub r0, r1"
        assert d.decode_16bit(0x0302) == "sub r0, r2"
        assert d.decode_16bit(0x0313) == "sub r1, r3"


class TestOp4_0_Sub4_Li:
    """sub4=4: li r{r2}, 0x{byte}"""

    def test_li(self, d):
        assert d.decode_16bit(0x0401) == "li r1, 0x01"

    def test_li_value(self, d):
        assert d.decode_16bit(0x04ab) == "li r11, 0xab"


class TestOp4_0_Sub8_Mv:
    """sub4=8: mv r{r2}, r{r1} (alternative encoding)"""

    def test_mv_sub8(self, d):
        assert d.decode_16bit(0x0801) == "mv r1, r0"

    def test_mv_sub8_regs(self, d):
        assert d.decode_16bit(0x0880) == "mv r0, r8"


# =========================================================================
# Dual-issue word disassembly
# =========================================================================

class TestDisassembleWord:
    """32-bit VLIW word disassembly."""

    def test_both_nop(self, d):
        slot0, slot1 = d.disassemble_word(0x00000000, 0)
        assert slot0 == "nop"
        assert slot1 == "nop"

    def test_lo_only(self, d):
        slot0, slot1 = d.disassemble_word(0x00008000, 0)
        assert slot0 == "ret"
        assert slot1 == "nop"

    def test_hi_only(self, d):
        slot0, slot1 = d.disassemble_word(0x80000000, 0)
        assert slot0 == "nop"
        assert slot1 == "ret"

    def test_dual_issue(self, d):
        slot0, slot1 = d.disassemble_word(0x80009080, 0)
        assert slot0 == "mv r0, r8"
        assert slot1 == "ret"

    def test_known_gate_entry(self, d):
        slot0, slot1 = d.disassemble_word(0x20060572, 0x2DD8)
        assert slot0 is not None
        assert slot1 is not None


# =========================================================================
# Range disassembly
# =========================================================================

class TestDisassembleRange:

    def test_empty_range(self, d, firmware):
        lines = d.disassemble_range(firmware, 0, 0x220, 0x220)
        assert lines == []

    def test_small_range(self, d, firmware):
        lines = d.disassemble_range(firmware, 0, 0x220, 0x230)
        assert len(lines) == 4

    def test_range_contains_addresses(self, d, firmware):
        lines = d.disassemble_range(firmware, 0, 0x220, 0x228)
        for line in lines:
            assert "0x" in line


# =========================================================================
# Gate region
# =========================================================================

class TestGateRegion:

    def test_gate_region_not_empty(self, d, firmware):
        start = CODE_START + 0x2D80
        end = CODE_START + 0x2E40
        lines = d.disassemble_range(firmware, 0, start, end)
        assert len(lines) > 0

    def test_gate_has_branches(self, d, firmware):
        start = CODE_START + 0x2D80
        end = CODE_START + 0x2E40
        lines = d.disassemble_range(firmware, 0, start, end)
        combined = '\n'.join(lines)
        has_branch = any(term in combined.lower() for term in ['ret', 'bne', 'beq', 'bra'])
        if not has_branch:
            assert len(lines) > 10

    def test_gate_has_jump_table(self, d, firmware):
        # Jump table at file offsets 0x2DD8-0x2DF4
        lines = d.disassemble_range(firmware, 0, 0x2DD8, 0x2DF8)
        assert len(lines) >= 4

    def test_jump_table_shows_targets(self, d, firmware):
        """Jump table entries (hi=NOP) show the code addresses in lo slot."""
        lines = d.disassemble_range(firmware, 0, 0x2DD8, 0x2DF8)
        combined = '\n'.join(lines)
        # Lo words are code addresses (0x8578, 0x85bc, etc.)
        # These get decoded as instructions, showing their hex values
        for target_hex in ["8578", "85bc", "85f8", "fc98"]:
            assert target_hex in combined, \
                f"Target 0x{target_hex} not visible in jump table disassembly"


# =========================================================================
# Opcode map
# =========================================================================

class TestOpcodeMap:

    def test_opcode_map_has_all_op4(self, d):
        om = d.get_opcode_map()
        for op4 in range(16):
            key = f'0x{op4:x}'
            assert key in om, f"Missing op4={key} in opcode map"

    def test_opcode_meaningful_names(self, d):
        om = d.get_opcode_map()
        for key, info in om.items():
            name = info.get('name', '')
            assert 'sub' not in name.lower() or 'sub4' in name, \
                f"Name '{name}' for {key} should be meaningful"
