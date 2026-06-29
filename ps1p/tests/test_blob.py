"""Tests for binary blob analysis."""

import struct

from ps1p.blob import BlobAnalyzer, BlobAnalysis, XILINX_SYNC


def test_analyze_empty():
    """Empty data returns 'empty' classification with zero size."""
    result = BlobAnalyzer.analyze(b'')
    assert result.classification == 'empty'
    assert result.size == 0
    assert result.entropy == 0.0
    assert result.is_arm_thumb is False
    assert result.has_xilinx_sync is False
    assert result.has_elf_header is False


def test_analyze_text():
    """Text data should be classified as 'text_strings'."""
    data = b'Hello World! This is a test string ' * 10
    result = BlobAnalyzer.analyze(data)
    assert result.classification == 'text_strings'
    assert result.printable_ratio > 0.6


def test_analyze_arm_thumb():
    """PUSH {LR} half-words should be detected as ARM Thumb code."""
    data = struct.pack('<H', 0xb580) * 10
    result = BlobAnalyzer.analyze(data)
    assert result.is_arm_thumb is True
    assert 'ARM Thumb' in result.potential_code_types


def test_analyze_null_data():
    """All-null data has null_ratio > 0.9 and entropy of 0.0."""
    data = b'\x00' * 100
    result = BlobAnalyzer.analyze(data)
    assert result.null_ratio > 0.9
    assert result.entropy == 0.0
    assert result.classification == 'sparse_data'


def test_find_blobs():
    """Finds binary blobs in mixed text/binary data, sorted largest first."""
    text_part = b'This is a text region with high printable ratio ' * 4
    binary_part = b'\x00\x01\x02\x03' * 32  # 128 bytes of binary

    mixed = text_part + binary_part
    blobs = BlobAnalyzer.find_blobs(mixed, min_size=16)

    assert len(blobs) > 0
    # The binary part should be found
    assert any(b.size >= 64 for b in blobs)


def test_xilinx_bitstream():
    """Data containing \\xaa\\x99 sync marker is detected."""
    data = b'\xaa\x99' + b'\x00' * 30 + b'\xaa\x99'
    result = BlobAnalyzer.analyze(data)
    assert result.has_xilinx_sync is True
    assert result.classification == 'xilinx_bitstream'


def test_elf_detection():
    """Bytes starting with \\x7fELF are classified as ELF."""
    data = b'\x7fELF' + b'\x00' * 60
    result = BlobAnalyzer.analyze(data)
    assert result.has_elf_header is True
    assert result.classification == 'elf_binary'


def test_high_entropy_classification():
    """Uniform distribution of all 256 bytes yields entropy > 7.0."""
    data = bytes(range(256)) * 4
    result = BlobAnalyzer.analyze(data)
    assert result.entropy > 7.0


def test_blobanalysis_dataclass():
    """BlobAnalysis is a proper dataclass with all fields."""
    analysis = BlobAnalysis(
        start_offset=0x100,
        size=1024,
        entropy=5.5,
        is_arm_thumb=False,
        has_xilinx_sync=False,
        has_elf_header=True,
        printable_ratio=0.1,
        null_ratio=0.02,
        classification='elf_binary',
        potential_code_types=['ELF'],
    )
    assert analysis.start_offset == 0x100
    assert analysis.size == 1024
    assert analysis.classification == 'elf_binary'
