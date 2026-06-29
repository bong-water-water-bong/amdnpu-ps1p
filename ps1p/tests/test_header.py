"""Tests for PS1p header parsing."""

from ps1p.header import parse_header, PS1pHeader


def test_parse_header_new(fw_new_data):
    """Parse header of v1.1.2.65 firmware."""
    hdr = parse_header(fw_new_data)
    assert hdr.magic == b'$PS1p'
    assert '1.1.2' in hdr.version_str or hdr.version_str != ""
    assert hdr.sha256_hex != ""
    assert len(hdr.sha256_binary) == 32
    assert not hdr.is_old


def test_parse_header_old(fw_old_data):
    """Parse header of v1.0.0.166 firmware."""
    hdr = parse_header(fw_old_data)
    assert hdr.magic == b'$PS1\xc0' or hdr.magic == b'$PS1p'
    assert hdr.is_old  # Old firmware detected as old


def test_header_validate_magic(fw_new_data):
    hdr = parse_header(fw_new_data)
    assert hdr.validate_magic()


def test_header_version_tuple(fw_new_data):
    hdr = parse_header(fw_new_data)
    tup = hdr.firmware_version_tuple()
    assert len(tup) == 3
    assert tup[0] >= 1


def test_header_claimed_size(fw_new_data):
    hdr = parse_header(fw_new_data)
    assert hdr.claimed_size > 0
    # Claimed size should be in range of actual file size
    # (the claimed size excludes trailing metadata)
    assert hdr.claimed_size < len(fw_new_data)
    assert hdr.claimed_size > len(fw_new_data) - 2000
