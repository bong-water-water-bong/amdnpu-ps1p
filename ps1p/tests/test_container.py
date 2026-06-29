"""Tests for PS1p container parsing."""

from ps1p.container import parse_ps1p, entropy, Section
import tempfile
import os


def test_parse_new(fw_new_data):
    """Parse entire new firmware container."""
    c = parse_ps1p(fw_new_data)
    assert c.header.magic == b'$PS1p'
    assert 'ipu_code' in c.sections
    assert 'string_table' in c.sections
    assert 'sub_payload' in c.sections
    assert 'rsa_sig' in c.sections


def test_parse_old(fw_old_data):
    """Parse entire old firmware container."""
    c = parse_ps1p(fw_old_data)
    assert c.header.magic == b'$PS1\xc0' or c.header.magic == b'$PS1p'
    assert 'ipu_code' in c.sections
    assert 'sub_payload' in c.sections
    assert 'part_table' in c.sections
    assert 'rsa_sig' in c.sections


def test_get_section(fw_new_data):
    c = parse_ps1p(fw_new_data)
    ipu = c.get_section('ipu_code')
    assert ipu is not None
    assert ipu.size > 100000  # IPU code is >100KB
    assert ipu.offset == 0x220


def test_section_entropy(fw_new_data):
    c = parse_ps1p(fw_new_data)
    ipu = c.get_section('ipu_code')
    # IPU code should have entropy around 5-7 (code, not encrypted)
    assert 3.0 < ipu.entropy_value < 8.0


def test_section_sha256(fw_new_data):
    c = parse_ps1p(fw_new_data)
    ipu = c.get_section('ipu_code')
    assert len(ipu.sha256) == 64  # hex string


def test_section_save(fw_new_data):
    c = parse_ps1p(fw_new_data)
    ipu = c.get_section('ipu_code')
    with tempfile.TemporaryDirectory() as tmpdir:
        path = ipu.save(tmpdir)
        assert os.path.exists(path)
        with open(path, 'rb') as f:
            saved = f.read()
        assert saved == ipu.data


def test_extract_all(fw_new_data):
    c = parse_ps1p(fw_new_data)
    with tempfile.TemporaryDirectory() as tmpdir:
        paths = c.extract_all(tmpdir)
        assert 'ipu_code' in paths
        assert os.path.exists(paths['ipu_code'])


def test_summarize(fw_new_data):
    c = parse_ps1p(fw_new_data)
    s = c.summarize()
    assert s['magic'] == '$PS1p'
    assert 'ipu_code' in s['sections']


def test_patch(fw_new_data):
    c = parse_ps1p(fw_new_data)
    patched = c.patch(0x10, b'\x00' * 5)  # Patch magic
    assert len(patched.raw_data) == len(fw_new_data)


def test_entropy():
    """Test Shannon entropy calculation."""
    # All same byte = 0 entropy
    assert entropy(b'\x00' * 100) == 0.0
    # Alternating = 1.0
    assert abs(entropy(bytes([0, 1]) * 50) - 1.0) < 0.01
    # Empty
    assert entropy(b'') == 0.0
