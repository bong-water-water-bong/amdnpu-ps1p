"""Tests for partition table parsing."""

from ps1p.partition import PartitionTable, PartitionEntry, PARTITION_MAGIC, parse_partition_table
from ps1p.container import parse_ps1p
import struct


def test_parse_partition_table_new(fw_new_data):
    """Parse partition table from new firmware footer."""
    c = parse_ps1p(fw_new_data)
    pt_section = c.get_section('part_table')
    assert pt_section is not None
    
    pt = PartitionTable.parse(pt_section.data)
    assert pt is not None
    assert pt.count >= 1
    assert len(pt.entries) > 0


def test_parse_partition_table_old(fw_old_data):
    """Parse partition table from old firmware (if section exists)."""
    c = parse_ps1p(fw_old_data)
    pt_section = c.get_section('part_table')
    if pt_section is None or len(pt_section.data) == 0:
        # Old firmware variant may have offset past EOF; skip gracefully
        return
    
    pt = PartitionTable.parse(pt_section.data)
    assert pt is not None
    assert pt.count >= 1
    assert len(pt.entries) > 0


def test_magic_detection():
    """Test magic detection with crafted data."""
    # Valid magic
    data = struct.pack('<II', PARTITION_MAGIC, 3) + b'\x00' * (32 * 3)
    pt = PartitionTable.parse(data)
    assert pt is not None
    assert pt.count == 3
    
    # Invalid magic
    data2 = struct.pack('<II', 0xDEADBEEF, 3) + b'\x00' * (32 * 3)
    pt2 = PartitionTable.parse(data2)
    assert pt2 is None
    
    # Too short
    pt3 = PartitionTable.parse(b'\x00' * 4)
    assert pt3 is None


def test_parse_partition_entry_fields(fw_new_data):
    """Parse partition entries and verify field structure."""
    c = parse_ps1p(fw_new_data)
    pt_section = c.get_section('part_table')
    pt = PartitionTable.parse(pt_section.data)
    
    assert len(pt.entries) > 0
    for entry in pt.entries:
        assert len(entry.fields) == 8
        assert entry.offset_in_table > 0


def test_code_entries_filtering(fw_new_data):
    """Test that code_entries returns entries with VA in code range."""
    c = parse_ps1p(fw_new_data)
    pt_section = c.get_section('part_table')
    pt = PartitionTable.parse(pt_section.data)
    
    code_entries = pt.code_entries()
    for e in code_entries:
        assert e.first_va is not None
        assert e.first_va >= 0x28B00000


def test_data_entries_filtering(fw_new_data):
    """Test that data_entries returns entries with VA in data range."""
    c = parse_ps1p(fw_new_data)
    pt_section = c.get_section('part_table')
    pt = PartitionTable.parse(pt_section.data)
    
    data_entries = pt.data_entries()
    for e in data_entries:
        assert e.first_va is not None
        assert 0x28A80000 <= e.first_va < 0x28B00000


def test_parse_partition_table_function(fw_new_data):
    """Test the convenience parse_partition_table function."""
    c = parse_ps1p(fw_new_data)
    pt_section = c.get_section('part_table')
    result = parse_partition_table(pt_section.data)
    assert result is not None
    assert len(result) > 0
    for entry in result:
        assert 'offset' in entry
        assert 'fields' in entry
        assert 'is_code' in entry


def test_partition_entry_repr():
    """Test partition entry string representation."""
    entry = PartitionEntry(fields=[0x28B00000, 0x1000, 0, 0, 0, 0, 0, 0], offset_in_table=0x68A08)
    r = repr(entry)
    assert '0x28b00000' in r


def test_parse_partition_table_none():
    """Test parse_partition_table returns None for invalid data."""
    result = parse_partition_table(b'\x00' * 8)
    assert result is None


def test_partition_entry_first_va():
    """Test first_va property behavior."""
    # Entry with VA-like first field
    entry = PartitionEntry(fields=[0x28B00000, 0, 0, 0, 0, 0, 0, 0], offset_in_table=0)
    assert entry.first_va == 0x28B00000
    
    # Entry with non-VA first field
    entry2 = PartitionEntry(fields=[0x1, 0, 0, 0, 0, 0, 0, 0], offset_in_table=0)
    assert entry2.first_va is None
    
    # Empty fields
    entry3 = PartitionEntry(fields=[], offset_in_table=0)
    assert entry3.first_va is None
