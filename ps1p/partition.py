"""PS1p partition table parser."""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional


PARTITION_MAGIC = 0x00ABCDEF
VA_CODE_BASE = 0x28B00000
VA_DATA_BASE = 0x28A80000
MAX_PARTITION_COUNT = 256  # 32 bytes * 256 = 8KB max for firmware partition tables


@dataclass
class PartitionEntry:
    """A single entry in a partition table."""
    fields: list[int]
    offset_in_table: int
    
    @property
    def first_va(self) -> Optional[int]:
        """If first field looks like a virtual address, return it."""
        if self.fields and (self.fields[0] & 0xFF000000) in (0x28000000, 0x08000000):
            return self.fields[0]
        return None
    
    @property
    def is_code(self) -> bool:
        """Check if this entry references code region."""
        va = self.first_va
        return va is not None and (va & 0xFFFF0000) in (0x28B00000, 0x28A80000)
    
    def __repr__(self) -> str:
        flds = ', '.join(f'0x{f:08x}' if f > 0xFFFF else str(f) for f in self.fields[:6])
        extra = '...' if len(self.fields) > 6 else ''
        return f"PartitionEntry([{flds}{extra}])"


@dataclass
class PartitionTable:
    """A parsed partition table."""
    count: int
    header_fields: list[int]
    entries: list[PartitionEntry]
    raw_data: bytes = field(repr=False)
    
    @classmethod
    def parse(cls, data: bytes, base_offset: int = 0) -> Optional[PartitionTable]:
        """Parse a partition table from raw bytes. Returns None if no magic found."""
        if len(data) < 8:
            return None
        
        header = struct.unpack('<II', data[:8])
        if header[0] != PARTITION_MAGIC:
            return None
        
        count = header[1]
        # Safety cap to prevent DoS from maliciously large count values
        count = min(count, MAX_PARTITION_COUNT)
        entries = []
        
        for i in range(count):
            off = 8 + i * 32
            if off + 32 > len(data):
                break
            fields = list(struct.unpack('<IIIIIIII', data[off:off + 32]))
            # Stop at first zero-only entry (padding)
            entries.append(PartitionEntry(
                fields=fields,
                offset_in_table=base_offset + off,
            ))
        
        return cls(
            count=count,
            header_fields=[],
            entries=entries,
            raw_data=data,
        )
    
    def code_entries(self) -> list[PartitionEntry]:
        """Return entries that look like code regions."""
        return [e for e in self.entries if e.first_va and e.first_va >= VA_CODE_BASE]
    
    def data_entries(self) -> list[PartitionEntry]:
        """Return entries that look like data regions."""
        return [e for e in self.entries if e.first_va and VA_DATA_BASE <= e.first_va < VA_CODE_BASE]


def parse_partition_table(data: bytes, base_offset: int = 0) -> Optional[list[dict]]:
    """Parse partition table into structured dictionaries for display."""
    pt = PartitionTable.parse(data, base_offset)
    if pt is None:
        return None
    
    result = []
    for entry in pt.entries:
        fields_hex = []
        for f in entry.fields[:8]:
            if f >= 0x20000000:
                fields_hex.append(f"VA=0x{f:08x}")
            elif f == 0xFFFFFFFF:
                fields_hex.append("-1")
            elif f <= 0x100:
                fields_hex.append(str(f))
            else:
                fields_hex.append(f"0x{f:08x}")
        
        result.append({
            'offset': f"0x{entry.offset_in_table:05X}",
            'fields': fields_hex,
            'is_code': entry.is_code,
        })
    
    return result
