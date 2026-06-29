"""PS1p container model — read, extract, write firmware containers."""

from __future__ import annotations
import hashlib
import math
import os
from dataclasses import dataclass, field
from typing import Optional

from ps1p.header import parse_header, PS1pHeader


# Known section boundaries for both firmware versions
# (discovered through reverse engineering)
SECTION_MAP_NEW = {
    'header':       (0x00,    0x220,   "PS1p container header + metadata"),
    'ipu_code':     (0x220,   0x1C000, "VE2 IPU firmware (custom VLIW ISA)"),
    'string_table': (0x1C000, 0x20000, "Log strings and data tables"),
    'sub_payload':  (0x20000, 0x68C70, "AIE2 kernels, SOC headers, Xilinx bitstream"),
    'part_table':   (0x68A00, 0x68C70, "AIE partition table (0xABCDEF format)"),
    'padding':      (0x68C70, 0x68D70, "Zero padding"),
    'rsa_sig':      (0x68D70, 0x68E70, "RSA-2048 signature (256 bytes)"),
    'trailer':      (0x68E70, 0x68E72, "Trailer bytes (0x00 0x52)"),
}

SECTION_MAP_OLD = {
    'header':       (0x00,    0x220,   "PS1p container header + metadata"),
    'ipu_code':     (0x220,   0x1C000, "VE2 IPU firmware (custom VLIW ISA)"),
    'sub_payload':  (0x1C000, 0x5C940, "AIE2 kernels and data (old layout)"),
    'part_table':   (0x5C73A, 0x5C940, "Partition table (0xABCDEF format)"),
    'padding':      (0x5C940, 0x5CA80, "Non-zero padding (may contain data)"),
    'rsa_sig':      (0x5CA80, 0x5CB80, "RSA-2048 signature (256 bytes)"),
    'trailer':      (0x5CB80, 0x5CB82, "Trailer bytes"),
}


def entropy(data: bytes) -> float:
    """Compute Shannon entropy of binary data."""
    if len(data) == 0:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    result = -sum((c / total) * math.log2(c / total) for c in counts if c > 0)
    return max(0.0, result)  # Clamp -0.0 to 0.0


@dataclass
class Section:
    """A named section within the PS1p container."""
    name: str
    offset: int
    size: int
    description: str
    data: bytes = field(repr=False)

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def entropy_value(self) -> float:
        return entropy(self.data)

    def save(self, directory: str) -> str:
        """Save section data to a file. Returns path."""
        os.makedirs(directory, exist_ok=True)
        safe_name = self.name.replace('/', '_')
        path = os.path.join(directory, f"{safe_name}.bin")
        with open(path, 'wb') as f:
            f.write(self.data)
        return path


@dataclass
class PS1pContainer:
    """A parsed $PS1p firmware container."""
    header: PS1pHeader
    raw_data: bytes = field(repr=False)
    section_map: dict = field(repr=False)

    def __post_init__(self):
        self._sections: Optional[dict[str, Section]] = None

    @property
    def sections(self) -> dict[str, Section]:
        """Lazily extract all sections on first access."""
        if self._sections is None:
            self._sections = self._extract_sections()
        return self._sections

    def _extract_sections(self) -> dict[str, Section]:
        """Extract all named sections from raw data."""
        section_map = self.section_map
        result = {}
        for name, (start, end, desc) in section_map.items():
            if end > len(self.raw_data):
                end = len(self.raw_data)
            data = self.raw_data[start:end]
            result[name] = Section(
                name=name,
                offset=start,
                size=len(data),
                description=desc,
                data=data,
            )
        return result

    def get_section(self, name: str) -> Optional[Section]:
        """Get a section by name."""
        return self.sections.get(name)

    def extract_all(self, output_dir: str) -> dict[str, str]:
        """Extract all sections to output_dir. Returns {name: path}."""
        paths = {}
        for name, section in self.sections.items():
            path = section.save(output_dir)
            paths[name] = path
        return paths

    def compute_sha256(self) -> str:
        """Compute SHA256 of entire container."""
        return hashlib.sha256(self.raw_data).hexdigest()

    def summarize(self) -> dict:
        """Return a summary dict of the container."""
        summary = {
            'magic': self.header.magic.decode(errors='replace'),
            'version': self.header.version_str,
            'claimed_size': self.header.claimed_size,
            'actual_size': len(self.raw_data),
            'sha256_header': self.header.sha256_hex,
            'sha256_data': self.compute_sha256(),
            'is_old_format': self.header.is_old,
            'sections': {},
        }
        for name, section in self.sections.items():
            summary['sections'][name] = {
                'offset': f"0x{section.offset:05X}",
                'size': section.size,
                'end': f"0x{section.end:05X}",
                'entropy': round(section.entropy_value, 4),
                'sha256': section.sha256[:16] + '...',
            }
        return summary

    def patch(self, offset: int, new_data: bytes) -> PS1pContainer:
        """Create a new container with patched bytes at offset.

        Re-parses the header from the patched data so the returned
        container is internally consistent.
        """
        patched = bytearray(self.raw_data)
        patched[offset:offset + len(new_data)] = new_data
        patched_bytes = bytes(patched)
        header = parse_header(patched_bytes)
        section_map = SECTION_MAP_NEW if not header.is_old else SECTION_MAP_OLD
        return PS1pContainer(
            header=header,
            raw_data=patched_bytes,
            section_map=section_map,
        )

    def get_partition_table(self) -> Optional[list[dict]]:
        """Parse the partition table section into structured entries."""
        pt_section = self.get_section('part_table')
        if pt_section is None:
            return None

        from ps1p.partition import parse_partition_table
        return parse_partition_table(pt_section.data)


def open_ps1p(path: str) -> PS1pContainer:
    """Open a $PS1p firmware file and return a parsed container."""
    with open(path, 'rb') as f:
        data = f.read()
    return parse_ps1p(data)


def parse_ps1p(data: bytes) -> PS1pContainer:
    """Parse raw $PS1p firmware bytes into a container."""
    header = parse_header(data)
    section_map = SECTION_MAP_NEW if not header.is_old else SECTION_MAP_OLD
    return PS1pContainer(
        header=header,
        raw_data=data,
        section_map=section_map,
    )
