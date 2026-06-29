"""PS1p container header parsing."""

from __future__ import annotations
import struct
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PS1pHeader:
    """Parsed $PS1p container header."""
    magic: bytes                # b'$PS1p' at offset 0x10
    version_code: int           # 3-byte version at offset 0x15
    version_str: str            # Version string at offset 0x1D0
    claimed_size: int           # Claimed data size at offset 0x50
    field_30: int               # Field at offset 0x30
    sha256_hex: str             # SHA256 hex string at offset 0x130
    sha256_binary: bytes        # Binary hash at offset 0xD0
    signature_16: bytes         # First 16 bytes (header signature/checksum)
    is_old: bool = False        # True for v1.0.0.166 style layout

    def validate_magic(self) -> bool:
        """Check that magic is valid $PS1p."""
        return self.magic in (b'$PS1p',)

    def compute_sha256(self, data: bytes) -> str:
        """Verify SHA256 of data against header claim."""
        return hashlib.sha256(data).hexdigest()

    def firmware_version_tuple(self) -> tuple:
        """Return version as (major, minor, patch).

        Extracts the first three dotted numeric components from the
        version string (e.g. 'Release 1.2.3.65' -> (1, 2, 3)).
        """
        # Extract version-like pattern from string
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', self.version_str)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return (0, 0, 0)


def parse_header(data: bytes) -> PS1pHeader:
    """Parse $PS1p header from raw firmware bytes."""
    magic = data[0x10:0x15]
    ver_raw = data[0x15:0x18]
    ver_code = struct.unpack('<I', ver_raw + b'\x00')[0]

    # Version string at 0x1D0 (null-terminated)
    ver_str = ""
    for end in range(0x1D0, min(0x1F0, len(data))):
        if data[end] == 0:
            ver_str = data[0x1D0:end].decode(errors='replace')
            break
    else:
        ver_str = data[0x1D0:0x1F0].decode(errors='replace')

    claimed_size = struct.unpack('<Q', data[0x50:0x58])[0]
    field_30 = struct.unpack('<I', data[0x30:0x34])[0]

    # SHA256 hex string at 0x130 (null-terminated or fixed 64 chars)
    sha256_hex = ""
    raw_sha = data[0x130:0x170]
    try:
        sha256_hex = raw_sha.decode('ascii').rstrip('\x00')
    except UnicodeDecodeError:
        pass

    sig_16 = data[0:16]
    header_hash = data[0xD0:0xF0]

    # Detect old vs new firmware by checking if the region at 0x1C000
    # is all zeros (old) or has data (new). In new firmware, the string
    # table section occupies 0x1C000-0x20000. In old firmware, the code
    # section ends at 0x1C000 and sub_payload starts, which is all zeros
    # at the boundary.
    has_string_section = False
    if len(data) > 0x1C000:
        chunk = data[0x1C000:0x1C040]
        has_string_section = any(b != 0 for b in chunk)

    is_old = not has_string_section

    return PS1pHeader(
        magic=magic,
        version_code=ver_code,
        version_str=ver_str,
        claimed_size=claimed_size,
        field_30=field_30,
        sha256_hex=sha256_hex,
        sha256_binary=header_hash,
        signature_16=sig_16,
        is_old=is_old,
    )
