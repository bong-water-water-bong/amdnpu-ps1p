"""Binary blob analysis and classification.

Detects ARM/Thumb code, Xilinx bitstreams, ELF binaries, and other
binary content types within $PS1p firmware sections.
"""

from __future__ import annotations
import math
import struct
from dataclasses import dataclass
from typing import Optional


# ARM Thumb prologue opcodes — PUSH instructions that mark function entry
THUMB_PROLOGUES = {
    0xb580: 'PUSH {LR}',
    0xb510: 'PUSH {R4,LR}',
    0xb570: 'PUSH {R4-R6,LR}',
    0xb530: 'PUSH {R4-R5,LR}',
    0xb5f0: 'PUSH {R4-R7,LR}',
}

# Xilinx bitstream sync word
XILINX_SYNC = b'\xaa\x99'


@dataclass
class BlobAnalysis:
    """Results of analyzing a binary blob within firmware data."""

    start_offset: int
    size: int
    entropy: float
    is_arm_thumb: bool
    has_xilinx_sync: bool
    has_elf_header: bool
    printable_ratio: float
    null_ratio: float
    classification: str
    potential_code_types: list[str]


class BlobAnalyzer:
    """Analyzes binary regions found within firmware sections.

    Provides static methods for content classification, blob finding,
    and entropy computation.
    """

    @staticmethod
    def analyze(data: bytes, start_offset: int = 0) -> BlobAnalysis:
        """Analyze a binary blob and classify its content type.

        Parameters
        ----------
        data : bytes
            Raw binary data to analyze.
        start_offset : int
            Offset in the parent container (for reporting).

        Returns
        -------
        BlobAnalysis
            Structured analysis results.
        """
        if len(data) == 0:
            return BlobAnalysis(
                start_offset=start_offset,
                size=0,
                entropy=0.0,
                is_arm_thumb=False,
                has_xilinx_sync=False,
                has_elf_header=False,
                printable_ratio=0.0,
                null_ratio=0.0,
                classification='empty',
                potential_code_types=[],
            )

        ent = BlobAnalyzer._entropy(data)

        # ARM Thumb prologue detection — scan 16-bit aligned half-words
        thumb_count = 0
        for i in range(0, max(len(data), 1) - 1, 2):
            hw = struct.unpack('<H', data[i:i + 2])[0]
            if hw in THUMB_PROLOGUES:
                thumb_count += 1

        has_xilinx = XILINX_SYNC in data
        has_elf = data[:4] == b'\x7fELF'

        printable = sum(1 for b in data if 32 <= b < 127)
        nulls = sum(1 for b in data if b == 0)
        printable_ratio = printable / len(data)
        null_ratio = nulls / len(data)

        classification = BlobAnalyzer._classify(
            ent, printable_ratio, null_ratio, thumb_count, has_xilinx, has_elf
        )

        code_types: list[str] = []
        if thumb_count > 0:
            code_types.append('ARM Thumb')
        if has_elf:
            code_types.append('ELF')
        if has_xilinx:
            code_types.append('Xilinx FPGA')

        # Check for known magic patterns
        if data[:5] == b'$PS1p':
            code_types.append('PS1p Container')
        if data[:6] == b'XCLBIN':
            code_types.append('XCLBIN')

        return BlobAnalysis(
            start_offset=start_offset,
            size=len(data),
            entropy=round(ent, 4),
            is_arm_thumb=thumb_count > 0,
            has_xilinx_sync=has_xilinx,
            has_elf_header=has_elf,
            printable_ratio=round(printable_ratio, 4),
            null_ratio=round(null_ratio, 4),
            classification=classification,
            potential_code_types=code_types,
        )

    @staticmethod
    def find_blobs(
        data: bytes, min_size: int = 64, stride: int = 4
    ) -> list[BlobAnalysis]:
        """Scan for contiguous binary blobs in mixed text / binary data.

        Uses a sliding window to detect regions where ASCII printable
        bytes are sparse (< 15.6%), indicating binary content.

        Parameters
        ----------
        data : bytes
            Raw data to scan.
        min_size : int
            Minimum blob size to report.
        stride : int
            Step size between window positions.

        Returns
        -------
        list[BlobAnalysis]
            Detected blobs, sorted largest first.
        """
        current_start: Optional[int] = None
        blobs: list[BlobAnalysis] = []
        threshold = 10  # out of 64 bytes

        for i in range(0, len(data) - 64, stride):
            chunk = data[i:i + 64]
            ascii_bytes = sum(1 for b in chunk if 32 <= b < 127)

            if ascii_bytes < threshold:
                if current_start is None:
                    current_start = i
            else:
                if current_start is not None and (i - current_start) > min_size:
                    blob_data = data[current_start:i]
                    blobs.append(
                        BlobAnalyzer.analyze(blob_data, current_start)
                    )
                current_start = None

        # Handle blob that extends to end of data
        if current_start is not None and (len(data) - current_start) > min_size:
            blob_data = data[current_start:]
            blobs.append(BlobAnalyzer.analyze(blob_data, current_start))
        elif current_start is None:
            # Check for binary blob at the very end that wasn't caught
            # by the loop (e.g., data shorter than window, or window stride
            # missed the last few bytes)
            last_start = max(0, len(data) - min_size)
            for i in range(last_start, len(data) - 64 + 1, stride):
                chunk = data[i:i + 64]
                ascii_bytes = sum(1 for b in chunk if 32 <= b < 127)
                if ascii_bytes < threshold:
                    blob_data = data[i:]
                    if len(blob_data) > min_size:
                        blobs.append(BlobAnalyzer.analyze(blob_data, i))
                    break

        return sorted(blobs, key=lambda b: -b.size)

    @staticmethod
    def _classify(
        ent: float,
        printable_ratio: float,
        null_ratio: float,
        thumb_count: int,
        has_xilinx: bool,
        has_elf: bool,
    ) -> str:
        """Classify binary blob type based on computed metrics.

        Priority order: ELF > bitstream > ARM code > text > high entropy
        > binary code > sparse data > data table > low entropy data.
        """
        if has_elf:
            return 'elf_binary'
        if has_xilinx:
            return 'xilinx_bitstream'
        if thumb_count > 0:
            return 'arm_code'
        if printable_ratio > 0.6:
            return 'text_strings'
        if ent > 7.8:
            return 'high_entropy (possibly encrypted)'
        if ent > 6.0 and null_ratio < 0.2:
            return 'binary_code'
        if null_ratio > 0.6:
            return 'sparse_data'
        if ent > 4.0:
            return 'data_table'
        return 'low_entropy_data'

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Compute the Shannon entropy of *data*.

        Returns a float between 0.0 (all same byte) and 8.0 (perfectly
        uniform distribution of all 256 byte values).
        """
        if len(data) == 0:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        return -sum(
            (c / total) * math.log2(c / total) for c in counts if c > 0
        )
