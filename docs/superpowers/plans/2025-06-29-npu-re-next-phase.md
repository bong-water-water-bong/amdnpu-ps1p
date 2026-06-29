# NPU Reverse Engineering — Next Phase Implementation Plan

> **Context:** The `ps1p` package is complete and published (v0.1.0, MIT). This plan covers the next phase: AIE2 ELF extraction from sub_payload, VE2 disassembler v2 refinement, and pyxrt runtime integration.

**Goal:** Build the complete toolchain for AMD Strix Halo NPU firmware analysis — from $PS1p container → section extraction → AIE2 control data parsing → VE2 IPU disassembly → runtime NPU interaction via pyxrt.

**Architecture:** Each task builds on the previous. The `ps1p` package provides section extraction. The `tools/` directory holds analysis and interaction scripts.

---

## Current State

### What Exists
| Component | Status | Location |
|-----------|--------|----------|
| $PS1p container parser | ✅ Published v0.1.0 | `ps1p/` package |
| Blob analyzer (entropy, ARM thumb, Xilinx) | ✅ Published | `ps1p/blob.py` |
| Partition table parser | ✅ Published | `ps1p/partition.py` |
| CLI (info/extract/dump/repack) | ✅ Published | `ps1p/cli.py` |
| Serialization gate analysis | ✅ Complete | `tools/find_serialization_gate.py`, `tools/analyze_gate.py` |
| Patch scripts | ✅ Complete | `tools/patch_serialization_gate.py` |
| VE2 disassembler v1 (statistical) | ✅ Partial | `tools/ipu_disasm.py` |
| Old extraction scripts | ✅ Kept | `tools/decrypt_ipu_fw.py`, `tools/extract_ipu_fw.py` |
| C test programs | ✅ Present | `tools/npu_concurrent_test.c`, `tools/npu_xrt_test.cpp` |
| pyxrt device access | ✅ Working | NPU detected, device object created |

### What Needs Building

**Phase A — AIE2 Control Data Extraction (sub_payload deep dive)**
The `sub_payload` section (298KB at offset 0x20000) contains AIE2 column configuration, bitstream data, and control packets. We need to:
1. Parse the log format strings at the start of sub_payload
2. Locate AIE2 column configuration blocks
3. Extract any embedded AIE2 ELF sections (even without ELF magic, the data may be raw AIE2 machine code)
4. Transform extracted data into a format aiebu-dump can consume

**Phase B — VE2 Disassembler v2 (cross-verified)**
The existing `ipu_disasm.py` uses statistical decoding. We need to:
1. Use aiebu-asm to compile known instruction sequences
2. Cross-reference compiled output against firmware to build a real opcode map
3. Implement proper VLIW packet parsing (the dual-issue 16-bit slots)
4. Add label resolution for branches/calls

**Phase C — pyxrt Runtime Integration**
The device is accessible via pyxrt. We need to:
1. Extract the currently-loaded xclbin
2. Inspect kernel compute units
3. Run test workloads and measure performance
4. Integrate with the patched firmware (deployment verification)

---

## Task A1: Sub-Payload String Table Parser

**Files:**
- Create: `tools/sub_payload_parser.py`
- Read from: `ps1p` (`open_ps1p`, `PS1pContainer`)
- Data: `/tmp/orig_decomp.sbin`

**Verification:**
- Parses the format strings at the start of sub_payload
- Lists all log format strings with their offsets
- Groups strings by subsystem (xaie_reset, MGMT, etc.)

**Approach:**
The sub_payload starts with AIE log format strings like:
```
r: thd=%u
xaie_reset_init_ips0_all()
xaie_reset_init()
xaie_reset_init_col(column=%u)
[MGT] xaie_partition_init() start int...
```

These are format strings used by the AIE firmware layer. They precede the actual binary control data. We'll extract and categorize them.

---

## Task A2: AIE2 Column Configuration Extractor

**Files:**
- Modify: `tools/sub_payload_parser.py`
- Create: `tools/aiebu_dump_wrapper.py`

**Verification:**
- Identifies column config blocks (look for AIE2 tile patterns)
- Extracts raw AIE2 control packets
- Can feed extracted data to `aiebu-dump -m aie2txn` or `aiebu-dump -m aie2ps`

**Approach:**
AIE2 column configuration consists of:
1. Column header metadata (col number, num tiles, type)
2. Per-tile configuration (DMA descriptors, program memory)
3. Control packets (for aiebu-dump disassembly)

The `aiebu-dump` tool supports targets: `aie2ps`, `aie2asm`, `aie2txn`, `aie2dpu`. We need to:
1. Find AIE2 transaction blobs in sub_payload (look for 0xAA99 Xilinx sync word clusters)
2. Extract contiguous regions containing AIE2 control packets
3. Attempt disassembly with `aiebu-dump -m aie2txn`

---

## Task B1: aiebu-toolchain Cross-Reference

**Files:**
- Create: `tools/compile_isa_test.py` — Compile known AIE2PS instructions via aiebu-asm
- Create: `tools/isa_opcode_map_v2.py` — Build opcode map from compiled output
- Create: `tools/ipu_disasm_v2.py` — New disassembler with verified opcodes

**Verification:**
- `aiebu-asm -t aie2ps` can compile test programs
- Compiled output has known instruction encodings
- Encodings match firmware patterns at the serialization gate region

**Approach:**
The aiebu-asm tool supports `-t aie2ps` (the IPU's processor type). We'll:
1. Write minimal AIE2PS assembly test programs (NOP, ADD, SUB, branch, load, store)
2. Compile each with `aiebu-asm -t aie2ps -o test.o test.S`
3. Extract instruction encoding from the compiled ELF
4. Build a verified opcode map
5. Use the verified map to improve the disassembler

---

## Task B2: Verified Disassembler

**Files:**
- Create: `tools/ipu_disasm_v2.py` — Full disassembler with verified opcodes
- Create: `tools/ipu_disasm_test.py` — Tests against known encodings
- Data: `data/isa_map.md` — Documentation of the ISA

**Verification:**
- Correctly disassembles the serialization gate region (0x2DD8-0x2DF1)
- All 7 BEQ branches at the gate are properly decoded
- Regression: output matches manual analysis from existing gate analysis

**Approach:**
The existing analysis found:
- 7 BEQ branches at addresses: 0x2DD8, 0x2DDC, 0x2DE0, 0x2DE4, 0x2DE8, 0x2DEC, 0x2DF0
- String reference at 0x32B0 (literal pool entry for "not the last scheduled")

We'll verify the new disassembler produces correct mnemonics for these addresses.

---

## Task C1: pyxrt Runtime Toolkit

**Files:**
- Create: `tools/npu_runtime_info.py` — Query NPU device capabilities
- Create: `tools/npu_xclbin_inspector.py` — Extract and inspect the loaded xclbin
- Modify: `tools/npu_xrt_test.cpp` — Update for use with pyxrt runtime library

**Verification:**
- Reports NPU device info (PCIe BDF, UUID, name)
- Lists available xclbin kernels and compute units
- Can run a workload and measure execution time

**Approach:**
pyxrt provides Python bindings to XRT. We can:
1. `pyxrt.enumerate_devices()` → count
2. `pyxrt.device(0)` → device object
3. `device.get_info(pyxrt.xrt_info_device(0))` → BDF
4. `device.register_xclbin(xclbin)` / `device.load_xclbin()` → xclbin management
5. `pyxrt.xclbin()` → create/manage xclbin objects
6. `pyxrt.kernel(xclbin, "name")` → create kernel
7. `pyxrt.run(kernel)` → execute

---

## Task C2: Firmware Deployment Pipeline

**Files:**
- Create: `tools/fw_deploy.py` — Load patched firmware onto NPU
- Create: `tools/npu_stress_test.py` — Concurrent workload stress test

**Verification:**
- Can reload NPU firmware from a custom path
- With patched firmware, concurrent workloads execute without serialization
- Performance improves with concurrent access

**Approach:**
NPU firmware loading can be triggered by:
1. Writing to `/sys/bus/pci/drivers/amdxdna/unbind` then `bind`
2. Reloading the `amdxdna` kernel module with `modprobe -r amdxdna && modprobe amdxdna`
3. The firmware file path can be overridden (check kernel module params)

---

## Self-Review Checklist

1. **Phase A verification:** sub_payload string extraction + column config identification
2. **Phase B verification:** aiebu-asm compilation → verified opcode map → correct disassembly at gate region
3. **Phase C verification:** pyxrt device info, kernel listing, workload execution
4. **No regressions:** all 41 ps1p tests still pass
5. **No hardcoded internal paths** in any new files
6. **Intermediate commits** after each sub-task
