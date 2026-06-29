# VE2 IPU Firmware Serialization Gate Patch

## Summary
Patched the "one call at a time" serialization gate in the Strix Halo NPU VE2 firmware by NOP'ing the conditional branch chain that checks if the requesting application is the "last scheduled application".

## Patch Details

### File
- **Original**: `/lib/firmware/amdnpu/17f0_11/npu_7.sbin` (v1.1.2.65)
- **Patched**: `npu_patched.sbin`

### What was changed
The firmware contains a conditional branch chain (7 BEQ/BEQ-like instructions) at
**firmware address 0x2DD8-0x2DF4** that implements the scheduling serialization check:

```
0x2DD8: BEQ r7, r8    ; if (current_app == last_scheduled_app) continue
0x2DDC: BEQ r11, r12  ; if (other_app == last_scheduled) continue
0x2DE0: BEQ r15, r8   ; if (other_app == last_scheduled) continue
...
0x2DF0: BEQ r12, r8   ; if (other_app == last_scheduled) continue
```

If ALL checks fail (no context matches the "last scheduled" app), the firmware
rejects the command with error:
> "%s: Application %u is not the last scheduled. The last scheduled was %d."

**Patch**: All 7 conditional branches were replaced with NOP (0x00000000),
causing execution to always fall through to the success path.

### Bytes Changed
- 28 bytes of instructions NOP'd (0x2DD8-0x2DF7)
- 16 bytes of header hash updated (if using hash-fixed version)

### Patch Files
1. `npu_patched_original_hash.sbin` - preserves original header hash (risks loader rejection)
2. `npu_patched.sbin` - updated SHA256 header hash

## Installation

### Prerequisites
- Strix Halo system with NPU5 (PCI 17f0:11)
- Root access for firmware replacement

### Steps
```bash
# Backup original firmware
sudo cp /lib/firmware/amdnpu/17f0_11/npu_7.sbin /lib/firmware/amdnpu/17f0_11/npu_7.sbin.bak

# Install patched firmware
sudo cp /path/to/npu_patched.sbin /lib/firmware/amdnpu/17f0_11/npu_7.sbin

# Reload driver
sudo modprobe -r amdxdna
sudo modprobe amdxdna

# Test concurrent access
# Run two NPU workloads simultaneously
```

## Testing
After installation, test concurrent NPU access by running multiple workloads in parallel:
1. Launch two FastFlowLM inference requests simultaneously
2. Launch two raw NPU context creation requests
3. Measure latency vs sequential submission

## Risks
- Firmware hash validation may reject patched binary (use original hash version first)
- If firmware crashes, reload driver or reboot
- The firmware has a kernel-side serialization check too (`active_ctx` FIFO in `ve2_mgmt.c`)

## Code References
- `ve2_mgmt.c:1296` - Kernel-side "not the last scheduled" check (for coredump only)
- `ve2_mgmt.c:475` - `ve2_mgmt_schedule_cmd()` - kernel scheduling entry point
- `struct handshake` in `ve2_host_queue.h` - firmware-to-host communication protocol

## Technical Notes
- The firmware uses a dual-issue 16-bit VLIW ISA
- The serialization gate is in the firmware's interrupt handler (doorbell handler)
- Patching bypasses the "last scheduled application" check only
- The kernel's `active_ctx` FIFO still serializes at the driver level
- Full concurrent access requires patching BOTH firmware AND kernel driver
