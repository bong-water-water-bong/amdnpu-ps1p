# Strix Halo NPU Serialization Stack (Full Analysis)

## Date: 2025-06-29
## Firmware: 17f0_11/npu_7.sbin v1.1.2.65
## Platform: VE2 (NPU5) — NOT legacy NPU4/AIE2 SMU

---

## Discovery: VE2 Does Not Use SMU Mailbox Protocol for NPU Commands

**Major correction from earlier hypothesis:**
The Strix Halo NPU (NPU5/VE2, PCI 17f0:11) uses a fundamentally different architecture from the NPU4/AIE2 generation.

- **NPU4** (17f0:10): Uses SMU mailbox protocol via:
  - SMU_CMD_REG  = MP1_C2PMSG_0  = 0x3B10900 (BAR idx 5, offset 0)
  - SMU_ARG_REG  = MP1_C2PMSG_60 = 0x3B109F0
  - SMU_RESP_REG = MP1_C2PMSG_61 = 0x3B109F4
  - SMU_INTR_REG = MMNPU_APERTURE4_BASE (BAR0 offset)
  - Protocol: write(0->RESP) -> write(ARG) -> write(CMD) -> write(0->INTR) -> write(1->INTR) -> poll(RESP)

- **NPU5** (17f0:11, Strix Halo): Uses VE2 with Xilinx AI Engine Partition Driver
  - No SMU mailbox for NPU command submission
  - Firmware loaded via aie_partition_initialize() directly into IPU SRAM
  - Command submission via HSA queue mechanism (host writes packet ring in shared memory)
  - Doorbell via event generation register VE2_EVENT_GENERATE_REG = 0x00034008
  - Doorbell value: VE2_USER_EVENT_ID = 0xB6

---

## The Actual Serialization Stack

Userspace (XRT SHIM) -> DRM_IOCTL_AMDXDNA_EXEC_CMD
  Kernel Driver (amdxdna.ko):
    ve2_cmd_submit() -> "Only support single command for now"
    ve2_mgmt_schedule_cmd() -> ve2_fifo_enqueue()
    Only ONE active_ctx per partition
    notify_fw_cmd_ready() -> write 0xB6 to 0x34008
    wait_event_interruptible_timeout() in cmd_wait()
  IPU Firmware (runs on VE2 Image Processor Unit):
    Event handler for 0xB6:
      "not the last scheduled" check -> serialization gate
      Power on columns (DLDO/ONO) -> Execute -> Power off columns
      Update read_index -> Signal completion IRQ

---

## The 3 Serialization Gates

### Gate 1: Kernel Driver FIFO
- mgmtctx->active_ctx ensures only ONE context runs
- Context switch guarded by ctx_switch_req handshake bit

### Gate 2: Firmware "Last Scheduled Application" Check
- String "Application %u is not the last scheduled"
- Firmware checks last_executed_app_id against submitting app's ID

### Gate 3: Column Power Gating (DLDO/ONO)
- Each command: power on -> execute -> power off
- "ONO 0 trying to power off, but not all other ONO regions are off"

## Key Files

| Item | Location |
|------|----------|
| VE2 mgmt scheduling | xdna-driver/src/driver/amdxdna/ve2_mgmt.c |
| VE2 hwctx cmd_submit | xdna-driver/src/driver/amdxdna/ve2_hwctx.c:945 |
| VE2 notify_fw | xdna-driver/src/driver/amdxdna/ve2_mgmt.c:1440 |
| VE2 handshake | xdna-driver/src/driver/amdxdna/ve2_mgmt.h |
| VE2 host queue | xdna-driver/src/driver/amdxdna/ve2_host_queue.h |
| NPU5 regs | xdna-driver/src/driver/amdxdna/npu5_regs.c |
| SMU protocol (NPU4) | xdna-driver/src/driver/amdxdna/aie_smu.c |
| Firmware binary | /lib/firmware/amdnpu/17f0_11/npu_7.sbin |
| Active firmware | PCI 0000:c6:00.1, version 1.1.2.65 |
| XRT SHIM | /opt/xilinx/xrt/lib64/libxrt_driver_xdna.so.2.23.0 |

## ISA Status
The IPU uses a custom non-RISC-V 32-bit ISA:
- op4=0x0: 39.7% (dominant)
- Standard RISC-V decoder matches only 4.9% of instructions
- No stack frame prologues found
- Recommend Ghidra with custom processor module or xdna-emu test infra
