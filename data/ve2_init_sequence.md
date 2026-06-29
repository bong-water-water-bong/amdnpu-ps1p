# VE2 (NPU5/Strix Halo) Initialization Sequence

## Problem
We cannot create a HW context via raw IOCTLs because the VE2 kernel driver
requires specific initialization that only the XRT SHIM (userspace library) handles.

## Required Sequence
1. Open /dev/accel/accel0
2. Load/parse xclbin (stored in userspace - register_xclbin() is a no-op in SHIM)
3. Create DEV_HEAP BO with correct size (64MB, aligned to dev_mem_size)
4. Set up VA table with udma_fd and vaddr entries (via allocate_userptr_bo pattern)
5. Call DRM_IOCTL_AMDXDNA_CREATE_HWCTX with qos_p, num_tiles from xclbin
6. Kernel creates UMQ, returns doorbell and syncobj handles
7. Submit via DRM_IOCTL_AMDXDNA_EXEC_CMD
8. Wait via DRM_IOCTL_AMDXDNA_WAIT_CMD

## Blockers
- pyxrt Python bindings don't handle VE2 hw_context (mmap_range error)
- C raw IOCTL fails because DEV_HEAP needs VA table setup from XRT SHIM
- Error: "Invalid dev heap userptr" - heap's UVA is AMDXDNA_INVALID_ADDR
- XRT API version mismatch

## Next Steps
1. Build shim_test from xdna-driver source
2. Or run via the nop.elf + pyxrt.program path
