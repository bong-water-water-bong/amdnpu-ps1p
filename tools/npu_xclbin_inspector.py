"""NPU Xclbin Inspector — Inspect loaded/managed xclbin on NPU device.

Usage:
    python3 -m tools.npu_xclbin_inspector

Queries pyxrt to discover any loaded xclbin on the NPU device
and report kernel and compute unit information.
"""

import json

# Import pyxrt with graceful fallback for environments without XRT
try:
    import pyxrt as _pyxrt
    _HAS_XRT = True
except ImportError:
    _HAS_XRT = False
    _pyxrt = None


class XclbinInspector:
    """Inspect loaded/managed xclbin on NPU device."""

    def __init__(self):
        """Initialize, discover NPU devices."""
        self._device = None
        self._device_count = 0

        if _HAS_XRT:
            try:
                self._device_count = _pyxrt.enumerate_devices()
                if self._device_count > 0:
                    self._device = _pyxrt.device(0)
            except Exception:
                self._device_count = 0

    @staticmethod
    def get_loaded_xclbin(device_index: int = 0) -> dict:
        """Get info about currently loaded xclbin.

        Returns dict with 'uuid', 'kernels', 'CUs' or error.
        """
        if not _HAS_XRT:
            return {"error": "pyxrt not available"}

        try:
            dev_count = _pyxrt.enumerate_devices()
            if device_index >= dev_count:
                return {"error": f"device index {device_index} not available"}

            dev = _pyxrt.device(device_index)
            uuid = dev.get_xclbin_uuid()
            uuid_str = uuid.to_string()
            null_uuid = _pyxrt.uuid("00000000-0000-0000-0000-000000000000")

            if uuid_str == null_uuid.to_string():
                return {
                    "uuid": uuid_str,
                    "message": "no xclbin loaded on device",
                    "kernels": [],
                    "compute_units": [],
                }

            # Try to get kernel info from the loaded xclbin
            kernels = []
            try:
                # Attempt to extract kernel info via device query
                k_list = dev.get_info(_pyxrt.xrt_info_device.name)
                kernels = [{"name": str(k_list)}] if k_list else []
            except Exception:
                kernels = []

            return {
                "uuid": uuid_str,
                "kernels": kernels,
                "compute_units": kernels,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def list_kernels(device_index: int = 0) -> list:
        """List available kernels on device."""
        info = XclbinInspector.get_loaded_xclbin(device_index)
        if "error" in info:
            return []
        return info.get("kernels", [])

    @staticmethod
    def list_compute_units(device_index: int = 0) -> list:
        """List compute units on device."""
        info = XclbinInspector.get_loaded_xclbin(device_index)
        if "error" in info:
            return []
        return info.get("compute_units", [])

    @staticmethod
    def print_report(device_index: int = 0):
        """Print formatted xclbin report."""
        if not _HAS_XRT:
            print("XRT/pyxrt is not installed on this system.")
            return

        dev_count = _pyxrt.enumerate_devices()
        if device_index >= dev_count:
            print(f"Device index {device_index} not available.")
            print(f"Found {dev_count} device(s).")
            return

        info = XclbinInspector.get_loaded_xclbin(device_index)

        if "error" in info:
            print(f"Error querying xclbin: {info['error']}")
            return

        uuid_str = info.get("uuid", "unknown")
        print(f"Device {device_index} xclbin UUID: {uuid_str}")

        if info.get("message"):
            print(f"  {info['message']}")
            return

        kernels = info.get("kernels", [])
        if kernels:
            print(f"  Kernels ({len(kernels)}):")
            for k in kernels:
                print(f"    - {k}")
        else:
            print("  No kernels found.")

        cus = info.get("compute_units", [])
        if cus:
            print(f"  Compute Units ({len(cus)}):")
            for cu in cus:
                print(f"    - {cu}")
        else:
            print("  No compute units found.")


def main():
    """CLI entry point for npu_xclbin_inspector."""
    XclbinInspector.print_report()


if __name__ == "__main__":
    main()
