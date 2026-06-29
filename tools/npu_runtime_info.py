"""NPU Runtime Info — Query NPU device capabilities via pyxrt.

Usage:
    python3 -m tools.npu_runtime_info

This module provides a thin wrapper around pyxrt (Python XRT bindings)
to enumerate AMD NPU devices and report their capabilities.
"""

import json

# Import pyxrt with graceful fallback for environments without XRT
try:
    import pyxrt as _pyxrt
    _HAS_XRT = True
except ImportError:
    _HAS_XRT = False
    _pyxrt = None


class NpuRuntimeInfo:
    """Query NPU device capabilities via pyxrt."""

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

    def enumerate_devices(self) -> int:
        """Return count of XRT devices."""
        return self._device_count

    def get_device_info(self, device_index: int = 0) -> dict:
        """Get info dict for a device: BDF, UUID, name, etc.

        Returns 'info' dict or error dict if device not available.
        Keys: 'bdf', 'uuid', 'name', 'device_index'
        """
        if not _HAS_XRT:
            return {"error": "pyxrt not available", "device_index": device_index}

        if self._device is None or device_index >= self._device_count:
            return {"error": "no NPU device found", "device_index": device_index}

        try:
            info = {
                "bdf": self._device.get_info(_pyxrt.xrt_info_device.bdf),
                "name": self._device.get_info(_pyxrt.xrt_info_device.name),
                "device_index": device_index,
            }

            # Try to get additional info (may fail on some queries)
            try:
                uuid_str = self._device.get_xclbin_uuid().to_string()
                info["xclbin_uuid"] = uuid_str
            except Exception:
                info["xclbin_uuid"] = None

            try:
                host_info_raw = self._device.get_info(_pyxrt.xrt_info_device.host)
                info["xrt_version"] = json.loads(host_info_raw).get("version", "unknown")
            except Exception:
                info["xrt_version"] = "unknown"

            return info
        except Exception as e:
            return {"error": str(e), "device_index": device_index}

    def print_report(self):
        """Print formatted device report.

        If no NPU device found, prints helpful message about
        checking amdxdna driver.
        """
        if not _HAS_XRT:
            print("XRT/pyxrt is not installed on this system.")
            print("Install XRT and pyxrt Python bindings to query NPU devices.")
            return

        if self._device_count == 0:
            print("No NPU device found.")
            print()
            print("Possible causes:")
            print("  1. The amdxdna driver may not be loaded")
            print("     -> Run: sudo modprobe amdxdna")
            print("  2. No AMD NPU hardware present on this system")
            print("  3. The XRT daemon may not be running")
            print("     -> Run: sudo systemctl start xrtd")
            return

        print(f"Found {self._device_count} NPU device(s)")
        print()

        for i in range(self._device_count):
            info = self.get_device_info(i)
            print(f"--- Device {i} ---")
            for key, value in info.items():
                print(f"  {key}: {value}")
            print()

    def check_xrt_version(self) -> str:
        """Return pyxrt version string."""
        if not _HAS_XRT:
            return "pyxrt not available"

        try:
            host_info_raw = self._device.get_info(_pyxrt.xrt_info_device.host)
            host_info = json.loads(host_info_raw)
            return host_info.get("version", "unknown")
        except Exception:
            return "unknown"


def main():
    """CLI entry point for npu_runtime_info."""
    info = NpuRuntimeInfo()
    info.print_report()


if __name__ == "__main__":
    main()
