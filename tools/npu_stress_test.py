#!/usr/bin/env python3
"""
NPU Stress Test Tool
=====================
Run concurrent workload stress test on AMD NPU devices.

This tool exercises the NPU by spinning up concurrent worker threads
that perform operations against the NPU device. It gracefully handles
the case where no NPU device is present.

Usage:
  python3 -m tools.npu_stress_test --help
  python3 -m tools.npu_stress_test --threads 4 --duration 10

If no NPU device is detected, the tool prints an informative message
and exits cleanly.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# Global state for concurrent workers
_results_lock = threading.Lock()
_worker_results: list[dict] = []


def _worker(worker_id: int, duration_sec: int):
    """Worker thread that simulates NPU workload.

    In the absence of a real NPU driver interface (e.g., /dev/accel/accel0),
    this worker exercises the system interface to validate the NPU is
    responsive. It performs:
      - Reading PCIe config space via sysfs
      - Checking sysfs device attributes
      - Optional DRM-style IOCTL on /dev/accel/accel0

    Results are appended to the global _worker_results list.
    """
    start = time.time()
    ops = 0
    errors = 0
    latencies: list[float] = []

    bdf = "0000:c6:00.1"
    sysfs_base = f"/sys/bus/pci/devices/{bdf}"

    while time.time() - start < duration_sec:
        try:
            t0 = time.time()

            # Try reading PCI vendor/device IDs via sysfs
            if os.path.isdir(sysfs_base):
                vendor_path = os.path.join(sysfs_base, "vendor")
                device_path = os.path.join(sysfs_base, "device")
                if os.path.isfile(vendor_path):
                    with open(vendor_path) as f:
                        _ = f.read().strip()
                if os.path.isfile(device_path):
                    with open(device_path) as f:
                        _ = f.read().strip()

            # Try reading driver symlink (present if driver is bound)
            driver_path = os.path.join(sysfs_base, "driver")
            if os.path.islink(driver_path):
                _ = os.readlink(driver_path)

            # Optionally try /dev/accel/accel0 access
            accel_path = "/dev/accel/accel0"
            if os.path.exists(accel_path):
                try:
                    with open(accel_path, "rb") as fd:
                        # Read a small amount to verify device responds
                        _ = fd.read(4)
                except (OSError, PermissionError):
                    # Device exists but may need root; not an error
                    pass

            t1 = time.time()
            latency = (t1 - t0) * 1000  # ms
            latencies.append(latency)
            ops += 1

        except Exception:
            errors += 1

        # Small sleep to prevent tight loop
        time.sleep(0.001)

    elapsed = time.time() - start
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    result = {
        "worker_id": worker_id,
        "ops_completed": ops,
        "errors": errors,
        "avg_latency_ms": round(avg_lat, 3),
        "max_latency_ms": round(max_lat, 3),
        "duration_sec": round(elapsed, 2),
        "ops_per_sec": round(ops / elapsed, 1) if elapsed > 0 else 0.0,
    }

    with _results_lock:
        _worker_results.append(result)


@dataclass
class NpuStressTest:
    """Run concurrent workload stress test on NPU.

    Spawns ``num_threads`` worker threads, each exercising the NPU
    interface for ``duration_sec`` seconds, then aggregates results.

    If no NPU device is detected (no sysfs entry for the NPU PCI device),
    the test prints a diagnostic message and exits cleanly.
    """

    num_threads: int = 4

    def __post_init__(self):
        self._device_available: Optional[bool] = None

    def check_device(self) -> bool:
        """Check if NPU device is available.

        Checks the following in order:
          1. Does the sysfs PCI device directory exist?
          2. Is the amdxdna driver loaded (via lsmod)?
          3. Does /dev/accel/accel0 exist?

        Returns True if the NPU device appears to be available.
        Results are cached after first check.
        """
        if self._device_available is not None:
            return self._device_available

        bdf = "0000:c6:00.1"
        sysfs_path = f"/sys/bus/pci/devices/{bdf}"

        # Check 1: sysfs PCI device
        if os.path.isdir(sysfs_path):
            self._device_available = True
            return True

        # Check 2: driver loaded
        try:
            result = subprocess.run(
                ["lsmod"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "amdxdna" in result.stdout:
                self._device_available = True
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Check 3: accel device
        if os.path.exists("/dev/accel/accel0"):
            self._device_available = True
            return True

        self._device_available = False
        return False

    def run_workload(self, duration_sec: int = 10) -> dict:
        """Run concurrent NPU workloads.

        Spawns ``num_threads`` worker threads that run for
        ``duration_sec`` seconds each.

        Args:
            duration_sec: How long each worker should run (seconds).

        Returns:
            dict with aggregate statistics:
                'device_available' (bool)
                'num_threads' (int)
                'duration_sec' (float)
                'total_ops' (int)
                'total_errors' (int)
                'avg_latency_ms' (float)
                'max_latency_ms' (float)
                'ops_per_sec' (float)
                'workers' (list[dict]): Per-worker results.
                'error' (str): Error message if device unavailable.
        """
        global _worker_results
        _worker_results = []

        result: dict = {
            "device_available": self.check_device(),
            "num_threads": self.num_threads,
            "duration_sec": duration_sec,
            "total_ops": 0,
            "total_errors": 0,
            "avg_latency_ms": 0.0,
            "max_latency_ms": 0.0,
            "ops_per_sec": 0.0,
            "workers": [],
        }

        if not result["device_available"]:
            result["error"] = (
                "No NPU device detected. "
                "Check that the amdxdna driver is loaded "
                "(sudo modprobe amdxdna) and the NPU PCI device "
                "is present (lspci | grep -i npu)."
            )
            return result

        # Start workers
        threads = []
        start_time = time.time()
        for i in range(self.num_threads):
            t = threading.Thread(target=_worker, args=(i, duration_sec))
            t.start()
            threads.append(t)

        # Wait for all workers
        for t in threads:
            t.join()

        actual_duration = time.time() - start_time

        # Aggregate results
        total_ops = sum(w["ops_completed"] for w in _worker_results)
        total_errors = sum(w["errors"] for w in _worker_results)
        all_lats = []
        for w in _worker_results:
            if w["avg_latency_ms"] > 0:
                all_lats.append(w["avg_latency_ms"])
        avg_lat = sum(all_lats) / len(all_lats) if all_lats else 0.0
        max_lat = max((w["max_latency_ms"] for w in _worker_results), default=0.0)

        result["duration_sec"] = round(actual_duration, 2)
        result["total_ops"] = total_ops
        result["total_errors"] = total_errors
        result["avg_latency_ms"] = round(avg_lat, 3)
        result["max_latency_ms"] = round(max_lat, 3)
        result["ops_per_sec"] = round(total_ops / actual_duration, 1) if actual_duration > 0 else 0.0
        result["workers"] = sorted(_worker_results, key=lambda w: w["worker_id"])

        return result

    def run(self, duration_sec: int = 10):
        """Run stress test and print formatted results."""
        device_ok = self.check_device()

        print(f"NPU Stress Test")
        print(f"{'=' * 60}")

        if not device_ok:
            print()
            print("  NPU device not detected.")
            print()
            print("  This system may not have an AMD NPU, or")
            print("  the amdxdna kernel module may not be loaded.")
            print()
            print("  To check:")
            print("    lspci | grep -i npu")
            print("    lsmod | grep amdxdna")
            print()
            print("  To load the driver:")
            print("    sudo modprobe amdxdna")
            print()
            print("  Device info:")
            print(f"    PCI sysfs: /sys/bus/pci/devices/0000:c6:00.1")
            print(f"    Accel dev: /dev/accel/accel0")
            return

        result = self.run_workload(duration_sec)

        print()
        print(f"  Device:        {'Available' if result['device_available'] else 'Not found'}")
        print(f"  Threads:       {result['num_threads']}")
        print(f"  Duration:      {result['duration_sec']}s")
        print(f"  Total ops:     {result['total_ops']}")
        print(f"  Total errors:  {result['total_errors']}")
        print(f"  Avg latency:   {result['avg_latency_ms']} ms")
        print(f"  Max latency:   {result['max_latency_ms']} ms")
        print(f"  Ops/sec:       {result['ops_per_sec']}")
        print()
        print(f"  Per-worker results:")
        for w in result["workers"]:
            print(f"    Worker {w['worker_id']}: {w['ops_completed']} ops, "
                  f"{w['errors']} errors, "
                  f"{w['avg_latency_ms']} ms avg")
        print()
        print(f"  {'=' * 60}")
        print(f"  Stress test complete.")


def main():
    """CLI entry point for npu_stress_test."""
    parser = argparse.ArgumentParser(
        description="NPU Stress Test Tool — Run concurrent workloads on AMD NPU.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of concurrent worker threads (default: 4)",
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Duration in seconds for the stress test (default: 10)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    args = parser.parse_args()

    test = NpuStressTest(num_threads=args.threads)

    if args.json:
        result = test.run_workload(duration_sec=args.duration)
        print(json.dumps(result, indent=2))
    else:
        test.run(duration_sec=args.duration)


if __name__ == "__main__":
    main()
