#!/usr/bin/env python3
"""
NPU Firmware Deployment Tool
=============================
Deploy patched firmware to AMD NPU devices.

This tool provides a SAFE firmware deployment pipeline:

  1. VALIDATE — verify a firmware file is a valid $PS1p container
  2. DEPLOY   — validate, copy to firmware path, reload kernel module

Prerequisites:
  - Root access for module reload (check with --deploy)
  - amdxdna kernel module loaded
  - Firmware file at: /lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst

Usage:
  python3 -m tools.fw_deploy --validate /path/to/firmware.sbin
  python3 -m tools.fw_deploy --deploy /path/to/patched.sbin

--validate works without root. --deploy requires root.

Deployment Procedure (manual, for reference):
  1. (Optional) Backup original firmware:
     cp /lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst \\
        /lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst.bak

  2. Validate the patched firmware:
     python3 -m tools.fw_deploy --validate /path/to/patched.sbin

  3. Copy patched firmware (as root):
     sudo cp /path/to/patched.sbin \\
        /lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst

  4. Reload the amdxdna kernel module (as root):
     sudo modprobe -r amdxdna && sudo modprobe amdxdna

  (Steps 3-4 can be done in one command with --deploy)

  5. Verify the driver re-loaded:
     dmesg | tail -20
     ls -la /dev/accel/accel0
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from typing import Optional

try:
    from ps1p import open_ps1p
except ImportError:
    # Allow running from repo root
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ps1p import open_ps1p


class FirmwareDeployer:
    """Deploy patched firmware to NPU device.

    Provides a safe pipeline: validate first, then deploy.
    Deployment requires root for kernel module reload.
    """

    # Path to the currently loaded NPU firmware
    CURRENT_FW_PATH = "/lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst"

    def __init__(self):
        """Check environment: root status and driver loaded."""
        pass

    @staticmethod
    def check_root() -> bool:
        """Check if running as root (required for module reload)."""
        return os.geteuid() == 0

    @staticmethod
    def check_driver_loaded() -> bool:
        """Check if amdxdna kernel module is loaded.

        Uses ``lsmod`` to check module status.
        Returns True if module is found in the list.
        """
        try:
            result = subprocess.run(
                ["lsmod"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Check for amdxdna in the output (faster than modprobe --dry-run)
            return "amdxdna" in result.stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    @staticmethod
    def get_current_firmware_path() -> str:
        """Return path to currently installed firmware file.

        Returns the canonical path defined in CURRENT_FW_PATH.
        This is the file that gets loaded by the amdxdna driver.
        """
        return FirmwareDeployer.CURRENT_FW_PATH

    def validate_firmware(self, fw_path: str) -> dict:
        """Validate that a firmware file is a valid $PS1p container.

        Opens the file with ``ps1p.open_ps1p()`` which parses the header,
        section map, and partition table. Returns a dict with validation
        results and extracted section information.

        Args:
            fw_path: Path to the firmware .sbin file to validate.

        Returns:
            dict with keys:
                'valid' (bool): True if file is a valid $PS1p container.
                'sections' (list): List of section names found.
                'header_magic' (str): Magic bytes from header.
                'header_version' (str): Version string from header.
                'error' (str): Error message if validation failed.
                'path' (str): The file path that was validated.
        """
        result: dict = {
            "valid": False,
            "sections": [],
            "header_magic": None,
            "header_version": None,
            "error": None,
            "path": fw_path,
        }

        if not os.path.isfile(fw_path):
            result["error"] = f"File not found: {fw_path}"
            return result

        try:
            container = open_ps1p(fw_path)
            summary = container.summarize()

            result["valid"] = True
            result["header_magic"] = summary.get("magic")
            result["header_version"] = summary.get("version")
            result["sections"] = list(summary.get("sections", {}).keys())
            result["_summary"] = summary
        except Exception as e:
            result["error"] = f"Validation failed: {e}"

        return result

    @staticmethod
    def reload_module() -> dict:
        """Reload amdxdna kernel module.

        Runs ``modprobe -r amdxdna && modprobe amdxdna`` in sequence.
        Requires root — callers should check with check_root() first.

        Returns:
            dict with keys:
                'success' (bool): True if both unload and reload succeeded.
                'message' (str): Human-readable status message.
        """
        result: dict = {"success": False, "message": ""}

        if os.geteuid() != 0:
            result["message"] = "Module reload requires root (use sudo)"
            return result

        try:
            # Unload
            unload = subprocess.run(
                ["modprobe", "-r", "amdxdna"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if unload.returncode != 0:
                result["message"] = (
                    f"Failed to unload amdxdna: {unload.stderr.strip()}"
                )
                return result

            # Reload
            load = subprocess.run(
                ["modprobe", "amdxdna"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if load.returncode != 0:
                result["message"] = (
                    f"Failed to reload amdxdna: {load.stderr.strip()}"
                )
                return result

            result["success"] = True
            result["message"] = "amdxdna module reloaded successfully"
        except FileNotFoundError:
            result["message"] = "modprobe not found (install kmod package)"
        except subprocess.TimeoutExpired:
            result["message"] = "Module reload timed out"
        except Exception as e:
            result["message"] = f"Unexpected error during module reload: {e}"

        return result

    @staticmethod
    def unbind_bind() -> dict:
        """Unbind and rebind NPU PCI device.

        Uses sysfs to unbind/rebind the NPU PCI device.
        This avoids a full module reload and is faster.
        NPU PCI BDF = 0000:c6:00.1

        Returns:
            dict with keys:
                'success' (bool): True if rebind succeeded.
                'message' (str): Human-readable status message.
        """
        result: dict = {"success": False, "message": ""}

        if os.geteuid() != 0:
            result["message"] = "PCI rebind requires root (use sudo)"
            return result

        bdf = "0000:c6:00.1"
        driver_path = f"/sys/bus/pci/drivers/amdxdna"
        unbind_path = f"{driver_path}/unbind"
        bind_path = f"{driver_path}/bind"

        if not os.path.isdir(driver_path):
            result["message"] = (
                f"Driver directory not found: {driver_path}. "
                f"Is amdxdna loaded?"
            )
            return result

        try:
            # Unbind
            with open(unbind_path, "w") as f:
                f.write(bdf)

            # Small delay to let devices settle
            import time
            time.sleep(0.5)

            # Rebind
            with open(bind_path, "w") as f:
                f.write(bdf)

            result["success"] = True
            result["message"] = f"NPU device {bdf} rebound successfully"
        except PermissionError:
            result["message"] = "Permission denied. Run as root."
        except FileNotFoundError:
            result["message"] = (
                f"Device {bdf} not found under {driver_path}. "
                f"Check lspci output."
            )
        except OSError as e:
            result["message"] = f"Failed to rebind {bdf}: {e}"
        except Exception as e:
            result["message"] = f"Unexpected error during rebind: {e}"

        return result

    def deploy(self, fw_path: str) -> dict:
        """Full deployment pipeline: validate → copy → reload.

        Steps performed:
          1. Validate the firmware file is a valid $PS1p container
          2. Check root access
          3. Copy the firmware to the target path
          4. Reload the kernel module

        Args:
            fw_path: Path to the patched firmware .sbin file.

        Returns:
            dict with keys:
                'success' (bool): True if deployment was successful.
                'message' (str): Overall status message.
                'steps' (list): Step-by-step results, each a dict with
                    'step', 'success', and 'message'.
        """
        steps: list[dict] = []
        steps.append({
            "step": "validate",
            "success": False,
            "message": "",
        })
        steps.append({
            "step": "check_root",
            "success": False,
            "message": "",
        })
        steps.append({
            "step": "copy_firmware",
            "success": False,
            "message": "",
        })
        steps.append({
            "step": "reload_module",
            "success": False,
            "message": "",
        })

        # Step 1: Validate
        validation = self.validate_firmware(fw_path)
        steps[0]["success"] = validation["valid"]
        if validation["valid"]:
            steps[0]["message"] = (
                f"Firmware validated: {validation['header_magic']} "
                f"v{validation['header_version']} "
                f"({len(validation['sections'])} sections)"
            )
        else:
            steps[0]["message"] = validation.get("error", "Validation failed")
            return {
                "success": False,
                "message": "Deployment aborted: firmware validation failed",
                "steps": steps,
            }

        # Step 2: Check root
        if not self.check_root():
            steps[1]["message"] = "Root access required for deployment"
            return {
                "success": False,
                "message": "Deployment aborted: root access required (use sudo)",
                "steps": steps,
            }
        steps[1]["success"] = True
        steps[1]["message"] = "Running as root"

        # Step 3: Copy firmware
        target = self.CURRENT_FW_PATH
        try:
            # Backup existing firmware
            if os.path.isfile(target):
                backup = f"{target}.bak"
                shutil.copy2(target, backup)
                steps[2]["message"] = f"Backed up existing firmware to {backup}"

            shutil.copy2(fw_path, target)
            steps[2]["success"] = True
            steps[2]["message"] = (
                f"Copied {fw_path} -> {target}"
                if not steps[2]["message"]
                else steps[2]["message"] + f"; copied {fw_path} -> {target}"
            )
        except PermissionError:
            steps[2]["message"] = f"Permission denied copying to {target}"
            return {
                "success": False,
                "message": "Deployment failed: permission denied during copy",
                "steps": steps,
            }
        except OSError as e:
            steps[2]["message"] = f"Copy failed: {e}"
            return {
                "success": False,
                "message": f"Deployment failed: {e}",
                "steps": steps,
            }

        # Step 4: Reload module
        reload_result = self.reload_module()
        steps[3]["success"] = reload_result["success"]
        steps[3]["message"] = reload_result["message"]

        overall = all(s["success"] for s in steps)
        return {
            "success": overall,
            "message": "Deployment completed successfully" if overall
                       else "Deployment completed with warnings",
            "steps": steps,
        }


def main():
    """CLI entry point for fw_deploy tool."""
    parser = argparse.ArgumentParser(
        description="NPU Firmware Deployment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Deployment Procedure:
  The NPU firmware can be deployed manually or using this tool.

  Manual procedure:
    1. Validate:    python3 -m tools.fw_deploy --validate <patched.sbin>
    2. Deploy:      sudo python3 -m tools.fw_deploy --deploy <patched.sbin>

  --validate works without root and only checks that the file is
  a valid $PS1p firmware container.

  --deploy performs the full pipeline:
      1. Validate the firmware file
      2. Copy it to /lib/firmware/amdnpu/17f0_11/npu.sbin.1.1.2.65.zst
         (with automatic backup of the existing firmware)
      3. Reload the amdxdna kernel module

  Requirements:
    - Root access (sudo) for --deploy
    - amdxdna kernel module
    - Valid $PS1p firmware container
        """.strip(),
    )

    parser.add_argument(
        "--validate",
        metavar="FW_PATH",
        dest="validate_path",
        default=None,
        help="Validate firmware file (no root required)",
    )

    parser.add_argument(
        "--deploy",
        metavar="FW_PATH",
        dest="deploy_path",
        default=None,
        help="Validate and deploy firmware (requires root)",
    )

    args = parser.parse_args()

    if not args.validate_path and not args.deploy_path:
        parser.print_help()
        sys.exit(0)

    deployer = FirmwareDeployer()

    if args.validate_path:
        print(f"Validating: {args.validate_path}")
        print()
        result = deployer.validate_firmware(args.validate_path)
        if result["valid"]:
            print(f"  Status: VALID")
            print(f"  Magic:  {result['header_magic']}")
            print(f"  Version: {result['header_version']}")
            print(f"  Sections ({len(result['sections'])}):")
            for s in result["sections"]:
                print(f"    - {s}")
            sys.exit(0)
        else:
            print(f"  Status: INVALID")
            print(f"  Error:  {result['error']}")
            sys.exit(1)

    if args.deploy_path:
        print(f"Deploying: {args.deploy_path}")
        print()

        if not deployer.check_root():
            print("  ERROR: --deploy requires root access.")
            print("  Run with: sudo python3 -m tools.fw_deploy --deploy <fw>")
            print()
            print("  Current firmware path:", deployer.get_current_firmware_path())
            sys.exit(1)

        result = deployer.deploy(args.deploy_path)
        print()
        for step in result["steps"]:
            icon = "OK" if step["success"] else "FAIL"
            print(f"  [{icon}] {step['step']}: {step['message']}")
        print()
        if result["success"]:
            print(f"  Result: {result['message']}")
            sys.exit(0)
        else:
            print(f"  Result: {result['message']}")
            sys.exit(1)


if __name__ == "__main__":
    main()
