#!/bin/bash
# Deploy the patched VE2 firmware
# Run as root

ORIGINAL="/lib/firmware/amdnpu/17f0_11/npu_7.sbin"
PATCHED="/home/bcloud/npu_re_workspace/data/npu_patched.sbin"
BACKUP="/lib/firmware/amdnpu/17f0_11/npu_7.sbin.bak"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

if [ ! -f "$PATCHED" ]; then
    echo "ERROR: Patched firmware not found at $PATCHED"
    exit 1
fi

echo "=== VE2 NPU Firmware Patch Deployment ==="
echo "Original: $ORIGINAL ($(wc -c < $ORIGINAL) bytes)"
echo "Patched:  $PATCHED ($(wc -c < $PATCHED) bytes)"
echo ""

# Backup
echo "[1] Backing up original firmware..."
cp "$ORIGINAL" "$BACKUP"
echo "    -> $BACKUP"

# Install patch
echo "[2] Installing patched firmware..."
cp "$PATCHED" "$ORIGINAL"
echo "    Done."

# Reload driver
echo "[3] Reloading amdxdna driver..."
modprobe -r amdxdna 2>&1 || echo "    Warning: modprobe -r failed (might be in use)"
modprobe amdxdna 2>&1
echo "    Done."

# Verify
echo "[4] Verification..."
ls -la "$ORIGINAL"
sha256sum "$ORIGINAL" | head -c 64
echo ""

# Test
echo "[5] Testing NPU access..."
if [ -c /dev/accel/accel0 ]; then
    echo "    /dev/accel/accel0 present"
    # Try basic IOCTL
    python3 -c "
import fcntl, struct
fd = open('/dev/accel/accel0')
# Try DRM version ioctl (0x00)
DRM_IOCTL_VERSION = 0x6400
buf = struct.pack('IIII', 0, 0, 0, 0)
try:
    ret = fcntl.ioctl(fd, DRM_IOCTL_VERSION, buf)
    name_len, date_len, desc_len, _ = struct.unpack('IIII', ret)
    print(f'    DRM version IOCTL successful')
except Exception as e:
    print(f'    DRM IOCTL test: {e}')
" 2>&1 || echo "    Basic IOCTL test failed"
else
    echo "    ERROR: /dev/accel/accel0 not found!"
fi

echo ""
echo "=== Deployment complete ==="
