"""Pytest fixtures for $PS1p firmware tests."""

import pytest
import os

# Default firmware paths
FW_NEW = "/tmp/orig_decomp.sbin"      # v1.1.2.65 (new)
FW_OLD = "/tmp/old_fw.sbin"           # v1.0.0.166 (old)
FW_DIR = "/tmp/decrypted_new/"
FW_OLD_DIR = "/tmp/decrypted_old/"


@pytest.fixture(scope="session")
def fw_new_path():
    """Path to the newer firmware (v1.1.2.65)."""
    if not os.path.exists(FW_NEW):
        pytest.skip(f"Firmware not found: {FW_NEW}")
    return FW_NEW


@pytest.fixture(scope="session")
def fw_old_path():
    """Path to the older firmware (v1.0.0.166)."""
    if not os.path.exists(FW_OLD):
        pytest.skip(f"Firmware not found: {FW_OLD}")
    return FW_OLD


@pytest.fixture(scope="session")
def fw_new_data(fw_new_path):
    """Raw bytes of the newer firmware."""
    with open(fw_new_path, 'rb') as f:
        return f.read()


@pytest.fixture(scope="session")
def fw_old_data(fw_old_path):
    """Raw bytes of the older firmware."""
    with open(fw_old_path, 'rb') as f:
        return f.read()


@pytest.fixture(scope="session")
def fw_new_extracted():
    """Directory with already-extracted sections (new firmware)."""
    if not os.path.isdir(FW_DIR):
        pytest.skip(f"Extraction dir not found: {FW_DIR}")
    return FW_DIR


@pytest.fixture(scope="session")
def fw_old_extracted():
    """Directory with already-extracted sections (old firmware)."""
    if not os.path.isdir(FW_OLD_DIR):
        pytest.skip(f"Extraction dir not found: {FW_OLD_DIR}")
    return FW_OLD_DIR
