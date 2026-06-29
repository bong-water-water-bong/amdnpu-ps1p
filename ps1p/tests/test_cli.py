"""Tests for PS1p CLI commands."""

from __future__ import annotations

import os
import sys
import tempfile
from io import StringIO

import pytest

from ps1p.cli import main, build_parser


def test_cli_help():
    """Running with no args prints help and returns 0."""
    exit_code = main([])
    assert exit_code == 0


def test_cli_no_args():
    """Running with --help prints help and returns 0."""
    exit_code = main(["--help"])
    assert exit_code == 0


def test_cli_info(new_container):
    """ps1p info shows container details."""
    exit_code = main(["info", new_container.path])
    assert exit_code == 0


def test_cli_extract(new_container):
    """ps1p extract dumps all sections to files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, "extracted")
        exit_code = main(["extract", new_container.path, "-o", output_dir])
        assert exit_code == 0
        assert os.path.isdir(output_dir)
        # Should have at least a few section files
        files = os.listdir(output_dir)
        assert len(files) > 0


def test_cli_dump(new_container):
    """ps1p dump shows section details."""
    # First get a valid section name via info (JSON)
    exit_code = main(["dump", new_container.path, "ipu_code", "-v"])
    assert exit_code == 0


def test_cli_dump_blobs(new_container):
    """ps1p dump --blobs finds binary blobs in a section."""
    exit_code = main(["dump", new_container.path, "sub_payload",
                       "--blobs", "--min-blob-size", "32", "-v"])
    assert exit_code == 0


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def new_container():
    """Provide a parsed container wrapper with path for CLI tests."""
    from ps1p.container import open_ps1p
    from ps1p.tests.conftest import FW_NEW

    if not os.path.exists(FW_NEW):
        pytest.skip(f"Firmware not found: {FW_NEW}")

    class _Container:
        path = FW_NEW
        container = open_ps1p(FW_NEW)
    return _Container()
