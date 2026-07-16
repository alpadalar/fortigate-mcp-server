"""
Repository hygiene regression tests.

Guards against reintroduction of orphan artifacts that were removed from
the repository root and source tree (stale ``*.backup`` files, and the
non-pytest ``integration_tests.py`` script that requires a live server).
"""

import os
import subprocess
import zipfile
from pathlib import Path

import pytest


def _repo_root() -> Path:
    """Resolve the repository root from this test file's location."""
    return Path(__file__).resolve().parent.parent


def test_no_backup_files_in_source_tree():
    """No stale ``*.backup`` files should exist anywhere under ``src/``."""
    repo_root = _repo_root()
    backup_files = list((repo_root / "src").rglob("*.backup"))

    assert backup_files == [], (
        f"Found orphan .backup files in src/: {backup_files}. "
        "Remove stale backup files before committing."
    )


def test_integration_tests_script_removed_from_root():
    """The orphan integration_tests.py script must stay removed from repo root."""
    repo_root = _repo_root()
    orphan_script = repo_root / "integration_tests.py"

    assert not orphan_script.exists(), (
        "integration_tests.py reappeared at the repo root. This script requires "
        "a live server at localhost:8814 and is not picked up by pytest; it "
        "should not live at the repo root."
    )


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("PACKAGING_CHECKS") != "1",
    reason="one-off packaging check - set PACKAGING_CHECKS=1 to run",
)
def test_wheel_build_excludes_backup_files(tmp_path):
    """A freshly built wheel must contain zero backup-named entries.

    This is a one-off packaging proof, not a permanent suite member: it
    shells out to ``uv build`` which is slow and depends on network/build
    isolation, so it is gated behind the PACKAGING_CHECKS=1 environment
    variable rather than running on every test invocation.
    """
    repo_root = _repo_root()

    subprocess.run(
        ["uv", "build", "--wheel", "-o", str(tmp_path)],
        check=True,
        capture_output=True,
        cwd=repo_root,
    )

    wheel_files = list(tmp_path.glob("*.whl"))
    assert wheel_files, f"No wheel file produced in {tmp_path}"

    with zipfile.ZipFile(wheel_files[0]) as wheel:
        names = wheel.namelist()

    backup_entries = [name for name in names if "backup" in name]
    assert backup_entries == [], (
        f"Wheel contains backup-named entries: {backup_entries}"
    )
