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


def test_http_server_docstring_matches_reality():
    """server_http.py's class docstring must not claim capabilities that
    are not actually enforced. Rate limiting and CORS remain
    parsed-but-unenforced config (CONF-04); authentication is now enforced
    by AuthMiddleware when require_auth is True (SEC-05, Phase 4) -- the
    docstring must no longer claim it is unenforced."""
    repo_root = _repo_root()
    text = (repo_root / "src" / "fortigate_mcp" / "server_http.py").read_text()

    assert "Authentication (optional)" not in text
    assert "CORS for browser access" not in text
    assert "Authentication is not currently enforced" not in text
    assert "is enforced by a pure-ASGI Bearer-token middleware" in text
    # Only rate limiting remains in the "not currently enforced" state --
    # authentication's bullet was rewritten by SEC-05; CORS uses distinct
    # "not configured" phrasing, so it was never counted here.
    assert text.count("not currently enforced") == 1


def test_readme_tr_removed():
    """The Turkish-duplicate readme_tr.md must stay removed -- one canonical
    English README going forward (05-CONTEXT.md locked decision)."""
    repo_root = _repo_root()

    assert not (repo_root / "readme_tr.md").exists(), (
        "readme_tr.md reappeared at the repo root. This project ships a "
        "single canonical English README; no bilingual sync going forward."
    )


def test_readme_has_no_requirements_txt_reference():
    """README.md must not reference a requirements file that does not exist
    anywhere in this repository -- the real install path is uv/pyproject.toml."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "requirements.txt" not in text


def test_readme_python_version_matches_pyproject():
    """README.md must state the actual >=3.11 requirement from pyproject.toml,
    not the stale 3.8+ claim."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "3.11+" in text
    assert "3.8+" not in text


def test_readme_tool_count_phrasing():
    """README.md must use the qualified tool-count phrasing from
    tests/test_tool_schema_snapshot.py's docstring -- a bare '61 tools'
    claim is misleading (61 is transport registrations, not unique tools)."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "33 unique tools" in text


def test_dockerfile_does_not_copy_pytest_ini():
    """Dockerfile must not COPY the deleted pytest.ini -- pytest config now
    lives entirely in pyproject.toml."""
    repo_root = _repo_root()
    text = (repo_root / "Dockerfile").read_text()

    assert "pytest.ini" not in text


def test_readme_no_verify_ssl_false_recommendation():
    """README.md must never recommend disabling TLS certificate verification,
    in its config example block or its Troubleshooting section."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "verify_ssl: false" not in text
    assert '"verify_ssl": false' not in text


def test_readme_recommends_loopback_bind():
    """README.md must present 127.0.0.1 (loopback) as the bind-address
    recommendation for unauthenticated HTTP."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "127.0.0.1" in text


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
