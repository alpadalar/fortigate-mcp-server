"""
Repository hygiene regression tests.

Guards against reintroduction of orphan artifacts that were removed from
the repository root and source tree (stale ``*.backup`` files, and the
non-pytest ``integration_tests.py`` script that requires a live server).
"""

import json
import os
import re
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml

from src.fortigate_mcp.registry import RISK_CLASSIFICATION


def _repo_root() -> Path:
    """Resolve the repository root from this test file's location."""
    return Path(__file__).resolve().parent.parent


def _assert_no_underscore_keys(obj, file_label: str) -> None:
    """Recursively assert no dict key (at any nesting level) starts with '_'."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            assert not str(key).startswith("_"), (
                f"{file_label} contains a non-standard '_'-prefixed key: {key!r}"
            )
            _assert_no_underscore_keys(value, file_label)
    elif isinstance(obj, list):
        for item in obj:
            _assert_no_underscore_keys(item, file_label)


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


def test_http_guide_has_no_requirements_txt_reference():
    """HTTP_MCP_GUIDE.md must not reference a requirements file that does not
    exist anywhere in this repository -- the real install path is uv/pyproject.toml."""
    repo_root = _repo_root()
    text = (repo_root / "HTTP_MCP_GUIDE.md").read_text()

    assert "requirements.txt" not in text


def test_http_guide_python_version_matches_pyproject():
    """HTTP_MCP_GUIDE.md must not claim the stale Python 3.8+ requirement."""
    repo_root = _repo_root()
    text = (repo_root / "HTTP_MCP_GUIDE.md").read_text()

    assert "3.8+" not in text


def test_http_guide_no_verify_ssl_false_recommendation():
    """HTTP_MCP_GUIDE.md must never recommend disabling TLS certificate
    verification, in its config example block or its Sorun Giderme section."""
    repo_root = _repo_root()
    text = (repo_root / "HTTP_MCP_GUIDE.md").read_text()

    assert "verify_ssl: false" not in text
    assert '"verify_ssl": false' not in text


# --- SECURITY.md (REL-03) --------------------------------------------------

_ROW_GRAMMAR = re.compile(r"^\| `(\w+)` \| (read|write|destructive) \|$")


def test_security_md_risk_table_matches_registry():
    """SECURITY.md's '### Tool Risk Classification' table must parse to
    EXACTLY RISK_CLASSIFICATION -- row count checked on the raw list BEFORE
    any dict conversion (so a duplicated row cannot silently collapse and
    pass), and every table-body line must match the exact row grammar or
    the test fails immediately (Cycle 2, Codex HIGH-3)."""
    repo_root = _repo_root()
    text = (repo_root / "SECURITY.md").read_text()

    match = re.search(r"### Tool Risk Classification\n(.*?)\n\n", text, re.DOTALL)
    assert match, "'### Tool Risk Classification' section not found in SECURITY.md"

    table_lines = [
        line.strip() for line in match.group(1).splitlines() if line.strip().startswith("|")
    ]
    # First two "|"-prefixed lines are the header row and the "|---|---|"
    # separator row -- everything after that is table body.
    body_lines = table_lines[2:]

    parsed_rows = []
    for line in body_lines:
        row_match = _ROW_GRAMMAR.match(line)
        assert row_match, f"Table body line does not match expected row grammar: {line!r}"
        parsed_rows.append((row_match.group(1), row_match.group(2)))

    # (1) Row count checked on the LIST, before any dict conversion.
    assert len(parsed_rows) == len(RISK_CLASSIFICATION), (
        f"Parsed {len(parsed_rows)} rows, expected {len(RISK_CLASSIFICATION)} "
        "(RISK_CLASSIFICATION entry count) -- a duplicated row would silently "
        "collapse if checked only after dict conversion."
    )
    # (2) Exact dict equality -- not a subset/superset check.
    assert dict(parsed_rows) == RISK_CLASSIFICATION


def test_security_md_documents_add_device_tls_exception():
    """The add_device verify_ssl runtime exception must appear as a windowed,
    same-section limitation -- not merely 'appears anywhere in the file'."""
    repo_root = _repo_root()
    text = (repo_root / "SECURITY.md").read_text()

    heading_index = text.index("## Known Security Limitations")
    window = text[heading_index : heading_index + 1500]

    assert "add_device" in window
    assert "verify_ssl" in window


def test_security_md_does_not_overclaim_rate_limiting():
    """SECURITY.md must state rate limiting is not enforced, and must not
    instruct readers to 'Enable rate limiting' as if it were a working control."""
    repo_root = _repo_root()
    text = (repo_root / "SECURITY.md").read_text()
    lowered = text.lower()

    assert "not enforced" in lowered
    assert "rate limiting" in lowered
    assert "enable rate limiting" not in lowered


def test_security_md_mentions_pvr_reporting_channel():
    """SECURITY.md must name GitHub Private Vulnerability Reporting (or link
    the security/advisories path) as the vulnerability-reporting channel."""
    repo_root = _repo_root()
    text = (repo_root / "SECURITY.md").read_text()

    assert "Private Vulnerability Reporting" in text or "security/advisories" in text


def test_security_md_recommends_loopback_bind():
    """SECURITY.md's Implemented Security Controls section must recommend
    127.0.0.1 (loopback) for unauthenticated HTTP, contrasted with 0.0.0.0."""
    repo_root = _repo_root()
    text = (repo_root / "SECURITY.md").read_text()

    heading_index = text.index("Implemented Security Controls")
    window = text[heading_index:]

    assert "127.0.0.1" in window
    assert "0.0.0.0" in window


# --- MCP client config examples (examples/*.json) -------------------------

_STDIO_UV_ENTRIES = {
    "claude_desktop_config.stdio.json": "fortigate-mcp",
    "claude_code_mcp.json": "fortigate-mcp-stdio",
    "cursor_mcp_config.json": "fortigate-mcp",
}


def test_mcp_client_examples_are_valid_json():
    """Every file under examples/*.json must parse as valid JSON."""
    repo_root = _repo_root()

    for path in sorted((repo_root / "examples").glob("*.json")):
        json.loads(path.read_text())


def test_claude_code_example_sets_explicit_type():
    """Every mcpServers entry in claude_code_mcp.json must set an explicit
    'type' -- a URL entry without 'type' is read as stdio and silently
    skipped by Claude Code."""
    repo_root = _repo_root()
    data = json.loads((repo_root / "examples" / "claude_code_mcp.json").read_text())

    assert all("type" in entry for entry in data["mcpServers"].values())


def test_stdio_examples_use_uv_run_convention():
    """The 3 stdio-server entries (Claude Desktop stdio, Claude Code's stdio
    entry, Cursor's command entry) must launch via 'uv', not bare 'python'.
    Deliberately excludes claude_desktop_config.http.json, whose entry
    launches the mcp-remote bridge, not this project's own stdio server."""
    repo_root = _repo_root()

    for filename, entry_name in _STDIO_UV_ENTRIES.items():
        data = json.loads((repo_root / "examples" / filename).read_text())
        entry = data["mcpServers"][entry_name]
        assert entry["command"] == "uv", (
            f"{filename}::{entry_name} must use 'uv', got {entry['command']!r}"
        )


def test_claude_desktop_http_bridge_uses_npx_mcp_remote():
    """claude_desktop_config.http.json is the one file intentionally not
    uv-based -- it bridges to the HTTP transport via the community
    mcp-remote npm package launched through npx. Validated separately so
    this file and the uv-convention test never contradict each other."""
    repo_root = _repo_root()
    data = json.loads(
        (repo_root / "examples" / "claude_desktop_config.http.json").read_text()
    )
    entry = next(iter(data["mcpServers"].values()))

    assert entry["command"] == "npx"
    assert "mcp-remote" in entry["args"]


def test_stdio_examples_use_absolute_or_variable_directory_flag():
    """Each of the 3 uv-based stdio entries must pass --directory. Claude
    Desktop's and Cursor's entries must use an absolute path (starts with
    '/'); Claude Code's stdio entry must use its own directory variable
    instead of a literal absolute path."""
    repo_root = _repo_root()

    for filename, entry_name in _STDIO_UV_ENTRIES.items():
        data = json.loads((repo_root / "examples" / filename).read_text())
        args = data["mcpServers"][entry_name]["args"]

        assert "--directory" in args, f"{filename}::{entry_name} missing --directory"
        directory_value = args[args.index("--directory") + 1]

        if filename == "claude_code_mcp.json":
            assert directory_value == "${CLAUDE_PROJECT_DIR}"
        else:
            assert directory_value.startswith("/"), (
                f"{filename}::{entry_name} --directory value must be an "
                f"absolute path, got {directory_value!r}"
            )


def test_no_examples_target_wildcard_bind_address():
    """No examples/*.json file may point a client at 0.0.0.0 -- a bind-all
    address is never a valid client-side destination."""
    repo_root = _repo_root()

    for path in sorted((repo_root / "examples").glob("*.json")):
        text = path.read_text()
        assert "0.0.0.0" not in text, f"{path.name} targets a wildcard bind address"


def test_examples_have_no_underscore_prefixed_keys():
    """No examples/*.json file may carry a non-standard '_'-prefixed key
    (e.g. a stray '_note' field) -- machine-consumed client config must only
    contain keys its schema actually defines."""
    repo_root = _repo_root()

    for path in sorted((repo_root / "examples").glob("*.json")):
        data = json.loads(path.read_text())
        _assert_no_underscore_keys(data, path.name)


# --- CHANGELOG.md / .github templates (REL-04, REL-05) --------------------


def test_changelog_has_1_0_0_heading():
    """CHANGELOG.md must have a '## [1.0.0]' first-release heading."""
    repo_root = _repo_root()
    text = (repo_root / "CHANGELOG.md").read_text()

    assert "## [1.0.0]" in text


def test_changelog_has_unreleased_heading():
    """CHANGELOG.md must have a '## [Unreleased]' heading per Keep a
    Changelog convention, even if currently empty."""
    repo_root = _repo_root()
    text = (repo_root / "CHANGELOG.md").read_text()

    assert "## [Unreleased]" in text


def test_changelog_records_rel06_remediation_accurately():
    """CHANGELOG.md's [1.0.0] Security subsection must record the completed
    REL-06 remediation accurately: token rotation (the primary mitigation)
    plus local refs cleanup (the secondary hygiene step) -- and must NOT
    claim git-filter-repo was used (Plan 05-04 dropped it entirely, per its
    Cycle-2 redesign) or that history was fully removed from GitHub (the
    residual-risk framing must stay honest)."""
    repo_root = _repo_root()
    text = (repo_root / "CHANGELOG.md").read_text()
    lowered = text.lower()

    assert "REL-06" in text
    assert "rotated" in lowered
    assert "filter-repo" not in lowered
    assert "fully removed from github" not in lowered


def test_pr_template_references_frozen_tool_surface():
    """The PR template must reference the golden tool-schema fixtures so
    contributors see the frozen-tool-surface rule at PR-open time."""
    repo_root = _repo_root()
    text = (repo_root / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text()

    assert "tool_schemas" in text


def test_issue_template_config_has_security_contact_link():
    """.github/ISSUE_TEMPLATE/config.yml must keep blank issues enabled and
    route security reports to Private Vulnerability Reporting, not a blank
    issue."""
    repo_root = _repo_root()
    data = yaml.safe_load((repo_root / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text())

    assert data["blank_issues_enabled"] is True
    assert any(
        "security/advisories" in contact.get("url", "") for contact in data["contact_links"]
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
