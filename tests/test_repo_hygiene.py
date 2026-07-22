"""
Repository hygiene regression tests.

Guards against reintroduction of orphan artifacts that were removed from
the repository root and source tree (stale ``*.backup`` files, and the
non-pytest ``integration_tests.py`` script that requires a live server).
"""

import argparse
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


# --- AI-residue scan marker fragments (REL-07) -----------------------------
#
# Every marker below is assembled from fragments at runtime so that NONE of
# these matchable substrings ever appears as one contiguous literal anywhere
# in this file's own source. A tree-content scan of HEAD (05-05 Task 1, Scan
# B) greps for these exact marker shapes; if this file wrote them as
# contiguous literals it would self-match its own guard tests the moment it
# was committed (Cycle 2, Codex HIGH-4).
#
# Scan-pattern contract (Scan B and any history/tree AI-residue scan): the
# commit-trailer marker is matched ONLY in its full colon-suffixed form
# assembled below (_TRAILER_PREFIX + _TRAILER_SUFFIX) -- scans must not grep
# the shorter colon-less prefix on its own. CONTRIBUTING.md is the single
# allowlisted file for the trailer marker; it quotes the trailer shape as
# policy prose explaining the prohibition, and that framing is verified by
# test_contributing_md_mentions_trailer_as_policy_not_accident below.
_NOREPLY_LOCAL = "noreply"
_NOREPLY_DOMAIN = "@anthropic"
_NOREPLY_MARKER = _NOREPLY_LOCAL + _NOREPLY_DOMAIN

_ROBOT_EMOJI = chr(0x1F916)  # constructed at runtime; never the raw glyph in source

_GENERATED_PREFIX = "Generated with "
_GENERATED_CLAUDE = _GENERATED_PREFIX + "Claude"
_GENERATED_CODEX = _GENERATED_PREFIX + "Codex"

_TRAILER_PREFIX = "Co-Authored-"
_TRAILER_SUFFIX = "By:"
_TRAILER_MARKER = _TRAILER_PREFIX + _TRAILER_SUFFIX

_ALL_RESIDUE_MARKERS = (
    _NOREPLY_MARKER,
    _ROBOT_EMOJI,
    _GENERATED_CLAUDE,
    _GENERATED_CODEX,
    _TRAILER_MARKER,
)


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
    tests/test_tool_schema_snapshot.py's docstring -- a bare '69 tools'
    claim is misleading (69 is transport registrations, not unique tools)."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "37 unique tools" in text


def test_dockerfile_does_not_copy_pytest_ini():
    """Dockerfile must not COPY the deleted pytest.ini -- pytest config now
    lives entirely in pyproject.toml."""
    repo_root = _repo_root()
    text = (repo_root / "Dockerfile").read_text()

    assert "pytest.ini" not in text


def test_dockerfile_installs_from_lockfile():
    """Dockerfile must install from uv.lock (`uv sync --locked`), not a
    fresh unlocked PyPI resolution -- otherwise the shipped image's
    dependency graph can silently diverge from what CI/tests actually
    exercised (06-RESEARCH.md Pitfall 3)."""
    repo_root = _repo_root()
    text = (repo_root / "Dockerfile").read_text()

    assert "uv sync --locked" in text
    assert "uv pip install --system --no-cache-dir -e ." not in text


def test_dockerfile_images_are_pinned():
    """FROM / COPY --from= image references must never use the mutable
    ``latest`` tag, and the uv toolchain image -- which performs the entire
    dependency install -- must be digest-pinned. A floating registry tag is
    the same mutable-reference supply-chain class the workflows eliminate
    with SHA-pinned ``uses:`` (T-06-05-01)."""
    repo_root = _repo_root()
    text = (repo_root / "Dockerfile").read_text()

    image_refs = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("FROM "):
            image_refs.append(stripped.split()[1])
        match = re.search(r"--from=(\S+)", stripped)
        if match:
            image_refs.append(match.group(1))

    assert image_refs, "Dockerfile must contain at least one FROM"
    for ref in image_refs:
        assert not ref.endswith(":latest"), (
            f"mutable :latest image reference in Dockerfile: {ref}"
        )

    uv_refs = [ref for ref in image_refs if "astral-sh/uv" in ref]
    assert uv_refs, "Dockerfile must COPY the uv binary from the uv image"
    for ref in uv_refs:
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), (
            f"uv toolchain image must be digest-pinned (@sha256:...): {ref}"
        )

    python_refs = [ref for ref in image_refs if ref.startswith("python:")]
    assert python_refs, "Dockerfile must FROM a python: base image"
    for ref in python_refs:
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), (
            f"python base image must be digest-pinned (@sha256:...): {ref}"
        )


def test_dockerfile_cmd_does_not_sync_at_runtime():
    """The container CMD must never perform an implicit ``uv sync`` at
    startup: a bare ``uv run`` re-syncs the project on every container
    start, re-installing it editable (the build used --no-editable) and --
    because the image is built with --no-cache -- fetching the build
    backend from PyPI, which mutates the audited uv.lock venv and fails
    outright in egress-restricted deployments. Require ``uv run
    --no-sync`` (or a global UV_NO_SYNC=1 env) on any uv-run CMD."""
    repo_root = _repo_root()
    text = (repo_root / "Dockerfile").read_text()

    cmd_lines = [
        line for line in text.splitlines() if line.strip().startswith("CMD ")
    ]
    assert cmd_lines, "Dockerfile must declare a CMD"

    for line in cmd_lines:
        if '"uv"' in line and '"run"' in line:
            assert '"--no-sync"' in line or "ENV UV_NO_SYNC=1" in text, (
                "Dockerfile CMD invokes `uv run` without --no-sync and "
                f"without UV_NO_SYNC=1: {line.strip()!r}"
            )


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


def test_http_guide_startup_example_does_not_bind_wildcard():
    """HTTP_MCP_GUIDE.md's startup command must not instruct --host 0.0.0.0.

    The shipped config defaults to auth.require_auth=false, so a wildcard
    bind in the primary startup instruction would expose an unauthenticated
    firewall-management API on every interface -- contradicting the guide's
    own loopback guidance, README, and SECURITY.md."""
    repo_root = _repo_root()
    text = (repo_root / "HTTP_MCP_GUIDE.md").read_text()

    assert "--host 0.0.0.0" not in text


def test_http_server_command_argparse_host_default_is_loopback():
    """FortiGateMCPCommand's --host argparse default must resolve to
    127.0.0.1, not a wildcard bind -- a fail-safe default matters because
    this class can be invoked directly (bypassing start_http_server.sh's
    own 127.0.0.1 default) via `python -m src.fortigate_mcp.server_http`."""
    from src.fortigate_mcp.server_http import FortiGateMCPCommand

    parser = argparse.ArgumentParser()
    command = FortiGateMCPCommand()
    command.add_arguments(parser)

    args = parser.parse_args([])

    assert args.host == "127.0.0.1"


def test_start_http_server_script_defaults_to_loopback():
    """start_http_server.sh must default MCP_HTTP_HOST to 127.0.0.1, not a
    wildcard bind -- both README and HTTP_MCP_GUIDE endorse this script as
    the primary start method for the (default-unauthenticated) HTTP server."""
    repo_root = _repo_root()
    text = (repo_root / "start_http_server.sh").read_text()

    assert "${MCP_HTTP_HOST:-127.0.0.1}" in text
    assert "MCP_HTTP_HOST:-0.0.0.0" not in text


def test_docker_compose_publishes_loopback_only():
    """Every host-port publish spec in docker-compose.yml must bind loopback.

    The shipped config defaults to auth.require_auth=false, and SECURITY.md
    forbids exposing the unauthenticated server on 0.0.0.0 or any routable
    interface. This iterates ALL services' publish specs (parsed from YAML,
    so quoting variants cannot slip past a substring check) rather than
    checking only the MCP service's mapping: the removed optional nginx
    profile published 80/443 on all host interfaces and proxied straight to
    the unauthenticated backend over the internal network, silently
    bypassing the MCP service's loopback publish. Any reintroduced sidecar
    or extra mapping must also bind 127.0.0.1 to pass."""
    repo_root = _repo_root()
    compose = yaml.safe_load((repo_root / "docker-compose.yml").read_text())

    publish_specs = [
        str(spec)
        for service in compose["services"].values()
        for spec in service.get("ports", [])
    ]

    assert "127.0.0.1:8814:8814" in publish_specs
    non_loopback = [spec for spec in publish_specs if not spec.startswith("127.0.0.1:")]
    assert non_loopback == [], (
        f"docker-compose.yml publishes non-loopback host ports: {non_loopback}. "
        "Bind 127.0.0.1, or document the exposure and require "
        "auth.require_auth=true before widening -- see SECURITY.md."
    )


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


# --- AI-residue and badge hygiene (REL-07, REL-08) ------------------------


def test_no_ai_attribution_in_new_docs():
    """Release-facing docs must contain none of the fragment-assembled
    AI-residue markers, and every one of them must EXIST (each is a required
    release deliverable -- a silently deleted file must not pass vacuously).
    CONTRIBUTING.md is scanned against every marker EXCEPT the commit-trailer
    one: it is the single file allowed to reference that trailer pattern, as
    policy prose explaining the project's no-AI-attribution rule (framing
    verified by the proximity test below)."""
    repo_root = _repo_root()

    non_trailer_markers = tuple(
        marker for marker in _ALL_RESIDUE_MARKERS if marker != _TRAILER_MARKER
    )
    scan_plan = {
        "README.md": _ALL_RESIDUE_MARKERS,
        "HTTP_MCP_GUIDE.md": _ALL_RESIDUE_MARKERS,
        "CHANGELOG.md": _ALL_RESIDUE_MARKERS,
        "SECURITY.md": _ALL_RESIDUE_MARKERS,
        "CODE_OF_CONDUCT.md": _ALL_RESIDUE_MARKERS,
        "CONTRIBUTING.md": non_trailer_markers,
    }

    for filename, markers in scan_plan.items():
        path = repo_root / filename
        assert path.exists(), f"{filename} is a release-facing doc and must exist"
        text = path.read_text()
        for marker in markers:
            assert marker not in text, f"{filename} contains AI-residue marker {marker!r}"


def test_contributing_md_mentions_trailer_as_policy_not_accident():
    """CONTRIBUTING.md must mention the AI co-author trailer pattern as
    deliberate policy prose (explaining the prohibition), not as an
    accidental real trailer -- confirmed by proximity to a negation word."""
    repo_root = _repo_root()
    text = (repo_root / "CONTRIBUTING.md").read_text()

    index = text.find(_TRAILER_MARKER)
    assert index != -1, "CONTRIBUTING.md must mention the AI co-author trailer pattern"

    window = text[max(0, index - 80) : index + 80].lower()
    assert any(word in window for word in ("no", "not", "prohibited", "forbidden")), (
        "CONTRIBUTING.md's AI co-author trailer mention must be framed as a prohibition"
    )


def test_readme_badges_reference_real_workflows():
    """README.md must ship badges referencing only real, on-disk workflow
    files. As of this test's authoring, all 4 GitHub Actions workflows this
    phase created (test.yml, lint.yml, security.yml, release.yml) have real
    hosted-green (or hosted-verified dry-run, for release.yml) proof behind
    them, so badges are required, not just permitted -- and each one must
    name-check against a workflow file that actually exists on disk, so a
    future rename/deletion without a README update fails this test
    immediately rather than silently going stale."""
    repo_root = _repo_root()
    text = (repo_root / "README.md").read_text()

    assert "badge.svg" in text

    for filename in _WORKFLOW_FILES:
        assert filename in text, f"README.md badge markup must reference {filename}"
        workflow_path = repo_root / ".github" / "workflows" / filename
        assert workflow_path.exists(), (
            f"README.md references {filename} but it does not exist on disk"
        )


# --- GitHub Actions workflow hygiene (CI-01..CI-05) ------------------------

_WORKFLOW_FILES = (
    "test.yml",
    "lint.yml",
    "security.yml",
    "release.yml",
)

_SHA_PINNED_USES = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _workflow_triggers(data: dict) -> dict:
    """Return a workflow YAML's trigger ("on:") mapping.

    PyYAML follows the YAML 1.1 spec, under which a bare `on` scalar key is
    a boolean literal -- ``yaml.safe_load`` parses GitHub Actions' `on:` key
    as the Python boolean ``True``, not the string ``"on"``. Handle both so
    this helper is correct regardless of which key PyYAML produced.
    """
    return data["on"] if "on" in data else data[True]


def test_all_workflow_actions_are_sha_pinned():
    """Every `uses:` reference across all 4 workflow files must be pinned to
    a full 40-hex-char commit SHA, never a mutable tag -- the T-06-05-01
    supply-chain mitigation (a moved tag can silently swap in malicious
    code, per the CLAUDE.md-cited trivy-action incident)."""
    repo_root = _repo_root()

    for filename in _WORKFLOW_FILES:
        path = repo_root / ".github" / "workflows" / filename
        data = yaml.safe_load(path.read_text())

        for job_name, job in data["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if uses is None:
                    continue
                assert _SHA_PINNED_USES.match(uses), (
                    f"{filename} job {job_name!r} has a non-SHA-pinned "
                    f"uses: {uses!r}"
                )


def test_workflow_docker_run_images_are_digest_pinned():
    """``run:`` steps that invoke ``docker run`` bypass the ``uses:``
    SHA-pin audit above, yet pull and execute registry images all the same
    -- and registry tags are mutable. Require every such step to reference
    a digest-pinned image (``@sha256:<64-hex>``); the gitleaks scanner in
    particular gets read access to the full repository history
    (T-06-05-01 gap closure)."""
    repo_root = _repo_root()
    digest_ref = re.compile(r"@sha256:[0-9a-f]{64}\b")

    for filename in _WORKFLOW_FILES:
        path = repo_root / ".github" / "workflows" / filename
        data = yaml.safe_load(path.read_text())

        for job_name, job in data["jobs"].items():
            for step in job.get("steps", []):
                run = step.get("run")
                if run is None or "docker run" not in run:
                    continue
                assert digest_ref.search(run), (
                    f"{filename} job {job_name!r} invokes `docker run` "
                    "without a digest-pinned (@sha256:...) image reference"
                )


def test_release_workflow_never_triggers_on_pull_request():
    """release.yml must never trigger on pull_request -- it is the only
    workflow in this phase that can push to GHCR, and a fork PR must never
    reach that path (T-06-05-04)."""
    repo_root = _repo_root()
    data = yaml.safe_load((repo_root / ".github" / "workflows" / "release.yml").read_text())

    assert "pull_request" not in _workflow_triggers(data)


def test_release_workflow_latest_flavor_is_conditional_on_push_event():
    """release.yml's `latest` tag flavor must be gated on a real push (tag-ref)
    event, never auto-applied on a workflow_dispatch dry run (CI-05)."""
    repo_root = _repo_root()
    text = (repo_root / ".github" / "workflows" / "release.yml").read_text()

    assert "latest=${{ github.event_name == 'push' && 'auto' || 'false' }}" in text


def test_release_workflow_never_uses_branch_tag_scheme():
    """release.yml must never rely on docker/metadata-action's `{{branch}}`
    token -- it renders empty on the tag-push events this workflow triggers
    on (06-RESEARCH.md Pitfall 4)."""
    repo_root = _repo_root()
    text = (repo_root / ".github" / "workflows" / "release.yml").read_text()

    assert "{{branch}}" not in text


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
