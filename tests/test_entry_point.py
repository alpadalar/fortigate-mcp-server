"""
Tests for the `fortigate-mcp-server` console script entry point.

Covers the STAB-01 regression: the `[project.scripts]` entry previously
pointed at a non-existent `src.main:main`, so every fresh install failed
with `ModuleNotFoundError` on first run. These tests prove (1) the real
import target resolves, (2) pyproject.toml is wired to that target, and
(3) the spawned process actually starts and stays alive past a grace
period -- not merely that it fails to raise one specific exception.
"""

import os
import subprocess
import sys
import time

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - repo requires-python >=3.11
    import tomli as tomllib

from src.fortigate_mcp.server import server_main


def test_console_script_target_is_importable():
    """The entry point's import target resolves to a callable."""
    assert callable(server_main)


def test_console_script_registered_correctly():
    """pyproject.toml's [project.scripts] points at the real entry point."""
    pyproject_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pyproject.toml"
    )
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)

    assert (
        data["project"]["scripts"]["fortigate-mcp-server"]
        == "src.fortigate_mcp.server:server_main"
    )


def test_console_script_version_exits_zero_without_config():
    """`fortigate-mcp-server --version` must exit 0 even when
    FORTIGATE_MCP_CONFIG is unset -- argparse's --version action must
    short-circuit before the config-path enforcement runs."""
    env = {k: v for k, v in os.environ.items() if k != "FORTIGATE_MCP_CONFIG"}

    result = subprocess.run(
        ["uv", "run", "fortigate-mcp-server", "--version"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "fortigate-mcp-server" in result.stdout


def test_console_script_help_exits_zero_without_config():
    """`fortigate-mcp-server --help` must exit 0 even when
    FORTIGATE_MCP_CONFIG is unset."""
    env = {k: v for k, v in os.environ.items() if k != "FORTIGATE_MCP_CONFIG"}

    result = subprocess.run(
        ["uv", "run", "fortigate-mcp-server", "--help"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "usage" in result.stdout.lower()


def test_console_script_missing_config_still_exits_nonzero():
    """Regression guard: without --version/--help AND without
    FORTIGATE_MCP_CONFIG (or --config), the entry point must still error
    out exactly as before -- the argparse addition must not accidentally
    make the config requirement optional."""
    env = {k: v for k, v in os.environ.items() if k != "FORTIGATE_MCP_CONFIG"}

    result = subprocess.run(
        ["uv", "run", "fortigate-mcp-server"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    assert result.returncode == 1
    assert "FORTIGATE_MCP_CONFIG environment variable must be set" in result.stderr


def test_console_script_stays_alive(tmp_config_path):
    """The console script starts, holds stdio open, and stays alive.

    Strict liveness check: stdin is held open (not closed) so the MCP
    stdio transport does not see EOF and exit early. Any early exit --
    for ANY reason -- fails this test with the captured stdout/stderr,
    not just a specific exception string. There is no early-exit
    whitelist here by design: a narrower check could silently pass while
    masking a real startup crash.
    """
    proc = subprocess.Popen(
        ["uv", "run", "fortigate-mcp-server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "FORTIGATE_MCP_CONFIG": tmp_config_path},
    )
    try:
        time.sleep(5.0)

        if proc.poll() is not None:
            out, err = proc.communicate(timeout=5)
            assert False, (
                f"entry point exited early with rc={proc.returncode}\n"
                f"stdout:\n{out}\nstderr:\n{err}"
            )

        assert proc.poll() is None, f"entry point exited early with rc={proc.returncode}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
        if proc.stdin:
            proc.stdin.close()
