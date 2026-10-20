"""Offline stdio smoke test: spawn the real server as a subprocess and list its tools.

Proves the production stdio entry point speaks MCP over a real pipe (initialize +
tools/list) with only protocol framing on stdout, and that its tool-name set equals
the frozen stdio golden. No network I/O: the config points at an RFC 5737 address
and ``list_tools`` never contacts a device.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from tests.test_tool_schema_snapshot import STDIO_GOLDEN

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_stdio_subprocess_lists_golden_tool_names(tmp_config_path) -> None:
    env = {k: v for k, v in os.environ.items() if k != "FORTIGATE_MCP_ALLOW_WRITES"}
    env["FORTIGATE_MCP_CONFIG"] = str(tmp_config_path)
    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "src.fortigate_mcp.server"],
        env=env,
        cwd=str(REPO_ROOT),
    )

    async def _run():
        async with Client(transport) as client:
            return await asyncio.wait_for(client.list_tools(), timeout=30)

    tools = asyncio.run(asyncio.wait_for(_run(), timeout=60))

    assert {t.name for t in tools} == set(json.loads(STDIO_GOLDEN.read_text()).keys())
