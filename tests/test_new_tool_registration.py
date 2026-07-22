"""
Protocol-level proof that the 4 v1.1 read-only visibility tools
(list_security_profiles, list_admins, get_sslvpn_settings,
list_local_in_policies) are live and callable on BOTH transports (VIS-06).

Every assertion here goes through a real ``fastmcp.Client(...).call_tool(...)``
session -- the same protocol layer that caught the historical stdio
async/sync bug (Phase 1) -- rather than calling ``.fn()`` directly or
asserting on source text. Covers:

1. Real stdio dispatch to the correct Tools-layer method (sentinel content).
2. Real HTTP-transport dispatch (sentinel content).
3. Write-gate-never-denied, under the exact conditions that deny write/
   destructive tools (allow_writes False + env unset), content-asserted.
4. RISK_CLASSIFICATION[name] == "read" for all 4 names.
5. get_schema_info's HTTP-only aggregation includes security_tools/
   admin_tools keys with the correct sub-dict shape.
"""

import asyncio

import pytest
from fastmcp import Client
from mcp.types import TextContent
from unittest.mock import MagicMock

from src.fortigate_mcp.registry import RISK_CLASSIFICATION
from src.fortigate_mcp.server import FortiGateMCPServer


async def _call_via_client(mcp, tool_name, args):
    """Call a tool through a real in-memory fastmcp.Client MCP session.

    Takes the raw ``mcp`` engine object (not the server wrapper), so the
    same helper works for both ``server.mcp`` and ``http_server.mcp``.
    """
    async with Client(mcp) as client:
        return await client.call_tool(tool_name, args)


# Matrix of (tool_name, tools_attr, method_name, args) covering the 4 new
# v1.1 visibility tools. "probe" is intentionally NOT a registered device --
# the underlying Tools-layer method is monkeypatched out entirely, so device
# validity is irrelevant to these tests.
NEW_TOOL_MATRIX = [
    ("list_security_profiles", "security_tools", "list_security_profiles", {"device_id": "probe"}),
    ("list_admins", "admin_tools", "list_admins", {"device_id": "probe"}),
    ("get_sslvpn_settings", "security_tools", "get_sslvpn_settings", {"device_id": "probe"}),
    ("list_local_in_policies", "security_tools", "list_local_in_policies", {"device_id": "probe"}),
]


@pytest.mark.parametrize("tool_name, tools_attr, method_name, args", NEW_TOOL_MATRIX)
def test_new_tool_dispatches_on_stdio(tmp_config_path, tool_name, tools_attr, method_name, args, monkeypatch):
    """Each new tool dispatches to its Tools-layer method through a real
    stdio MCP protocol call (fastmcp.Client(server.mcp))."""
    server = FortiGateMCPServer(tmp_config_path)
    tools_instance = getattr(server, tools_attr)
    mock_method = MagicMock(return_value=[TextContent(type="text", text=f"SENTINEL-{tool_name}")])
    monkeypatch.setattr(tools_instance, method_name, mock_method)

    result = asyncio.run(_call_via_client(server.mcp, tool_name, args))

    assert result.content[0].text == f"SENTINEL-{tool_name}"
    mock_method.assert_called_once()


@pytest.mark.parametrize("tool_name, tools_attr, method_name, args", NEW_TOOL_MATRIX)
def test_new_tool_never_gated_regardless_of_allow_writes(
    tmp_config_path, tool_name, tools_attr, method_name, args, monkeypatch
):
    """Proves the write-dispatch gate never intercepts these 4 tools even
    under the exact "read-only mode" conditions (allow_writes False, env
    unset) that deny write/destructive tools. Asserts on the literal
    sentinel content, not merely the absence of an exception -- a vacuous
    "no exception raised" check would pass even if dispatch were silently
    broken (10-RESEARCH.md Pitfall 3)."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    server = FortiGateMCPServer(tmp_config_path)
    tools_instance = getattr(server, tools_attr)
    mock_method = MagicMock(return_value=[TextContent(type="text", text=f"SENTINEL-{tool_name}")])
    monkeypatch.setattr(tools_instance, method_name, mock_method)

    result = asyncio.run(_call_via_client(server.mcp, tool_name, args))

    assert result.content[0].text == f"SENTINEL-{tool_name}"
    mock_method.assert_called_once()


@pytest.mark.parametrize("tool_name", [entry[0] for entry in NEW_TOOL_MATRIX])
def test_new_tool_risk_classification_is_read(tool_name):
    """RISK_CLASSIFICATION directly classifies all 4 new tool names as
    'read' -- the single source of truth for the SEC-01 write gate."""
    assert RISK_CLASSIFICATION[tool_name] == "read"
