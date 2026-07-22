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
import json

import pytest
from fastmcp import Client
from mcp.types import TextContent
from unittest.mock import MagicMock, patch

from src.fortigate_mcp.registry import RISK_CLASSIFICATION
from src.fortigate_mcp.server import FortiGateMCPServer
from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer


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
# validity is irrelevant to these tests. The final entry repeats list_admins
# with an explicit vdom so vdom pass-through is pinned at the registry layer
# (the closures dispatch positionally: method(device_id, vdom)).
NEW_TOOL_MATRIX = [
    ("list_security_profiles", "security_tools", "list_security_profiles", {"device_id": "probe"}),
    ("list_admins", "admin_tools", "list_admins", {"device_id": "probe"}),
    ("get_sslvpn_settings", "security_tools", "get_sslvpn_settings", {"device_id": "probe"}),
    ("list_local_in_policies", "security_tools", "list_local_in_policies", {"device_id": "probe"}),
    ("list_admins", "admin_tools", "list_admins", {"device_id": "probe", "vdom": "vd-test"}),
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
    mock_method.assert_called_once_with(args["device_id"], args.get("vdom"))


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
    # Guard against fixture drift: this test is only meaningful in
    # read-only mode -- if the shared config fixture ever flips
    # allow_writes on, the never-gated proof would become vacuous.
    assert server.config.server.allow_writes is False
    tools_instance = getattr(server, tools_attr)
    mock_method = MagicMock(return_value=[TextContent(type="text", text=f"SENTINEL-{tool_name}")])
    monkeypatch.setattr(tools_instance, method_name, mock_method)

    result = asyncio.run(_call_via_client(server.mcp, tool_name, args))

    assert result.content[0].text == f"SENTINEL-{tool_name}"
    mock_method.assert_called_once_with(args["device_id"], args.get("vdom"))


@pytest.mark.parametrize("tool_name", list(dict.fromkeys(entry[0] for entry in NEW_TOOL_MATRIX)))
def test_new_tool_risk_classification_is_read(tool_name):
    """RISK_CLASSIFICATION directly classifies all 4 new tool names as
    'read' -- the single source of truth for the SEC-01 write gate."""
    assert RISK_CLASSIFICATION[tool_name] == "read"


@pytest.mark.parametrize("tool_name, tools_attr, method_name, args", NEW_TOOL_MATRIX)
def test_new_tool_dispatches_on_http(tmp_config_path, tool_name, tools_attr, method_name, args, monkeypatch):
    """Each new tool dispatches to its Tools-layer method through a real
    HTTP-transport-registered MCP protocol call
    (fastmcp.Client(http_server.mcp)). The real network probe at
    construction is patched out (per test_e2e_http.py's established
    idiom) -- no background-thread test server or wire-level mock router
    is needed since the Tools-layer method is monkeypatched out entirely."""
    with patch.object(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None):
        server = FortiGateMCPHTTPServer(config_path=tmp_config_path, host="127.0.0.1", port=0, path="/fortigate-mcp")
    tools_instance = getattr(server, tools_attr)
    mock_method = MagicMock(return_value=[TextContent(type="text", text=f"SENTINEL-{tool_name}")])
    monkeypatch.setattr(tools_instance, method_name, mock_method)

    result = asyncio.run(_call_via_client(server.mcp, tool_name, args))

    assert result.content[0].text == f"SENTINEL-{tool_name}"
    mock_method.assert_called_once_with(args["device_id"], args.get("vdom"))


def test_get_schema_info_includes_security_and_admin_tools_schema_info(tmp_config_path):
    """get_schema_info's HTTP-only aggregation includes security_tools and
    admin_tools keys with the exact get_schema_info() sub-dict shape
    ({'name', 'description', 'operations'}), each with a non-empty
    operations list -- closes 10-RESEARCH.md Pitfall 4's "unverified by
    any existing test" gap with more than a vacuous key-presence check."""
    with patch.object(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None):
        server = FortiGateMCPHTTPServer(config_path=tmp_config_path, host="127.0.0.1", port=0, path="/fortigate-mcp")

    result = asyncio.run(_call_via_client(server.mcp, "get_schema_info", {}))

    schema = json.loads(result.content[0].text)
    assert "security_tools" in schema["tools"]
    assert "admin_tools" in schema["tools"]
    assert schema["tools"]["security_tools"]["name"] == "security_tools"
    assert schema["tools"]["admin_tools"]["name"] == "admin_tools"
    assert len(schema["tools"]["security_tools"]["operations"]) >= 3
    assert len(schema["tools"]["admin_tools"]["operations"]) >= 1
