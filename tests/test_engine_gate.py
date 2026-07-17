"""Engine Gate: cause-separated evidence tests for CONS-01's stdio engine decision.

This is a PERMANENT regression guard, not a throwaway migration script. It
separates the engine-gate's two possible failure causes into independent
tests with distinct remedies:

  - ``test_registry_stdio_output_matches_frozen_golden`` /
    ``test_registry_http_output_matches_frozen_golden``: registry.py's
    output, on the CURRENT engine for each transport, must equal the frozen
    golden contract. FAILURE HERE MEANS registry.py IS WRONG -- fix it,
    never fall back on this cause, never record a decision.
  - ``test_full_30_tool_schema_diff_across_engines``: only meaningful once
    the two tests above are green. FAILURE HERE means the two candidate
    engines genuinely disagree on schema shape -- the fallback trigger.

Golden immutability is enforced independently of git-diff windows via
embedded SHA-256 hashes -- an accidentally regenerated-and-committed
fixture fails these forever, not just within one commit's diff.

Runtime/protocol compatibility on the REAL, selected-engine production
server (not just fake-tools schema snapshots) is proven by the
``test_real_stdio_server_*`` tests appended in Task 3.
"""
import asyncio
import hashlib
import json
import types
from functools import lru_cache
from typing import Any, Dict, Tuple
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Client
from fastmcp import FastMCP as PrefectFastMCP
from mcp.server.fastmcp import FastMCP as SDKFastMCP
from mcp.types import TextContent

from src.fortigate_mcp.registry import register_tools
from src.fortigate_mcp.server import FortiGateMCPServer
from tests.test_tool_schema_snapshot import HTTP_GOLDEN, STDIO_GOLDEN, _normalize_schema

# Computed from the committed fixtures during Phase 3 Plan 03 planning --
# if either assertion below fails at creation time, the goldens changed
# since planning and the phase premise (byte-frozen contract) is broken.
STDIO_GOLDEN_SHA256 = "ca5ddfcce490c5155ffe3a406c6b8d5a17c62d4cd9652967f0bd7bf0e4ec88e4"
HTTP_GOLDEN_SHA256 = "a51d632aa943e28d0b1ae4d48dff4ef17aa4756df25eacf62e0df95041853994"


def _fake_tools():
    """Lightweight fake `tools` object, identical in shape to test_registry.py's
    (duplicated locally on purpose -- no cross-import between test files)."""
    fake = types.SimpleNamespace(
        device_tools=MagicMock(),
        firewall_tools=MagicMock(),
        network_tools=MagicMock(),
        routing_tools=MagicMock(),
        virtual_ip_tools=MagicMock(),
        fortigate_manager=MagicMock(devices={}, failed_devices={}),
        # allow_writes=True: this file proves engine/schema equivalence, not
        # gating semantics (owned by tests/test_write_gate.py).
        config=types.SimpleNamespace(
            server=types.SimpleNamespace(
                name="test", version="1.0.0", host="0.0.0.0", port=8814, allow_writes=True
            )
        ),
        host="127.0.0.1",
        port=8814,
        path="/fortigate-mcp",
        _tests_passed=None,
        logger=MagicMock(),
    )

    # get_policy_detail_async is awaited -- MUST be an AsyncMock, not a plain
    # MagicMock attribute (not awaitable, raises TypeError).
    fake.firewall_tools.get_policy_detail_async = AsyncMock(
        return_value=[TextContent(type="text", text="SENTINEL-async")]
    )

    return fake


def _sdk_stdio_snapshot() -> Dict[str, Dict[str, Any]]:
    """(a) stdio registration on the SDK's mcp.server.fastmcp.FastMCP."""
    mcp = SDKFastMCP("engine-gate-sdk-stdio")
    register_tools(mcp, _fake_tools(), transport="stdio")
    tools = asyncio.run(mcp.list_tools())
    return {t.name: {"inputSchema": _normalize_schema(t.inputSchema)} for t in tools}


def _prefect_stdio_snapshot() -> Dict[str, Dict[str, Any]]:
    """(b) stdio registration on fastmcp.FastMCP -- the candidate engine."""
    mcp = PrefectFastMCP("engine-gate-prefect-stdio")
    register_tools(mcp, _fake_tools(), transport="stdio")

    async def _get() -> Dict[str, Any]:
        tools = await mcp.get_tools()
        return {name: tool.to_mcp_tool() for name, tool in tools.items()}

    mcp_tools = asyncio.run(_get())
    return {name: {"inputSchema": _normalize_schema(t.inputSchema)} for name, t in mcp_tools.items()}


def _prefect_http_snapshot() -> Dict[str, Dict[str, Any]]:
    """(c) http registration on fastmcp.FastMCP (unchanged by this plan)."""
    mcp = PrefectFastMCP("engine-gate-prefect-http")
    register_tools(mcp, _fake_tools(), transport="http")

    async def _get() -> Dict[str, Any]:
        tools = await mcp.get_tools()
        return {name: tool.to_mcp_tool() for name, tool in tools.items()}

    mcp_tools = asyncio.run(_get())
    return {name: {"inputSchema": _normalize_schema(t.inputSchema)} for name, t in mcp_tools.items()}


@lru_cache(maxsize=1)
def _snapshots() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Build the three registry-driven snapshots once per session."""
    return _sdk_stdio_snapshot(), _prefect_stdio_snapshot(), _prefect_http_snapshot()


def _load_golden(path) -> Dict[str, Dict[str, Any]]:
    return json.loads(path.read_text())


# --- Golden immutability guards ----------------------------------------------


def test_stdio_golden_sha256_frozen() -> None:
    assert hashlib.sha256(STDIO_GOLDEN.read_bytes()).hexdigest() == STDIO_GOLDEN_SHA256


def test_http_golden_sha256_frozen() -> None:
    assert hashlib.sha256(HTTP_GOLDEN.read_bytes()).hexdigest() == HTTP_GOLDEN_SHA256


# --- Cause-separated gate tests -----------------------------------------------


def test_registry_stdio_output_matches_frozen_golden() -> None:
    """FAILURE = registry.py bug. Fix registry.py; do NOT fall back; do NOT record a decision."""
    sdk_stdio, _, _ = _snapshots()
    assert sdk_stdio == _load_golden(STDIO_GOLDEN)


def test_registry_http_output_matches_frozen_golden() -> None:
    """FAILURE = registry.py bug (http transport). Fix registry.py; do NOT fall back; do NOT record a decision."""
    _, _, prefect_http = _snapshots()
    assert prefect_http == _load_golden(HTTP_GOLDEN)


def test_full_30_tool_schema_diff_across_engines() -> None:
    """FAILURE (with the two registry-vs-golden tests green) = engines genuinely
    disagree -> dual-engine fallback; this test then gets xfail(strict=True)
    with the divergence as reason."""
    sdk_stdio, prefect_stdio, _ = _snapshots()
    assert len(sdk_stdio) == 30
    assert set(sdk_stdio) == set(prefect_stdio)
    assert sdk_stdio == prefect_stdio


# --- Runtime compatibility on the REAL, selected-engine production server --
# (Schema equality proves shape, not behavior -- these prove a full
# in-memory MCP session against the actual FortiGateMCPServer object.)


def test_real_stdio_server_serves_full_mcp_session(tmp_config_path) -> None:
    """A real FortiGateMCPServer serves a full in-memory MCP session: initialize,
    list_tools matching the frozen stdio golden's name set, and a sync tool call."""

    async def _run():
        server = FortiGateMCPServer(tmp_config_path)
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            assert len(tools) == 30
            assert {t.name for t in tools} == set(json.loads(STDIO_GOLDEN.read_text()).keys())

            result = await client.call_tool("list_devices", {})
            assert "default" in result.content[0].text

    asyncio.run(_run())


def test_real_stdio_server_dict_payload_roundtrip(tmp_config_path, monkeypatch) -> None:
    """A dict-payload create tool round-trips through the same real session,
    proving runtime dispatch (not just schema equality) on the selected engine."""
    # create_static_route is a write tool: this real server's ServerConfig
    # now defaults allow_writes=False (SEC-01), so the env override is
    # required for this round-trip to reach the mocked target at all.
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")

    async def _run():
        server = FortiGateMCPServer(tmp_config_path)
        mock_create = MagicMock(return_value=[TextContent(type="text", text="SENTINEL-route")])
        monkeypatch.setattr(server.routing_tools, "create_static_route_from_payload", mock_create)

        route_data = {"dst": "10.0.0.0/24", "gateway": "10.0.0.1", "distance": 10}
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "create_static_route", {"device_id": "default", "route_data": route_data}
            )

        mock_create.assert_called_once_with("default", route_data, None)
        assert result.content[0].text == "SENTINEL-route"

    asyncio.run(_run())
