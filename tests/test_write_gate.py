"""Tests for the SEC-01 dispatch-layer read-only gate and the SEC-02
canonical risk classification in ``src/fortigate_mcp/registry.py``.

Classification tests (this file's `-k classification` slice) prove
`RISK_CLASSIFICATION` exactly covers every tool name either transport
registers, and that its class assignment matches the naming rule
mechanically (not just by eyeballing the dict). Gate tests prove
denial/opt-in behaviorally on BOTH MCP engines (SDK stdio + fastmcp HTTP),
never merely on one, per CONTEXT.md's CVE-2026-46519 lesson: enforcement
must be proven at dispatch, not assumed from a single engine's behavior.
"""
import asyncio
import types
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Client
from fastmcp import FastMCP as PrefectFastMCP
from mcp.server.fastmcp import FastMCP as SDKFastMCP
from mcp.types import TextContent

from src.fortigate_mcp.registry import RISK_CLASSIFICATION, register_tools


def _fake_tools():
    """Lightweight fake `tools` object (same shape as test_registry.py's,
    duplicated locally per that file's own no-cross-import convention).

    `config.server.allow_writes=False` so gate reads at call time never
    AttributeError, and denial tests exercise a genuine read-only default.
    """
    fake = types.SimpleNamespace(
        device_tools=MagicMock(),
        firewall_tools=MagicMock(),
        network_tools=MagicMock(),
        routing_tools=MagicMock(),
        virtual_ip_tools=MagicMock(),
        security_tools=MagicMock(),
        admin_tools=MagicMock(),
        fortigate_manager=MagicMock(devices={}, failed_devices={}),
        config=types.SimpleNamespace(
            server=types.SimpleNamespace(
                name="test", version="1.0.0", host="0.0.0.0", port=8814, allow_writes=False
            )
        ),
        host="127.0.0.1",
        port=8814,
        path="/fortigate-mcp",
        _tests_passed=None,
        logger=MagicMock(),
    )

    # get_policy_detail_async is awaited -- MUST be an AsyncMock, not a plain
    # MagicMock attribute (which is not awaitable and raises TypeError).
    fake.firewall_tools.get_policy_detail_async = AsyncMock(
        return_value=[TextContent(type="text", text="SENTINEL-async")]
    )

    fake.device_tools.list_devices = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-list_devices")]
    )
    fake.network_tools.create_address_object_from_payload = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-payload")]
    )

    return fake


# --- Group 1: classification completeness + naming-rule proof ---------------


def test_classification_completeness_matches_registered_tools():
    """set(RISK_CLASSIFICATION) equals the union of tool names registered by
    register_tools() for both transports -- exactly 37 unique names."""
    sdk_mcp = SDKFastMCP("classification-stdio")
    register_tools(sdk_mcp, _fake_tools(), transport="stdio")
    stdio_names = set(sdk_mcp._tool_manager._tools)

    # fastmcp>=3.2.0 removed the private _tool_manager._tools path the SDK
    # engine (above) still exposes -- the HTTP engine's only remaining
    # tool-name introspection surface is the public async list_tools().
    http_mcp = PrefectFastMCP("classification-http")
    register_tools(http_mcp, _fake_tools(), transport="http")
    http_names = {tool.name for tool in asyncio.run(http_mcp.list_tools())}

    union = stdio_names | http_names

    assert union == set(RISK_CLASSIFICATION)
    assert len(RISK_CLASSIFICATION) == 37
    assert len(RISK_CLASSIFICATION) == len(set(RISK_CLASSIFICATION))  # no duplicate keys


def test_classification_matches_naming_rule():
    """Every write-classified name matches create_*/update_*/add_device;
    every destructive-classified name matches delete_*/remove_device;
    everything else is read -- re-derived from the name itself, not the
    dict, so a future misclassified addition fails this test even if
    completeness alone would not catch it."""
    for name, risk_class in RISK_CLASSIFICATION.items():
        if name.startswith("create_") or name.startswith("update_") or name == "add_device":
            expected = "write"
        elif name.startswith("delete_") or name == "remove_device":
            expected = "destructive"
        else:
            expected = "read"
        assert risk_class == expected, f"{name}: expected {expected!r}, got {risk_class!r}"


# --- Group 2: dispatch-layer gate (SEC-01) -----------------------------------


def _unwrap(result):
    """Match test_registry.py's tuple-or-list unwrap convention for SDK call_tool."""
    return result[0] if isinstance(result, tuple) else result


def _fake_tools_with(allow_writes: bool):
    """A _fake_tools() variant with explicit sentinel returns for the
    write tool (create_firewall_policy -> firewall_tools.create_policy)
    and destructive tool (delete_firewall_policy -> firewall_tools.delete_policy)
    used across the gate tests below."""
    fake = _fake_tools()
    fake.config.server.allow_writes = allow_writes
    fake.firewall_tools.create_policy = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-create_policy")]
    )
    fake.firewall_tools.delete_policy = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-delete_policy")]
    )
    return fake


# -- Denial: proven on both engines, zero calls to the tools layer ----------


def test_write_tool_denied_by_default_sdk_engine(monkeypatch):
    """SDK stdio engine: awaiting call_tool on a gated write tool in
    read-only mode raises the SDK's ToolError whose message contains
    'read-only mode'; the underlying mock is never called."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = SDKFastMCP("gate-sdk-denied")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    with pytest.raises(Exception, match="read-only mode"):
        asyncio.run(
            mcp.call_tool(
                "create_firewall_policy", {"device_id": "d", "policy_data": {"name": "p"}}
            )
        )

    fake_tools.firewall_tools.create_policy.assert_not_called()


def test_write_tool_denied_by_default_fastmcp_engine(monkeypatch):
    """fastmcp HTTP engine: Client.call_tool(..., raise_on_error=False)
    returns is_error=True whose content text contains 'read-only mode';
    the underlying mock is never called. This is a protocol-level tool
    error, not ordinary success content."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-fastmcp-denied")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="http")

    async def _call():
        async with Client(mcp) as client:
            return await client.call_tool(
                "create_firewall_policy",
                {"device_id": "d", "policy_data": {"name": "p"}},
                raise_on_error=False,
            )

    result = asyncio.run(_call())

    assert result.is_error is True
    assert "read-only mode" in result.content[0].text
    fake_tools.firewall_tools.create_policy.assert_not_called()


# -- Opt-in via config.server.allow_writes=True, proven on both engines -----


def test_write_tool_allowed_with_config_opt_in_sdk_engine(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = SDKFastMCP("gate-sdk-allowed")
    fake_tools = _fake_tools_with(allow_writes=True)
    register_tools(mcp, fake_tools, transport="stdio")

    result = asyncio.run(
        mcp.call_tool("create_firewall_policy", {"device_id": "d", "policy_data": {"name": "p"}})
    )
    content = _unwrap(result)

    assert content[0].text == "SENTINEL-create_policy"
    fake_tools.firewall_tools.create_policy.assert_called_once()


def test_write_tool_allowed_with_config_opt_in_fastmcp_engine(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-fastmcp-allowed")
    fake_tools = _fake_tools_with(allow_writes=True)
    register_tools(mcp, fake_tools, transport="http")

    async def _call():
        async with Client(mcp) as client:
            return await client.call_tool(
                "create_firewall_policy", {"device_id": "d", "policy_data": {"name": "p"}}
            )

    result = asyncio.run(_call())

    assert result.content[0].text == "SENTINEL-create_policy"
    fake_tools.firewall_tools.create_policy.assert_called_once()


# -- FORTIGATE_MCP_ALLOW_WRITES env override -- always delenv-isolated ------


def test_env_override_enables_writes_when_config_false(monkeypatch):
    """FORTIGATE_MCP_ALLOW_WRITES=1 enables writes even when
    config.server.allow_writes is False."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    mcp = SDKFastMCP("gate-env-override")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    result = asyncio.run(
        mcp.call_tool("create_firewall_policy", {"device_id": "d", "policy_data": {"name": "p"}})
    )
    content = _unwrap(result)

    assert content[0].text == "SENTINEL-create_policy"
    fake_tools.firewall_tools.create_policy.assert_called_once()


@pytest.mark.parametrize("env_value", ["0", None])
def test_env_zero_or_unset_does_not_enable_writes(monkeypatch, env_value):
    """Regression guard for the '0'-is-not-truthy pitfall: neither an
    explicit '0' nor an unset env var enables writes when config is False."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    if env_value is not None:
        monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", env_value)

    mcp = SDKFastMCP("gate-env-not-truthy")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    with pytest.raises(Exception, match="read-only mode"):
        asyncio.run(
            mcp.call_tool(
                "create_firewall_policy", {"device_id": "d", "policy_data": {"name": "p"}}
            )
        )

    fake_tools.firewall_tools.create_policy.assert_not_called()


# -- Destructive tool gated identically to a write tool ----------------------


def test_destructive_tool_denied_by_default(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = SDKFastMCP("gate-destructive-denied")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    with pytest.raises(Exception, match="read-only mode"):
        asyncio.run(mcp.call_tool("delete_firewall_policy", {"device_id": "d", "policy_id": "1"}))

    fake_tools.firewall_tools.delete_policy.assert_not_called()


def test_destructive_tool_allowed_with_opt_in(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = SDKFastMCP("gate-destructive-allowed")
    fake_tools = _fake_tools_with(allow_writes=True)
    register_tools(mcp, fake_tools, transport="stdio")

    result = asyncio.run(mcp.call_tool("delete_firewall_policy", {"device_id": "d", "policy_id": "1"}))
    content = _unwrap(result)

    assert content[0].text == "SENTINEL-delete_policy"
    fake_tools.firewall_tools.delete_policy.assert_called_once()


# -- Read tool never gated, regardless of allow_writes state -----------------


@pytest.mark.parametrize("allow_writes", [False, True])
def test_read_tool_always_dispatches_regardless_of_allow_writes(monkeypatch, allow_writes):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = SDKFastMCP("gate-read-always")
    fake_tools = _fake_tools_with(allow_writes=allow_writes)
    register_tools(mcp, fake_tools, transport="stdio")

    result = asyncio.run(mcp.call_tool("list_devices", {}))
    content = _unwrap(result)

    assert content[0].text == "SENTINEL-list_devices"
    fake_tools.device_tools.list_devices.assert_called_once()
