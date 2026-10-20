"""Tests for the SEC-01 dispatch-layer read-only gate and the SEC-02
canonical risk classification in ``src/fortigate_mcp/registry.py``.

Classification tests (this file's `-k classification` slice) prove
`RISK_CLASSIFICATION` exactly covers every tool name either transport
registers, and that its class assignment matches the naming rule
mechanically (not just by eyeballing the dict). Gate tests prove
denial/opt-in behaviorally at dispatch on the fastmcp engine (both the stdio
and http registrations), per CONTEXT.md's CVE-2026-46519 lesson: enforcement
must be proven at dispatch, not assumed.
"""
import asyncio
import types
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Client
from fastmcp import FastMCP as PrefectFastMCP
from mcp_types import TextContent

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
    register_tools() for both transports -- exactly 47 unique names."""
    # The only tool-name introspection surface is the public async list_tools().
    stdio_mcp = PrefectFastMCP("classification-stdio")
    register_tools(stdio_mcp, _fake_tools(), transport="stdio")
    stdio_names = {tool.name for tool in asyncio.run(stdio_mcp.list_tools())}

    http_mcp = PrefectFastMCP("classification-http")
    register_tools(http_mcp, _fake_tools(), transport="http")
    http_names = {tool.name for tool in asyncio.run(http_mcp.list_tools())}

    union = stdio_names | http_names

    assert union == set(RISK_CLASSIFICATION)
    assert len(RISK_CLASSIFICATION) == 50
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


def _call(mcp, name, arguments, raise_on_error=True):
    """Dispatch a tool call through a real in-memory fastmcp Client session."""

    async def _run():
        async with Client(mcp) as client:
            return await client.call_tool(name, arguments, raise_on_error=raise_on_error)

    return asyncio.run(_run())


_CREATE_ARGS = {"device_id": "d", "policy_data": {"name": "p"}}
_DELETE_ARGS = {"device_id": "d", "policy_id": "1"}


def _assert_denied(result):
    """Protocol-level tool error (not ordinary success content)."""
    assert result.is_error is True
    assert "read-only mode" in result.content[0].text


# -- Denial: zero calls to the tools layer ----------------------------------


@pytest.mark.parametrize("transport", ["stdio", "http"])
def test_write_tool_denied_by_default(monkeypatch, transport):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-denied")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport=transport)

    _assert_denied(_call(mcp, "create_firewall_policy", _CREATE_ARGS, raise_on_error=False))

    fake_tools.firewall_tools.create_policy.assert_not_called()


# -- Opt-in via config.server.allow_writes=True ------------------------------


@pytest.mark.parametrize("transport", ["stdio", "http"])
def test_write_tool_allowed_with_config_opt_in(monkeypatch, transport):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-allowed")
    fake_tools = _fake_tools_with(allow_writes=True)
    register_tools(mcp, fake_tools, transport=transport)

    result = _call(mcp, "create_firewall_policy", _CREATE_ARGS)

    assert result.content[0].text == "SENTINEL-create_policy"
    fake_tools.firewall_tools.create_policy.assert_called_once()


# -- FORTIGATE_MCP_ALLOW_WRITES env override -- always delenv-isolated ------


def test_env_override_enables_writes_when_config_false(monkeypatch):
    """FORTIGATE_MCP_ALLOW_WRITES=1 enables writes even when
    config.server.allow_writes is False."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    mcp = PrefectFastMCP("gate-env-override")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    result = _call(mcp, "create_firewall_policy", _CREATE_ARGS)

    assert result.content[0].text == "SENTINEL-create_policy"
    fake_tools.firewall_tools.create_policy.assert_called_once()


@pytest.mark.parametrize("env_value", ["0", None])
def test_env_zero_or_unset_does_not_enable_writes(monkeypatch, env_value):
    """Regression guard for the '0'-is-not-truthy pitfall: neither an
    explicit '0' nor an unset env var enables writes when config is False."""
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    if env_value is not None:
        monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", env_value)

    mcp = PrefectFastMCP("gate-env-not-truthy")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    _assert_denied(_call(mcp, "create_firewall_policy", _CREATE_ARGS, raise_on_error=False))

    fake_tools.firewall_tools.create_policy.assert_not_called()


# -- Destructive tool gated identically to a write tool ----------------------


def test_destructive_tool_denied_by_default(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-destructive-denied")
    fake_tools = _fake_tools_with(allow_writes=False)
    register_tools(mcp, fake_tools, transport="stdio")

    _assert_denied(_call(mcp, "delete_firewall_policy", _DELETE_ARGS, raise_on_error=False))

    fake_tools.firewall_tools.delete_policy.assert_not_called()


def test_destructive_tool_allowed_with_opt_in(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-destructive-allowed")
    fake_tools = _fake_tools_with(allow_writes=True)
    register_tools(mcp, fake_tools, transport="stdio")

    result = _call(mcp, "delete_firewall_policy", _DELETE_ARGS)

    assert result.content[0].text == "SENTINEL-delete_policy"
    fake_tools.firewall_tools.delete_policy.assert_called_once()


# -- Read tool never gated, regardless of allow_writes state -----------------


@pytest.mark.parametrize("allow_writes", [False, True])
def test_read_tool_always_dispatches_regardless_of_allow_writes(monkeypatch, allow_writes):
    monkeypatch.delenv("FORTIGATE_MCP_ALLOW_WRITES", raising=False)
    mcp = PrefectFastMCP("gate-read-always")
    fake_tools = _fake_tools_with(allow_writes=allow_writes)
    register_tools(mcp, fake_tools, transport="stdio")

    result = _call(mcp, "list_devices", {})

    assert result.content[0].text == "SENTINEL-list_devices"
    fake_tools.device_tools.list_devices.assert_called_once()
