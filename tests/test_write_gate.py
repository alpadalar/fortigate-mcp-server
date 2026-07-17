"""Tests for the SEC-01 dispatch-layer read-only gate and the SEC-02
canonical risk classification in ``src/fortigate_mcp/registry.py``.

Classification tests (this file's `-k classification` slice) prove
`RISK_CLASSIFICATION` exactly covers every tool name either transport
registers, and that its class assignment matches the naming rule
mechanically (not just by eyeballing the dict). Gate tests (added in a
later task) prove denial/opt-in behaviorally on both MCP engines.
"""
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
    register_tools() for both transports -- exactly 33 unique names."""
    sdk_mcp = SDKFastMCP("classification-stdio")
    register_tools(sdk_mcp, _fake_tools(), transport="stdio")
    stdio_names = set(sdk_mcp._tool_manager._tools)

    http_mcp = PrefectFastMCP("classification-http")
    register_tools(http_mcp, _fake_tools(), transport="http")
    http_names = set(http_mcp._tool_manager._tools)

    union = stdio_names | http_names

    assert union == set(RISK_CLASSIFICATION)
    assert len(RISK_CLASSIFICATION) == 33
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
