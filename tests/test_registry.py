"""Tests for src/fortigate_mcp/registry.py -- the shared MCP tool registry (CONS-01).

Proves register_tools' tool counts, transport validation, dispatch
correctness for the 3 divergent create-tools plus the unified async
get_firewall_policy_detail, AND protocol-level invocation through each
engine's REAL MCP call path (SDK call_tool / fastmcp in-memory Client),
not only direct .fn() closure calls -- exercising the .fn() closure alone
would miss any registration-layer bug that a real dispatch path would
catch. None of this depends on server.py/server_http.py wiring (that
happens in later plans).
"""
import asyncio
import types
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Client
from fastmcp import FastMCP as PrefectFastMCP
from mcp.server.fastmcp import FastMCP as SDKFastMCP
from mcp.types import TextContent

from src.fortigate_mcp.registry import register_tools


def _fake_tools():
    """Lightweight fake `tools` object (NOT a full FortiGateMCPServer)."""
    fake = types.SimpleNamespace(
        device_tools=MagicMock(),
        firewall_tools=MagicMock(),
        network_tools=MagicMock(),
        routing_tools=MagicMock(),
        virtual_ip_tools=MagicMock(),
        fortigate_manager=MagicMock(devices={}, failed_devices={}),
        config=types.SimpleNamespace(
            server=types.SimpleNamespace(name="test", version="1.0.0", host="0.0.0.0", port=8814)
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

    # Explicit Content-list return values for tools invoked via the protocol
    # path, so FastMCP's real result conversion has something real to convert.
    fake.device_tools.list_devices = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-list_devices")]
    )
    fake.network_tools.create_address_object_from_payload = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-payload")]
    )
    fake.network_tools.create_address_object = MagicMock(
        return_value=[TextContent(type="text", text="SENTINEL-fields")]
    )

    return fake


def _unwrap(result):
    """Match test_server.py's tuple-or-list unwrap convention for SDK call_tool."""
    return result[0] if isinstance(result, tuple) else result


# --- Group 1: counts and validation -----------------------------------------


def test_register_tools_stdio_count():
    mcp = SDKFastMCP("probe")
    count = register_tools(mcp, _fake_tools(), transport="stdio")
    assert count == 30


def test_register_tools_http_count():
    mcp = PrefectFastMCP("probe")
    count = register_tools(mcp, _fake_tools(), transport="http")
    assert count == 31


def test_unknown_transport_rejected():
    mcp = PrefectFastMCP("probe")
    with pytest.raises(ValueError):
        register_tools(mcp, _fake_tools(), transport="grpc")
    assert len(mcp._tool_manager._tools) == 0


def test_transport_exclusive_registration():
    stdio_mcp = SDKFastMCP("probe-stdio")
    register_tools(stdio_mcp, _fake_tools(), transport="stdio")
    assert "health_check" in stdio_mcp._tool_manager._tools
    assert "test_connection" not in stdio_mcp._tool_manager._tools

    http_mcp = PrefectFastMCP("probe-http")
    register_tools(http_mcp, _fake_tools(), transport="http")
    assert "test_connection" in http_mcp._tool_manager._tools
    assert "health_check" not in http_mcp._tool_manager._tools


def test_private_tool_manager_path_exists_on_both_fastmcp_classes():
    """CI guard: both FastMCP classes still expose _tool_manager._tools.

    This private path is used ONLY by the tests below (for .fn access) --
    registry.py itself no longer depends on it. An SDK rename must fail
    LOUDLY here instead of scattering AttributeErrors across the dispatch
    tests further down this file.
    """
    for cls in (SDKFastMCP, PrefectFastMCP):
        inst = cls("guard-probe")
        assert hasattr(inst, "_tool_manager")
        assert hasattr(inst._tool_manager, "_tools")


# --- Group 2: direct dispatch proofs (.fn(), exact target + arg shape) -----


def test_stdio_create_address_object_dispatches_to_payload_method():
    mcp = SDKFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="stdio")

    fn = mcp._tool_manager._tools["create_address_object"].fn
    fn(device_id="d", address_data={"name": "a"})

    fake_tools.network_tools.create_address_object_from_payload.assert_called_once_with(
        "d", {"name": "a"}, None
    )


def test_http_create_address_object_dispatches_to_individual_field_method():
    mcp = PrefectFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="http")

    fn = mcp._tool_manager._tools["create_address_object"].fn
    fn(device_id="d", name="a", address_type="ipmask", address="10.0.0.0/24")

    fake_tools.network_tools.create_address_object.assert_called_once_with(
        "d", "a", "ipmask", "10.0.0.0/24", None
    )


def test_stdio_create_service_object_dispatches_to_payload_method():
    mcp = SDKFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="stdio")

    fn = mcp._tool_manager._tools["create_service_object"].fn
    fn(device_id="d", service_data={"name": "s", "protocol": "TCP"})

    fake_tools.network_tools.create_service_object_from_payload.assert_called_once_with(
        "d", {"name": "s", "protocol": "TCP"}, None
    )


def test_http_create_service_object_dispatches_to_individual_field_method():
    mcp = PrefectFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="http")

    fn = mcp._tool_manager._tools["create_service_object"].fn
    fn(device_id="d", name="s", service_type="TCP", protocol="TCP", port="80")

    fake_tools.network_tools.create_service_object.assert_called_once_with(
        "d", "s", "TCP", "TCP", "80", None
    )


def test_stdio_create_static_route_dispatches_to_payload_method():
    mcp = SDKFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="stdio")

    fn = mcp._tool_manager._tools["create_static_route"].fn
    fn(device_id="d", route_data={"dst": "10.0.0.0/24", "gateway": "10.0.0.1"})

    fake_tools.routing_tools.create_static_route_from_payload.assert_called_once_with(
        "d", {"dst": "10.0.0.0/24", "gateway": "10.0.0.1"}, None
    )


def test_http_create_static_route_dispatches_to_individual_field_method():
    mcp = PrefectFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="http")

    fn = mcp._tool_manager._tools["create_static_route"].fn
    fn(device_id="d", dst="10.0.0.0/24", gateway="10.0.0.1")

    fake_tools.routing_tools.create_static_route.assert_called_once_with(
        "d", "10.0.0.0/24", "10.0.0.1", None, None
    )


# --- Group 3: protocol-level invocation (real MCP call path) ---------------


def test_protocol_sync_tool_via_sdk_call_tool():
    mcp = SDKFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="stdio")

    result = asyncio.run(mcp.call_tool("list_devices", {}))
    content = _unwrap(result)

    assert content[0].text == "SENTINEL-list_devices"
    fake_tools.device_tools.list_devices.assert_called_once()


def test_protocol_sync_tool_via_fastmcp_client():
    mcp = PrefectFastMCP("probe")
    fake_tools = _fake_tools()
    register_tools(mcp, fake_tools, transport="http")

    async def _call():
        async with Client(mcp) as client:
            return await client.call_tool("list_devices", {})

    result = asyncio.run(_call())

    assert result.content[0].text == "SENTINEL-list_devices"
    fake_tools.device_tools.list_devices.assert_called_once()


def test_protocol_async_tool_both_engines():
    # SDK engine (stdio)
    sdk_mcp = SDKFastMCP("probe-stdio")
    sdk_fake = _fake_tools()
    register_tools(sdk_mcp, sdk_fake, transport="stdio")

    sdk_result = asyncio.run(
        sdk_mcp.call_tool("get_firewall_policy_detail", {"device_id": "d", "policy_id": "1"})
    )
    sdk_content = _unwrap(sdk_result)
    assert sdk_content[0].text == "SENTINEL-async"
    sdk_fake.firewall_tools.get_policy_detail_async.assert_awaited_once_with("d", "1", None)

    # fastmcp engine (http)
    http_mcp = PrefectFastMCP("probe-http")
    http_fake = _fake_tools()
    register_tools(http_mcp, http_fake, transport="http")

    async def _call():
        async with Client(http_mcp) as client:
            return await client.call_tool(
                "get_firewall_policy_detail", {"device_id": "d", "policy_id": "1"}
            )

    http_result = asyncio.run(_call())
    assert http_result.content[0].text == "SENTINEL-async"
    http_fake.firewall_tools.get_policy_detail_async.assert_awaited_once_with("d", "1", None)


def test_protocol_divergent_create_both_engines():
    # stdio: dict payload dispatches to the _from_payload method
    sdk_mcp = SDKFastMCP("probe-stdio")
    sdk_fake = _fake_tools()
    register_tools(sdk_mcp, sdk_fake, transport="stdio")

    sdk_result = asyncio.run(
        sdk_mcp.call_tool(
            "create_address_object", {"device_id": "d", "address_data": {"name": "a"}}
        )
    )
    sdk_content = _unwrap(sdk_result)
    assert sdk_content[0].text == "SENTINEL-payload"
    sdk_fake.network_tools.create_address_object_from_payload.assert_called_once_with(
        "d", {"name": "a"}, None
    )
    sdk_fake.network_tools.create_address_object.assert_not_called()

    # http: individual fields dispatch to the individual-field method
    http_mcp = PrefectFastMCP("probe-http")
    http_fake = _fake_tools()
    register_tools(http_mcp, http_fake, transport="http")

    async def _call():
        async with Client(http_mcp) as client:
            return await client.call_tool(
                "create_address_object",
                {
                    "device_id": "d",
                    "name": "a",
                    "address_type": "ipmask",
                    "address": "10.0.0.0/24",
                },
            )

    http_result = asyncio.run(_call())
    assert http_result.content[0].text == "SENTINEL-fields"
    http_fake.network_tools.create_address_object.assert_called_once_with(
        "d", "a", "ipmask", "10.0.0.0/24", None
    )
    http_fake.network_tools.create_address_object_from_payload.assert_not_called()
