"""
Tests for the stdio MCP server (FortiGateMCPServer).

Covers regression fixes for the known stdio-server bugs cataloged in
Phase 1 (Stability Baseline): construction NameError, sync/async
dispatch mismatches, and dict-payload forwarding.
"""

import asyncio

import pytest
from fastmcp import Client
from mcp.types import TextContent
from unittest.mock import MagicMock

from src.fortigate_mcp.core.fortigate import FortiGateAPI
from src.fortigate_mcp.server import FortiGateMCPServer


async def _list_via_client(server):
    """List tools through a real in-memory fastmcp.Client MCP session."""
    async with Client(server.mcp) as client:
        return await client.list_tools()


async def _call_via_client(server, tool_name, args):
    """Call a tool through a real in-memory fastmcp.Client MCP session.

    Preferred over direct ``.fn()`` calls or the SDK's ``call_tool`` --
    this exercises the real protocol path (initialize, argument validation,
    dispatch, result conversion), the exact layer the historical
    async/sync bug lived in.
    """
    async with Client(server.mcp) as client:
        return await client.call_tool(tool_name, args)


def test_stdio_server_constructs_successfully(tmp_config_path):
    """FortiGateMCPServer constructs without exception and registers 30 tools."""
    server = FortiGateMCPServer(tmp_config_path)

    assert server is not None
    tools = asyncio.run(_list_via_client(server))
    assert len(tools) == 31


# Matrix of (tool_name, tools_attr, method_name, args) covering every one of the
# 27 sync-forwarding wrappers registered by registry.register_tools() for
# transport="stdio" (excludes get_firewall_policy_detail, which stays
# genuinely async, and the 2 stdio-only system tools).
# Each entry is proven independently by monkeypatching the target Tools-layer
# method with a sentinel-returning mock and dispatching the stdio tool call.
TOOL_CALL_MATRIX = [
    # Device management tools
    ("list_devices", "device_tools", "list_devices", {}),
    ("get_device_status", "device_tools", "get_device_status", {"device_id": "probe"}),
    ("test_device_connection", "device_tools", "test_device_connection", {"device_id": "probe"}),
    ("discover_vdoms", "device_tools", "discover_vdoms", {"device_id": "probe"}),
    ("add_device", "device_tools", "add_device", {"device_id": "probe2", "host": "198.51.100.20"}),
    ("remove_device", "device_tools", "remove_device", {"device_id": "probe"}),
    # Firewall policy tools
    ("list_firewall_policies", "firewall_tools", "list_policies", {"device_id": "probe"}),
    (
        "create_firewall_policy",
        "firewall_tools",
        "create_policy",
        {"device_id": "probe", "policy_data": {"name": "p1"}},
    ),
    (
        "update_firewall_policy",
        "firewall_tools",
        "update_policy",
        {"device_id": "probe", "policy_id": "1", "policy_data": {"name": "p1"}},
    ),
    ("delete_firewall_policy", "firewall_tools", "delete_policy", {"device_id": "probe", "policy_id": "1"}),
    # Network object tools
    ("list_address_objects", "network_tools", "list_address_objects", {"device_id": "probe"}),
    (
        "create_address_object",
        "network_tools",
        "create_address_object_from_payload",
        {"device_id": "probe", "address_data": {"name": "a1", "type": "ipmask", "subnet": "10.0.0.0/24"}},
    ),
    ("list_service_objects", "network_tools", "list_service_objects", {"device_id": "probe"}),
    (
        "create_service_object",
        "network_tools",
        "create_service_object_from_payload",
        {"device_id": "probe", "service_data": {"name": "s1", "protocol": "TCP"}},
    ),
    # Routing tools
    ("list_static_routes", "routing_tools", "list_static_routes", {"device_id": "probe"}),
    (
        "create_static_route",
        "routing_tools",
        "create_static_route_from_payload",
        {"device_id": "probe", "route_data": {"dst": "10.0.0.0/24", "gateway": "10.0.0.1"}},
    ),
    ("get_routing_table", "routing_tools", "get_routing_table", {"device_id": "probe"}),
    ("list_interfaces", "routing_tools", "list_interfaces", {"device_id": "probe"}),
    (
        "get_interface_status",
        "routing_tools",
        "get_interface_status",
        {"device_id": "probe", "interface_name": "port1"},
    ),
    (
        "update_static_route",
        "routing_tools",
        "update_static_route",
        {"device_id": "probe", "route_id": "1", "route_data": {"dst": "10.0.0.0/24"}},
    ),
    ("delete_static_route", "routing_tools", "delete_static_route", {"device_id": "probe", "route_id": "1"}),
    ("get_static_route_detail", "routing_tools", "get_static_route_detail", {"device_id": "probe", "route_id": "1"}),
    # Virtual IP tools
    ("list_virtual_ips", "virtual_ip_tools", "list_virtual_ips", {"device_id": "probe"}),
    (
        "create_virtual_ip",
        "virtual_ip_tools",
        "create_virtual_ip",
        {
            "device_id": "probe",
            "name": "vip1",
            "extip": "198.51.100.30",
            "mappedip": "10.0.0.5",
            "extintf": "port1",
        },
    ),
    (
        "update_virtual_ip",
        "virtual_ip_tools",
        "update_virtual_ip",
        {"device_id": "probe", "name": "vip1", "vip_data": {"extip": "198.51.100.30"}},
    ),
    ("get_virtual_ip_detail", "virtual_ip_tools", "get_virtual_ip_detail", {"device_id": "probe", "name": "vip1"}),
    ("delete_virtual_ip", "virtual_ip_tools", "delete_virtual_ip", {"device_id": "probe", "name": "vip1"}),
]


@pytest.mark.parametrize("tool_name, tools_attr, method_name, args", TOOL_CALL_MATRIX)
def test_all_sync_wrappers_dispatch(tmp_config_path, tool_name, tools_attr, method_name, args, monkeypatch):
    """Every sync-forwarding stdio wrapper dispatches to its Tools-layer method.

    Proven behaviorally (not by grep): the target Tools-layer method is
    replaced with a sentinel-returning mock, the stdio tool is dispatched
    through the real MCP call path, and the sentinel text plus the exactly-
    once call are asserted.

    This matrix proves dispatch wiring, not gating semantics (owned by
    tests/test_write_gate.py) -- writes are unconditionally enabled here so
    write/destructive entries in the matrix reach their mocked target too.
    """
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server = FortiGateMCPServer(tmp_config_path)
    tools_instance = getattr(server, tools_attr)
    mock_method = MagicMock(return_value=[TextContent(type="text", text=f"SENTINEL-{tool_name}")])
    monkeypatch.setattr(tools_instance, method_name, mock_method)

    result = asyncio.run(_call_via_client(server, tool_name, args))

    content = result.content
    assert content[0].text == f"SENTINEL-{tool_name}"
    mock_method.assert_called_once()


def test_get_firewall_policy_detail_still_async(tmp_config_path):
    """get_firewall_policy_detail remains the one genuinely-async wrapper."""
    server = FortiGateMCPServer(tmp_config_path)
    mock_api = MagicMock(spec=FortiGateAPI)
    mock_api.device_id = "default"
    mock_api.get_firewall_policy_detail.return_value = {
        "results": {
            "policyid": 1,
            "name": "Test-Policy",
            "srcintf": [{"name": "port1"}],
            "dstintf": [{"name": "port2"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "action": "accept",
            "status": "enable",
        }
    }
    mock_api.get_address_objects.return_value = {"results": [{"name": "all", "subnet": "0.0.0.0 0.0.0.0"}]}
    mock_api.get_service_objects.return_value = {"results": [{"name": "ALL", "protocol": "TCP/UDP/SCTP"}]}
    server.fortigate_manager.devices["default"] = mock_api

    result = asyncio.run(
        _call_via_client(server, "get_firewall_policy_detail", {"device_id": "default", "policy_id": "1"})
    )

    content = result.content
    assert "Test-Policy" in content[0].text


def _server_with_mocked_device(tmp_config_path):
    """Build a server with a MagicMock(spec=FortiGateAPI) device named 'probe'."""
    server = FortiGateMCPServer(tmp_config_path)
    mock_api = MagicMock(spec=FortiGateAPI)
    mock_api.device_id = "probe"
    mock_api.create_static_route.return_value = {"status": "success"}
    mock_api.create_address_object.return_value = {"status": "success"}
    mock_api.create_service_object.return_value = {"status": "success"}
    server.fortigate_manager.devices["probe"] = mock_api
    return server, mock_api


def test_route_payload_preserves_optional_fields(tmp_config_path, monkeypatch):
    """create_static_route forwards distance/comment, not just dst/gateway."""
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server, mock_api = _server_with_mocked_device(tmp_config_path)
    route_data = {
        "dst": "10.0.0.0/24",
        "gateway": "10.0.0.1",
        "device": "port1",
        "distance": 10,
        "comment": "test route",
    }

    asyncio.run(_call_via_client(server, "create_static_route", {"device_id": "probe", "route_data": route_data}))

    mock_api.create_static_route.assert_called_once_with(route_data, vdom=None)


def test_address_payload_ipmask_variant(tmp_config_path, monkeypatch):
    """create_address_object forwards the full ipmask payload unchanged."""
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server, mock_api = _server_with_mocked_device(tmp_config_path)
    address_data = {"name": "addr1", "type": "ipmask", "subnet": "10.0.0.0/24", "comment": "c"}

    asyncio.run(_call_via_client(server, "create_address_object", {"device_id": "probe", "address_data": address_data}))

    mock_api.create_address_object.assert_called_once_with(address_data, vdom=None)


def test_address_payload_iprange_variant(tmp_config_path, monkeypatch):
    """create_address_object forwards start-ip AND end-ip for the iprange variant."""
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server, mock_api = _server_with_mocked_device(tmp_config_path)
    address_data = {"name": "addr2", "type": "iprange", "start-ip": "10.0.0.10", "end-ip": "10.0.0.20"}

    asyncio.run(_call_via_client(server, "create_address_object", {"device_id": "probe", "address_data": address_data}))

    mock_api.create_address_object.assert_called_once_with(address_data, vdom=None)


def test_address_payload_fqdn_variant(tmp_config_path, monkeypatch):
    """create_address_object keeps the fqdn key as-is, never remapped to subnet."""
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server, mock_api = _server_with_mocked_device(tmp_config_path)
    address_data = {"name": "addr3", "type": "fqdn", "fqdn": "example.com"}

    asyncio.run(_call_via_client(server, "create_address_object", {"device_id": "probe", "address_data": address_data}))

    mock_api.create_address_object.assert_called_once_with(address_data, vdom=None)
    called_payload = mock_api.create_address_object.call_args.args[0]
    assert "subnet" not in called_payload
    assert called_payload["fqdn"] == "example.com"


def test_service_payload_tcp_variant(tmp_config_path, monkeypatch):
    """create_service_object forwards tcp-portrange and comment intact."""
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server, mock_api = _server_with_mocked_device(tmp_config_path)
    service_data = {"name": "svc1", "protocol": "TCP", "tcp-portrange": "8080", "comment": "c"}

    asyncio.run(_call_via_client(server, "create_service_object", {"device_id": "probe", "service_data": service_data}))

    mock_api.create_service_object.assert_called_once_with(service_data, vdom=None)


def test_service_payload_udp_variant(tmp_config_path, monkeypatch):
    """create_service_object forwards udp-portrange intact, not remapped to a generic 'port'."""
    monkeypatch.setenv("FORTIGATE_MCP_ALLOW_WRITES", "1")
    server, mock_api = _server_with_mocked_device(tmp_config_path)
    service_data = {"name": "svc2", "protocol": "UDP", "udp-portrange": "514"}

    asyncio.run(_call_via_client(server, "create_service_object", {"device_id": "probe", "service_data": service_data}))

    mock_api.create_service_object.assert_called_once_with(service_data, vdom=None)
    called_payload = mock_api.create_service_object.call_args.args[0]
    assert "port" not in called_payload
    assert called_payload["udp-portrange"] == "514"
