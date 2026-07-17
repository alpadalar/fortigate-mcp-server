"""Shared MCP tool registry for FortiGate MCP (CONS-01).

Both the stdio server (server.py) and the HTTP server (server_http.py)
register tools from this single module instead of each hand-duplicating a
~30-tool ``_setup_tools()`` body. 24 of the 33 unique tool names are
schema-identical and share ONE tool definition; ``get_firewall_policy_detail``
is schema-identical but was dispatch-divergent (sync vs async on the same
class) -- it is unified here to a single async definition, verified safe
because FirewallTools' sync and async policy-detail method bodies are
byte-identical except for the ``async`` keyword. 3 create-tools
(``create_address_object``, ``create_service_object``, ``create_static_route``)
have genuinely divergent parameter schemas (dict payload on stdio vs
individual fields on HTTP) and register transport-marked variants -- this is
a locked CONS-01 decision, not an oversight; unifying their signatures is a
contract change deferred to a post-release milestone. 5 tools are
transport-exclusive (``health_check``/``get_server_info`` stdio-only;
``test_connection``/``health``/``get_schema_info`` HTTP-only).

``register_tools`` never constructs a FastMCP instance -- it only decorates
the ``mcp`` object passed in, so it is duck-typed across whichever engine(s)
stdio and HTTP end up on (``mcp.server.fastmcp.FastMCP`` and/or
``fastmcp.FastMCP``).
"""
import json
from datetime import datetime
from typing import Annotated, Any, List, Literal, Optional

from pydantic import Field
from mcp.types import TextContent as Content

from .formatting import FortiGateFormatters
from .tools.definitions import (
    LIST_DEVICES_DESC,
    GET_DEVICE_STATUS_DESC,
    TEST_DEVICE_CONNECTION_DESC,
    ADD_DEVICE_DESC,
    REMOVE_DEVICE_DESC,
    DISCOVER_VDOMS_DESC,
    LIST_FIREWALL_POLICIES_DESC,
    CREATE_FIREWALL_POLICY_DESC,
    UPDATE_FIREWALL_POLICY_DESC,
    DELETE_FIREWALL_POLICY_DESC,
    LIST_ADDRESS_OBJECTS_DESC,
    CREATE_ADDRESS_OBJECT_DESC,
    LIST_SERVICE_OBJECTS_DESC,
    CREATE_SERVICE_OBJECT_DESC,
    LIST_VIRTUAL_IPS_DESC,
    CREATE_VIRTUAL_IP_DESC,
    UPDATE_VIRTUAL_IP_DESC,
    GET_VIRTUAL_IP_DETAIL_DESC,
    DELETE_VIRTUAL_IP_DESC,
    UPDATE_STATIC_ROUTE_DESC,
    DELETE_STATIC_ROUTE_DESC,
    GET_STATIC_ROUTE_DETAIL_DESC,
    LIST_STATIC_ROUTES_DESC,
    CREATE_STATIC_ROUTE_DESC,
    GET_ROUTING_TABLE_DESC,
    LIST_INTERFACES_DESC,
    GET_INTERFACE_STATUS_DESC,
    HEALTH_CHECK_DESC,
    GET_SERVER_INFO_DESC,
)


def _format_json_response(data: Any, operation: str = "operation", logger: Any = None) -> List[Content]:
    """Module-level replacement for server_http.py's ``self._format_response``.

    Used only by the 3 HTTP-only tools (test_connection/health/get_schema_info)
    so the registry's duck-type contract for ``tools`` never requires a
    ``_format_response`` method.
    """
    try:
        if isinstance(data, (dict, list)):
            formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
        else:
            formatted_data = str(data)

        return [Content(type="text", text=formatted_data)]

    except Exception as e:
        if logger is not None:
            logger.error(f"Error formatting response for {operation}: {e}")
        error_response = {
            "error": f"Failed to format response: {str(e)}",
            "operation": operation,
        }
        return [Content(type="text", text=json.dumps(error_response, indent=2))]


def register_tools(mcp: Any, tools: Any, transport: Literal["stdio", "http"]) -> int:
    """Register every FortiGate MCP tool on ``mcp`` for the given ``transport``.

    ``transport`` is an explicit parameter, not type-introspection on ``mcp``
    (two structurally similar FastMCP classes make isinstance-checks fragile).
    Unknown transport values are rejected BEFORE any registration, so an
    invalid value can never produce a malformed partial surface. The returned
    count is maintained locally (via the ``registered`` list below), not by
    inspecting either engine's private tool-manager internals.
    """
    if transport not in ("stdio", "http"):
        raise ValueError(f"unknown transport: {transport!r} (expected 'stdio' or 'http')")

    registered: list = []

    def _tool(description):
        def decorator(fn):
            registered.append(fn.__name__)
            return mcp.tool(description=description)(fn)
        return decorator

    # --- (A) 24 unconditionally-registered, schema-identical tools ---------

    @_tool(LIST_DEVICES_DESC)
    def list_devices():
        return tools.device_tools.list_devices()

    @_tool(GET_DEVICE_STATUS_DESC)
    def get_device_status(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ):
        return tools.device_tools.get_device_status(device_id)

    @_tool(TEST_DEVICE_CONNECTION_DESC)
    def test_device_connection(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ):
        return tools.device_tools.test_device_connection(device_id)

    @_tool(DISCOVER_VDOMS_DESC)
    def discover_vdoms(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ):
        return tools.device_tools.discover_vdoms(device_id)

    @_tool(ADD_DEVICE_DESC)
    def add_device(
        device_id: Annotated[str, Field(description="Unique device identifier")],
        host: Annotated[str, Field(description="FortiGate IP address or hostname")],
        port: Annotated[int, Field(description="HTTPS port", default=443)] = 443,
        username: Annotated[Optional[str], Field(description="Username", default=None)] = None,
        password: Annotated[Optional[str], Field(description="Password", default=None)] = None,
        api_token: Annotated[Optional[str], Field(description="API token", default=None)] = None,
        vdom: Annotated[str, Field(description="Virtual Domain", default="root")] = "root",
        verify_ssl: Annotated[bool, Field(description="Verify SSL", default=False)] = False,
        timeout: Annotated[int, Field(description="Timeout in seconds", default=30)] = 30
    ):
        return tools.device_tools.add_device(
            device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
        )

    @_tool(REMOVE_DEVICE_DESC)
    def remove_device(
        device_id: Annotated[str, Field(description="Device identifier to remove")]
    ):
        return tools.device_tools.remove_device(device_id)

    @_tool(LIST_FIREWALL_POLICIES_DESC)
    def list_firewall_policies(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.firewall_tools.list_policies(device_id, vdom)

    @_tool(CREATE_FIREWALL_POLICY_DESC)
    def create_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.firewall_tools.create_policy(device_id, policy_data, vdom)

    @_tool(UPDATE_FIREWALL_POLICY_DESC)
    def update_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to update")],
        policy_data: Annotated[dict, Field(description="Updated policy configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

    @_tool(DELETE_FIREWALL_POLICY_DESC)
    def delete_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to delete")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.firewall_tools.delete_policy(device_id, policy_id, vdom)

    @_tool(LIST_ADDRESS_OBJECTS_DESC)
    def list_address_objects(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.network_tools.list_address_objects(device_id, vdom)

    @_tool(LIST_SERVICE_OBJECTS_DESC)
    def list_service_objects(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.network_tools.list_service_objects(device_id, vdom)

    @_tool(LIST_STATIC_ROUTES_DESC)
    def list_static_routes(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.list_static_routes(device_id, vdom)

    @_tool(GET_ROUTING_TABLE_DESC)
    def get_routing_table(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.get_routing_table(device_id, vdom)

    @_tool(LIST_INTERFACES_DESC)
    def list_interfaces(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.list_interfaces(device_id, vdom)

    @_tool(GET_INTERFACE_STATUS_DESC)
    def get_interface_status(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        interface_name: Annotated[str, Field(description="Interface name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.get_interface_status(device_id, interface_name, vdom)

    @_tool(UPDATE_STATIC_ROUTE_DESC)
    def update_static_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        route_data: Annotated[dict, Field(description="Route configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

    @_tool(DELETE_STATIC_ROUTE_DESC)
    def delete_static_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.delete_static_route(device_id, route_id, vdom)

    @_tool(GET_STATIC_ROUTE_DETAIL_DESC)
    def get_static_route_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.routing_tools.get_static_route_detail(device_id, route_id, vdom)

    @_tool(LIST_VIRTUAL_IPS_DESC)
    def list_virtual_ips(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.virtual_ip_tools.list_virtual_ips(device_id, vdom)

    @_tool(CREATE_VIRTUAL_IP_DESC)
    def create_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        extip: Annotated[str, Field(description="External IP address")],
        mappedip: Annotated[str, Field(description="Mapped internal IP address")],
        extintf: Annotated[str, Field(description="External interface name")],
        portforward: Annotated[str, Field(description="Enable/disable port forwarding", default="disable")] = "disable",
        protocol: Annotated[str, Field(description="Protocol type", default="tcp")] = "tcp",
        extport: Annotated[Optional[str], Field(description="External port")] = None,
        mappedport: Annotated[Optional[str], Field(description="Mapped port")] = None,
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.virtual_ip_tools.create_virtual_ip(
            device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
        )

    @_tool(UPDATE_VIRTUAL_IP_DESC)
    def update_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

    @_tool(GET_VIRTUAL_IP_DETAIL_DESC)
    def get_virtual_ip_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

    @_tool(DELETE_VIRTUAL_IP_DESC)
    def delete_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return tools.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

    # --- (B) get_firewall_policy_detail: unified to ONE async definition ---
    # firewall.py's sync and async policy-detail method bodies are
    # byte-identical except for the async keyword -- safe to register a
    # single async def for BOTH transports.

    @_tool("Get detailed information for a specific firewall policy")
    async def get_firewall_policy_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to get details for")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ):
        return await tools.firewall_tools.get_policy_detail_async(device_id, policy_id, vdom)

    # --- (C) 3 divergent create-tools: transport-marked variants -----------
    # Locked CONS-01 decision: dict payload on stdio vs individual fields on
    # HTTP, dispatching to genuinely different Tools-layer methods.

    if transport == "stdio":
        @_tool(CREATE_ADDRESS_OBJECT_DESC)
        def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            address_data: Annotated[dict, Field(description="Address object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return tools.network_tools.create_address_object_from_payload(device_id, address_data, vdom)
    else:  # http
        @_tool("Create address object")
        def create_address_object(device_id: str, name: str, address_type: str, address: str, vdom: Optional[str] = None):
            return tools.network_tools.create_address_object(device_id, name, address_type, address, vdom)

    if transport == "stdio":
        @_tool(CREATE_SERVICE_OBJECT_DESC)
        def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            service_data: Annotated[dict, Field(description="Service object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return tools.network_tools.create_service_object_from_payload(device_id, service_data, vdom)
    else:  # http
        @_tool("Create service object")
        def create_service_object(device_id: str, name: str, service_type: str, protocol: str,
                                   port: Optional[str] = None, vdom: Optional[str] = None):
            return tools.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom)

    if transport == "stdio":
        @_tool(CREATE_STATIC_ROUTE_DESC)
        def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return tools.routing_tools.create_static_route_from_payload(device_id, route_data, vdom)
    else:  # http
        @_tool("Create static route")
        def create_static_route(device_id: str, dst: str, gateway: str, device: Optional[str] = None, vdom: Optional[str] = None):
            return tools.routing_tools.create_static_route(device_id, dst, gateway, device, vdom)

    # --- (D) stdio-only: health_check, get_server_info ----------------------

    if transport == "stdio":
        @_tool(HEALTH_CHECK_DESC)
        async def health_check():
            failed_devices = tools.fortigate_manager.failed_devices
            if failed_devices:
                status = "degraded"
            elif tools._tests_passed is True:
                status = "healthy"
            elif tools._tests_passed is False:
                status = "degraded"
            else:
                status = "unknown"
            details = {
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": failed_devices,
                "server_version": tools.config.server.version,
                "timestamp": datetime.now().isoformat()
            }
            return FortiGateFormatters.format_health_status(status, details)

        @_tool(GET_SERVER_INFO_DESC)
        async def get_server_info():
            info = {
                "name": tools.config.server.name,
                "version": tools.config.server.version,
                "host": tools.config.server.host,
                "port": tools.config.server.port,
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": tools.fortigate_manager.failed_devices,
                "available_tools": [
                    "Device Management (6 tools)",
                    "Firewall Policy Management (4 tools)",
                    "Network Objects Management (4 tools)",
                    "Routing Management (4 tools)",
                    "System Tools (2 tools)"
                ]
            }
            return FortiGateFormatters.format_json_response(info, "Server Information")

    # --- (E) http-only: test_connection, health, get_schema_info -----------
    # These use the module-level _format_json_response helper (mirroring
    # server_http.py's local self._format_response), not FortiGateFormatters.

    if transport == "http":
        @_tool("Test FortiGate connection")
        def test_connection():
            try:
                devices = tools.fortigate_manager.list_devices()
                connection_results = {}

                for device_id in devices:
                    try:
                        api_client = tools.fortigate_manager.get_device(device_id)
                        success = api_client.test_connection()
                        connection_results[device_id] = {
                            "connected": success,
                            "status": "connected" if success else "failed"
                        }
                    except Exception as e:
                        connection_results[device_id] = {
                            "connected": False,
                            "status": "error",
                            "error": str(e)
                        }

                return _format_json_response({
                    "devices": connection_results,
                    "total_devices": len(devices)
                }, "test_connection", logger=getattr(tools, "logger", None))
            except Exception as e:
                return _format_json_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection", logger=getattr(tools, "logger", None))

        @_tool("Health check for FortiGate MCP server")
        def health():
            failed_devices = tools.fortigate_manager.failed_devices
            health_info = {
                "status": "degraded" if failed_devices else "ok",
                "server": "FortiGateMCP-HTTP",
                "timestamp": datetime.now().isoformat(),
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": failed_devices,
                "device_connections": {}
            }

            try:
                devices = tools.fortigate_manager.list_devices()
                for device_id in devices:
                    try:
                        api_client = tools.fortigate_manager.get_device(device_id)
                        success = api_client.test_connection()
                        health_info["device_connections"][device_id] = "connected" if success else "disconnected"
                    except Exception as e:
                        health_info["device_connections"][device_id] = "error"
                        health_info["status"] = "degraded"
            except Exception as e:
                health_info["status"] = "error"
                health_info["error"] = str(e)

            return _format_json_response(health_info, "health", logger=getattr(tools, "logger", None))

        @_tool("Get schema information for all available tools")
        def get_schema_info():
            schema_info = {
                "server": "FortiGateMCP-HTTP",
                "version": "0.1.0",
                "endpoint": f"http://{tools.host}:{tools.port}{tools.path}",
                "tools": {
                    "device_tools": tools.device_tools.get_schema_info(),
                    "firewall_tools": tools.firewall_tools.get_schema_info(),
                    "network_tools": tools.network_tools.get_schema_info(),
                    "routing_tools": tools.routing_tools.get_schema_info(),
                    "virtual_ip_tools": tools.virtual_ip_tools.get_schema_info()
                }
            }
            return _format_json_response(schema_info, "get_schema_info", logger=getattr(tools, "logger", None))

    return len(registered)
