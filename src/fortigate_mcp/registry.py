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
import asyncio
import functools
import json
import os
from datetime import datetime
from typing import Annotated, Any, Callable, List, Literal, Optional, cast

from fastmcp.exceptions import ToolError
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
    LIST_SECURITY_PROFILES_DESC,
    LIST_ADMINS_DESC,
    GET_SSLVPN_SETTINGS_DESC,
    LIST_LOCAL_IN_POLICIES_DESC,
)


RISK_CLASSIFICATION = {
    # read -- list/get/discover/test/health/schema/server-info, never gated
    "list_devices": "read",
    "get_device_status": "read",
    "test_device_connection": "read",
    "discover_vdoms": "read",
    "list_firewall_policies": "read",
    "get_firewall_policy_detail": "read",
    "list_address_objects": "read",
    "list_service_objects": "read",
    "list_static_routes": "read",
    "get_routing_table": "read",
    "list_interfaces": "read",
    "get_interface_status": "read",
    "get_static_route_detail": "read",
    "list_virtual_ips": "read",
    "get_virtual_ip_detail": "read",
    "health_check": "read",
    "get_server_info": "read",
    "test_connection": "read",
    "health": "read",
    "get_schema_info": "read",
    # write -- create_*/update_*/add_device
    "add_device": "write",
    "create_firewall_policy": "write",
    "update_firewall_policy": "write",
    "create_address_object": "write",
    "create_service_object": "write",
    "update_static_route": "write",
    "create_static_route": "write",
    "create_virtual_ip": "write",
    "update_virtual_ip": "write",
    # destructive -- delete_*/remove_device
    "remove_device": "destructive",
    "delete_firewall_policy": "destructive",
    "delete_static_route": "destructive",
    "delete_virtual_ip": "destructive",
    # v1.1 visibility tools (Phase 10)
    "list_security_profiles": "read",
    "list_admins": "read",
    "get_sslvpn_settings": "read",
    "list_local_in_policies": "read",
}
"""Canonical per-tool risk classification (SEC-02).

Single source of truth for BOTH the dispatch-layer read-only gate (SEC-01,
``_tool()``'s ``_gate`` helper below) and Phase 5's SECURITY.md tool-risk
table. Covers all 33 unique tool names registered across transports;
completeness is enforced by ``tests/test_write_gate.py``. An unclassified
name is a registration-time KeyError (see ``_gate``), not a silent gap.
"""


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

    def _writes_allowed() -> bool:
        """Read config + env fresh on EVERY call -- never cached at
        import/registration time, so a test's or operator's override
        always takes effect immediately. Mirrors server.py:90's
        RUN_TESTS_ON_START truthy-parsing convention verbatim for
        FORTIGATE_MCP_ALLOW_WRITES.
        """
        if tools.config.server.allow_writes:
            return True
        return os.getenv("FORTIGATE_MCP_ALLOW_WRITES", "0").lower() in ("1", "true", "yes", "on")

    def _gate(fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a write/destructive tool closure with the SEC-01
        read-only-by-default gate. Looks up ``RISK_CLASSIFICATION[fn.__name__]``
        -- an uncaught KeyError here is intentional: an unclassified tool
        must crash registration loudly instead of shipping ungated. Returns
        ``fn`` unchanged for read-classified tools (never gated).

        Denial raises ``ToolError`` -- a protocol-level tool error
        (``CallToolResult.is_error=True``), not ordinary Content, so MCP
        clients can distinguish it mechanically from tool output.
        """
        risk_class = RISK_CLASSIFICATION[fn.__name__]
        if risk_class == "read":
            return fn

        denial_message = (
            f"{fn.__name__} is a {risk_class} tool and this server is running "
            "in read-only mode; set server.allow_writes=true or "
            "FORTIGATE_MCP_ALLOW_WRITES=1 to enable it"
        )

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if not _writes_allowed():
                    raise ToolError(denial_message)
                return await fn(*args, **kwargs)
            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not _writes_allowed():
                raise ToolError(denial_message)
            return fn(*args, **kwargs)
        return sync_wrapper

    def _tool(description: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            registered.append(fn.__name__)
            # Gate is the INNER wrap, mcp.tool() stays OUTER: FastMCP
            # introspects whatever _gate(fn) returns, and functools.wraps
            # keeps that introspectable signature byte-identical to `fn`'s
            # for read-classified tools (_gate returns fn unchanged) and
            # gated tools alike -- this is what keeps the golden schema
            # byte-frozen (SEC-01 must never change tools/list surface).
            return cast(Callable[..., Any], mcp.tool(description=description)(_gate(fn)))
        return decorator

    # --- (A) 24 unconditionally-registered, schema-identical tools ---------

    @_tool(LIST_DEVICES_DESC)
    def list_devices() -> List[Content]:
        return cast(List[Content], tools.device_tools.list_devices())

    @_tool(GET_DEVICE_STATUS_DESC)
    def get_device_status(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.get_device_status(device_id))

    @_tool(TEST_DEVICE_CONNECTION_DESC)
    def test_device_connection(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.test_device_connection(device_id))

    @_tool(DISCOVER_VDOMS_DESC)
    def discover_vdoms(
        device_id: Annotated[str, Field(description="FortiGate device identifier")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.discover_vdoms(device_id))

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
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.add_device(
            device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
        ))

    @_tool(REMOVE_DEVICE_DESC)
    def remove_device(
        device_id: Annotated[str, Field(description="Device identifier to remove")]
    ) -> List[Content]:
        return cast(List[Content], tools.device_tools.remove_device(device_id))

    @_tool(LIST_FIREWALL_POLICIES_DESC)
    def list_firewall_policies(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.list_policies(device_id, vdom))

    @_tool(CREATE_FIREWALL_POLICY_DESC)
    def create_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.create_policy(device_id, policy_data, vdom))

    @_tool(UPDATE_FIREWALL_POLICY_DESC)
    def update_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to update")],
        policy_data: Annotated[dict, Field(description="Updated policy configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom))

    @_tool(DELETE_FIREWALL_POLICY_DESC)
    def delete_firewall_policy(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to delete")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.firewall_tools.delete_policy(device_id, policy_id, vdom))

    @_tool(LIST_ADDRESS_OBJECTS_DESC)
    def list_address_objects(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.list_address_objects(device_id, vdom))

    @_tool(LIST_SERVICE_OBJECTS_DESC)
    def list_service_objects(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.network_tools.list_service_objects(device_id, vdom))

    @_tool(LIST_STATIC_ROUTES_DESC)
    def list_static_routes(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.list_static_routes(device_id, vdom))

    @_tool(GET_ROUTING_TABLE_DESC)
    def get_routing_table(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.get_routing_table(device_id, vdom))

    @_tool(LIST_INTERFACES_DESC)
    def list_interfaces(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.list_interfaces(device_id, vdom))

    @_tool(GET_INTERFACE_STATUS_DESC)
    def get_interface_status(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        interface_name: Annotated[str, Field(description="Interface name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.get_interface_status(device_id, interface_name, vdom))

    @_tool(UPDATE_STATIC_ROUTE_DESC)
    def update_static_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        route_data: Annotated[dict, Field(description="Route configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.update_static_route(device_id, route_id, route_data, vdom))

    @_tool(DELETE_STATIC_ROUTE_DESC)
    def delete_static_route(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.delete_static_route(device_id, route_id, vdom))

    @_tool(GET_STATIC_ROUTE_DETAIL_DESC)
    def get_static_route_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        route_id: Annotated[str, Field(description="Route identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.routing_tools.get_static_route_detail(device_id, route_id, vdom))

    @_tool(LIST_VIRTUAL_IPS_DESC)
    def list_virtual_ips(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.list_virtual_ips(device_id, vdom))

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
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.create_virtual_ip(
            device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
        ))

    @_tool(UPDATE_VIRTUAL_IP_DESC)
    def update_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom))

    @_tool(GET_VIRTUAL_IP_DETAIL_DESC)
    def get_virtual_ip_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom))

    @_tool(DELETE_VIRTUAL_IP_DESC)
    def delete_virtual_ip(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        name: Annotated[str, Field(description="Virtual IP name")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom))

    # --- (B) get_firewall_policy_detail: unified to ONE async definition ---
    # firewall.py's sync and async policy-detail method bodies are
    # byte-identical except for the async keyword -- safe to register a
    # single async def for BOTH transports.

    @_tool("Get detailed information for a specific firewall policy")
    async def get_firewall_policy_detail(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        policy_id: Annotated[str, Field(description="Policy ID to get details for")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], await tools.firewall_tools.get_policy_detail_async(device_id, policy_id, vdom))

    # --- (C) 3 divergent create-tools: transport-marked variants -----------
    # Locked CONS-01 decision: dict payload on stdio vs individual fields on
    # HTTP, dispatching to genuinely different Tools-layer methods.

    if transport == "stdio":
        @_tool(CREATE_ADDRESS_OBJECT_DESC)
        def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            address_data: Annotated[dict, Field(description="Address object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_address_object_from_payload(device_id, address_data, vdom))
    else:  # http
        @_tool("Create address object")
        def create_address_object(device_id: str, name: str, address_type: str, address: str, vdom: Optional[str] = None) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_address_object(device_id, name, address_type, address, vdom))

    if transport == "stdio":
        @_tool(CREATE_SERVICE_OBJECT_DESC)
        def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            service_data: Annotated[dict, Field(description="Service object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_service_object_from_payload(device_id, service_data, vdom))
    else:  # http
        @_tool("Create service object")
        def create_service_object(device_id: str, name: str, service_type: str, protocol: str,
                                   port: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
            return cast(List[Content], tools.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom))

    if transport == "stdio":
        @_tool(CREATE_STATIC_ROUTE_DESC)
        def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ) -> List[Content]:
            return cast(List[Content], tools.routing_tools.create_static_route_from_payload(device_id, route_data, vdom))
    else:  # http
        @_tool("Create static route")
        def create_static_route(device_id: str, dst: str, gateway: str, device: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
            return cast(List[Content], tools.routing_tools.create_static_route(device_id, dst, gateway, device, vdom))

    # --- (D) stdio-only: health_check, get_server_info ----------------------

    if transport == "stdio":
        @_tool(HEALTH_CHECK_DESC)
        async def health_check() -> List[Content]:
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
        async def get_server_info() -> List[Content]:
            info = {
                "name": tools.config.server.name,
                "version": tools.config.server.version,
                "host": tools.config.server.host,
                "port": tools.config.server.port,
                "registered_devices": len(tools.fortigate_manager.devices),
                "failed_devices": tools.fortigate_manager.failed_devices,
                # Derived from the registry's own `registered` list (fully
                # populated by the time any tool call executes) -- never a
                # hand-maintained inventory, which drifted to 20 claimed vs
                # 30 registered before this was derived.
                "tool_count": len(registered),
                "available_tools": sorted(registered),
            }
            return FortiGateFormatters.format_json_response(info, "Server Information")

    # --- (E) http-only: test_connection, health, get_schema_info -----------
    # These use the module-level _format_json_response helper (mirroring
    # server_http.py's local self._format_response), not FortiGateFormatters.

    if transport == "http":
        @_tool("Test FortiGate connection")
        def test_connection() -> List[Content]:
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
        def health() -> List[Content]:
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
                    except Exception:
                        health_info["device_connections"][device_id] = "error"
                        health_info["status"] = "degraded"
            except Exception as e:
                health_info["status"] = "error"
                health_info["error"] = str(e)

            return _format_json_response(health_info, "health", logger=getattr(tools, "logger", None))

        @_tool("Get schema information for all available tools")
        def get_schema_info() -> List[Content]:
            schema_info = {
                "server": "FortiGateMCP-HTTP",
                "version": tools.config.server.version,
                "endpoint": f"http://{tools.host}:{tools.port}{tools.path}",
                "tools": {
                    "device_tools": tools.device_tools.get_schema_info(),
                    "firewall_tools": tools.firewall_tools.get_schema_info(),
                    "network_tools": tools.network_tools.get_schema_info(),
                    "routing_tools": tools.routing_tools.get_schema_info(),
                    "virtual_ip_tools": tools.virtual_ip_tools.get_schema_info(),
                    "security_tools": tools.security_tools.get_schema_info(),
                    "admin_tools": tools.admin_tools.get_schema_info()
                }
            }
            return _format_json_response(schema_info, "get_schema_info", logger=getattr(tools, "logger", None))

    # --- (F) v1.1 read-only visibility tools (Phase 10) ---------------------
    # Unconditional -- registered for BOTH transports (VIS-06 requires
    # identical dual-transport registration; do NOT wrap this section in an
    # `if transport == ...:` guard).

    @_tool(LIST_SECURITY_PROFILES_DESC)
    def list_security_profiles(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.security_tools.list_security_profiles(device_id, vdom))

    @_tool(LIST_ADMINS_DESC)
    def list_admins(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.admin_tools.list_admins(device_id, vdom))

    @_tool(GET_SSLVPN_SETTINGS_DESC)
    def get_sslvpn_settings(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.security_tools.get_sslvpn_settings(device_id, vdom))

    @_tool(LIST_LOCAL_IN_POLICIES_DESC)
    def list_local_in_policies(
        device_id: Annotated[str, Field(description="FortiGate device identifier")],
        vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
    ) -> List[Content]:
        return cast(List[Content], tools.security_tools.list_local_in_policies(device_id, vdom))

    return len(registered)
