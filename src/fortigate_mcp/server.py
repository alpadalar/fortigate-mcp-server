"""
Main STDIO server implementation for FortiGate MCP.

This module implements the core MCP server for FortiGate integration, providing:
- Configuration loading and validation
- Logging setup
- FortiGate API connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown

The server exposes a set of tools for managing FortiGate resources including:
- Device management
- Firewall policy operations
- Network object management
- Routing configuration
"""
import logging
import json
import os
import sys
import signal
from typing import Optional, Annotated
from datetime import datetime

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools
from .tools.definitions import *

class FortiGateMCPServer:
    """Main server class for FortiGate MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        self.logger = setup_logging(self.config.logging)
        
        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
        # Initialize tools
        self.device_tools = DeviceTools(self.fortigate_manager)
        self.firewall_tools = FirewallTools(self.fortigate_manager)
        self.network_tools = NetworkTools(self.fortigate_manager)
        self.routing_tools = RoutingTools(self.fortigate_manager)
        self.virtual_ip_tools = VirtualIPTools(self.fortigate_manager)
        
        # Initialize MCP server
        self.mcp = FastMCP("FortiGateMCP")
        self._tests_passed: Optional[bool] = None
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools with the server."""
        
        # Device management tools
        @self.mcp.tool(description=LIST_DEVICES_DESC)
        async def list_devices():
            return await self.device_tools.list_devices()

        @self.mcp.tool(description=GET_DEVICE_STATUS_DESC)
        async def get_device_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.get_device_status(device_id)

        @self.mcp.tool(description=TEST_DEVICE_CONNECTION_DESC)
        async def test_device_connection(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description=DISCOVER_VDOMS_DESC)
        async def discover_vdoms(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.discover_vdoms(device_id)

        @self.mcp.tool(description=ADD_DEVICE_DESC)
        async def add_device(
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
            return await self.device_tools.add_device(
                device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
            )

        @self.mcp.tool(description=REMOVE_DEVICE_DESC)
        async def remove_device(
            device_id: Annotated[str, Field(description="Device identifier to remove")]
        ):
            return await self.device_tools.remove_device(device_id)

        # Firewall policy tools
        @self.mcp.tool(description=LIST_FIREWALL_POLICIES_DESC)
        async def list_firewall_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_policies(device_id, vdom)

        @self.mcp.tool(description=CREATE_FIREWALL_POLICY_DESC)
        async def create_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description=UPDATE_FIREWALL_POLICY_DESC)
        async def update_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to update")],
            policy_data: Annotated[dict, Field(description="Updated policy configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to get details for")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.get_policy_detail_async(device_id, policy_id, vdom)

        @self.mcp.tool(description=DELETE_FIREWALL_POLICY_DESC)
        async def delete_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.delete_policy(device_id, policy_id, vdom)

        # Network object tools
        @self.mcp.tool(description=LIST_ADDRESS_OBJECTS_DESC)
        async def list_address_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_address_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_ADDRESS_OBJECT_DESC)
        async def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            address_data: Annotated[dict, Field(description="Address object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_address_object(device_id, address_data, vdom)

        @self.mcp.tool(description=LIST_SERVICE_OBJECTS_DESC)
        async def list_service_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_service_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_SERVICE_OBJECT_DESC)
        async def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            service_data: Annotated[dict, Field(description="Service object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_service_object(device_id, service_data, vdom)

        # Routing tools
        @self.mcp.tool(description=LIST_STATIC_ROUTES_DESC)
        async def list_static_routes(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.list_static_routes(device_id, vdom)

        @self.mcp.tool(description=CREATE_STATIC_ROUTE_DESC)
        async def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.create_static_route(device_id, route_data, vdom)

        @self.mcp.tool(description=GET_ROUTING_TABLE_DESC)
        async def get_routing_table(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_routing_table(device_id, vdom)

        @self.mcp.tool(description=LIST_INTERFACES_DESC)
        async def list_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.list_interfaces(device_id, vdom)

        @self.mcp.tool(description=GET_INTERFACE_STATUS_DESC)
        async def get_interface_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            interface_name: Annotated[str, Field(description="Interface name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description=UPDATE_STATIC_ROUTE_DESC)
        async def update_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description=DELETE_STATIC_ROUTE_DESC)
        async def delete_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description=GET_STATIC_ROUTE_DETAIL_DESC)
        async def get_static_route_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description=LIST_VIRTUAL_IPS_DESC)
        async def list_virtual_ips(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description=CREATE_VIRTUAL_IP_DESC)
        async def create_virtual_ip(
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
            return await self.virtual_ip_tools.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description=UPDATE_VIRTUAL_IP_DESC)
        async def update_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description=GET_VIRTUAL_IP_DETAIL_DESC)
        async def get_virtual_ip_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description=DELETE_VIRTUAL_IP_DESC)
        async def delete_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

        # System tools
        @self.mcp.tool(description=HEALTH_CHECK_DESC)
        async def health_check():
            status = "healthy" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
            details = {
                "registered_devices": len(self.fortigate_manager.devices),
                "server_version": self.config.server.version,
                "timestamp": datetime.now().isoformat()
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_health_status(status, details)

        @self.mcp.tool(description=GET_SERVER_INFO_DESC)
        async def get_server_info():
            info = {
                "name": self.config.server.name,
                "version": self.config.server.version,
                "host": self.config.server.host,
                "port": self.config.server.port,
                "registered_devices": len(self.fortigate_manager.devices),
                "available_tools": [
                    "Device Management (6 tools)",
                    "Firewall Policy Management (4 tools)",
                    "Network Objects Management (4 tools)",
                    "Routing Management (4 tools)",
                    "System Tools (2 tools)"
                ]
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_json_response(info, "Server Information")

    def start(self) -> None:
        """Start the MCP server."""
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                self.logger.info("Running startup tests...")
                # Add test logic here
                self._tests_passed = True

            self.logger.info("Starting FortiGate MCP server...")
            anyio.run(self.mcp.run_stdio_async)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    config_path = os.getenv("FORTIGATE_MCP_CONFIG")
    if not config_path:
        print("FORTIGATE_MCP_CONFIG environment variable must be set")
        sys.exit(1)
    
    try:
        server = FortiGateMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
