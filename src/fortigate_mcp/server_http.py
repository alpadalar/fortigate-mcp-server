"""
HTTP-based MCP server implementation for FortiGate MCP.

This module provides an HTTP transport layer for the MCP server,
supporting HTTP transport for web-based integrations and external access.
"""

import logging
import json
import os
import sys
import signal
from typing import Optional
from datetime import datetime

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools

logger = logging.getLogger("fortigate-mcp.http")

class FortiGateMCPHTTPServer:
    """
    HTTP-based MCP server for FortiGate management.
    
    This server supports:
    - HTTP transport for web integration
    - CORS for browser access
    - Authentication (optional)
    - Rate limiting
    """
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8814,
                 path: str = "/fortigate-mcp"):
        """
        Initialize the HTTP MCP server.
        
        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        if not FASTMCP_AVAILABLE:
            raise RuntimeError("FastMCP is not available. Please install fastmcp package.")
            
        # Load and validate configuration
        self.config = load_config(config_path)
        
        # Setup logging
        self.logger = setup_logging(self.config.logging)
        
        self.host = host
        self.port = port
        self.path = path
        
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
        
        # Initialize FastMCP
        self.mcp = FastMCP("FortiGateMCP-HTTP")
        
        # Setup tools
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools with appropriate descriptions."""
        
        # Device tools
        @self.mcp.tool(description="List all registered FortiGate devices")
        async def list_devices():
            return await self.device_tools.list_devices()

        @self.mcp.tool(description="Get device system status")
        async def get_device_status(device_id: str):
            return await self.device_tools.get_device_status(device_id)

        @self.mcp.tool(description="Test device connection")
        async def test_device_connection(device_id: str):
            return await self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description="Discover device VDOMs")
        async def discover_vdoms(device_id: str):
            return await self.device_tools.discover_vdoms(device_id)

        @self.mcp.tool(description="Add a new FortiGate device")
        async def add_device(device_id: str, host: str, port: int = 443,
                      username: Optional[str] = None, password: Optional[str] = None,
                      api_token: Optional[str] = None, vdom: str = "root",
                      verify_ssl: bool = False, timeout: int = 30):
            return await self.device_tools.add_device(device_id, host, port, username, password,
                                              api_token, vdom, verify_ssl, timeout)

        @self.mcp.tool(description="Remove a FortiGate device")
        async def remove_device(device_id: str):
            return await self.device_tools.remove_device(device_id)

        # Firewall tools
        @self.mcp.tool(description="List firewall policies")
        async def list_firewall_policies(device_id: str, vdom: Optional[str] = None):
            return await self.firewall_tools.list_policies(device_id, vdom)

        @self.mcp.tool(description="Create firewall policy")
        async def create_firewall_policy(device_id: str, policy_data: dict, vdom: Optional[str] = None):
            return await self.firewall_tools.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="Update firewall policy")
        async def update_firewall_policy(device_id: str, policy_id: str, policy_data: dict, vdom: Optional[str] = None):
            return await self.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(device_id: str, policy_id: str, vdom: Optional[str] = None):
            return await self.firewall_tools.get_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="Delete firewall policy")
        async def delete_firewall_policy(device_id: str, policy_id: str, vdom: Optional[str] = None):
            return await self.firewall_tools.delete_policy(device_id, policy_id, vdom)

        # Network tools
        @self.mcp.tool(description="List address objects")
        async def list_address_objects(device_id: str, vdom: Optional[str] = None):
            return await self.network_tools.list_address_objects(device_id, vdom)

        @self.mcp.tool(description="Create address object")
        async def create_address_object(device_id: str, name: str, address_type: str, address: str, vdom: Optional[str] = None):
            return await self.network_tools.create_address_object(device_id, name, address_type, address, vdom)

        @self.mcp.tool(description="List service objects")
        async def list_service_objects(device_id: str, vdom: Optional[str] = None):
            return await self.network_tools.list_service_objects(device_id, vdom)

        @self.mcp.tool(description="Create service object")
        async def create_service_object(device_id: str, name: str, service_type: str, protocol: str,
                                port: Optional[str] = None, vdom: Optional[str] = None):
            return await self.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom)

        # Routing tools
        @self.mcp.tool(description="List static routes")
        async def list_static_routes(device_id: str, vdom: Optional[str] = None):
            return await self.routing_tools.list_static_routes(device_id, vdom)

        @self.mcp.tool(description="Create static route")
        async def create_static_route(device_id: str, dst: str, gateway: str, device: Optional[str] = None, vdom: Optional[str] = None):
            return await self.routing_tools.create_static_route(device_id, dst, gateway, device, vdom)

        @self.mcp.tool(description="Get routing table")
        async def get_routing_table(device_id: str, vdom: Optional[str] = None):
            return await self.routing_tools.get_routing_table(device_id, vdom)

        @self.mcp.tool(description="List network interfaces")
        async def list_interfaces(device_id: str, vdom: Optional[str] = None):
            return await self.routing_tools.list_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get interface status")
        async def get_interface_status(device_id: str, interface_name: str, vdom: Optional[str] = None):
            return await self.routing_tools.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description="Update static route")
        async def update_static_route(device_id: str, route_id: str, route_data: dict, vdom: Optional[str] = None):
            return await self.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description="Delete static route")
        async def delete_static_route(device_id: str, route_id: str, vdom: Optional[str] = None):
            return await self.routing_tools.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description="Get static route detail")
        async def get_static_route_detail(device_id: str, route_id: str, vdom: Optional[str] = None):
            return await self.routing_tools.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description="List virtual IPs")
        async def list_virtual_ips(device_id: str, vdom: Optional[str] = None):
            return await self.virtual_ip_tools.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description="Create virtual IP")
        async def create_virtual_ip(device_id: str, name: str, extip: str, mappedip: str,
                             extintf: str, portforward: str = "disable",
                             protocol: str = "tcp", extport: Optional[str] = None,
                             mappedport: Optional[str] = None, vdom: Optional[str] = None):
            return await self.virtual_ip_tools.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description="Update virtual IP")
        async def update_virtual_ip(device_id: str, name: str, vip_data: dict, vdom: Optional[str] = None):
            return await self.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description="Get virtual IP detail")
        async def get_virtual_ip_detail(device_id: str, name: str, vdom: Optional[str] = None):
            return await self.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description="Delete virtual IP")
        async def delete_virtual_ip(device_id: str, name: str, vdom: Optional[str] = None):
            return await self.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

        # System tools
        @self.mcp.tool(description="Test FortiGate connection")
        async def test_connection():
            try:
                devices = self.fortigate_manager.list_devices()
                connection_results = {}

                for device_id in devices:
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = await api_client.test_connection()
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

                return self._format_response({
                    "devices": connection_results,
                    "total_devices": len(devices)
                }, "test_connection")
            except Exception as e:
                return self._format_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection")

        @self.mcp.tool(description="Health check for FortiGate MCP server")
        async def health():
            health_info = {
                "status": "ok",
                "server": "FortiGateMCP-HTTP",
                "timestamp": datetime.now().isoformat(),
                "registered_devices": len(self.fortigate_manager.devices),
                "device_connections": {}
            }

            # Test device connections
            try:
                devices = self.fortigate_manager.list_devices()
                for device_id in devices:
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = await api_client.test_connection()
                        health_info["device_connections"][device_id] = "connected" if success else "disconnected"
                    except Exception as e:
                        health_info["device_connections"][device_id] = "error"
                        health_info["status"] = "degraded"
            except Exception as e:
                health_info["status"] = "error"
                health_info["error"] = str(e)

            return self._format_response(health_info, "health")

    def _format_response(self, data, operation: str = "operation"):
        """Format response data for MCP."""
        from mcp.types import TextContent as Content
        
        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def run(self) -> None:
        """
        Start the HTTP MCP server.
        
        Runs the server with HTTP transport on the configured
        host and port.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting FortiGate MCP HTTP server on {self.host}:{self.port}{self.path}")
            self.logger.info(f"Registered devices: {len(self.fortigate_manager.devices)}")
            
            # Run with FastMCP's built-in HTTP transport
            self.mcp.run(
                transport="http",
                host=self.host,
                port=self.port,
                path=self.path
            )
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            sys.exit(1)


class FortiGateMCPCommand:
    """
    Command runner for FortiGate MCP HTTP server.
    
    This class can be used as a standalone command runner.
    """
    
    help = "FortiGate MCP HTTP Server"
    
    def __init__(self):
        self.server = None
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8814,
            help='Server port (default: 8814)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/fortigate-mcp',
            help='HTTP path (default: /fortigate-mcp)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('FORTIGATE_MCP_CONFIG')
        
        self.server = FortiGateMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8814),
            path=options.get('path', '/fortigate-mcp')
        )
        
        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FortiGate MCP HTTP Server')
    command = FortiGateMCPCommand()
    command.add_arguments(parser)
    
    args = parser.parse_args()
    options = vars(args)
    
    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
