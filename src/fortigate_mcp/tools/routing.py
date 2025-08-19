"""Routing management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class RoutingTools(FortiGateTool):
    """Tools for FortiGate routing management."""
    
    def list_static_routes(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List static routes."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            routes_data = api_client.get_static_routes(vdom=vdom)
            return self._format_response(routes_data, "static_routes")
        except Exception as e:
            return self._handle_error("list static routes", device_id, e)
    
    def create_static_route(self, device_id: str, dst: str, gateway: str, device: Optional[str] = None, 
                           vdom: Optional[str] = None) -> List[Content]:
        """Create static route."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(dst=dst, gateway=gateway)
            
            route_data = {
                "dst": dst,
                "gateway": gateway
            }
            
            if device:
                route_data["device"] = device
            
            api_client = self._get_device_api(device_id)
            result = api_client.create_static_route(route_data, vdom=vdom)
            return self._format_operation_result("create static route", device_id, True, f"Static route to {dst} created successfully")
        except Exception as e:
            return self._handle_error("create static route", device_id, e)
    
    def get_routing_table(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get routing table."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            routing_data = api_client.get_routing_table(vdom=vdom)
            return self._format_response(routing_data, "routing_table")
        except Exception as e:
            return self._handle_error("get routing table", device_id, e)
    
    def list_interfaces(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List interfaces."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            interfaces_data = api_client.get_interfaces(vdom=vdom)
            return self._format_response(interfaces_data, "interfaces")
        except Exception as e:
            return self._handle_error("list interfaces", device_id, e)
    
    def get_interface_status(self, device_id: str, interface_name: str, vdom: Optional[str] = None) -> List[Content]:
        """Get interface status."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(interface_name=interface_name)
            
            api_client = self._get_device_api(device_id)
            interface_data = api_client.get_interface_status(interface_name, vdom=vdom)
            return self._format_response((interface_name, interface_data), "interface_status")
        except Exception as e:
            return self._handle_error("get interface status", device_id, e)
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for routing tools.
        
        Returns:
            Dictionary with schema information
        """
        return {
            "name": "routing_tools",
            "description": "FortiGate routing management tools",
            "operations": [
                {
                    "name": "list_static_routes",
                    "description": "List static routes",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_static_route",
                    "description": "Create static route",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "dst", "type": "string", "required": True},
                        {"name": "gateway", "type": "string", "required": True},
                        {"name": "device", "type": "string", "required": False},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_routing_table",
                    "description": "Get routing table",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_interfaces",
                    "description": "List interfaces",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_interface_status",
                    "description": "Get interface status",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "interface_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
