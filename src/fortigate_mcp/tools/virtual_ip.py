"""Virtual IP management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class VirtualIPTools(FortiGateTool):
    """Tools for FortiGate Virtual IP management."""
    
    def list_virtual_ips(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List virtual IPs."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            vips_data = api_client.get_virtual_ips(vdom=vdom)
            return self._format_response(vips_data, "virtual_ips")
        except Exception as e:
            return self._handle_error("list virtual IPs", device_id, e)
    
    def create_virtual_ip(self, device_id: str, name: str, extip: str, mappedip: str, 
                         extintf: str, portforward: str = "disable", 
                         protocol: str = "tcp", extport: Optional[str] = None,
                         mappedport: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create virtual IP."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, extip=extip, mappedip=mappedip, extintf=extintf)
            
            vip_data = {
                "name": name,
                "extip": extip,
                "mappedip": mappedip,
                "extintf": extintf,
                "portforward": portforward
            }
            
            if protocol:
                vip_data["protocol"] = protocol
            
            if extport:
                vip_data["extport"] = extport
            
            if mappedport:
                vip_data["mappedport"] = mappedport
            
            api_client = self._get_device_api(device_id)
            result = api_client.create_virtual_ip(vip_data, vdom=vdom)
            return self._format_operation_result("create virtual IP", device_id, True, f"Virtual IP '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create virtual IP", device_id, e)
    
    def update_virtual_ip(self, device_id: str, name: str, vip_data: Dict[str, Any], 
                         vdom: Optional[str] = None) -> List[Content]:
        """Update virtual IP."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            
            api_client = self._get_device_api(device_id)
            result = api_client.update_virtual_ip(name, vip_data, vdom=vdom)
            return self._format_operation_result("update virtual IP", device_id, True, f"Virtual IP '{name}' updated successfully")
        except Exception as e:
            return self._handle_error("update virtual IP", device_id, e)
    
    def get_virtual_ip_detail(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Get virtual IP detail."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            
            api_client = self._get_device_api(device_id)
            vip_data = api_client.get_virtual_ip_detail(name, vdom=vdom)
            return self._format_response(vip_data, "virtual_ip_detail")
        except Exception as e:
            return self._handle_error("get virtual IP detail", device_id, e)
    
    def delete_virtual_ip(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Delete virtual IP."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            
            api_client = self._get_device_api(device_id)
            result = api_client.delete_virtual_ip(name, vdom=vdom)
            return self._format_operation_result("delete virtual IP", device_id, True, f"Virtual IP '{name}' deleted successfully")
        except Exception as e:
            return self._handle_error("delete virtual IP", device_id, e)
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for Virtual IP tools."""
        return {
            "name": "virtual_ip_tools",
            "description": "FortiGate Virtual IP management tools",
            "operations": [
                {
                    "name": "list_virtual_ips",
                    "description": "List virtual IPs",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_virtual_ip",
                    "description": "Create virtual IP",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "extip", "type": "string", "required": True},
                        {"name": "mappedip", "type": "string", "required": True},
                        {"name": "extintf", "type": "string", "required": True},
                        {"name": "portforward", "type": "string", "required": False},
                        {"name": "protocol", "type": "string", "required": False},
                        {"name": "extport", "type": "string", "required": False},
                        {"name": "mappedport", "type": "string", "required": False},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "update_virtual_ip",
                    "description": "Update virtual IP",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "vip_data", "type": "object", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_virtual_ip_detail",
                    "description": "Get virtual IP detail",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_virtual_ip",
                    "description": "Delete virtual IP",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
