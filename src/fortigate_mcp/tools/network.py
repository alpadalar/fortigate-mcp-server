"""Network object management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class NetworkTools(FortiGateTool):
    """Tools for FortiGate network object management."""
    
    def list_address_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            addresses_data = api_client.get_address_objects(vdom=vdom)
            return self._format_response(addresses_data, "address_objects")
        except Exception as e:
            return self._handle_error("list address objects", device_id, e)
    
    def create_address_object(self, device_id: str, name: str, address_type: str, address: str, 
                             vdom: Optional[str] = None) -> List[Content]:
        """Create address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_type=address_type, address=address)
            
            address_data = {
                "name": name,
                "type": address_type,
                "subnet": address
            }
            
            api_client = self._get_device_api(device_id)
            result = api_client.create_address_object(address_data, vdom=vdom)
            return self._format_operation_result("create address object", device_id, True, f"Address object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create address object", device_id, e)
    
    def list_service_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            services_data = api_client.get_service_objects(vdom=vdom)
            return self._format_response(services_data, "service_objects")
        except Exception as e:
            return self._handle_error("list service objects", device_id, e)
    
    def create_service_object(self, device_id: str, name: str, service_type: str, protocol: str, 
                             port: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_type=service_type, protocol=protocol)
            
            service_data = {
                "name": name,
                "type": service_type,
                "protocol": protocol
            }
            
            if port:
                service_data["port"] = port
            
            api_client = self._get_device_api(device_id)
            result = api_client.create_service_object(service_data, vdom=vdom)
            return self._format_operation_result("create service object", device_id, True, f"Service object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create service object", device_id, e)
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for network tools.
        
        Returns:
            Dictionary with schema information
        """
        return {
            "name": "network_tools",
            "description": "FortiGate network object management tools",
            "operations": [
                {
                    "name": "list_address_objects",
                    "description": "List address objects",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_address_object",
                    "description": "Create address object",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "address_type", "type": "string", "required": True},
                        {"name": "address", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_service_objects",
                    "description": "List service objects",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_service_object",
                    "description": "Create service object",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                        {"name": "service_type", "type": "string", "required": True},
                        {"name": "protocol", "type": "string", "required": True},
                        {"name": "port", "type": "string", "required": False},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
