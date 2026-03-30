"""Network object management tools for FortiGate MCP."""
from typing import List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class NetworkTools(FortiGateTool):
    """Tools for FortiGate network object management."""

    async def list_address_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            addresses_data = await api_client.get_address_objects(vdom=vdom)
            return self._format_response(addresses_data, "address_objects")
        except Exception as e:
            return self._handle_error("list address objects", device_id, e)

    async def create_address_object(self, device_id: str, name: str, address_type: str, address: str,
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
            await api_client.create_address_object(address_data, vdom=vdom)
            return self._format_operation_result("create address object", device_id, True, f"Address object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create address object", device_id, e)

    async def list_service_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            services_data = await api_client.get_service_objects(vdom=vdom)
            return self._format_response(services_data, "service_objects")
        except Exception as e:
            return self._handle_error("list service objects", device_id, e)

    async def create_service_object(self, device_id: str, name: str, service_type: str, protocol: str,
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
            await api_client.create_service_object(service_data, vdom=vdom)
            return self._format_operation_result("create service object", device_id, True, f"Service object '{name}' created successfully")
        except Exception as e:
            return self._handle_error("create service object", device_id, e)
