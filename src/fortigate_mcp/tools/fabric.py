"""
Security Fabric tools for FortiGate MCP.

This module provides MCP tools for Security Fabric management:
- Fabric topology discovery
- Fabric member listing
- HA cluster status
- SDN connector management
"""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.fortigate import FortiGateAPIError


class FabricTools(FortiGateTool):
    """Tools for FortiGate Security Fabric management."""

    def get_security_fabric_config(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get Security Fabric (CSF) configuration.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with fabric configuration
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            fabric_data = api_client.get_security_fabric_config(vdom)
            return self._format_response(fabric_data, "security_fabric_config")

        except Exception as e:
            return self._handle_error("get security fabric config", device_id, e)

    def get_security_fabric_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get Security Fabric runtime status and topology.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with fabric status
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            status_data = api_client.get_security_fabric_status(vdom)
            return self._format_response(status_data, "security_fabric_status")

        except Exception as e:
            return self._handle_error("get security fabric status", device_id, e)

    def get_fabric_devices(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get list of fabric devices/connectors.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with fabric devices
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            devices_data = api_client.get_fabric_devices(vdom)
            return self._format_response(devices_data, "fabric_devices")

        except Exception as e:
            return self._handle_error("get fabric devices", device_id, e)

    def get_fabric_connectors(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get SDN and cloud fabric connector configuration.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with fabric connectors
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            connectors_data = api_client.get_fabric_connectors(vdom)
            return self._format_response(connectors_data, "fabric_connectors")

        except Exception as e:
            return self._handle_error("get fabric connectors", device_id, e)

    def get_ha_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get High Availability (HA) cluster status.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with HA status
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            ha_data = api_client.get_ha_status(vdom)
            return self._format_response(ha_data, "ha_status")

        except Exception as e:
            return self._handle_error("get HA status", device_id, e)

    def get_ha_config(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get High Availability (HA) configuration.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with HA configuration
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            ha_config = api_client.get_ha_config(vdom)
            return self._format_response(ha_config, "ha_config")

        except Exception as e:
            return self._handle_error("get HA config", device_id, e)

    def get_fabric_topology(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get comprehensive Security Fabric topology.

        This combines fabric configuration, status, and device information
        to provide a complete view of the Security Fabric.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with complete fabric topology
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            # Gather all fabric information
            topology = {
                "device_id": device_id,
                "fabric_config": None,
                "fabric_status": None,
                "fabric_devices": None,
                "ha_config": None,
                "ha_status": None,
                "errors": []
            }

            # Get fabric configuration
            try:
                topology["fabric_config"] = api_client.get_security_fabric_config(vdom)
            except Exception as e:
                topology["errors"].append(f"fabric_config: {str(e)}")

            # Get fabric status
            try:
                topology["fabric_status"] = api_client.get_security_fabric_status(vdom)
            except Exception as e:
                topology["errors"].append(f"fabric_status: {str(e)}")

            # Get fabric devices
            try:
                topology["fabric_devices"] = api_client.get_fabric_devices(vdom)
            except Exception as e:
                topology["errors"].append(f"fabric_devices: {str(e)}")

            # Get HA configuration
            try:
                topology["ha_config"] = api_client.get_ha_config(vdom)
            except Exception as e:
                topology["errors"].append(f"ha_config: {str(e)}")

            # Get HA status
            try:
                topology["ha_status"] = api_client.get_ha_status(vdom)
            except Exception as e:
                topology["errors"].append(f"ha_status: {str(e)}")

            return self._format_response(topology, "fabric_topology")

        except Exception as e:
            return self._handle_error("get fabric topology", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for fabric tools.

        Returns:
            Dictionary with schema information
        """
        return {
            "name": "fabric_tools",
            "description": "FortiGate Security Fabric management tools",
            "operations": [
                {
                    "name": "get_security_fabric_config",
                    "description": "Get Security Fabric configuration",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_security_fabric_status",
                    "description": "Get Security Fabric runtime status",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_fabric_devices",
                    "description": "Get list of fabric devices",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_fabric_connectors",
                    "description": "Get SDN/cloud fabric connectors",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_ha_status",
                    "description": "Get HA cluster status",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_ha_config",
                    "description": "Get HA configuration",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_fabric_topology",
                    "description": "Get comprehensive Security Fabric topology",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
