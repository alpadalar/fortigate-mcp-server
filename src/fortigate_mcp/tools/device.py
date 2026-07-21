"""
Device management tools for FortiGate MCP.

This module provides MCP tools for managing FortiGate devices:
- Device registration and removal
- Connection testing
- System status monitoring
- VDOM discovery
"""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.logging import register_secrets
from ..validation import validate_object_name

class DeviceTools(FortiGateTool):
    """Tools for FortiGate device management."""
    
    def list_devices(self) -> List[Content]:
        """List all registered FortiGate devices.
        
        Returns:
            List of Content objects with device information
        """
        try:
            devices_info = self.fortigate_manager.list_devices()
            return self._format_response(devices_info, "devices")
        except Exception as e:
            return self._handle_error("list devices", "all", e)
    
    def get_device_status(self, device_id: str) -> List[Content]:
        """Get system status for a specific device.
        
        Args:
            device_id: Target device identifier
            
        Returns:
            List of Content objects with device status
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            status_data = api_client.get_system_status()
            return self._format_response((device_id, status_data), "device_status")

        except Exception as e:
            return self._handle_error("get device status", device_id, e)
    
    def test_device_connection(self, device_id: str) -> List[Content]:
        """Test connection to a specific device.
        
        Args:
            device_id: Target device identifier
            
        Returns:
            List of Content objects with connection test result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            
            success = api_client.test_connection()
            return self._format_connection_test(device_id, success)
            
        except Exception as e:
            return self._format_connection_test(device_id, False, str(e))
    
    def discover_vdoms(self, device_id: str) -> List[Content]:
        """Discover VDOMs on a FortiGate device.
        
        Args:
            device_id: Target device identifier
            
        Returns:
            List of Content objects with VDOM information
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            
            vdoms_data = api_client.get_vdoms()
            return self._format_response(vdoms_data, "vdoms")
            
        except Exception as e:
            return self._handle_error("discover VDOMs", device_id, e)
    
    def add_device(self, device_id: str, host: str, port: int = 443,
                   username: Optional[str] = None, password: Optional[str] = None,
                   api_token: Optional[str] = None, vdom: str = "root",
                   verify_ssl: bool = False, timeout: int = 30) -> List[Content]:
        """Add a new FortiGate device.
        
        Args:
            device_id: Unique identifier for the device
            host: Device IP address or hostname
            port: HTTPS port (default: 443)
            username: Username for authentication
            password: Password for authentication
            api_token: API token for authentication (preferred)
            vdom: Virtual Domain name (default: "root")
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            
        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_required_params(device_id=device_id, host=host)

            # device_id has no charset/length limit at the MCP schema level
            # and is interpolated raw into log lines for the lifetime of the
            # device (core/fortigate.py's "Initialized/Added/Removed device"
            # lines, plus every _handle_error call for this device). Reject
            # it here -- before it is ever stored -- so a CRLF/control-
            # character device_id can never become part of persistent state
            # that gets logged repeatedly.
            validate_object_name(device_id, "device_id")

            # Check if device already exists
            if device_id in self.fortigate_manager.devices:
                return self._format_operation_result(
                    "add device", device_id, False, 
                    error=f"Device '{device_id}' already exists"
                )
            
            # Runtime-added device credentials must enter the redaction
            # registry BEFORE the client is constructed below -- client
            # construction logs an init line, and this is the single
            # dispatch path both the stdio and HTTP transports' add_device
            # tools route through, so this one call site covers both.
            register_secrets({api_token, password})

            # Add device to manager
            self.fortigate_manager.add_device(
                device_id=device_id,
                host=host,
                port=port,
                username=username,
                password=password,
                api_token=api_token,
                vdom=vdom,
                verify_ssl=verify_ssl,
                timeout=timeout
            )
            
            return self._format_operation_result(
                "add device", device_id, True,
                f"Device '{device_id}' added successfully"
            )
            
        except Exception as e:
            return self._handle_error("add device", device_id, e)
    
    def remove_device(self, device_id: str) -> List[Content]:
        """Remove a FortiGate device.
        
        Args:
            device_id: Device identifier to remove
            
        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)

            # Intentionally does NOT deregister this device's credentials
            # from the redaction filter: a removed device's token must
            # stay redacted in any later log line (e.g. a stale reference
            # elsewhere still logging it). Retention is strictly safer
            # than premature deregistration -- do not "fix" this.
            self.fortigate_manager.remove_device(device_id)
            
            return self._format_operation_result(
                "remove device", device_id, True,
                f"Device '{device_id}' removed successfully"
            )
            
        except Exception as e:
            return self._handle_error("remove device", device_id, e)
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for device tools.
        
        Returns:
            Dictionary with schema information
        """
        return {
            "name": "device_tools",
            "description": "FortiGate device management tools",
            "operations": [
                {
                    "name": "list_devices",
                    "description": "List all registered FortiGate devices",
                    "parameters": []
                },
                {
                    "name": "get_device_status",
                    "description": "Get system status for a specific device",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True}
                    ]
                },
                {
                    "name": "test_device_connection",
                    "description": "Test connection to a specific device",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True}
                    ]
                },
                {
                    "name": "discover_vdoms",
                    "description": "Discover VDOMs on a FortiGate device",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True}
                    ]
                },
                {
                    "name": "add_device",
                    "description": "Add a new FortiGate device",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "host", "type": "string", "required": True},
                        {"name": "port", "type": "integer", "required": False, "default": 443},
                        {"name": "username", "type": "string", "required": False},
                        {"name": "password", "type": "string", "required": False},
                        {"name": "api_token", "type": "string", "required": False},
                        {"name": "vdom", "type": "string", "required": False, "default": "root"},
                        {"name": "verify_ssl", "type": "boolean", "required": False, "default": False},
                        {"name": "timeout", "type": "integer", "required": False, "default": 30}
                    ]
                },
                {
                    "name": "remove_device",
                    "description": "Remove a FortiGate device",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True}
                    ]
                }
            ]
        }
