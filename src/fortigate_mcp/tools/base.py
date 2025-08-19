"""
Base classes and utilities for FortiGate MCP tools.

This module provides the foundation for all FortiGate MCP tools, including:
- Base tool class with common functionality
- Response formatting utilities
- Error handling mechanisms
- Logging setup

All tool implementations inherit from the FortiGateTool base class to ensure
consistent behavior and error handling across the MCP server.
"""
import logging
import time
from typing import Any, Dict, List, Optional, Union
from mcp.types import TextContent as Content
from ..core.fortigate import FortiGateAPI, FortiGateAPIError, FortiGateManager
from ..core.logging import get_logger, log_tool_call
from ..formatting import FortiGateFormatters

class FortiGateTool:
    """Base class for FortiGate MCP tools.
    
    This class provides common functionality used by all FortiGate tool implementations:
    - FortiGate device access through manager
    - Standardized logging
    - Response formatting
    - Error handling
    - Performance monitoring
    
    All tool classes should inherit from this base class to ensure consistent
    behavior and error handling across the MCP server.
    """

    def __init__(self, fortigate_manager: FortiGateManager):
        """Initialize the tool.

        Args:
            fortigate_manager: FortiGateManager instance for device access
        """
        self.fortigate_manager = fortigate_manager
        self.logger = get_logger(f"tools.{self.__class__.__name__.lower()}")

    def _get_device_api(self, device_id: str) -> FortiGateAPI:
        """Get FortiGate API client for a device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            FortiGateAPI client instance
            
        Raises:
            ValueError: If device not found
        """
        try:
            return self.fortigate_manager.get_device(device_id)
        except ValueError as e:
            self.logger.error(f"Device {device_id} not found")
            raise ValueError(f"Device '{device_id}' not found. Available devices: {list(self.fortigate_manager.devices.keys())}")

    def _format_response(self, data: Any, resource_type: Optional[str] = None, **kwargs) -> List[Content]:
        """Format response data into MCP content using formatters.

        This method handles formatting of various FortiGate resource types into
        consistent MCP content responses. It uses specialized formatters for
        different resource types and falls back to JSON formatting for unknown types.

        Args:
            data: Raw data from FortiGate API to format
            resource_type: Type of resource for formatter selection. Valid types:
                         'devices', 'device_status', 'firewall_policies', 
                         'address_objects', 'service_objects', 'static_routes',
                         'interfaces', 'vdoms'

        Returns:
            List of Content objects formatted according to resource type
        """
        if resource_type == "devices":
            # Handle list of device IDs (new format) vs dict of device info (old format)
            if isinstance(data, list):
                # New format: list of device IDs
                if not data:
                    return [Content(type="text", text="📱 No FortiGate devices configured")]
                
                lines = ["📱 **Registered FortiGate Devices**", ""]
                for device_id in data:
                    lines.append(f"  • {device_id}")
                return [Content(type="text", text="\n".join(lines))]
            else:
                # Old format: dict of device info
                return FortiGateFormatters.format_devices(data)
        elif resource_type == "device_status":
            # For device_status, data should be a tuple of (device_id, status_dict)
            if isinstance(data, tuple) and len(data) == 2:
                return FortiGateFormatters.format_device_status(data[0], data[1])
            else:
                return FortiGateFormatters.format_device_status("unknown", data)
        elif resource_type == "firewall_policies":
            return FortiGateFormatters.format_firewall_policies(data)
        elif resource_type == "firewall_policy_detail":
            device_id = kwargs.get('device_id', 'unknown')
            address_objects = kwargs.get('address_objects')
            service_objects = kwargs.get('service_objects')
            return FortiGateFormatters.format_firewall_policy_detail(
                data, device_id, address_objects, service_objects
            )
        elif resource_type == "address_objects":
            return FortiGateFormatters.format_address_objects(data)
        elif resource_type == "service_objects":
            return FortiGateFormatters.format_service_objects(data)
        elif resource_type == "static_routes":
            return FortiGateFormatters.format_static_routes(data)
        elif resource_type == "interfaces":
            return FortiGateFormatters.format_interfaces(data)
        elif resource_type == "vdoms":
            return FortiGateFormatters.format_vdoms(data)
        else:
            # Fallback to JSON formatting for unknown types
            return FortiGateFormatters.format_json_response(data)

    def _handle_error(self, operation: str, device_id: str, error: Exception) -> List[Content]:
        """Handle and log errors from FortiGate operations.

        Provides standardized error handling across all tools by:
        - Logging errors with appropriate context
        - Categorizing errors into specific exception types
        - Converting FortiGate-specific errors into user-friendly messages
        - Returning formatted error content

        Args:
            operation: Description of the operation that failed
            device_id: Target device identifier
            error: The exception that occurred during the operation

        Returns:
            List of Content objects with formatted error message
        """
        error_msg = str(error)
        self.logger.error(f"Failed to {operation} on device {device_id}: {error_msg}")

        # Categorize common error types
        if isinstance(error, FortiGateAPIError):
            if error.status_code == 401:
                error_msg = "Authentication failed. Check device credentials."
            elif error.status_code == 403:
                error_msg = "Permission denied. Insufficient privileges for this operation."
            elif error.status_code == 404:
                error_msg = "Resource not found. The specified item may not exist."
            elif error.status_code == 500:
                error_msg = "FortiGate internal server error. Check device status."
        elif "not found" in error_msg.lower():
            error_msg = "Resource not found. The specified item may not exist."
        elif "permission denied" in error_msg.lower():
            error_msg = "Permission denied. Check user privileges."
        elif "timeout" in error_msg.lower():
            error_msg = "Operation timed out. Check network connectivity."
        elif "connection" in error_msg.lower():
            error_msg = "Connection failed. Check device network settings."
        
        return FortiGateFormatters.format_error(error_msg, device_id, operation)

    async def _execute_with_logging(self, operation: str, device_id: str, 
                                   func, *args, **kwargs) -> List[Content]:
        """Execute a function with logging and error handling.
        
        Args:
            operation: Operation description for logging
            device_id: Target device ID
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function
            
        Returns:
            List of Content objects with operation result
        """
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            log_tool_call(self.logger, operation, device_id, True, duration_ms)
            return result
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_tool_call(self.logger, operation, device_id, False, duration_ms, str(e))
            return self._handle_error(operation, device_id, e)

    def _validate_device_exists(self, device_id: str) -> None:
        """Validate that a device exists.
        
        Args:
            device_id: Device identifier to validate
            
        Raises:
            ValueError: If device doesn't exist
        """
        if device_id not in self.fortigate_manager.devices:
            available = list(self.fortigate_manager.devices.keys())
            raise ValueError(f"Device '{device_id}' not found. Available devices: {available}")

    def _validate_required_params(self, **params) -> None:
        """Validate that required parameters are provided.
        
        Args:
            **params: Parameters to validate
            
        Raises:
            ValueError: If any required parameter is missing
        """
        for name, value in params.items():
            if value is None or (isinstance(value, str) and not value.strip()):
                raise ValueError(f"Parameter '{name}' is required")

    def _format_operation_result(self, operation: str, device_id: str, 
                                success: bool, details: Optional[str] = None,
                                error: Optional[str] = None) -> List[Content]:
        """Format operation result.
        
        Args:
            operation: Operation name
            device_id: Target device ID
            success: Whether operation succeeded
            details: Success details
            error: Error message if failed
            
        Returns:
            List of Content objects with formatted result
        """
        return FortiGateFormatters.format_operation_result(
            operation, device_id, success, details, error
        )

    def _format_connection_test(self, device_id: str, success: bool,
                              error: Optional[str] = None) -> List[Content]:
        """Format connection test result.
        
        Args:
            device_id: Device identifier
            success: Whether connection succeeded
            error: Error message if failed
            
        Returns:
            List of Content objects with formatted result
        """
        return FortiGateFormatters.format_connection_test(device_id, success, error)
