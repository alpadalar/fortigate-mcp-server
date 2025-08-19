"""
Response formatters for FortiGate MCP.

This module provides utilities for formatting FortiGate API responses
into structured MCP content. It acts as a bridge between raw API data
and user-friendly formatted output.
"""
import json
from typing import Any, Dict, List, Optional
from mcp.types import TextContent as Content
from .templates import FortiGateTemplates

class FortiGateFormatters:
    """Formatter collection for FortiGate resources.
    
    Provides static methods for converting FortiGate API responses
    into MCP Content objects with appropriate formatting.
    """
    
    @staticmethod
    def format_devices(devices_data: Dict[str, Dict[str, Any]]) -> List[Content]:
        """Format device list response.
        
        Args:
            devices_data: Dictionary of device information
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.device_list(devices_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_device_status(device_id: str, status_data: Dict[str, Any]) -> List[Content]:
        """Format device status response.
        
        Args:
            device_id: Device identifier
            status_data: Raw status data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.device_status(device_id, status_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_firewall_policies(policies_data: Dict[str, Any]) -> List[Content]:
        """Format firewall policies response.
        
        Args:
            policies_data: Raw policies data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.firewall_policies(policies_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_firewall_policy_detail(policy_data: Dict[str, Any], device_id: str,
                                    address_objects: Optional[Dict[str, Any]] = None,
                                    service_objects: Optional[Dict[str, Any]] = None) -> List[Content]:
        """Format detailed firewall policy response.
        
        Args:
            policy_data: Raw policy detail data from FortiGate API
            device_id: Device identifier
            address_objects: Address objects data for resolution
            service_objects: Service objects data for resolution
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.firewall_policy_detail(
            policy_data, device_id, address_objects, service_objects
        )
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_address_objects(addresses_data: Dict[str, Any]) -> List[Content]:
        """Format address objects response.
        
        Args:
            addresses_data: Raw address objects data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.address_objects(addresses_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_service_objects(services_data: Dict[str, Any]) -> List[Content]:
        """Format service objects response.
        
        Args:
            services_data: Raw service objects data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.service_objects(services_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_static_routes(routes_data: Dict[str, Any]) -> List[Content]:
        """Format static routes response.
        
        Args:
            routes_data: Raw static routes data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.static_routes(routes_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_interfaces(interfaces_data: Dict[str, Any]) -> List[Content]:
        """Format interfaces response.
        
        Args:
            interfaces_data: Raw interfaces data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.interfaces(interfaces_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_vdoms(vdoms_data: Dict[str, Any]) -> List[Content]:
        """Format VDOMs response.
        
        Args:
            vdoms_data: Raw VDOMs data from FortiGate API
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.vdoms(vdoms_data)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_operation_result(operation: str, device_id: str, success: bool,
                              details: Optional[str] = None, 
                              error: Optional[str] = None) -> List[Content]:
        """Format operation result.
        
        Args:
            operation: Name of the operation performed
            device_id: Target device identifier
            success: Whether the operation succeeded
            details: Additional details about the operation
            error: Error message if operation failed
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.operation_result(
            operation, device_id, success, details, error
        )
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_health_status(status: str, details: Dict[str, Any]) -> List[Content]:
        """Format health check status.
        
        Args:
            status: Overall health status
            details: Health check details
            
        Returns:
            List containing formatted Content object
        """
        formatted_text = FortiGateTemplates.health_status(status, details)
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_json_response(data: Any, title: Optional[str] = None) -> List[Content]:
        """Format JSON response data.
        
        Args:
            data: Data to format as JSON
            title: Optional title for the response
            
        Returns:
            List containing formatted Content object
        """
        if title:
            formatted_text = f"{title}\n\n{json.dumps(data, indent=2, ensure_ascii=False)}"
        else:
            formatted_text = json.dumps(data, indent=2, ensure_ascii=False)
        
        return [Content(type="text", text=formatted_text)]
    
    @staticmethod
    def format_error(error_message: str, device_id: str, operation: str) -> List[Content]:
        """Format error response.
        
        Args:
            error_message: Error message
            device_id: Device identifier
            operation: Operation that failed
            
        Returns:
            List containing formatted Content object
        """
        lines = [
            f"Error in operation: {operation}",
            f"Device: {device_id}",
            f"Error: {error_message}",
            ""
        ]
        
        return [Content(type="text", text="\n".join(lines))]
    
    @staticmethod
    def format_connection_test(device_id: str, success: bool, 
                             error: Optional[str] = None) -> List[Content]:
        """Format connection test result.
        
        Args:
            device_id: Device identifier
            success: Whether connection succeeded
            error: Error message if failed
            
        Returns:
            List containing formatted Content object
        """
        status = "SUCCESS" if success else "FAILED"
        
        lines = [
            f"Connection Test {status}",
            f"Device: {device_id}",
            ""
        ]
        
        if success:
            lines.append("Connection established successfully")
        elif error:
            lines.append(f"Connection failed: {error}")
        else:
            lines.append("Connection failed")
        
        return [Content(type="text", text="\n".join(lines))]
    
    @staticmethod
    def format_validation_result(valid: bool, errors: List[str], 
                               warnings: List[str]) -> List[Content]:
        """Format validation result.
        
        Args:
            valid: Whether validation passed
            errors: List of validation errors
            warnings: List of validation warnings
            
        Returns:
            List containing formatted Content object
        """
        status = "VALID" if valid else "INVALID"
        
        lines = [f"Validation: {status}", ""]
        
        if errors:
            lines.extend(["Errors:"])
            for error in errors:
                lines.append(f"  {error}")
            lines.append("")
        
        if warnings:
            lines.extend(["Warnings:"])
            for warning in warnings:
                lines.append(f"  {warning}")
            lines.append("")
        
        if valid and not warnings:
            lines.append("Configuration is valid!")
        
        return [Content(type="text", text="\n".join(lines))]
