"""
FortiGate API management for the MCP server.

This module provides the core FortiGate API integration:
- Device connection management
- Authentication handling
- API session management
- Request/response processing
- Error handling and recovery
"""
import logging
import time
from typing import Dict, Any, Optional, Union, List
import httpx
import json
from ..config.models import FortiGateDeviceConfig, AuthConfig
from .logging import get_logger, log_api_call

class FortiGateAPIError(Exception):
    """Custom exception for FortiGate API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, 
                 device_id: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.device_id = device_id

class FortiGateAPI:
    """FortiGate API client for individual device communication.
    
    Handles all HTTP communication with a single FortiGate device:
    - Authentication management
    - Request/response processing
    - Error handling and retries
    - Session management
    """
    
    def __init__(self, device_id: str, config: FortiGateDeviceConfig):
        """Initialize FortiGate API client.
        
        Args:
            device_id: Unique identifier for this device
            config: Device configuration including connection details
        """
        self.device_id = device_id
        self.config = config
        self.logger = get_logger(f"device.{device_id}")
        
        # Build base URL
        self.base_url = f"https://{config.host}:{config.port}/api/v2"
        
        # Setup authentication headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        if config.api_token:
            self.headers["Authorization"] = f"Bearer {config.api_token}"
            self.auth_method = "token"
        elif config.username and config.password:
            self.auth_method = "basic"
            self._basic_auth = (config.username, config.password)
        else:
            raise ValueError(f"Device {device_id}: Either api_token or username/password must be provided")
        
        self.logger.info(f"Initialized FortiGate API client (auth: {self.auth_method})")
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to FortiGate API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (without /api/v2 prefix)
            params: Query parameters
            data: Request body data
            vdom: Virtual Domain (uses device default if not specified)
            
        Returns:
            API response as dictionary
            
        Raises:
            FortiGateAPIError: If API request fails
        """
        # Build URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        # Setup parameters
        if not params:
            params = {}
        params["vdom"] = vdom or self.config.vdom
        
        # Setup authentication
        auth = None
        if self.auth_method == "basic":
            auth = self._basic_auth
        
        start_time = time.time()
        
        try:
            with httpx.Client(
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
                auth=auth
            ) as client:
                response = client.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    params=params,
                    json=data if data else None
                )
                
                duration_ms = (time.time() - start_time) * 1000
                log_api_call(self.logger, method, endpoint, response.status_code, duration_ms)
                
                # Handle error responses
                if response.status_code >= 400:
                    error_msg = f"API request failed: {response.status_code}"
                    try:
                        error_data = response.json()
                        if "error" in error_data:
                            error_msg += f" - {error_data['error']}"
                    except:
                        error_msg += f" - {response.text}"
                    
                    raise FortiGateAPIError(
                        error_msg, 
                        status_code=response.status_code,
                        device_id=self.device_id
                    )
                
                # Parse response
                try:
                    return response.json()
                except json.JSONDecodeError:
                    # Some endpoints may return empty responses
                    return {"status": "success"}
                
        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, None, duration_ms)
            raise FortiGateAPIError(
                f"Network error: {str(e)}", 
                device_id=self.device_id
            )
    
    def test_connection(self) -> bool:
        """Test connection to FortiGate device.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.get_system_status()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    # System endpoints
    def get_system_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system status information."""
        return self._make_request("GET", "monitor/system/status", vdom=vdom)
    
    def get_system_interface(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system interface information."""
        return self._make_request("GET", "monitor/system/interface", vdom=vdom)
    
    def get_vdoms(self) -> Dict[str, Any]:
        """Get list of Virtual Domains."""
        return self._make_request("GET", "cmdb/system/vdom")
    
    # Interface endpoints
    def get_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get interface configuration."""
        return self._make_request("GET", "cmdb/system/interface", vdom=vdom)
    
    def get_interface_status(self, interface_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get specific interface status."""
        return self._make_request("GET", f"monitor/system/interface?interface={interface_name}", vdom=vdom)
    
    # Firewall policy endpoints
    def get_firewall_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policies."""
        return self._make_request("GET", "cmdb/firewall/policy", vdom=vdom)
    
    def create_firewall_policy(self, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new firewall policy."""
        return self._make_request("POST", "cmdb/firewall/policy", data=policy_data, vdom=vdom)
    
    def update_firewall_policy(self, policy_id: str, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing firewall policy."""
        return self._make_request("PUT", f"cmdb/firewall/policy/{policy_id}", data=policy_data, vdom=vdom)
    
    def get_firewall_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific firewall policy."""
        return self._make_request("GET", f"cmdb/firewall/policy/{policy_id}", vdom=vdom)
    
    def delete_firewall_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete firewall policy."""
        return self._make_request("DELETE", f"cmdb/firewall/policy/{policy_id}", vdom=vdom)
    
    # Address object endpoints
    def get_address_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address objects."""
        return self._make_request("GET", "cmdb/firewall/address", vdom=vdom)
    
    def create_address_object(self, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new address object."""
        return self._make_request("POST", "cmdb/firewall/address", data=address_data, vdom=vdom)
    
    def update_address_object(self, address_name: str, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing address object."""
        return self._make_request("PUT", f"cmdb/firewall/address/{address_name}", data=address_data, vdom=vdom)
    
    def delete_address_object(self, address_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete address object."""
        return self._make_request("DELETE", f"cmdb/firewall/address/{address_name}", vdom=vdom)
    
    # Service object endpoints
    def get_service_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get service objects."""
        return self._make_request("GET", "cmdb/firewall.service/custom", vdom=vdom)
    
    def create_service_object(self, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new service object."""
        return self._make_request("POST", "cmdb/firewall.service/custom", data=service_data, vdom=vdom)
    
    def update_service_object(self, service_name: str, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing service object."""
        return self._make_request("PUT", f"cmdb/firewall.service/custom/{service_name}", data=service_data, vdom=vdom)
    
    def delete_service_object(self, service_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete service object."""
        return self._make_request("DELETE", f"cmdb/firewall.service/custom/{service_name}", vdom=vdom)
    
    # Routing endpoints
    def get_static_routes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get static routes."""
        return self._make_request("GET", "cmdb/router/static", vdom=vdom)
    
    def create_static_route(self, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new static route."""
        return self._make_request("POST", "cmdb/router/static", data=route_data, vdom=vdom)
    
    def update_static_route(self, route_id: str, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing static route."""
        return self._make_request("PUT", f"cmdb/router/static/{route_id}", data=route_data, vdom=vdom)
    
    def delete_static_route(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete static route."""
        return self._make_request("DELETE", f"cmdb/router/static/{route_id}", vdom=vdom)
    
    def get_routing_table(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get routing table."""
        return self._make_request("GET", "monitor/router/ipv4", vdom=vdom)


class FortiGateManager:
    """Manager for multiple FortiGate devices.
    
    Handles device registration, connection management, and provides
    unified access to multiple FortiGate devices.
    """
    
    def __init__(self, devices: Dict[str, FortiGateDeviceConfig], auth_config: AuthConfig):
        """Initialize FortiGate manager.
        
        Args:
            devices: Dictionary of device configurations
            auth_config: Authentication configuration
        """
        self.devices: Dict[str, FortiGateAPI] = {}
        self.auth_config = auth_config
        self.logger = get_logger("fortigate_manager")
        
        # Initialize devices
        for device_id, config in devices.items():
            try:
                self.devices[device_id] = FortiGateAPI(device_id, config)
                self.logger.info(f"Initialized device: {device_id}")
            except Exception as e:
                self.logger.error(f"Failed to initialize device {device_id}: {e}")
    
    def get_device(self, device_id: str) -> FortiGateAPI:
        """Get FortiGate API client for a device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            FortiGateAPI client instance
            
        Raises:
            ValueError: If device not found
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")
        return self.devices[device_id]
    
    def list_devices(self) -> List[str]:
        """List all registered device IDs.
        
        Returns:
            List of device identifiers
        """
        return list(self.devices.keys())
    
    def add_device(self, device_id: str, host: str, port: int = 443,
                   username: Optional[str] = None, password: Optional[str] = None,
                   api_token: Optional[str] = None, vdom: str = "root",
                   verify_ssl: bool = False, timeout: int = 30) -> None:
        """Add a new device to the manager.
        
        Args:
            device_id: Unique identifier for the device
            host: Device IP address or hostname
            port: HTTPS port
            username: Username for authentication
            password: Password for authentication
            api_token: API token for authentication
            vdom: Virtual Domain name
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        if device_id in self.devices:
            raise ValueError(f"Device '{device_id}' already exists")
        
        # Create device configuration
        device_config = FortiGateDeviceConfig(
            host=host,
            port=port,
            username=username,
            password=password,
            api_token=api_token,
            vdom=vdom,
            verify_ssl=verify_ssl,
            timeout=timeout
        )
        
        # Create API client
        self.devices[device_id] = FortiGateAPI(device_id, device_config)
        self.logger.info(f"Added device: {device_id}")
    
    def remove_device(self, device_id: str) -> None:
        """Remove a device from the manager.
        
        Args:
            device_id: Device identifier to remove
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")
        
        del self.devices[device_id]
        self.logger.info(f"Removed device: {device_id}")
    
    def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all devices.
        
        Returns:
            Dictionary mapping device IDs to connection status
        """
        results = {}
        for device_id, api_client in self.devices.items():
            try:
                results[device_id] = api_client.test_connection()
            except Exception as e:
                self.logger.error(f"Connection test failed for {device_id}: {e}")
                results[device_id] = False
        return results
