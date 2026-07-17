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
from ..validation import (
    scrub_secrets,
    validate_interface_name,
    validate_numeric_id,
    validate_object_name,
    validate_vdom,
)
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

        # SEC-04: explicit opt-out of TLS verification is a deliberate,
        # logged operator/caller choice -- fires at construction time for
        # both config-loaded devices and devices added at runtime, since
        # both paths construct a FortiGateAPI here.
        if not config.verify_ssl:
            self.logger.warning(
                f"Device {device_id}: TLS certificate verification is DISABLED "
                f"(verify_ssl=False) -- this connection is exposed to "
                f"man-in-the-middle tampering"
            )

        # Build base URL (IPv6 literals must be bracketed in the URL authority --
        # a validated host containing ':' can only be an IPv6 literal, since
        # validate_host rejects embedded :port for IPv4/hostnames)
        host_part = f"[{config.host}]" if ":" in config.host else config.host
        self.base_url = f"https://{host_part}:{config.port}/api/v2"

        # Setup authentication headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Device's own secret set, used ONLY to scrub untrusted error text
        # (CONF-03) -- never used to build the request itself.
        self._own_secrets: set = set()

        if config.api_token:
            self.headers["Authorization"] = f"Bearer {config.api_token.get_secret_value()}"
            self.auth_method = "token"
        elif config.username and config.password:
            self.auth_method = "basic"
            self._basic_auth = (config.username, config.password.get_secret_value())
        else:
            raise ValueError(f"Device {device_id}: Either api_token or username/password must be provided")

        if config.api_token:
            self._own_secrets.add(config.api_token.get_secret_value())
        if config.password:
            self._own_secrets.add(config.password.get_secret_value())

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
        # None-checked fallback: an explicit "" override must be validated
        # and rejected, never silently swapped for the device default.
        resolved_vdom = self.config.vdom if vdom is None else vdom
        params["vdom"] = validate_vdom(resolved_vdom)
        
        # Setup authentication
        auth = None
        if self.auth_method == "basic":
            auth = self._basic_auth
        
        start_time = time.time()
        
        try:
            with httpx.Client(
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
                auth=auth,
                follow_redirects=False,
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

                    # error_msg is built from an UNTRUSTED response body -- a
                    # device, proxy, or middlebox can echo the request's
                    # Authorization header back in an error body. Scrub
                    # before this text can reach FortiGateAPIError / MCP output.
                    error_msg = scrub_secrets(error_msg, self._own_secrets)

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
            # httpx exception messages can embed request details -- scrub
            # before this text can reach FortiGateAPIError / MCP output.
            raise FortiGateAPIError(
                scrub_secrets(f"Network error: {str(e)}", self._own_secrets),
                device_id=self.device_id
            )
        except FortiGateAPIError:
            # Already scrubbed and well-formed (raised inside the try block
            # above) -- re-raise as-is, do not let the catch-all below
            # re-wrap it.
            raise
        except Exception as e:
            # Catch-all for any exception NOT covered by the two branches
            # above (e.g. an unexpected error from response.json() on the
            # success path, or any future httpx/library exception type that
            # isn't a RequestError subclass). Without this, such an
            # exception would propagate to tools/base.py's
            # `error_msg = str(error)` completely unscrubbed -- that path
            # builds MCP tool-response content directly and has no
            # TokenRedactionFilter fallback (that filter only touches log
            # records, not tool-response content).
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, None, duration_ms)
            raise FortiGateAPIError(
                scrub_secrets(f"Unexpected error: {e}", self._own_secrets),
                device_id=self.device_id,
            )

    def _validated_endpoint(
        self, prefix: str, identifier: str, field_name: str, numeric: bool = False
    ) -> str:
        """Validate `identifier` and build a safe REST path segment.

        Args:
            prefix: fixed, trusted path prefix (e.g. "cmdb/firewall/policy").
            identifier: caller-supplied identifier to validate before
                interpolation into the REST path.
            field_name: caller-facing field name for validator error messages.
            numeric: if True, validate as a numeric ID (policy_id/route_id);
                otherwise validate as an object name (address/service/vip name).

        Returns:
            "{prefix}/{safe_id}" -- safe to interpolate into a REST path.

        Raises:
            ValueError: if `identifier` fails validation.
        """
        safe_id = (
            validate_numeric_id(identifier, field_name)
            if numeric
            else validate_object_name(identifier, field_name)
        )
        return f"{prefix}/{safe_id}"

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
        # Dedicated dot-permitting grammar (VLAN subinterfaces like
        # "port1.100" are valid) -- NOT validate_object_name. Sent via
        # httpx params= (not a raw query string) so it is auto-encoded too.
        safe_name = validate_interface_name(interface_name)
        return self._make_request(
            "GET", "monitor/system/interface", params={"interface": safe_name}, vdom=vdom
        )
    
    # Firewall policy endpoints
    def get_firewall_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policies."""
        return self._make_request("GET", "cmdb/firewall/policy", vdom=vdom)
    
    def create_firewall_policy(self, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new firewall policy."""
        return self._make_request("POST", "cmdb/firewall/policy", data=policy_data, vdom=vdom)
    
    def update_firewall_policy(self, policy_id: str, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing firewall policy."""
        endpoint = self._validated_endpoint("cmdb/firewall/policy", policy_id, "policy_id", numeric=True)
        return self._make_request("PUT", endpoint, data=policy_data, vdom=vdom)

    def get_firewall_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific firewall policy."""
        endpoint = self._validated_endpoint("cmdb/firewall/policy", policy_id, "policy_id", numeric=True)
        return self._make_request("GET", endpoint, vdom=vdom)

    def delete_firewall_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete firewall policy."""
        endpoint = self._validated_endpoint("cmdb/firewall/policy", policy_id, "policy_id", numeric=True)
        return self._make_request("DELETE", endpoint, vdom=vdom)
    
    # Address object endpoints
    def get_address_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address objects."""
        return self._make_request("GET", "cmdb/firewall/address", vdom=vdom)
    
    def create_address_object(self, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new address object."""
        return self._make_request("POST", "cmdb/firewall/address", data=address_data, vdom=vdom)
    
    def update_address_object(self, address_name: str, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing address object."""
        endpoint = self._validated_endpoint("cmdb/firewall/address", address_name, "address_name")
        return self._make_request("PUT", endpoint, data=address_data, vdom=vdom)

    def delete_address_object(self, address_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete address object."""
        endpoint = self._validated_endpoint("cmdb/firewall/address", address_name, "address_name")
        return self._make_request("DELETE", endpoint, vdom=vdom)
    
    # Service object endpoints
    def get_service_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get service objects."""
        return self._make_request("GET", "cmdb/firewall.service/custom", vdom=vdom)
    
    def create_service_object(self, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new service object."""
        return self._make_request("POST", "cmdb/firewall.service/custom", data=service_data, vdom=vdom)
    
    def update_service_object(self, service_name: str, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing service object."""
        endpoint = self._validated_endpoint("cmdb/firewall.service/custom", service_name, "service_name")
        return self._make_request("PUT", endpoint, data=service_data, vdom=vdom)

    def delete_service_object(self, service_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete service object."""
        endpoint = self._validated_endpoint("cmdb/firewall.service/custom", service_name, "service_name")
        return self._make_request("DELETE", endpoint, vdom=vdom)
    
    # Routing endpoints
    def get_static_routes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get static routes."""
        return self._make_request("GET", "cmdb/router/static", vdom=vdom)
    
    def create_static_route(self, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new static route."""
        return self._make_request("POST", "cmdb/router/static", data=route_data, vdom=vdom)
    
    def update_static_route(self, route_id: str, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing static route."""
        endpoint = self._validated_endpoint("cmdb/router/static", route_id, "route_id", numeric=True)
        return self._make_request("PUT", endpoint, data=route_data, vdom=vdom)

    def delete_static_route(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete static route."""
        endpoint = self._validated_endpoint("cmdb/router/static", route_id, "route_id", numeric=True)
        return self._make_request("DELETE", endpoint, vdom=vdom)

    def get_static_route_detail(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific static route."""
        endpoint = self._validated_endpoint("cmdb/router/static", route_id, "route_id", numeric=True)
        return self._make_request("GET", endpoint, vdom=vdom)
    
    def get_routing_table(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get routing table."""
        return self._make_request("GET", "monitor/router/ipv4", vdom=vdom)
    
    # Virtual IP endpoints
    def get_virtual_ips(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get virtual IPs."""
        return self._make_request("GET", "cmdb/firewall/vip", vdom=vdom)
    
    def create_virtual_ip(self, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new virtual IP."""
        return self._make_request("POST", "cmdb/firewall/vip", data=vip_data, vdom=vdom)
    
    def update_virtual_ip(self, vip_name: str, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing virtual IP."""
        endpoint = self._validated_endpoint("cmdb/firewall/vip", vip_name, "vip_name")
        return self._make_request("PUT", endpoint, data=vip_data, vdom=vdom)

    def delete_virtual_ip(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete virtual IP."""
        endpoint = self._validated_endpoint("cmdb/firewall/vip", vip_name, "vip_name")
        return self._make_request("DELETE", endpoint, vdom=vdom)

    def get_virtual_ip_detail(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific virtual IP."""
        endpoint = self._validated_endpoint("cmdb/firewall/vip", vip_name, "vip_name")
        return self._make_request("GET", endpoint, vdom=vdom)


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
        # Devices whose FortiGateAPI construction raised during startup,
        # mapped to the error string. Startup continues past a single
        # device failure (so one misconfigured device doesn't take down
        # the whole server), but this dict makes the failure visible to
        # health_check/get_server_info instead of requiring an operator to
        # grep logs -- list_devices()/self.devices alone would silently
        # under-report the configured device count.
        self.failed_devices: Dict[str, str] = {}
        self.auth_config = auth_config
        self.logger = get_logger("fortigate_manager")

        # Initialize devices
        for device_id, config in devices.items():
            try:
                self.devices[device_id] = FortiGateAPI(device_id, config)
                self.logger.info(f"Initialized device: {device_id}")
            except Exception as e:
                self.logger.error(f"Failed to initialize device {device_id}: {e}")
                self.failed_devices[device_id] = str(e)
    
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
        # A device that failed at startup is absent from self.devices, so
        # re-adding it with corrected settings succeeds -- clear the stale
        # failure entry, otherwise health_check/health//health report
        # "degraded" forever for a now-working device.
        self.failed_devices.pop(device_id, None)
        self.logger.info(f"Added device: {device_id}")

    def remove_device(self, device_id: str) -> None:
        """Remove a device from the manager.

        Also clears a startup-failure entry for the device, so an operator
        can retire a device that never initialized without restarting the
        process.

        Args:
            device_id: Device identifier to remove
        """
        if device_id in self.failed_devices:
            del self.failed_devices[device_id]
            if device_id not in self.devices:
                self.logger.info(f"Cleared failed device: {device_id}")
                return
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
