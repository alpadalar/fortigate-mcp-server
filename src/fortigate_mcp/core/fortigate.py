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
    
    def get_static_route_detail(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific static route."""
        return self._make_request("GET", f"cmdb/router/static/{route_id}", vdom=vdom)
    
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
        return self._make_request("PUT", f"cmdb/firewall/vip/{vip_name}", data=vip_data, vdom=vdom)
    
    def delete_virtual_ip(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete virtual IP."""
        return self._make_request("DELETE", f"cmdb/firewall/vip/{vip_name}", vdom=vdom)
    
    def get_virtual_ip_detail(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific virtual IP."""
        return self._make_request("GET", f"cmdb/firewall/vip/{vip_name}", vdom=vdom)

    # Certificate endpoints
    def get_local_certificates(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get local (device) certificates."""
        return self._make_request("GET", "cmdb/certificate/local", vdom=vdom)

    def get_local_certificate_detail(self, cert_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific local certificate."""
        return self._make_request("GET", f"cmdb/certificate/local/{cert_name}", vdom=vdom)

    def get_ca_certificates(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get CA certificates."""
        return self._make_request("GET", "cmdb/certificate/ca", vdom=vdom)

    def get_ca_certificate_detail(self, cert_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific CA certificate."""
        return self._make_request("GET", f"cmdb/certificate/ca/{cert_name}", vdom=vdom)

    def get_remote_certificates(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get remote certificates."""
        return self._make_request("GET", "cmdb/certificate/remote", vdom=vdom)

    def get_remote_certificate_detail(self, cert_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific remote certificate."""
        return self._make_request("GET", f"cmdb/certificate/remote/{cert_name}", vdom=vdom)

    def get_crl(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get certificate revocation lists."""
        return self._make_request("GET", "cmdb/certificate/crl", vdom=vdom)

    def get_crl_detail(self, crl_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific CRL."""
        return self._make_request("GET", f"cmdb/certificate/crl/{crl_name}", vdom=vdom)

    def delete_local_certificate(self, cert_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a local certificate."""
        return self._make_request("DELETE", f"cmdb/certificate/local/{cert_name}", vdom=vdom)

    def delete_ca_certificate(self, cert_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a CA certificate."""
        return self._make_request("DELETE", f"cmdb/certificate/ca/{cert_name}", vdom=vdom)

    def delete_remote_certificate(self, cert_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a remote certificate."""
        return self._make_request("DELETE", f"cmdb/certificate/remote/{cert_name}", vdom=vdom)

    def import_local_certificate(
        self,
        cert_name: str,
        certificate: str,
        private_key: str,
        password: Optional[str] = None,
        scope: str = "global",
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Import a local certificate with private key.

        Args:
            cert_name: Name for the certificate
            certificate: PEM-encoded certificate (or base64)
            private_key: PEM-encoded private key (or base64)
            password: Optional password for encrypted private key
            scope: Certificate scope ('global' or 'vdom')
            vdom: Virtual domain

        Returns:
            Import result
        """
        import base64

        # Ensure certificate and key are base64 encoded
        if certificate.startswith("-----"):
            certificate = base64.b64encode(certificate.encode()).decode()
        if private_key.startswith("-----"):
            private_key = base64.b64encode(private_key.encode()).decode()

        data = {
            "type": "regular",
            "certname": cert_name,
            "file_content": certificate,
            "key_file_content": private_key,
            "scope": scope
        }

        if password:
            data["password"] = password

        return self._make_request(
            "POST",
            "monitor/vpn-certificate/local/import",
            data=data,
            vdom=vdom
        )

    def import_ca_certificate(
        self,
        cert_name: str,
        certificate: str,
        scope: str = "global",
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Import a CA certificate.

        Args:
            cert_name: Name for the CA certificate
            certificate: PEM-encoded certificate (or base64)
            scope: Certificate scope ('global' or 'vdom')
            vdom: Virtual domain

        Returns:
            Import result
        """
        import base64

        # Ensure certificate is base64 encoded
        if certificate.startswith("-----"):
            certificate = base64.b64encode(certificate.encode()).decode()

        data = {
            "type": "ca",
            "import_method": "file",
            "file_content": certificate,
            "scope": scope
        }

        return self._make_request(
            "POST",
            "monitor/vpn-certificate/ca/import",
            data=data,
            vdom=vdom
        )

    # Security Fabric endpoints
    def get_security_fabric_config(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get Security Fabric (CSF) configuration.

        Returns the Security Fabric settings including fabric name,
        upstream/downstream configuration, and fabric members.
        """
        return self._make_request("GET", "cmdb/system/csf", vdom=vdom)

    def get_security_fabric_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get Security Fabric runtime status and topology.

        Returns real-time information about the Security Fabric including
        connected devices, their roles, and connection status.
        """
        return self._make_request("GET", "monitor/system/csf", vdom=vdom)

    def get_fabric_devices(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get list of fabric devices/connectors.

        Returns information about FortiGate devices configured as
        fabric connectors.
        """
        return self._make_request("GET", "cmdb/system/csf/fabric-device", vdom=vdom)

    def get_fabric_connectors(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get fabric connector configuration.

        Returns SDN and cloud connector configurations used in the fabric.
        """
        return self._make_request("GET", "cmdb/system/sdn-connector", vdom=vdom)

    def get_ha_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get High Availability (HA) cluster status.

        Returns HA cluster configuration and member status.
        """
        return self._make_request("GET", "monitor/system/ha-peer", vdom=vdom)

    def get_ha_config(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get High Availability (HA) configuration.

        Returns HA settings including group name, mode, and priority.
        """
        return self._make_request("GET", "cmdb/system/ha", vdom=vdom)

    # Packet Capture (Sniffer) endpoints
    def get_packet_captures(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get list of all packet capture profiles.

        Returns configured packet sniffer profiles with their settings.
        """
        return self._make_request("GET", "cmdb/system/sniffer", vdom=vdom)

    def get_packet_capture(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific packet capture profile.

        Args:
            capture_id: Sniffer profile ID
            vdom: Virtual domain

        Returns:
            Packet capture profile configuration
        """
        return self._make_request("GET", f"cmdb/system/sniffer/{capture_id}", vdom=vdom)

    def create_packet_capture(
        self,
        interface: str,
        filter_str: Optional[str] = None,
        max_packet_count: int = 10000,
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a packet capture profile.

        Args:
            interface: Interface to capture on (e.g., 'any', 'port1')
            filter_str: BPF-style filter string
            max_packet_count: Maximum packets to capture
            vdom: Virtual domain

        Returns:
            API response with created capture profile
        """
        capture_data = {
            "interface": interface,
            "max-packet-count": max_packet_count,
        }
        if filter_str:
            capture_data["filter"] = filter_str

        return self._make_request("POST", "cmdb/system/sniffer", data=capture_data, vdom=vdom)

    def delete_packet_capture(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a packet capture profile.

        Args:
            capture_id: Sniffer profile ID to delete
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request("DELETE", f"cmdb/system/sniffer/{capture_id}", vdom=vdom)

    def start_packet_capture(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Start a packet capture.

        Args:
            capture_id: Sniffer profile ID to start
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request(
            "POST",
            "monitor/system/sniffer/start",
            params={"mkey": capture_id},
            vdom=vdom
        )

    def stop_packet_capture(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Stop a packet capture.

        Args:
            capture_id: Sniffer profile ID to stop
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request(
            "POST",
            "monitor/system/sniffer/stop",
            params={"mkey": capture_id},
            vdom=vdom
        )

    def get_packet_capture_status(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get packet capture status.

        Args:
            capture_id: Sniffer profile ID
            vdom: Virtual domain

        Returns:
            Capture status including packet count, state, etc.
        """
        return self._make_request(
            "GET",
            "monitor/system/sniffer",
            params={"mkey": capture_id},
            vdom=vdom
        )

    def download_packet_capture(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Download packet capture file.

        Args:
            capture_id: Sniffer profile ID
            vdom: Virtual domain

        Returns:
            Capture file data or download information
        """
        return self._make_request(
            "GET",
            "monitor/system/sniffer/download",
            params={"mkey": capture_id},
            vdom=vdom
        )

    def clear_packet_capture(self, capture_id: int, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Clear captured packets from a capture profile.

        Args:
            capture_id: Sniffer profile ID
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request(
            "POST",
            "monitor/system/sniffer/clear",
            params={"mkey": capture_id},
            vdom=vdom
        )

    # IPSec VPN Phase 1 endpoints
    def get_ipsec_phase1_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get all IPSec VPN Phase 1 interface configurations.

        Returns:
            List of Phase 1 tunnel configurations
        """
        return self._make_request("GET", "cmdb/vpn.ipsec/phase1-interface", vdom=vdom)

    def get_ipsec_phase1_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific IPSec VPN Phase 1 interface configuration.

        Args:
            name: Phase 1 interface name
            vdom: Virtual domain

        Returns:
            Phase 1 tunnel configuration
        """
        return self._make_request("GET", f"cmdb/vpn.ipsec/phase1-interface/{name}", vdom=vdom)

    def create_ipsec_phase1_interface(self, phase1_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create an IPSec VPN Phase 1 interface.

        Args:
            phase1_data: Phase 1 configuration data including:
                - name: Tunnel name
                - interface: Outgoing interface
                - remote-gw: Remote gateway IP
                - psksecret: Pre-shared key
                - proposal: Phase 1 proposal (e.g., 'aes256-sha256')
                - ike-version: IKE version (1 or 2)
            vdom: Virtual domain

        Returns:
            API response with created tunnel
        """
        return self._make_request("POST", "cmdb/vpn.ipsec/phase1-interface", data=phase1_data, vdom=vdom)

    def update_ipsec_phase1_interface(self, name: str, phase1_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update an IPSec VPN Phase 1 interface.

        Args:
            name: Phase 1 interface name
            phase1_data: Updated configuration data
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request("PUT", f"cmdb/vpn.ipsec/phase1-interface/{name}", data=phase1_data, vdom=vdom)

    def delete_ipsec_phase1_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete an IPSec VPN Phase 1 interface.

        Args:
            name: Phase 1 interface name
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request("DELETE", f"cmdb/vpn.ipsec/phase1-interface/{name}", vdom=vdom)

    # IPSec VPN Phase 2 endpoints
    def get_ipsec_phase2_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get all IPSec VPN Phase 2 interface configurations.

        Returns:
            List of Phase 2 selector configurations
        """
        return self._make_request("GET", "cmdb/vpn.ipsec/phase2-interface", vdom=vdom)

    def get_ipsec_phase2_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a specific IPSec VPN Phase 2 interface configuration.

        Args:
            name: Phase 2 interface name
            vdom: Virtual domain

        Returns:
            Phase 2 selector configuration
        """
        return self._make_request("GET", f"cmdb/vpn.ipsec/phase2-interface/{name}", vdom=vdom)

    def create_ipsec_phase2_interface(self, phase2_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create an IPSec VPN Phase 2 interface.

        Args:
            phase2_data: Phase 2 configuration data including:
                - name: Selector name
                - phase1name: Associated Phase 1 tunnel
                - src-subnet: Source subnet
                - dst-subnet: Destination subnet
                - proposal: Phase 2 proposal
            vdom: Virtual domain

        Returns:
            API response with created selector
        """
        return self._make_request("POST", "cmdb/vpn.ipsec/phase2-interface", data=phase2_data, vdom=vdom)

    def update_ipsec_phase2_interface(self, name: str, phase2_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update an IPSec VPN Phase 2 interface.

        Args:
            name: Phase 2 interface name
            phase2_data: Updated configuration data
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request("PUT", f"cmdb/vpn.ipsec/phase2-interface/{name}", data=phase2_data, vdom=vdom)

    def delete_ipsec_phase2_interface(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete an IPSec VPN Phase 2 interface.

        Args:
            name: Phase 2 interface name
            vdom: Virtual domain

        Returns:
            API response
        """
        return self._make_request("DELETE", f"cmdb/vpn.ipsec/phase2-interface/{name}", vdom=vdom)

    # IPSec VPN Monitor endpoints
    def get_ipsec_tunnel_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get IPSec tunnel runtime status.

        Returns real-time status of all IPSec tunnels including:
        - Connection state
        - Traffic statistics
        - Peer information
        - Proxy IDs (Phase 2 selectors)

        Returns:
            Tunnel status information
        """
        return self._make_request("GET", "monitor/vpn/ipsec", vdom=vdom)


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
    
    def list_devices(self) -> Dict[str, Dict[str, Any]]:
        """List all registered devices with their info.

        Returns:
            Dict mapping device_id to device info (host, vdom)
        """
        return {
            device_id: {
                "host": device.config.host,
                "vdom": device.config.vdom
            }
            for device_id, device in self.devices.items()
        }
    
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
