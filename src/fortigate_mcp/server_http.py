"""
HTTP-based MCP server implementation for FortiGate MCP.

This module provides an HTTP transport layer for the MCP server,
supporting HTTP transport for web-based integrations and external access.
"""

import logging
import json
import os
import sys
import signal
from typing import Optional
from datetime import datetime

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .core.fortimanager import FortiManagerManager
from .core.fortianalyzer import FortiAnalyzerManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools
from .tools.certificate import CertificateTools
from .tools.acme import ACMETools
from .tools.fabric import FabricTools
from .tools.fortimanager import FortiManagerTools
from .tools.fortianalyzer import FortiAnalyzerTools
from .tools.packet_capture import PacketCaptureTools
from .tools.ipsec import IPSecTools

logger = logging.getLogger("fortigate-mcp.http")

class FortiGateMCPHTTPServer:
    """
    HTTP-based MCP server for FortiGate management.
    
    This server supports:
    - HTTP transport for web integration
    - CORS for browser access
    - Authentication (optional)
    - Rate limiting
    """
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8814,
                 path: str = "/fortigate-mcp"):
        """
        Initialize the HTTP MCP server.
        
        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        if not FASTMCP_AVAILABLE:
            raise RuntimeError("FastMCP is not available. Please install fastmcp package.")
            
        # Load and validate configuration
        self.config = load_config(config_path)
        
        # Setup logging
        self.logger = setup_logging(self.config.logging)
        
        self.host = host
        self.port = port
        self.path = path
        
        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
        # Test connection on startup
        self._test_initial_connection()
        
        # Initialize tools
        self.device_tools = DeviceTools(self.fortigate_manager)
        self.firewall_tools = FirewallTools(self.fortigate_manager)
        self.network_tools = NetworkTools(self.fortigate_manager)
        self.routing_tools = RoutingTools(self.fortigate_manager)
        self.virtual_ip_tools = VirtualIPTools(self.fortigate_manager)
        self.certificate_tools = CertificateTools(self.fortigate_manager)

        # Initialize ACME tools with config from environment or config file
        acme_config = {
            "cloudflare_api_token": (
                self.config.acme.cloudflare_api_token or
                os.environ.get("CLOUDFLARE_API_TOKEN")
            ),
            "acme_email": (
                self.config.acme.email or
                os.environ.get("ACME_EMAIL")
            ),
            "acme_account_key_path": (
                self.config.acme.account_key_path or
                os.environ.get("ACME_ACCOUNT_KEY_PATH")
            )
        }
        self.acme_tools = ACMETools(self.fortigate_manager, acme_config)
        self.fabric_tools = FabricTools(self.fortigate_manager)
        self.packet_capture_tools = PacketCaptureTools(self.fortigate_manager)
        self.ipsec_tools = IPSecTools(self.fortigate_manager)

        # Initialize FortiManager
        self.fmg_manager = FortiManagerManager()
        self.fmg_tools = FortiManagerTools(self.fmg_manager)

        # Initialize FortiAnalyzer
        self.faz_manager = FortiAnalyzerManager()
        self.faz_tools = FortiAnalyzerTools(self.faz_manager)

        # Initialize FastMCP
        self.mcp = FastMCP("FortiGateMCP-HTTP")
        
        # Setup tools
        self._setup_tools()

    def _test_initial_connection(self) -> None:
        """Test initial FortiGate connection."""
        try:
            self.logger.info("Testing initial FortiGate connections...")
            devices = self.fortigate_manager.list_devices()
            
            for device_id in devices:
                try:
                    api_client = self.fortigate_manager.get_device(device_id)
                    success = api_client.test_connection()
                    if success:
                        self.logger.info(f"Successfully connected to device: {device_id}")
                    else:
                        self.logger.warning(f"Connection test failed for device: {device_id}")
                except Exception as e:
                    self.logger.error(f"Connection test error for device {device_id}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Initial connection test error: {e}")

    def _setup_tools(self) -> None:
        """Register MCP tools with appropriate descriptions."""
        
        # Device tools
        @self.mcp.tool(description="List all registered FortiGate devices")
        def list_devices():
            return self.device_tools.list_devices()

        @self.mcp.tool(description="Get device system status")
        def get_device_status(device_id: str):
            return self.device_tools.get_device_status(device_id)

        @self.mcp.tool(description="Test device connection")
        def test_device_connection(device_id: str):
            return self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description="Discover device VDOMs")
        def discover_vdoms(device_id: str):
            return self.device_tools.discover_vdoms(device_id)

        @self.mcp.tool(description="Add a new FortiGate device")
        def add_device(device_id: str, host: str, port: int = 443,
                      username: Optional[str] = None, password: Optional[str] = None,
                      api_token: Optional[str] = None, vdom: str = "root",
                      verify_ssl: bool = False, timeout: int = 30):
            return self.device_tools.add_device(device_id, host, port, username, password,
                                              api_token, vdom, verify_ssl, timeout)

        @self.mcp.tool(description="Remove a FortiGate device")
        def remove_device(device_id: str):
            return self.device_tools.remove_device(device_id)

        # Firewall tools
        @self.mcp.tool(description="List firewall policies")
        def list_firewall_policies(device_id: str, vdom: Optional[str] = None):
            return self.firewall_tools.list_policies(device_id, vdom)

        @self.mcp.tool(description="Create firewall policy")
        def create_firewall_policy(device_id: str, policy_data: dict, vdom: Optional[str] = None):
            return self.firewall_tools.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description="Update firewall policy")
        def update_firewall_policy(device_id: str, policy_id: str, policy_data: dict, vdom: Optional[str] = None):
            return self.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        def get_firewall_policy_detail(device_id: str, policy_id: str, vdom: Optional[str] = None):
            return self.firewall_tools.get_policy_detail(device_id, policy_id, vdom)

        @self.mcp.tool(description="Delete firewall policy")
        def delete_firewall_policy(device_id: str, policy_id: str, vdom: Optional[str] = None):
            return self.firewall_tools.delete_policy(device_id, policy_id, vdom)

        # Network tools
        @self.mcp.tool(description="List address objects")
        def list_address_objects(device_id: str, vdom: Optional[str] = None):
            return self.network_tools.list_address_objects(device_id, vdom)

        @self.mcp.tool(description="Create address object")
        def create_address_object(device_id: str, name: str, address_type: str, address: str, vdom: Optional[str] = None):
            return self.network_tools.create_address_object(device_id, name, address_type, address, vdom)

        @self.mcp.tool(description="List service objects")
        def list_service_objects(device_id: str, vdom: Optional[str] = None):
            return self.network_tools.list_service_objects(device_id, vdom)

        @self.mcp.tool(description="Create service object")
        def create_service_object(device_id: str, name: str, service_type: str, protocol: str, 
                                port: Optional[str] = None, vdom: Optional[str] = None):
            return self.network_tools.create_service_object(device_id, name, service_type, protocol, port, vdom)

        # Routing tools
        @self.mcp.tool(description="List static routes")
        def list_static_routes(device_id: str, vdom: Optional[str] = None):
            return self.routing_tools.list_static_routes(device_id, vdom)

        @self.mcp.tool(description="Create static route")
        def create_static_route(device_id: str, dst: str, gateway: str, device: Optional[str] = None, vdom: Optional[str] = None):
            return self.routing_tools.create_static_route(device_id, dst, gateway, device, vdom)

        @self.mcp.tool(description="Get routing table")
        def get_routing_table(device_id: str, vdom: Optional[str] = None):
            return self.routing_tools.get_routing_table(device_id, vdom)

        @self.mcp.tool(description="List network interfaces")
        def list_interfaces(device_id: str, vdom: Optional[str] = None):
            return self.routing_tools.list_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get interface status")
        def get_interface_status(device_id: str, interface_name: str, vdom: Optional[str] = None):
            return self.routing_tools.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description="Update static route")
        def update_static_route(device_id: str, route_id: str, route_data: dict, vdom: Optional[str] = None):
            return self.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description="Delete static route")
        def delete_static_route(device_id: str, route_id: str, vdom: Optional[str] = None):
            return self.routing_tools.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description="Get static route detail")
        def get_static_route_detail(device_id: str, route_id: str, vdom: Optional[str] = None):
            return self.routing_tools.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description="List virtual IPs")
        def list_virtual_ips(device_id: str, vdom: Optional[str] = None):
            return self.virtual_ip_tools.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description="Create virtual IP")
        def create_virtual_ip(device_id: str, name: str, extip: str, mappedip: str, 
                             extintf: str, portforward: str = "disable", 
                             protocol: str = "tcp", extport: Optional[str] = None,
                             mappedport: Optional[str] = None, vdom: Optional[str] = None):
            return self.virtual_ip_tools.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description="Update virtual IP")
        def update_virtual_ip(device_id: str, name: str, vip_data: dict, vdom: Optional[str] = None):
            return self.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description="Get virtual IP detail")
        def get_virtual_ip_detail(device_id: str, name: str, vdom: Optional[str] = None):
            return self.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description="Delete virtual IP")
        def delete_virtual_ip(device_id: str, name: str, vdom: Optional[str] = None):
            return self.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

        # Certificate tools
        @self.mcp.tool(description="List local (device) certificates")
        def list_local_certificates(device_id: str, vdom: Optional[str] = None):
            return self.certificate_tools.list_local_certificates(device_id, vdom)

        @self.mcp.tool(description="List CA certificates")
        def list_ca_certificates(device_id: str, vdom: Optional[str] = None):
            return self.certificate_tools.list_ca_certificates(device_id, vdom)

        @self.mcp.tool(description="List remote certificates")
        def list_remote_certificates(device_id: str, vdom: Optional[str] = None):
            return self.certificate_tools.list_remote_certificates(device_id, vdom)

        @self.mcp.tool(description="Get local certificate detail")
        def get_local_certificate_detail(device_id: str, cert_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.get_local_certificate_detail(device_id, cert_name, vdom)

        @self.mcp.tool(description="Get CA certificate detail")
        def get_ca_certificate_detail(device_id: str, cert_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.get_ca_certificate_detail(device_id, cert_name, vdom)

        @self.mcp.tool(description="Get remote certificate detail")
        def get_remote_certificate_detail(device_id: str, cert_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.get_remote_certificate_detail(device_id, cert_name, vdom)

        @self.mcp.tool(description="List certificate revocation lists (CRLs)")
        def list_crl(device_id: str, vdom: Optional[str] = None):
            return self.certificate_tools.list_crl(device_id, vdom)

        @self.mcp.tool(description="Get CRL detail")
        def get_crl_detail(device_id: str, crl_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.get_crl_detail(device_id, crl_name, vdom)

        @self.mcp.tool(description="Delete local certificate")
        def delete_local_certificate(device_id: str, cert_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.delete_local_certificate(device_id, cert_name, vdom)

        @self.mcp.tool(description="Delete CA certificate")
        def delete_ca_certificate(device_id: str, cert_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.delete_ca_certificate(device_id, cert_name, vdom)

        @self.mcp.tool(description="Delete remote certificate")
        def delete_remote_certificate(device_id: str, cert_name: str, vdom: Optional[str] = None):
            return self.certificate_tools.delete_remote_certificate(device_id, cert_name, vdom)

        # ACME/Let's Encrypt tools
        @self.mcp.tool(description="Request a Let's Encrypt certificate using Cloudflare DNS challenge")
        def request_certificate(
            domains: list,
            email: Optional[str] = None,
            cloudflare_api_token: Optional[str] = None,
            key_type: str = "rsa",
            key_size: int = 2048,
            staging: bool = False
        ):
            return self.acme_tools.request_certificate(
                domains, email, cloudflare_api_token, key_type, key_size, staging
            )

        @self.mcp.tool(description="Request Let's Encrypt certificate and import to FortiGate")
        def request_and_import_certificate(
            device_id: str,
            domains: list,
            cert_name: str,
            email: Optional[str] = None,
            cloudflare_api_token: Optional[str] = None,
            key_type: str = "rsa",
            key_size: int = 2048,
            staging: bool = False,
            vdom: Optional[str] = None
        ):
            return self.acme_tools.request_and_import_certificate(
                device_id, domains, cert_name, email, cloudflare_api_token,
                key_type, key_size, staging, vdom
            )

        @self.mcp.tool(description="Import an existing certificate to FortiGate")
        def import_certificate(
            device_id: str,
            cert_name: str,
            certificate: str,
            private_key: str,
            password: Optional[str] = None,
            vdom: Optional[str] = None
        ):
            return self.acme_tools.import_certificate(
                device_id, cert_name, certificate, private_key, password, vdom
            )

        @self.mcp.tool(description="Import a CA certificate to FortiGate")
        def import_ca_certificate(
            device_id: str,
            cert_name: str,
            certificate: str,
            vdom: Optional[str] = None
        ):
            return self.acme_tools.import_ca_certificate(device_id, cert_name, certificate, vdom)

        @self.mcp.tool(description="List Cloudflare zones available for DNS challenges")
        def list_cloudflare_zones(cloudflare_api_token: Optional[str] = None):
            return self.acme_tools.list_cloudflare_zones(cloudflare_api_token)

        @self.mcp.tool(description="Verify Cloudflare API token is valid")
        def verify_cloudflare_token(cloudflare_api_token: Optional[str] = None):
            return self.acme_tools.verify_cloudflare_token(cloudflare_api_token)

        # Security Fabric tools
        @self.mcp.tool(description="Get Security Fabric configuration")
        def get_security_fabric_config(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_security_fabric_config(device_id, vdom)

        @self.mcp.tool(description="Get Security Fabric runtime status and topology")
        def get_security_fabric_status(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_security_fabric_status(device_id, vdom)

        @self.mcp.tool(description="Get list of Security Fabric devices")
        def get_fabric_devices(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_fabric_devices(device_id, vdom)

        @self.mcp.tool(description="Get SDN/cloud fabric connectors")
        def get_fabric_connectors(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_fabric_connectors(device_id, vdom)

        @self.mcp.tool(description="Get High Availability (HA) cluster status")
        def get_ha_status(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_ha_status(device_id, vdom)

        @self.mcp.tool(description="Get High Availability (HA) configuration")
        def get_ha_config(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_ha_config(device_id, vdom)

        @self.mcp.tool(description="Get comprehensive Security Fabric topology including all fabric members")
        def get_fabric_topology(device_id: str, vdom: Optional[str] = None):
            return self.fabric_tools.get_fabric_topology(device_id, vdom)

        # Packet Capture tools
        @self.mcp.tool(description="List all packet capture profiles on a FortiGate device")
        def list_packet_captures(device_id: str, vdom: Optional[str] = None):
            return self.packet_capture_tools.list_packet_captures(device_id, vdom)

        @self.mcp.tool(description="Create a packet capture profile with optional filters (interface, src_ip, dst_ip, protocol, port)")
        def create_packet_capture(
            device_id: str,
            interface: str = "any",
            host: Optional[str] = None,
            src_ip: Optional[str] = None,
            dst_ip: Optional[str] = None,
            protocol: Optional[str] = None,
            port: Optional[int] = None,
            max_packet_count: int = 10000,
            vdom: Optional[str] = None
        ):
            return self.packet_capture_tools.create_packet_capture(
                device_id, interface, host, src_ip, dst_ip, protocol, port, max_packet_count, vdom
            )

        @self.mcp.tool(description="Get status of a packet capture (packets captured, state, etc.)")
        def get_packet_capture_status(device_id: str, capture_id: int, vdom: Optional[str] = None):
            return self.packet_capture_tools.get_packet_capture_status(device_id, capture_id, vdom)

        @self.mcp.tool(description="Start a packet capture")
        def start_packet_capture(device_id: str, capture_id: int, vdom: Optional[str] = None):
            return self.packet_capture_tools.start_packet_capture(device_id, capture_id, vdom)

        @self.mcp.tool(description="Stop a packet capture")
        def stop_packet_capture(device_id: str, capture_id: int, vdom: Optional[str] = None):
            return self.packet_capture_tools.stop_packet_capture(device_id, capture_id, vdom)

        @self.mcp.tool(description="Download captured packets as PCAP")
        def download_packet_capture(device_id: str, capture_id: int, vdom: Optional[str] = None):
            return self.packet_capture_tools.download_packet_capture(device_id, capture_id, vdom)

        @self.mcp.tool(description="Delete a packet capture profile")
        def delete_packet_capture(device_id: str, capture_id: int, vdom: Optional[str] = None):
            return self.packet_capture_tools.delete_packet_capture(device_id, capture_id, vdom)

        @self.mcp.tool(description="Clear captured packets from a capture profile")
        def clear_packet_capture(device_id: str, capture_id: int, vdom: Optional[str] = None):
            return self.packet_capture_tools.clear_packet_capture(device_id, capture_id, vdom)

        @self.mcp.tool(description="Capture traffic via SSH using 'diagnose sniffer packet' for specified duration (default 2 min)")
        def capture_and_analyze(
            device_id: str,
            interface: str = "any",
            host: Optional[str] = None,
            src_ip: Optional[str] = None,
            dst_ip: Optional[str] = None,
            protocol: Optional[str] = None,
            port: Optional[int] = None,
            duration_seconds: int = 120,
            max_packet_count: int = 10000,
            verbose: int = 4,
            vdom: Optional[str] = None
        ):
            return self.packet_capture_tools.capture_and_analyze(
                device_id, interface, host, src_ip, dst_ip, protocol, port,
                duration_seconds, max_packet_count, verbose, vdom
            )

        # IPSec VPN tools - Phase 1 Configuration
        @self.mcp.tool(description="List IPSec VPN Phase 1 tunnel configurations")
        def list_ipsec_phase1(device_id: str, vdom: Optional[str] = None):
            return self.ipsec_tools.list_phase1_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get IPSec VPN Phase 1 tunnel detail")
        def get_ipsec_phase1(device_id: str, name: str, vdom: Optional[str] = None):
            return self.ipsec_tools.get_phase1_interface(device_id, name, vdom)

        @self.mcp.tool(description="Create IPSec VPN Phase 1 tunnel")
        def create_ipsec_phase1(device_id: str, phase1_data: dict, vdom: Optional[str] = None):
            return self.ipsec_tools.create_phase1_interface(device_id, phase1_data, vdom)

        @self.mcp.tool(description="Update IPSec VPN Phase 1 tunnel")
        def update_ipsec_phase1(device_id: str, name: str, phase1_data: dict, vdom: Optional[str] = None):
            return self.ipsec_tools.update_phase1_interface(device_id, name, phase1_data, vdom)

        @self.mcp.tool(description="Delete IPSec VPN Phase 1 tunnel")
        def delete_ipsec_phase1(device_id: str, name: str, vdom: Optional[str] = None):
            return self.ipsec_tools.delete_phase1_interface(device_id, name, vdom)

        # IPSec VPN tools - Phase 2 Configuration
        @self.mcp.tool(description="List IPSec VPN Phase 2 selector configurations")
        def list_ipsec_phase2(device_id: str, vdom: Optional[str] = None):
            return self.ipsec_tools.list_phase2_interfaces(device_id, vdom)

        @self.mcp.tool(description="Get IPSec VPN Phase 2 selector detail")
        def get_ipsec_phase2(device_id: str, name: str, vdom: Optional[str] = None):
            return self.ipsec_tools.get_phase2_interface(device_id, name, vdom)

        @self.mcp.tool(description="Create IPSec VPN Phase 2 selector")
        def create_ipsec_phase2(device_id: str, phase2_data: dict, vdom: Optional[str] = None):
            return self.ipsec_tools.create_phase2_interface(device_id, phase2_data, vdom)

        @self.mcp.tool(description="Update IPSec VPN Phase 2 selector")
        def update_ipsec_phase2(device_id: str, name: str, phase2_data: dict, vdom: Optional[str] = None):
            return self.ipsec_tools.update_phase2_interface(device_id, name, phase2_data, vdom)

        @self.mcp.tool(description="Delete IPSec VPN Phase 2 selector")
        def delete_ipsec_phase2(device_id: str, name: str, vdom: Optional[str] = None):
            return self.ipsec_tools.delete_phase2_interface(device_id, name, vdom)

        # IPSec VPN tools - Status and Diagnostics
        @self.mcp.tool(description="Get IPSec tunnel runtime status and traffic stats")
        def get_ipsec_tunnel_status(device_id: str, vdom: Optional[str] = None):
            return self.ipsec_tools.get_tunnel_status(device_id, vdom)

        @self.mcp.tool(description="Get IKE gateway list with negotiation details via SSH")
        def diagnose_ipsec_ike_gateways(device_id: str):
            return self.ipsec_tools.diagnose_ike_gateways(device_id)

        @self.mcp.tool(description="Get IPSec tunnel list with traffic statistics via SSH")
        def diagnose_ipsec_tunnels(device_id: str, tunnel_name: Optional[str] = None):
            return self.ipsec_tools.diagnose_tunnels(device_id, tunnel_name)

        @self.mcp.tool(description="Bring up an IPSec tunnel via SSH")
        def ipsec_tunnel_up(device_id: str, phase1_name: str):
            return self.ipsec_tools.tunnel_up(device_id, phase1_name)

        @self.mcp.tool(description="Bring down an IPSec tunnel via SSH")
        def ipsec_tunnel_down(device_id: str, phase1_name: str):
            return self.ipsec_tools.tunnel_down(device_id, phase1_name)

        @self.mcp.tool(description="Clear IKE gateway to force renegotiation via SSH")
        def clear_ipsec_ike_gateway(device_id: str, gateway_name: Optional[str] = None):
            return self.ipsec_tools.clear_ike_gateway(device_id, gateway_name)

        # IPSec VPN tools - Troubleshooting
        @self.mcp.tool(description="Comprehensive IPSec tunnel troubleshooting (config + status + diagnostics)")
        def troubleshoot_ipsec_tunnel(device_id: str, tunnel_name: str, vdom: Optional[str] = None):
            return self.ipsec_tools.troubleshoot_tunnel(device_id, tunnel_name, vdom)

        @self.mcp.tool(description="Get complete IPSec VPN summary for a device")
        def get_ipsec_vpn_summary(device_id: str, vdom: Optional[str] = None):
            return self.ipsec_tools.get_vpn_summary(device_id, vdom)

        # FortiManager tools
        @self.mcp.tool(description="List registered FortiManager instances")
        def fmg_list_managers():
            return self.fmg_tools.list_managers()

        @self.mcp.tool(description="Add a FortiManager instance")
        def fmg_add_manager(
            manager_id: str,
            host: str,
            api_token: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            port: int = 443,
            verify_ssl: bool = False,
            adom: str = "root"
        ):
            return self.fmg_tools.add_manager(
                manager_id, host, api_token, username, password, port, verify_ssl, adom
            )

        @self.mcp.tool(description="Remove a FortiManager instance")
        def fmg_remove_manager(manager_id: str):
            return self.fmg_tools.remove_manager(manager_id)

        @self.mcp.tool(description="Test FortiManager connection")
        def fmg_test_connection(manager_id: str):
            return self.fmg_tools.test_connection(manager_id)

        @self.mcp.tool(description="Get FortiManager system status")
        def fmg_get_system_status(manager_id: str):
            return self.fmg_tools.get_system_status(manager_id)

        @self.mcp.tool(description="Get FortiManager Administrative Domains (ADOMs)")
        def fmg_get_adoms(manager_id: str):
            return self.fmg_tools.get_adoms(manager_id)

        @self.mcp.tool(description="Get managed devices from FortiManager")
        def fmg_get_devices(manager_id: str, adom: Optional[str] = None):
            return self.fmg_tools.get_devices(manager_id, adom)

        @self.mcp.tool(description="Get device status from FortiManager")
        def fmg_get_device_status(manager_id: str, device_name: str, adom: Optional[str] = None):
            return self.fmg_tools.get_device_status(manager_id, device_name, adom)

        @self.mcp.tool(description="Get all managed devices status from FortiManager")
        def fmg_get_all_devices_status(manager_id: str, adom: Optional[str] = None):
            return self.fmg_tools.get_all_devices_status(manager_id, adom)

        @self.mcp.tool(description="Get policy packages from FortiManager")
        def fmg_get_policy_packages(manager_id: str, adom: Optional[str] = None):
            return self.fmg_tools.get_policy_packages(manager_id, adom)

        @self.mcp.tool(description="Get firewall policies from FortiManager policy package")
        def fmg_get_firewall_policies(manager_id: str, pkg_name: str, adom: Optional[str] = None):
            return self.fmg_tools.get_firewall_policies(manager_id, pkg_name, adom)

        @self.mcp.tool(description="Get address objects from FortiManager")
        def fmg_get_address_objects(manager_id: str, adom: Optional[str] = None):
            return self.fmg_tools.get_address_objects(manager_id, adom)

        @self.mcp.tool(description="Get service objects from FortiManager")
        def fmg_get_service_objects(manager_id: str, adom: Optional[str] = None):
            return self.fmg_tools.get_service_objects(manager_id, adom)

        @self.mcp.tool(description="Get certificates from managed device via FortiManager")
        def fmg_get_device_certificates(manager_id: str, device_name: str, adom: Optional[str] = None):
            return self.fmg_tools.get_device_certificates(manager_id, device_name, adom)

        @self.mcp.tool(description="Install policy package to device via FortiManager")
        def fmg_install_policy(
            manager_id: str,
            pkg_name: str,
            device_name: str,
            adom: Optional[str] = None,
            vdom: str = "root"
        ):
            return self.fmg_tools.install_policy(manager_id, pkg_name, device_name, adom, vdom)

        @self.mcp.tool(description="Get policy installation status from FortiManager")
        def fmg_get_install_status(manager_id: str, adom: Optional[str] = None):
            return self.fmg_tools.get_install_status(manager_id, adom)

        @self.mcp.tool(description="Get task status from FortiManager")
        def fmg_get_task_status(manager_id: str, task_id: int):
            return self.fmg_tools.get_task_status(manager_id, task_id)

        # FortiAnalyzer tools
        @self.mcp.tool(description="List registered FortiAnalyzer instances")
        def faz_list_analyzers():
            return self.faz_tools.list_analyzers()

        @self.mcp.tool(description="Add a FortiAnalyzer instance")
        def faz_add_analyzer(
            analyzer_id: str,
            host: str,
            api_token: Optional[str] = None,
            username: Optional[str] = None,
            password: Optional[str] = None,
            port: int = 443,
            verify_ssl: bool = False,
            adom: str = "root"
        ):
            return self.faz_tools.add_analyzer(
                analyzer_id, host, api_token, username, password, port, verify_ssl, adom
            )

        @self.mcp.tool(description="Remove a FortiAnalyzer instance")
        def faz_remove_analyzer(analyzer_id: str):
            return self.faz_tools.remove_analyzer(analyzer_id)

        @self.mcp.tool(description="Test FortiAnalyzer connection")
        def faz_test_connection(analyzer_id: str):
            return self.faz_tools.test_connection(analyzer_id)

        @self.mcp.tool(description="Get FortiAnalyzer system status")
        def faz_get_system_status(analyzer_id: str):
            return self.faz_tools.get_system_status(analyzer_id)

        @self.mcp.tool(description="Get FortiAnalyzer Administrative Domains (ADOMs)")
        def faz_get_adoms(analyzer_id: str):
            return self.faz_tools.get_adoms(analyzer_id)

        @self.mcp.tool(description="Get devices reporting logs to FortiAnalyzer")
        def faz_get_devices(analyzer_id: str, adom: Optional[str] = None):
            return self.faz_tools.get_devices(analyzer_id, adom)

        @self.mcp.tool(description="Get device log status from FortiAnalyzer")
        def faz_get_device_status(analyzer_id: str, device_name: str, adom: Optional[str] = None):
            return self.faz_tools.get_device_status(analyzer_id, device_name, adom)

        @self.mcp.tool(description="Search logs with filters (traffic, event, security, etc.)")
        def faz_search_logs(
            analyzer_id: str,
            log_type: str = "traffic",
            filter_expr: Optional[str] = None,
            time_range: Optional[str] = None,
            limit: int = 100,
            device: Optional[str] = None,
            adom: Optional[str] = None
        ):
            return self.faz_tools.search_logs(
                analyzer_id, log_type, filter_expr, time_range, limit, device, adom
            )

        @self.mcp.tool(description="Get log statistics and volume metrics")
        def faz_get_log_stats(
            analyzer_id: str,
            time_range: Optional[str] = None,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_log_stats(analyzer_id, time_range, adom)

        @self.mcp.tool(description="Get available log fields for a log type")
        def faz_get_log_fields(
            analyzer_id: str,
            log_type: str = "traffic",
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_log_fields(analyzer_id, log_type, adom)

        @self.mcp.tool(description="Get raw log data for a time range")
        def faz_get_raw_logs(
            analyzer_id: str,
            log_type: str = "traffic",
            time_range: Optional[str] = None,
            limit: int = 100,
            device: Optional[str] = None,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_raw_logs(
                analyzer_id, log_type, time_range, limit, device, adom
            )

        @self.mcp.tool(description="List available report templates")
        def faz_list_reports(analyzer_id: str, adom: Optional[str] = None):
            return self.faz_tools.list_reports(analyzer_id, adom)

        @self.mcp.tool(description="Run a report with specified parameters")
        def faz_run_report(
            analyzer_id: str,
            report_name: str,
            time_range: Optional[str] = None,
            devices: Optional[str] = None,
            output_format: str = "pdf",
            adom: Optional[str] = None
        ):
            return self.faz_tools.run_report(
                analyzer_id, report_name, time_range, devices, output_format, adom
            )

        @self.mcp.tool(description="Get report execution status")
        def faz_get_report_status(
            analyzer_id: str,
            task_id: int,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_report_status(analyzer_id, task_id, adom)

        @self.mcp.tool(description="Download completed report")
        def faz_download_report(
            analyzer_id: str,
            task_id: int,
            adom: Optional[str] = None
        ):
            return self.faz_tools.download_report(analyzer_id, task_id, adom)

        @self.mcp.tool(description="Get FortiView dashboard data")
        def faz_get_fortiview(
            analyzer_id: str,
            view_type: str,
            time_range: Optional[str] = None,
            filter_expr: Optional[str] = None,
            limit: int = 20,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_fortiview(
                analyzer_id, view_type, time_range, filter_expr, limit, adom
            )

        @self.mcp.tool(description="Get threat statistics and trends")
        def faz_get_threat_stats(
            analyzer_id: str,
            time_range: Optional[str] = None,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_threat_stats(analyzer_id, time_range, adom)

        @self.mcp.tool(description="Get top traffic sources")
        def faz_get_top_sources(
            analyzer_id: str,
            time_range: Optional[str] = None,
            limit: int = 20,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_top_sources(analyzer_id, time_range, limit, adom)

        @self.mcp.tool(description="Get top traffic destinations")
        def faz_get_top_destinations(
            analyzer_id: str,
            time_range: Optional[str] = None,
            limit: int = 20,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_top_destinations(analyzer_id, time_range, limit, adom)

        @self.mcp.tool(description="Get top applications by traffic")
        def faz_get_top_applications(
            analyzer_id: str,
            time_range: Optional[str] = None,
            limit: int = 20,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_top_applications(analyzer_id, time_range, limit, adom)

        @self.mcp.tool(description="Get event summary and counts")
        def faz_get_event_summary(
            analyzer_id: str,
            time_range: Optional[str] = None,
            adom: Optional[str] = None
        ):
            return self.faz_tools.get_event_summary(analyzer_id, time_range, adom)

        @self.mcp.tool(description="List active alerts")
        def faz_list_alerts(
            analyzer_id: str,
            severity: Optional[str] = None,
            status: Optional[str] = None,
            limit: int = 100,
            adom: Optional[str] = None
        ):
            return self.faz_tools.list_alerts(analyzer_id, severity, status, limit, adom)

        @self.mcp.tool(description="Acknowledge an alert")
        def faz_acknowledge_alert(
            analyzer_id: str,
            alert_id: str,
            adom: Optional[str] = None
        ):
            return self.faz_tools.acknowledge_alert(analyzer_id, alert_id, adom)

        # System tools
        @self.mcp.tool(description="Test FortiGate connection")
        def test_connection():
            try:
                devices = self.fortigate_manager.list_devices()
                connection_results = {}
                
                for device_id in devices:
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = api_client.test_connection()
                        connection_results[device_id] = {
                            "connected": success,
                            "status": "connected" if success else "failed"
                        }
                    except Exception as e:
                        connection_results[device_id] = {
                            "connected": False,
                            "status": "error",
                            "error": str(e)
                        }
                
                return self._format_response({
                    "devices": connection_results,
                    "total_devices": len(devices)
                }, "test_connection")
            except Exception as e:
                return self._format_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection")

        @self.mcp.tool(description="Health check for FortiGate MCP server")
        def health():
            health_info = {
                "status": "ok",
                "server": "FortiGateMCP-HTTP",
                "timestamp": datetime.now().isoformat(),
                "registered_devices": len(self.fortigate_manager.devices),
                "device_connections": {}
            }
            
            # Test device connections
            try:
                devices = self.fortigate_manager.list_devices()
                for device_id in devices:
                    try:
                        api_client = self.fortigate_manager.get_device(device_id)
                        success = api_client.test_connection()
                        health_info["device_connections"][device_id] = "connected" if success else "disconnected"
                    except Exception as e:
                        health_info["device_connections"][device_id] = "error"
                        health_info["status"] = "degraded"
            except Exception as e:
                health_info["status"] = "error"
                health_info["error"] = str(e)
            
            return self._format_response(health_info, "health")

        @self.mcp.tool(description="Get schema information for all available tools")
        def get_schema_info():
            schema_info = {
                "server": "FortiGateMCP-HTTP",
                "version": "0.1.0",
                "endpoint": f"http://{self.host}:{self.port}{self.path}",
                "tools": {
                    "device_tools": self.device_tools.get_schema_info(),
                    "firewall_tools": self.firewall_tools.get_schema_info(),
                    "network_tools": self.network_tools.get_schema_info(),
                    "routing_tools": self.routing_tools.get_schema_info(),
                    "virtual_ip_tools": self.virtual_ip_tools.get_schema_info(),
                    "certificate_tools": self.certificate_tools.get_schema_info(),
                    "acme_tools": self.acme_tools.get_schema_info(),
                    "fabric_tools": self.fabric_tools.get_schema_info(),
                    "packet_capture_tools": self.packet_capture_tools.get_schema_info(),
                    "ipsec_tools": self.ipsec_tools.get_schema_info(),
                    "fortimanager_tools": {
                        "name": "fortimanager_tools",
                        "description": "FortiManager centralized management tools",
                        "managers": self.fmg_manager.list_managers()
                    }
                }
            }
            return self._format_response(schema_info, "get_schema_info")

    def _format_response(self, data, operation: str = "operation"):
        """Format response data for MCP."""
        from mcp.types import TextContent as Content
        
        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def run(self) -> None:
        """
        Start the HTTP MCP server.
        
        Runs the server with HTTP transport on the configured
        host and port.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting FortiGate MCP HTTP server on {self.host}:{self.port}{self.path}")
            self.logger.info(f"Registered devices: {len(self.fortigate_manager.devices)}")
            
            # Run with FastMCP's built-in HTTP transport
            self.mcp.run(
                transport="http",
                host=self.host,
                port=self.port,
                path=self.path
            )
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            sys.exit(1)


class FortiGateMCPCommand:
    """
    Command runner for FortiGate MCP HTTP server.
    
    This class can be used as a standalone command runner.
    """
    
    help = "FortiGate MCP HTTP Server"
    
    def __init__(self):
        self.server = None
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8814,
            help='Server port (default: 8814)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/fortigate-mcp',
            help='HTTP path (default: /fortigate-mcp)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('FORTIGATE_MCP_CONFIG')
        
        self.server = FortiGateMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8814),
            path=options.get('path', '/fortigate-mcp')
        )
        
        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FortiGate MCP HTTP Server')
    command = FortiGateMCPCommand()
    command.add_arguments(parser)
    
    args = parser.parse_args()
    options = vars(args)
    
    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
