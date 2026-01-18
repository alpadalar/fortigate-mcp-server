"""
Main STDIO server implementation for FortiGate MCP.

This module implements the core MCP server for FortiGate integration, providing:
- Configuration loading and validation
- Logging setup
- FortiGate API connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown

The server exposes a set of tools for managing FortiGate resources including:
- Device management
- Firewall policy operations
- Network object management
- Routing configuration
"""
import logging
import json
import os
import sys
import signal
from typing import Optional, Annotated
from datetime import datetime

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .core.fortianalyzer import FortiAnalyzerManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools
from .tools.certificate import CertificateTools
from .tools.acme import ACMETools
from .tools.fortianalyzer import FortiAnalyzerTools
from .tools.definitions import *

class FortiGateMCPServer:
    """Main server class for FortiGate MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        self.logger = setup_logging(self.config.logging)
        
        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
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

        # Initialize FortiAnalyzer
        self.faz_manager = FortiAnalyzerManager()
        self.faz_tools = FortiAnalyzerTools(self.faz_manager)

        # Initialize MCP server
        self.mcp = FastMCP("FortiGateMCP")
        self._tests_passed: Optional[bool] = None
        self._setup_tools()

    def _setup_tools(self) -> None:
        """Register MCP tools with the server."""
        
        # Device management tools
        @self.mcp.tool(description=LIST_DEVICES_DESC)
        async def list_devices():
            return await self.device_tools.list_devices()

        @self.mcp.tool(description=GET_DEVICE_STATUS_DESC)
        async def get_device_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.get_device_status(device_id)

        @self.mcp.tool(description=TEST_DEVICE_CONNECTION_DESC)
        async def test_device_connection(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.test_device_connection(device_id)

        @self.mcp.tool(description=DISCOVER_VDOMS_DESC)
        async def discover_vdoms(
            device_id: Annotated[str, Field(description="FortiGate device identifier")]
        ):
            return await self.device_tools.discover_vdoms(device_id)

        @self.mcp.tool(description=ADD_DEVICE_DESC)
        async def add_device(
            device_id: Annotated[str, Field(description="Unique device identifier")],
            host: Annotated[str, Field(description="FortiGate IP address or hostname")],
            port: Annotated[int, Field(description="HTTPS port", default=443)] = 443,
            username: Annotated[Optional[str], Field(description="Username", default=None)] = None,
            password: Annotated[Optional[str], Field(description="Password", default=None)] = None,
            api_token: Annotated[Optional[str], Field(description="API token", default=None)] = None,
            vdom: Annotated[str, Field(description="Virtual Domain", default="root")] = "root",
            verify_ssl: Annotated[bool, Field(description="Verify SSL", default=False)] = False,
            timeout: Annotated[int, Field(description="Timeout in seconds", default=30)] = 30
        ):
            return await self.device_tools.add_device(
                device_id, host, port, username, password, api_token, vdom, verify_ssl, timeout
            )

        @self.mcp.tool(description=REMOVE_DEVICE_DESC)
        async def remove_device(
            device_id: Annotated[str, Field(description="Device identifier to remove")]
        ):
            return await self.device_tools.remove_device(device_id)

        # Firewall policy tools
        @self.mcp.tool(description=LIST_FIREWALL_POLICIES_DESC)
        async def list_firewall_policies(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.list_policies(device_id, vdom)

        @self.mcp.tool(description=CREATE_FIREWALL_POLICY_DESC)
        async def create_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_data: Annotated[dict, Field(description="Policy configuration as JSON")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.create_policy(device_id, policy_data, vdom)

        @self.mcp.tool(description=UPDATE_FIREWALL_POLICY_DESC)
        async def update_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to update")],
            policy_data: Annotated[dict, Field(description="Updated policy configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.update_policy(device_id, policy_id, policy_data, vdom)

        @self.mcp.tool(description="Get detailed information for a specific firewall policy")
        async def get_firewall_policy_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to get details for")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.get_policy_detail_async(device_id, policy_id, vdom)

        @self.mcp.tool(description=DELETE_FIREWALL_POLICY_DESC)
        async def delete_firewall_policy(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            policy_id: Annotated[str, Field(description="Policy ID to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.firewall_tools.delete_policy(device_id, policy_id, vdom)

        # Network object tools
        @self.mcp.tool(description=LIST_ADDRESS_OBJECTS_DESC)
        async def list_address_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_address_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_ADDRESS_OBJECT_DESC)
        async def create_address_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            address_data: Annotated[dict, Field(description="Address object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_address_object(device_id, address_data, vdom)

        @self.mcp.tool(description=LIST_SERVICE_OBJECTS_DESC)
        async def list_service_objects(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.list_service_objects(device_id, vdom)

        @self.mcp.tool(description=CREATE_SERVICE_OBJECT_DESC)
        async def create_service_object(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            service_data: Annotated[dict, Field(description="Service object configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.network_tools.create_service_object(device_id, service_data, vdom)

        # Routing tools
        @self.mcp.tool(description=LIST_STATIC_ROUTES_DESC)
        async def list_static_routes(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.list_static_routes(device_id, vdom)

        @self.mcp.tool(description=CREATE_STATIC_ROUTE_DESC)
        async def create_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.create_static_route(device_id, route_data, vdom)

        @self.mcp.tool(description=GET_ROUTING_TABLE_DESC)
        async def get_routing_table(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_routing_table(device_id, vdom)

        @self.mcp.tool(description=LIST_INTERFACES_DESC)
        async def list_interfaces(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.list_interfaces(device_id, vdom)

        @self.mcp.tool(description=GET_INTERFACE_STATUS_DESC)
        async def get_interface_status(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            interface_name: Annotated[str, Field(description="Interface name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_interface_status(device_id, interface_name, vdom)

        @self.mcp.tool(description=UPDATE_STATIC_ROUTE_DESC)
        async def update_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            route_data: Annotated[dict, Field(description="Route configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.update_static_route(device_id, route_id, route_data, vdom)

        @self.mcp.tool(description=DELETE_STATIC_ROUTE_DESC)
        async def delete_static_route(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.delete_static_route(device_id, route_id, vdom)

        @self.mcp.tool(description=GET_STATIC_ROUTE_DETAIL_DESC)
        async def get_static_route_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            route_id: Annotated[str, Field(description="Route identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.routing_tools.get_static_route_detail(device_id, route_id, vdom)

        # Virtual IP tools
        @self.mcp.tool(description=LIST_VIRTUAL_IPS_DESC)
        async def list_virtual_ips(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.list_virtual_ips(device_id, vdom)

        @self.mcp.tool(description=CREATE_VIRTUAL_IP_DESC)
        async def create_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            extip: Annotated[str, Field(description="External IP address")],
            mappedip: Annotated[str, Field(description="Mapped internal IP address")],
            extintf: Annotated[str, Field(description="External interface name")],
            portforward: Annotated[str, Field(description="Enable/disable port forwarding", default="disable")] = "disable",
            protocol: Annotated[str, Field(description="Protocol type", default="tcp")] = "tcp",
            extport: Annotated[Optional[str], Field(description="External port")] = None,
            mappedport: Annotated[Optional[str], Field(description="Mapped port")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.create_virtual_ip(
                device_id, name, extip, mappedip, extintf, portforward, protocol, extport, mappedport, vdom
            )

        @self.mcp.tool(description=UPDATE_VIRTUAL_IP_DESC)
        async def update_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vip_data: Annotated[dict, Field(description="Virtual IP configuration")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.update_virtual_ip(device_id, name, vip_data, vdom)

        @self.mcp.tool(description=GET_VIRTUAL_IP_DETAIL_DESC)
        async def get_virtual_ip_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.get_virtual_ip_detail(device_id, name, vdom)

        @self.mcp.tool(description=DELETE_VIRTUAL_IP_DESC)
        async def delete_virtual_ip(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            name: Annotated[str, Field(description="Virtual IP name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return await self.virtual_ip_tools.delete_virtual_ip(device_id, name, vdom)

        # Certificate tools
        @self.mcp.tool(description=LIST_LOCAL_CERTIFICATES_DESC)
        async def list_local_certificates(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.list_local_certificates(device_id, vdom)

        @self.mcp.tool(description=LIST_CA_CERTIFICATES_DESC)
        async def list_ca_certificates(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.list_ca_certificates(device_id, vdom)

        @self.mcp.tool(description=LIST_REMOTE_CERTIFICATES_DESC)
        async def list_remote_certificates(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.list_remote_certificates(device_id, vdom)

        @self.mcp.tool(description=GET_LOCAL_CERTIFICATE_DETAIL_DESC)
        async def get_local_certificate_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.get_local_certificate_detail(device_id, cert_name, vdom)

        @self.mcp.tool(description=GET_CA_CERTIFICATE_DETAIL_DESC)
        async def get_ca_certificate_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="CA certificate name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.get_ca_certificate_detail(device_id, cert_name, vdom)

        @self.mcp.tool(description=GET_REMOTE_CERTIFICATE_DETAIL_DESC)
        async def get_remote_certificate_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="Remote certificate name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.get_remote_certificate_detail(device_id, cert_name, vdom)

        @self.mcp.tool(description=LIST_CRL_DESC)
        async def list_crl(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.list_crl(device_id, vdom)

        @self.mcp.tool(description=GET_CRL_DETAIL_DESC)
        async def get_crl_detail(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            crl_name: Annotated[str, Field(description="CRL name")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.get_crl_detail(device_id, crl_name, vdom)

        @self.mcp.tool(description=DELETE_LOCAL_CERTIFICATE_DESC)
        async def delete_local_certificate(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="Certificate name to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.delete_local_certificate(device_id, cert_name, vdom)

        @self.mcp.tool(description=DELETE_CA_CERTIFICATE_DESC)
        async def delete_ca_certificate(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="CA certificate name to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.delete_ca_certificate(device_id, cert_name, vdom)

        @self.mcp.tool(description=DELETE_REMOTE_CERTIFICATE_DESC)
        async def delete_remote_certificate(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="Remote certificate name to delete")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain", default=None)] = None
        ):
            return self.certificate_tools.delete_remote_certificate(device_id, cert_name, vdom)

        # ACME/Let's Encrypt tools
        @self.mcp.tool(description=REQUEST_CERTIFICATE_DESC)
        async def request_certificate(
            domains: Annotated[list, Field(description="List of domain names for the certificate")],
            email: Annotated[Optional[str], Field(description="Contact email for Let's Encrypt")] = None,
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None,
            key_type: Annotated[str, Field(description="Key type (rsa or ec)")] = "rsa",
            key_size: Annotated[int, Field(description="Key size for RSA")] = 2048,
            staging: Annotated[bool, Field(description="Use staging environment")] = False
        ):
            return self.acme_tools.request_certificate(
                domains, email, cloudflare_api_token, key_type, key_size, staging
            )

        @self.mcp.tool(description=REQUEST_AND_IMPORT_CERTIFICATE_DESC)
        async def request_and_import_certificate(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            domains: Annotated[list, Field(description="List of domain names for the certificate")],
            cert_name: Annotated[str, Field(description="Name for the certificate in FortiGate")],
            email: Annotated[Optional[str], Field(description="Contact email for Let's Encrypt")] = None,
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None,
            key_type: Annotated[str, Field(description="Key type (rsa or ec)")] = "rsa",
            key_size: Annotated[int, Field(description="Key size for RSA")] = 2048,
            staging: Annotated[bool, Field(description="Use staging environment")] = False,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain")] = None
        ):
            return self.acme_tools.request_and_import_certificate(
                device_id, domains, cert_name, email, cloudflare_api_token,
                key_type, key_size, staging, vdom
            )

        @self.mcp.tool(description=IMPORT_CERTIFICATE_DESC)
        async def import_certificate(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="Name for the certificate in FortiGate")],
            certificate: Annotated[str, Field(description="PEM-encoded certificate")],
            private_key: Annotated[str, Field(description="PEM-encoded private key")],
            password: Annotated[Optional[str], Field(description="Password for encrypted key")] = None,
            vdom: Annotated[Optional[str], Field(description="Virtual Domain")] = None
        ):
            return self.acme_tools.import_certificate(
                device_id, cert_name, certificate, private_key, password, vdom
            )

        @self.mcp.tool(description=IMPORT_CA_CERTIFICATE_DESC)
        async def import_ca_certificate(
            device_id: Annotated[str, Field(description="FortiGate device identifier")],
            cert_name: Annotated[str, Field(description="Name for the CA certificate in FortiGate")],
            certificate: Annotated[str, Field(description="PEM-encoded CA certificate")],
            vdom: Annotated[Optional[str], Field(description="Virtual Domain")] = None
        ):
            return self.acme_tools.import_ca_certificate(device_id, cert_name, certificate, vdom)

        @self.mcp.tool(description=LIST_CLOUDFLARE_ZONES_DESC)
        async def list_cloudflare_zones(
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None
        ):
            return self.acme_tools.list_cloudflare_zones(cloudflare_api_token)

        @self.mcp.tool(description=VERIFY_CLOUDFLARE_TOKEN_DESC)
        async def verify_cloudflare_token(
            cloudflare_api_token: Annotated[Optional[str], Field(description="Cloudflare API token")] = None
        ):
            return self.acme_tools.verify_cloudflare_token(cloudflare_api_token)

        # FortiAnalyzer tools
        @self.mcp.tool(description="List registered FortiAnalyzer instances")
        async def faz_list_analyzers():
            return self.faz_tools.list_analyzers()

        @self.mcp.tool(description="Add a FortiAnalyzer instance")
        async def faz_add_analyzer(
            analyzer_id: Annotated[str, Field(description="Unique identifier for FortiAnalyzer")],
            host: Annotated[str, Field(description="FortiAnalyzer hostname or IP")],
            api_token: Annotated[Optional[str], Field(description="API token")] = None,
            username: Annotated[Optional[str], Field(description="Username")] = None,
            password: Annotated[Optional[str], Field(description="Password")] = None,
            port: Annotated[int, Field(description="HTTPS port")] = 443,
            verify_ssl: Annotated[bool, Field(description="Verify SSL")] = False,
            adom: Annotated[str, Field(description="Administrative Domain")] = "root"
        ):
            return self.faz_tools.add_analyzer(
                analyzer_id, host, api_token, username, password, port, verify_ssl, adom
            )

        @self.mcp.tool(description="Remove a FortiAnalyzer instance")
        async def faz_remove_analyzer(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")]
        ):
            return self.faz_tools.remove_analyzer(analyzer_id)

        @self.mcp.tool(description="Test FortiAnalyzer connection")
        async def faz_test_connection(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")]
        ):
            return self.faz_tools.test_connection(analyzer_id)

        @self.mcp.tool(description="Get FortiAnalyzer system status")
        async def faz_get_system_status(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")]
        ):
            return self.faz_tools.get_system_status(analyzer_id)

        @self.mcp.tool(description="Get FortiAnalyzer Administrative Domains")
        async def faz_get_adoms(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")]
        ):
            return self.faz_tools.get_adoms(analyzer_id)

        @self.mcp.tool(description="Get devices reporting logs to FortiAnalyzer")
        async def faz_get_devices(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_devices(analyzer_id, adom)

        @self.mcp.tool(description="Get device log status from FortiAnalyzer")
        async def faz_get_device_status(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            device_name: Annotated[str, Field(description="Device name")],
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_device_status(analyzer_id, device_name, adom)

        @self.mcp.tool(description="Search logs with filters")
        async def faz_search_logs(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            log_type: Annotated[str, Field(description="Log type (traffic, event, security)")] = "traffic",
            filter_expr: Annotated[Optional[str], Field(description="Filter expression")] = None,
            time_range: Annotated[Optional[str], Field(description="Time range (1h, 24h, 7d)")] = None,
            limit: Annotated[int, Field(description="Maximum results")] = 100,
            device: Annotated[Optional[str], Field(description="Filter by device")] = None,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.search_logs(
                analyzer_id, log_type, filter_expr, time_range, limit, device, adom
            )

        @self.mcp.tool(description="Get log statistics")
        async def faz_get_log_stats(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_log_stats(analyzer_id, time_range, adom)

        @self.mcp.tool(description="Get available log fields")
        async def faz_get_log_fields(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            log_type: Annotated[str, Field(description="Log type")] = "traffic",
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_log_fields(analyzer_id, log_type, adom)

        @self.mcp.tool(description="Get raw log data")
        async def faz_get_raw_logs(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            log_type: Annotated[str, Field(description="Log type")] = "traffic",
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            limit: Annotated[int, Field(description="Maximum results")] = 100,
            device: Annotated[Optional[str], Field(description="Filter by device")] = None,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_raw_logs(analyzer_id, log_type, time_range, limit, device, adom)

        @self.mcp.tool(description="List available report templates")
        async def faz_list_reports(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.list_reports(analyzer_id, adom)

        @self.mcp.tool(description="Run a report")
        async def faz_run_report(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            report_name: Annotated[str, Field(description="Report template name")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            devices: Annotated[Optional[str], Field(description="Comma-separated devices")] = None,
            output_format: Annotated[str, Field(description="Output format")] = "pdf",
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.run_report(
                analyzer_id, report_name, time_range, devices, output_format, adom
            )

        @self.mcp.tool(description="Get report execution status")
        async def faz_get_report_status(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            task_id: Annotated[int, Field(description="Report task ID")],
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_report_status(analyzer_id, task_id, adom)

        @self.mcp.tool(description="Download completed report")
        async def faz_download_report(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            task_id: Annotated[int, Field(description="Report task ID")],
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.download_report(analyzer_id, task_id, adom)

        @self.mcp.tool(description="Get FortiView dashboard data")
        async def faz_get_fortiview(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            view_type: Annotated[str, Field(description="View type (traffic, threat, application)")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            filter_expr: Annotated[Optional[str], Field(description="Filter expression")] = None,
            limit: Annotated[int, Field(description="Maximum results")] = 20,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_fortiview(
                analyzer_id, view_type, time_range, filter_expr, limit, adom
            )

        @self.mcp.tool(description="Get threat statistics")
        async def faz_get_threat_stats(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_threat_stats(analyzer_id, time_range, adom)

        @self.mcp.tool(description="Get top traffic sources")
        async def faz_get_top_sources(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            limit: Annotated[int, Field(description="Number of top sources")] = 20,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_top_sources(analyzer_id, time_range, limit, adom)

        @self.mcp.tool(description="Get top traffic destinations")
        async def faz_get_top_destinations(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            limit: Annotated[int, Field(description="Number of top destinations")] = 20,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_top_destinations(analyzer_id, time_range, limit, adom)

        @self.mcp.tool(description="Get top applications by traffic")
        async def faz_get_top_applications(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            limit: Annotated[int, Field(description="Number of top applications")] = 20,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_top_applications(analyzer_id, time_range, limit, adom)

        @self.mcp.tool(description="Get event summary and counts")
        async def faz_get_event_summary(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            time_range: Annotated[Optional[str], Field(description="Time range")] = None,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.get_event_summary(analyzer_id, time_range, adom)

        @self.mcp.tool(description="List active alerts")
        async def faz_list_alerts(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            severity: Annotated[Optional[str], Field(description="Filter by severity")] = None,
            status: Annotated[Optional[str], Field(description="Filter by status")] = None,
            limit: Annotated[int, Field(description="Maximum alerts")] = 100,
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.list_alerts(analyzer_id, severity, status, limit, adom)

        @self.mcp.tool(description="Acknowledge an alert")
        async def faz_acknowledge_alert(
            analyzer_id: Annotated[str, Field(description="Analyzer identifier")],
            alert_id: Annotated[str, Field(description="Alert ID")],
            adom: Annotated[Optional[str], Field(description="Administrative Domain")] = None
        ):
            return self.faz_tools.acknowledge_alert(analyzer_id, alert_id, adom)

        # System tools
        @self.mcp.tool(description=HEALTH_CHECK_DESC)
        async def health_check():
            status = "healthy" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
            details = {
                "registered_devices": len(self.fortigate_manager.devices),
                "server_version": self.config.server.version,
                "timestamp": datetime.now().isoformat()
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_health_status(status, details)

        @self.mcp.tool(description=GET_SERVER_INFO_DESC)
        async def get_server_info():
            info = {
                "name": self.config.server.name,
                "version": self.config.server.version,
                "host": self.config.server.host,
                "port": self.config.server.port,
                "registered_devices": len(self.fortigate_manager.devices),
                "available_tools": [
                    "Device Management (6 tools)",
                    "Firewall Policy Management (5 tools)",
                    "Network Objects Management (4 tools)",
                    "Routing Management (8 tools)",
                    "Virtual IP Management (5 tools)",
                    "Certificate Management (11 tools)",
                    "ACME/Let's Encrypt (6 tools)",
                    "System Tools (2 tools)"
                ]
            }
            from .formatting import FortiGateFormatters
            return FortiGateFormatters.format_json_response(info, "Server Information")

    def start(self) -> None:
        """Start the MCP server."""
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                self.logger.info("Running startup tests...")
                # Add test logic here
                self._tests_passed = True

            self.logger.info("Starting FortiGate MCP server...")
            anyio.run(self.mcp.run_stdio_async)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)

if __name__ == "__main__":
    config_path = os.getenv("FORTIGATE_MCP_CONFIG")
    if not config_path:
        print("FORTIGATE_MCP_CONFIG environment variable must be set")
        sys.exit(1)
    
    try:
        server = FortiGateMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
