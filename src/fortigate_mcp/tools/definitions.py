"""
Tool definitions and descriptions for FortiGate MCP tools.

This module contains the descriptions and metadata for all MCP tools
provided by the FortiGate MCP server. These descriptions are used
for tool registration and help documentation.
"""

# Device Management Tool Descriptions
LIST_DEVICES_DESC = """
List all registered FortiGate devices with their configuration details.

This tool displays information about all FortiGate devices that are currently
registered with the MCP server, including connection details, authentication
methods, and status information.

Returns:
- Device ID and name
- Host address and port
- VDOM configuration
- Authentication method
- SSL verification status
"""

GET_DEVICE_STATUS_DESC = """
Get detailed system status information for a specific FortiGate device.

This tool retrieves comprehensive system information from a FortiGate device,
including hardware details, software version, hostname, and operational status.

Parameters:
- device_id: Identifier of the FortiGate device to query

Returns:
- Device model and serial number
- Software version and build
- System hostname
- Current operational status
- Virtual Domain information
"""

TEST_DEVICE_CONNECTION_DESC = """
Test network connectivity to a specific FortiGate device.

This tool performs a connection test to verify that the MCP server can
successfully communicate with the specified FortiGate device.

Parameters:
- device_id: Identifier of the FortiGate device to test

Returns:
- Connection status (success/failure)
- Response time information
- Error details if connection fails
"""

ADD_DEVICE_DESC = """
Add a new FortiGate device to the MCP server.

This tool registers a new FortiGate device with the server, configuring
connection parameters and authentication credentials.

Parameters:
- device_id: Unique identifier for the new device
- host: IP address or hostname of the FortiGate device
- port: HTTPS port (default: 443)
- username: Username for authentication (if not using API token)
- password: Password for authentication (if not using API token)
- api_token: API token for authentication (preferred method)
- vdom: Virtual Domain name (default: "root")
- verify_ssl: Whether to verify SSL certificates (default: false)
- timeout: Connection timeout in seconds (default: 30)

Returns:
- Registration status
- Device configuration summary
"""

REMOVE_DEVICE_DESC = """
Remove a FortiGate device from the MCP server.

This tool unregisters a FortiGate device from the server, removing
all associated configuration and terminating active connections.

Parameters:
- device_id: Identifier of the device to remove

Returns:
- Removal status confirmation
"""

DISCOVER_VDOMS_DESC = """
Discover and list all Virtual Domains (VDOMs) on a FortiGate device.

This tool queries the specified FortiGate device to retrieve information
about all configured Virtual Domains, including their status and settings.

Parameters:
- device_id: Identifier of the FortiGate device to query

Returns:
- List of VDOMs with their configuration
- VDOM status (enabled/disabled)
- Resource allocation information
"""

# Firewall Policy Tool Descriptions
LIST_FIREWALL_POLICIES_DESC = """
List all firewall policies configured on a FortiGate device.

This tool retrieves and displays all firewall security policies from the
specified device and Virtual Domain, showing traffic control rules and settings.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Policy ID and name
- Source and destination addresses
- Services and ports
- Action (allow/deny)
- Policy status (enabled/disabled)
"""

CREATE_FIREWALL_POLICY_DESC = """
Create a new firewall policy on a FortiGate device.

This tool adds a new security policy to control traffic flow through
the FortiGate device, defining rules for source, destination, and services.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_data: Policy configuration as JSON object
- vdom: Virtual Domain name (optional, uses device default)

Policy data should include:
- name: Policy name
- srcintf: Source interface(s)
- dstintf: Destination interface(s)
- srcaddr: Source address object(s)
- dstaddr: Destination address object(s)
- service: Service object(s)
- action: accept or deny

Returns:
- Creation status
- Policy ID assigned
- Configuration summary
"""

UPDATE_FIREWALL_POLICY_DESC = """
Update an existing firewall policy on a FortiGate device.

This tool modifies the configuration of an existing firewall policy,
allowing changes to rules, addresses, services, and other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_id: ID of the policy to update
- policy_data: Updated policy configuration as JSON object
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

DELETE_FIREWALL_POLICY_DESC = """
Delete a firewall policy from a FortiGate device.

This tool removes an existing firewall policy from the device configuration,
permanently deleting the specified security rule.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_id: ID of the policy to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

VALIDATE_FIREWALL_POLICY_DESC = """
Validate firewall policy configuration before applying.

This tool checks the syntax and validity of a firewall policy configuration
without actually creating or modifying any policies on the device.

Parameters:
- device_id: Identifier of the FortiGate device
- policy_data: Policy configuration to validate
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Validation status (valid/invalid)
- List of validation errors if any
- Configuration recommendations
"""

# Network Objects Tool Descriptions
LIST_ADDRESS_OBJECTS_DESC = """
List all address objects configured on a FortiGate device.

This tool retrieves all network address objects defined on the device,
including IP addresses, subnets, ranges, and FQDN objects.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Object name and type
- IP address or subnet configuration
- Comments and descriptions
"""

CREATE_ADDRESS_OBJECT_DESC = """
Create a new address object on a FortiGate device.

This tool adds a new network address object that can be used in
firewall policies and other security rules.

Parameters:
- device_id: Identifier of the FortiGate device
- address_data: Address object configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Address data should include:
- name: Object name
- type: ipmask, iprange, or fqdn
- subnet: IP/netmask (for ipmask type)
- start-ip/end-ip: IP range (for iprange type)
- fqdn: Domain name (for fqdn type)
- comment: Optional description

Returns:
- Creation status
- Object configuration summary
"""

UPDATE_ADDRESS_OBJECT_DESC = """
Update an existing address object on a FortiGate device.

This tool modifies the configuration of an existing network address object,
allowing changes to IP addresses, subnets, or other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the address object to update
- address_data: Updated configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

DELETE_ADDRESS_OBJECT_DESC = """
Delete an address object from a FortiGate device.

This tool removes an existing network address object from the device
configuration. Note that objects in use by policies cannot be deleted.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the address object to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

LIST_SERVICE_OBJECTS_DESC = """
List all service objects configured on a FortiGate device.

This tool retrieves all network service objects defined on the device,
including TCP/UDP port definitions and protocol specifications.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Service name and protocol
- Port configurations
- Comments and descriptions
"""

CREATE_SERVICE_OBJECT_DESC = """
Create a new service object on a FortiGate device.

This tool adds a new network service object that defines protocols
and ports for use in firewall policies.

Parameters:
- device_id: Identifier of the FortiGate device
- service_data: Service object configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Service data should include:
- name: Service name
- protocol: TCP, UDP, or ICMP
- tcp-portrange: TCP port range (for TCP)
- udp-portrange: UDP port range (for UDP)
- comment: Optional description

Returns:
- Creation status
- Service configuration summary
"""

UPDATE_SERVICE_OBJECT_DESC = """
Update an existing service object on a FortiGate device.

This tool modifies the configuration of an existing network service object,
allowing changes to protocols, ports, or other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the service object to update
- service_data: Updated configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

DELETE_SERVICE_OBJECT_DESC = """
Delete a service object from a FortiGate device.

This tool removes an existing network service object from the device
configuration. Note that objects in use by policies cannot be deleted.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the service object to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

# Virtual IP Tool Descriptions
LIST_VIRTUAL_IPS_DESC = """
List all Virtual IPs configured on a FortiGate device.

This tool retrieves all Virtual IP objects defined on the device,
including port forwarding configurations and NAT mappings.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Virtual IP name and configuration
- External and mapped IP addresses
- Port forwarding settings
- Interface assignments
"""

CREATE_VIRTUAL_IP_DESC = """
Create a new Virtual IP on a FortiGate device.

This tool adds a new Virtual IP object that can be used for
port forwarding, NAT, and external access to internal services.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Virtual IP name
- extip: External IP address
- mappedip: Mapped internal IP address
- extintf: External interface name
- portforward: Enable/disable port forwarding (default: disable)
- protocol: Protocol type (tcp/udp, default: tcp)
- extport: External port (optional)
- mappedport: Mapped port (optional)
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Creation status
- Virtual IP configuration summary
"""

UPDATE_VIRTUAL_IP_DESC = """
Update an existing Virtual IP on a FortiGate device.

This tool modifies the configuration of an existing Virtual IP object,
allowing changes to IP addresses, ports, or other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the Virtual IP to update
- vip_data: Updated configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

GET_VIRTUAL_IP_DETAIL_DESC = """
Get detailed information for a specific Virtual IP.

This tool retrieves comprehensive configuration details for a
specific Virtual IP object, including all settings and mappings.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the Virtual IP to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete Virtual IP configuration
- Port forwarding details
- Interface assignments
- Status information
"""

DELETE_VIRTUAL_IP_DESC = """
Delete a Virtual IP from a FortiGate device.

This tool removes an existing Virtual IP object from the device
configuration. Note that Virtual IPs in use by policies cannot be deleted.

Parameters:
- device_id: Identifier of the FortiGate device
- name: Name of the Virtual IP to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

# Enhanced Routing Tool Descriptions
UPDATE_STATIC_ROUTE_DESC = """
Update an existing static route on a FortiGate device.

This tool modifies the configuration of an existing static route,
allowing changes to destination, gateway, or other settings.

Parameters:
- device_id: Identifier of the FortiGate device
- route_id: ID of the route to update
- route_data: Updated configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Update status
- Configuration changes applied
"""

DELETE_STATIC_ROUTE_DESC = """
Delete a static route from a FortiGate device.

This tool removes an existing static route from the device
configuration.

Parameters:
- device_id: Identifier of the FortiGate device
- route_id: ID of the route to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

GET_STATIC_ROUTE_DETAIL_DESC = """
Get detailed information for a specific static route.

This tool retrieves comprehensive configuration details for a
specific static route, including all settings and status.

Parameters:
- device_id: Identifier of the FortiGate device
- route_id: ID of the route to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete route configuration
- Gateway and interface details
- Status information
"""

# Routing Tool Descriptions
LIST_STATIC_ROUTES_DESC = """
List all static routes configured on a FortiGate device.

This tool retrieves all manually configured static routes from the
device's routing table, showing destination networks and gateways.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Route destinations and gateways
- Interface assignments
- Administrative distances
- Route status (enabled/disabled)
"""

CREATE_STATIC_ROUTE_DESC = """
Create a new static route on a FortiGate device.

This tool adds a new static route to the device's routing configuration,
defining how traffic to specific networks should be forwarded.

Parameters:
- device_id: Identifier of the FortiGate device
- route_data: Route configuration as JSON
- vdom: Virtual Domain name (optional, uses device default)

Route data should include:
- dst: Destination network (IP/netmask)
- gateway: Next hop gateway IP
- device: Outgoing interface name
- distance: Administrative distance (optional)
- comment: Optional description

Returns:
- Creation status
- Route configuration summary
"""

GET_ROUTING_TABLE_DESC = """
Get the current routing table from a FortiGate device.

This tool retrieves the active routing table showing all routes
currently installed on the device, including static, dynamic, and connected routes.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Active route entries
- Route sources (static, OSPF, BGP, etc.)
- Metrics and preferences
- Interface assignments
"""

LIST_POLICY_ROUTES_DESC = """
List all policy-based routes configured on a FortiGate device.

This tool retrieves policy routing rules that direct traffic based
on source, destination, or other criteria rather than just destination.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Policy route rules
- Match criteria
- Routing actions
- Rule priorities
"""

LIST_INTERFACES_DESC = """
List all network interfaces configured on a FortiGate device.

This tool retrieves information about all network interfaces,
including physical ports, VLANs, and virtual interfaces.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Interface names and types
- IP address configurations
- Interface status (up/down)
- VLAN and zone assignments
"""

# System Tool Descriptions
HEALTH_CHECK_DESC = """
Perform a comprehensive health check of the FortiGate MCP server.

This tool checks the overall health and status of the MCP server,
including device connectivity, service availability, and system resources.

Returns:
- Overall server health status
- Registered device count
- Service availability
- Performance metrics
- Error conditions if any
"""

GET_SERVER_INFO_DESC = """
Get detailed information about the FortiGate MCP server.

This tool provides comprehensive information about the server
configuration, capabilities, and current operational status.

Returns:
- Server version and build information
- Available tools and capabilities
- Configuration summary
- Runtime statistics
- API endpoints
"""

# Certificate Tool Descriptions
LIST_LOCAL_CERTIFICATES_DESC = """
List all local (device) certificates on a FortiGate device.

This tool retrieves all locally installed certificates on the device,
including SSL certificates, VPN certificates, and other device certificates.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Certificate name and type
- Subject and issuer information
- Validity period (start and end dates)
- Certificate status
"""

LIST_CA_CERTIFICATES_DESC = """
List all CA (Certificate Authority) certificates on a FortiGate device.

This tool retrieves all trusted CA certificates installed on the device,
used for validating SSL/TLS connections and VPN authentication.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- CA certificate name
- Subject and issuer information
- Validity period
- Trust status
"""

LIST_REMOTE_CERTIFICATES_DESC = """
List all remote certificates on a FortiGate device.

This tool retrieves certificates obtained from remote peers,
typically used in VPN and SSL inspection scenarios.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Remote certificate name
- Subject and issuer information
- Source information
- Certificate status
"""

GET_LOCAL_CERTIFICATE_DETAIL_DESC = """
Get detailed information for a specific local certificate.

This tool retrieves comprehensive details about a locally installed
certificate, including its full certificate chain and usage information.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name of the certificate to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete certificate details
- Public key information
- Signature algorithm
- Certificate chain
- Usage and constraints
"""

GET_CA_CERTIFICATE_DETAIL_DESC = """
Get detailed information for a specific CA certificate.

This tool retrieves comprehensive details about a CA certificate,
including trust settings and validation parameters.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name of the CA certificate to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete CA certificate details
- Trust chain information
- Validation settings
- Associated services
"""

GET_REMOTE_CERTIFICATE_DETAIL_DESC = """
Get detailed information for a specific remote certificate.

This tool retrieves comprehensive details about a remote certificate,
including peer information and validation status.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name of the remote certificate to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete remote certificate details
- Peer information
- Validation status
- Last update time
"""

LIST_CRL_DESC = """
List all Certificate Revocation Lists (CRLs) on a FortiGate device.

This tool retrieves all configured CRLs used for checking
certificate revocation status.

Parameters:
- device_id: Identifier of the FortiGate device
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- CRL name and source
- Last update time
- Next update time
- Number of revoked certificates
"""

GET_CRL_DETAIL_DESC = """
Get detailed information for a specific Certificate Revocation List.

This tool retrieves comprehensive details about a CRL,
including its update schedule and revocation entries.

Parameters:
- device_id: Identifier of the FortiGate device
- crl_name: Name of the CRL to query
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Complete CRL details
- Distribution point information
- Update schedule
- Revocation entries count
"""

DELETE_LOCAL_CERTIFICATE_DESC = """
Delete a local certificate from a FortiGate device.

This tool removes a locally installed certificate from the device.
Note that certificates in use by services cannot be deleted.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name of the certificate to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

DELETE_CA_CERTIFICATE_DESC = """
Delete a CA certificate from a FortiGate device.

This tool removes a CA certificate from the device's trusted store.
Note that CA certificates in use for validation cannot be deleted.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name of the CA certificate to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

DELETE_REMOTE_CERTIFICATE_DESC = """
Delete a remote certificate from a FortiGate device.

This tool removes a remote certificate from the device.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name of the remote certificate to delete
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Deletion status confirmation
"""

# ACME/Let's Encrypt Tool Descriptions
REQUEST_CERTIFICATE_DESC = """
Request a Let's Encrypt certificate using Cloudflare DNS challenge.

This tool uses the ACME protocol to request a free SSL/TLS certificate
from Let's Encrypt, using Cloudflare DNS for domain validation.

Parameters:
- domains: List of domain names for the certificate (first is primary)
- email: Contact email for Let's Encrypt account (optional if configured)
- cloudflare_api_token: Cloudflare API token with DNS edit permissions (optional if configured)
- key_type: Key type - 'rsa' or 'ec' (default: rsa)
- key_size: Key size for RSA - 2048 or 4096 (default: 2048)
- staging: Use Let's Encrypt staging environment for testing (default: false)

Returns:
- Certificate details including subject, issuer, validity
- Private key in PEM format
- Certificate in PEM format
- Certificate chain in PEM format
"""

REQUEST_AND_IMPORT_CERTIFICATE_DESC = """
Request a Let's Encrypt certificate and import it to FortiGate.

This tool combines certificate request and import into a single operation:
1. Requests a certificate from Let's Encrypt via ACME
2. Uses Cloudflare DNS for domain validation
3. Imports the certificate directly to the FortiGate device

Parameters:
- device_id: Identifier of the FortiGate device
- domains: List of domain names for the certificate
- cert_name: Name for the certificate in FortiGate
- email: Contact email for Let's Encrypt (optional if configured)
- cloudflare_api_token: Cloudflare API token (optional if configured)
- key_type: Key type - 'rsa' or 'ec' (default: rsa)
- key_size: Key size for RSA (default: 2048)
- staging: Use staging environment for testing (default: false)
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Import status confirmation
- Certificate details including validity information
"""

IMPORT_CERTIFICATE_DESC = """
Import an existing certificate to a FortiGate device.

This tool imports a PEM-encoded certificate and private key
to a FortiGate device's local certificate store.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name for the certificate in FortiGate
- certificate: PEM-encoded certificate content
- private_key: PEM-encoded private key content
- password: Password for encrypted private key (optional)
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Import status confirmation
"""

IMPORT_CA_CERTIFICATE_DESC = """
Import a CA certificate to a FortiGate device.

This tool imports a PEM-encoded CA certificate to a FortiGate
device's trusted CA store.

Parameters:
- device_id: Identifier of the FortiGate device
- cert_name: Name for the CA certificate in FortiGate
- certificate: PEM-encoded CA certificate content
- vdom: Virtual Domain name (optional, uses device default)

Returns:
- Import status confirmation
"""

LIST_CLOUDFLARE_ZONES_DESC = """
List Cloudflare zones available for DNS challenges.

This tool lists all DNS zones in your Cloudflare account that
can be used for ACME DNS-01 domain validation.

Parameters:
- cloudflare_api_token: Cloudflare API token (optional if configured)

Returns:
- List of zones with name, ID, and status
"""

VERIFY_CLOUDFLARE_TOKEN_DESC = """
Verify Cloudflare API token is valid.

This tool verifies that the Cloudflare API token has valid
permissions for DNS operations required for ACME challenges.

Parameters:
- cloudflare_api_token: Cloudflare API token (optional if configured)

Returns:
- Token validation status
"""
