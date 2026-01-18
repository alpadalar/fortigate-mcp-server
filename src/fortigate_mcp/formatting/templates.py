"""
Template system for FortiGate MCP response formatting.

This module provides structured templates for formatting FortiGate API responses
into human-readable and consistent output formats. Templates are organized by
resource type and operation.
"""
from typing import Dict, List, Any, Optional
import json
from datetime import datetime

class FortiGateTemplates:
    """Template collection for FortiGate resource formatting.
    
    Provides static methods for formatting different types of FortiGate
    resources into structured, readable text output.
    """
    
    @staticmethod
    def device_list(devices: Dict[str, Dict[str, Any]]) -> str:
        """Format device list for display.
        
        Args:
            devices: Dictionary of device info keyed by device ID
            
        Returns:
            Formatted string with device information
        """
        if not devices:
            return "No FortiGate devices configured"
        
        lines = ["FortiGate Devices", ""]
        
        for device_id, info in devices.items():
            lines.extend([
                f"Device: {device_id}",
                f"  Host: {info['host']}:{info['port']}",
                f"  VDOM: {info['vdom']}",
                f"  Auth: {info['auth_method']}",
                f"  SSL Verify: {'Yes' if info['verify_ssl'] else 'No'}",
                ""
            ])
        
        return "\n".join(lines)
    
    @staticmethod
    def device_status(device_id: str, status_data: Dict[str, Any]) -> str:
        """Format device system status.
        
        Args:
            device_id: Device identifier
            status_data: System status response from FortiGate API
            
        Returns:
            Formatted system status information
        """
        lines = [f"Device Status: {device_id}", ""]
        
        if "results" in status_data:
            results = status_data["results"]
            
            lines.extend([
                "System Information",
                f"  Model: {results.get('model_name', 'Unknown')} {results.get('model_number', '')}",
                f"  Hostname: {results.get('hostname', 'Unknown')}",
                f"  Version: {status_data.get('version', 'Unknown')}",
                f"  Serial: {status_data.get('serial', 'Unknown')}",
                f"  VDOM: {status_data.get('vdom', 'Unknown')}",
                ""
            ])
            
            # Add additional status info if available
            if results.get('log_disk_status'):
                lines.append(f"  Log Disk: {results['log_disk_status']}")
            if results.get('current_time'):
                lines.append(f"  Current Time: {results['current_time']}")
        else:
            lines.append("No status information available")
        
        return "\n".join(lines)
    
    @staticmethod
    def firewall_policies(policies_data: Dict[str, Any]) -> str:
        """Format firewall policies list.
        
        Args:
            policies_data: Firewall policies response from FortiGate API
            
        Returns:
            Formatted firewall policies information
        """
        lines = ["Firewall Policies", ""]
        
        if "results" in policies_data and policies_data["results"]:
            policies = policies_data["results"]
            
            for policy in policies:
                status = "Enabled" if policy.get("status") == "enable" else "Disabled"
                action = policy.get("action", "unknown")
                
                # Extract source addresses from dict list
                srcaddr_list = policy.get('srcaddr', [])
                src_names = []
                for addr in srcaddr_list:
                    if isinstance(addr, dict) and 'name' in addr:
                        src_names.append(addr['name'])
                    elif isinstance(addr, str):
                        src_names.append(addr)
                src_text = ', '.join(src_names)
                
                # Extract destination addresses from dict list
                dstaddr_list = policy.get('dstaddr', [])
                dst_names = []
                for addr in dstaddr_list:
                    if isinstance(addr, dict) and 'name' in addr:
                        dst_names.append(addr['name'])
                    elif isinstance(addr, str):
                        dst_names.append(addr)
                dst_text = ', '.join(dst_names)
                
                # Extract services from dict list
                service_list = policy.get('service', [])
                svc_names = []
                for svc in service_list:
                    if isinstance(svc, dict) and 'name' in svc:
                        svc_names.append(svc['name'])
                    elif isinstance(svc, str):
                        svc_names.append(svc)
                svc_text = ', '.join(svc_names)
                
                lines.extend([
                    f"Policy {policy.get('policyid', 'N/A')} ({status})",
                    f"  Name: {policy.get('name', 'Unnamed')}",
                    f"  Source: {src_text if src_text else 'any'}",
                    f"  Destination: {dst_text if dst_text else 'any'}",
                    f"  Service: {svc_text if svc_text else 'any'}",
                    f"  Action: {action}",
                    ""
                ])
            

                
        else:
            lines.append("No firewall policies found")
        
        return "\n".join(lines)
    
    @staticmethod
    def firewall_policy_detail(policy_data: Dict[str, Any], device_id: str, 
                              address_objects: Optional[Dict[str, Any]] = None,
                              service_objects: Optional[Dict[str, Any]] = None) -> str:
        """Format detailed firewall policy information.
        
        Args:
            policy_data: Detailed policy response from FortiGate API
            device_id: Device identifier
            address_objects: Address objects data for resolution
            service_objects: Service objects data for resolution
            
        Returns:
            Formatted detailed policy information
        """
        if "results" not in policy_data or not policy_data["results"]:
            return f"Policy not found on device {device_id}"
        
        # FortiGate API returns results as a single object for specific policy ID
        results = policy_data["results"]
        if isinstance(results, list):
            if not results:
                return f"Policy not found on device {device_id}"
            policy = results[0]  # Get first (and only) policy from list
        else:
            policy = results
        lines = [f"Policy Detail - Device: {device_id}", ""]
        
        # Basic Policy Information
        lines.extend([
            "Basic Information",
            f"  Policy ID: {policy.get('policyid', 'N/A')}",
            f"  Policy Name: {policy.get('name', 'Unnamed')}",
            f"  Status: {'Active' if policy.get('status') == 'enable' else 'Disabled'}",
            f"  UUID: {policy.get('uuid', 'N/A')}",
            ""
        ])
        
        # Traffic Direction
        src_intf = policy.get('srcintf', [])
        dst_intf = policy.get('dstintf', [])
        src_intf_names = [intf.get('name', 'unknown') if isinstance(intf, dict) else str(intf) for intf in src_intf]
        dst_intf_names = [intf.get('name', 'unknown') if isinstance(intf, dict) else str(intf) for intf in dst_intf]
        
        lines.extend([
            "Traffic Direction",
            f"  Source Interface: {', '.join(src_intf_names)}",
            f"  Destination Interface: {', '.join(dst_intf_names)}",
            ""
        ])
        
        # Source Information
        srcaddr_list = policy.get('srcaddr', [])
        src_names = []
        for addr in srcaddr_list:
            if isinstance(addr, dict) and 'name' in addr:
                src_names.append(addr['name'])
            elif isinstance(addr, str):
                src_names.append(addr)
        
        lines.extend([
            "Source",
            f"  Address Objects: {', '.join(src_names)}",
            f"  Total Objects: {len(src_names)}",
        ])
        
        # Resolve source addresses if address_objects provided
        if address_objects and "results" in address_objects:
            addr_dict = {addr["name"]: addr for addr in address_objects["results"]}
            lines.append("  Resolved Addresses:")
            for src_name in src_names:
                if src_name in addr_dict:
                    addr = addr_dict[src_name]
                    if addr.get("subnet"):
                        lines.append(f"    {src_name}: {addr['subnet']}")
                    elif addr.get("start-ip") and addr.get("end-ip"):
                        lines.append(f"    {src_name}: {addr['start-ip']} - {addr['end-ip']}")
                    elif addr.get("fqdn"):
                        lines.append(f"    {src_name}: {addr['fqdn']}")
                else:
                    lines.append(f"    {src_name}: Not resolved")
        
        lines.append("")
        
        # Destination Information
        dstaddr_list = policy.get('dstaddr', [])
        dst_names = []
        for addr in dstaddr_list:
            if isinstance(addr, dict) and 'name' in addr:
                dst_names.append(addr['name'])
            elif isinstance(addr, str):
                dst_names.append(addr)
        
        lines.extend([
            "Destination",
            f"  Address Objects: {', '.join(dst_names)}",
            f"  Total Objects: {len(dst_names)}",
        ])
        
        # Resolve destination addresses
        if address_objects and "results" in address_objects:
            lines.append("  Resolved Addresses:")
            for dst_name in dst_names:
                if dst_name in addr_dict:
                    addr = addr_dict[dst_name]
                    if addr.get("subnet"):
                        lines.append(f"    {dst_name}: {addr['subnet']}")
                    elif addr.get("start-ip") and addr.get("end-ip"):
                        lines.append(f"    {dst_name}: {addr['start-ip']} - {addr['end-ip']}")
                    elif addr.get("fqdn"):
                        lines.append(f"    {dst_name}: {addr['fqdn']}")
                else:
                    lines.append(f"    {dst_name}: Not resolved")
        
        lines.append("")
        
        # Service Information
        service_list = policy.get('service', [])
        svc_names = []
        for svc in service_list:
            if isinstance(svc, dict) and 'name' in svc:
                svc_names.append(svc['name'])
            elif isinstance(svc, str):
                svc_names.append(svc)
        
        lines.extend([
            "Services",
            f"  Service Objects: {', '.join(svc_names)}",
            f"  Total Services: {len(svc_names)}",
        ])
        
        # Resolve services
        if service_objects and "results" in service_objects:
            svc_dict = {svc["name"]: svc for svc in service_objects["results"]}
            lines.append("  Resolved Services:")
            for svc_name in svc_names:
                if svc_name in svc_dict:
                    svc = svc_dict[svc_name]
                    protocol = svc.get("protocol", "unknown").upper()
                    if svc.get("tcp-portrange"):
                        lines.append(f"    {svc_name}: TCP {svc['tcp-portrange']}")
                    elif svc.get("udp-portrange"):
                        lines.append(f"    {svc_name}: UDP {svc['udp-portrange']}")
                    else:
                        lines.append(f"    {svc_name}: {protocol}")
                else:
                    lines.append(f"    {svc_name}: Not resolved")
        
        lines.append("")
        
        # Action and Security
        action = policy.get('action', 'unknown')
        
        lines.extend([
            "Action and Security",
            f"  Action: {action.upper()}",
            f"  Log Traffic: {'Yes' if policy.get('logtraffic') == 'all' else 'No'}",
            f"  NAT: {'Yes' if policy.get('nat') == 'enable' else 'No'}",
        ])
        
        # Schedule
        schedule = policy.get('schedule', [])
        schedule_name = schedule[0].get('name') if schedule and isinstance(schedule[0], dict) else str(schedule[0]) if schedule else 'always'
        lines.append(f"  Schedule: {schedule_name}")
        
        # Comments
        if policy.get('comments'):
            lines.extend([
                "",
                "Comments",
                f"  {policy['comments']}"
            ])
        
        lines.append("")
        
        # Technical Details
        lines.extend([
            "Technical Details",
            f"  Sequence Number: {policy.get('seq-num', 'N/A')}",
            f"  Internet Service: {'Yes' if policy.get('internet-service') == 'enable' else 'No'}",
            f"  Application Control: {'Yes' if policy.get('application-list') else 'No'}",
            f"  Antivirus: {'Yes' if policy.get('av-profile') else 'No'}",
            f"  Web Filter: {'Yes' if policy.get('webfilter-profile') else 'No'}",
            f"  IPS: {'Yes' if policy.get('ips-sensor') else 'No'}",
            ""
        ])
        
        return "\n".join(lines)
    
    @staticmethod
    def address_objects(addresses_data: Dict[str, Any]) -> str:
        """Format address objects list.
        
        Args:
            addresses_data: Address objects response from FortiGate API
            
        Returns:
            Formatted address objects information
        """
        lines = ["Address Objects", ""]
        
        if "results" in addresses_data and addresses_data["results"]:
            addresses = addresses_data["results"]
            
            for addr in addresses:
                lines.extend([
                    f"Address Object: {addr.get('name', 'Unnamed')}",
                    f"  Type: {addr.get('type', 'unknown')}",
                ])
                
                # Add type-specific information
                if addr.get("subnet"):
                    lines.append(f"  Subnet: {addr['subnet']}")
                elif addr.get("start-ip") and addr.get("end-ip"):
                    lines.append(f"  Range: {addr['start-ip']} - {addr['end-ip']}")
                elif addr.get("fqdn"):
                    lines.append(f"  FQDN: {addr['fqdn']}")
                
                if addr.get("comment"):
                    lines.append(f"  Comment: {addr['comment']}")
                
                lines.append("")
            

                
        else:
            lines.append("No address objects found")
        
        return "\n".join(lines)
    
    @staticmethod
    def virtual_ips(vips_data: Dict[str, Any]) -> str:
        """Format virtual IPs list.
        
        Args:
            vips_data: Virtual IPs response from FortiGate API
            
        Returns:
            Formatted virtual IPs information
        """
        lines = ["Virtual IPs", ""]
        
        if "results" in vips_data and vips_data["results"]:
            vips = vips_data["results"]
            
            for vip in vips:
                lines.extend([
                    f"Virtual IP: {vip.get('name', 'Unnamed')}",
                    f"  External IP: {vip.get('extip', 'N/A')}",
                    f"  Mapped IP: {vip.get('mappedip', 'N/A')}",
                    f"  External Interface: {vip.get('extintf', 'N/A')}",
                    f"  Port Forwarding: {vip.get('portforward', 'disable')}",
                ])
                
                if vip.get("protocol"):
                    lines.append(f"  Protocol: {vip['protocol']}")
                
                if vip.get("extport"):
                    lines.append(f"  External Port: {vip['extport']}")
                
                if vip.get("mappedport"):
                    lines.append(f"  Mapped Port: {vip['mappedport']}")
                
                if vip.get("comment"):
                    lines.append(f"  Comment: {vip['comment']}")
                
                lines.append("")
        else:
            lines.append("No virtual IPs found")
        
        return "\n".join(lines)
    
    @staticmethod
    def virtual_ip_detail(vip_data: Dict[str, Any]) -> str:
        """Format virtual IP detail.
        
        Args:
            vip_data: Virtual IP detail response from FortiGate API
            
        Returns:
            Formatted virtual IP detail information
        """
        lines = ["Virtual IP Detail", ""]
        
        if "results" in vip_data and vip_data["results"]:
            vip = vip_data["results"][0] if isinstance(vip_data["results"], list) else vip_data["results"]
            
            lines.extend([
                f"Name: {vip.get('name', 'N/A')}",
                f"External IP: {vip.get('extip', 'N/A')}",
                f"Mapped IP: {vip.get('mappedip', 'N/A')}",
                f"External Interface: {vip.get('extintf', 'N/A')}",
                f"Port Forwarding: {vip.get('portforward', 'disable')}",
            ])
            
            if vip.get("protocol"):
                lines.append(f"Protocol: {vip['protocol']}")
            
            if vip.get("extport"):
                lines.append(f"External Port: {vip['extport']}")
            
            if vip.get("mappedport"):
                lines.append(f"Mapped Port: {vip['mappedport']}")
            
            if vip.get("comment"):
                lines.append(f"Comment: {vip['comment']}")
            
            if vip.get("status"):
                lines.append(f"Status: {vip['status']}")
        else:
            lines.append("Virtual IP not found")
        
        return "\n".join(lines)
    
    @staticmethod
    def service_objects(services_data: Dict[str, Any]) -> str:
        """Format service objects list.
        
        Args:
            services_data: Service objects response from FortiGate API
            
        Returns:
            Formatted service objects information
        """
        lines = ["Service Objects", ""]
        
        if "results" in services_data and services_data["results"]:
            services = services_data["results"]
            
            for service in services:
                protocol = service.get("protocol", "unknown").upper()
                
                lines.extend([
                    f"Service: {service.get('name', 'Unnamed')} ({protocol})",
                ])
                
                # Add protocol-specific port information
                if service.get("tcp-portrange"):
                    lines.append(f"  TCP Ports: {service['tcp-portrange']}")
                if service.get("udp-portrange"):
                    lines.append(f"  UDP Ports: {service['udp-portrange']}")
                
                if service.get("comment"):
                    lines.append(f"  Comment: {service['comment']}")
                
                lines.append("")
            

                
        else:
            lines.append("No service objects found")
        
        return "\n".join(lines)
    
    @staticmethod
    def routing_table(routing_data: Dict[str, Any]) -> str:
        """Format routing table.
        
        Args:
            routing_data: Routing table response from FortiGate API
            
        Returns:
            Formatted routing table information
        """
        lines = ["Routing Table", ""]
        
        if "results" in routing_data and routing_data["results"]:
            routes = routing_data["results"]
            
            for route in routes:
                lines.extend([
                    f"Route: {route.get('dst', 'N/A')}",
                    f"  Gateway: {route.get('gateway', 'N/A')}",
                    f"  Interface: {route.get('interface', 'N/A')}",
                    f"  Distance: {route.get('distance', 'N/A')}",
                    f"  Priority: {route.get('priority', 'N/A')}",
                ])
                
                if route.get("status"):
                    lines.append(f"  Status: {route['status']}")
                
                if route.get("type"):
                    lines.append(f"  Type: {route['type']}")
                
                lines.append("")
        else:
            lines.append("No routes found")
        
        return "\n".join(lines)
    
    @staticmethod
    def static_routes(routes_data: Dict[str, Any]) -> str:
        """Format static routes list.
        
        Args:
            routes_data: Static routes response from FortiGate API
            
        Returns:
            Formatted static routes information
        """
        lines = ["Static Routes", ""]
        
        if "results" in routes_data and routes_data["results"]:
            routes = routes_data["results"]
            
            for route in routes:
                status = "Enabled" if route.get("status") == "enable" else "Disabled"
                
                lines.extend([
                    f"Route {route.get('seq-num', 'N/A')} ({status})",
                    f"  Destination: {route.get('dst', '0.0.0.0/0')}",
                    f"  Gateway: {route.get('gateway', 'N/A')}",
                    f"  Device: {route.get('device', 'N/A')}",
                    f"  Distance: {route.get('distance', 'N/A')}",
                ])
                
                if route.get("comment"):
                    lines.append(f"  Comment: {route['comment']}")
                
                lines.append("")
            

                
        else:
            lines.append("No static routes found")
        
        return "\n".join(lines)
    
    @staticmethod
    def interfaces(interfaces_data: Dict[str, Any]) -> str:
        """Format interfaces list.
        
        Args:
            interfaces_data: Interfaces response from FortiGate API
            
        Returns:
            Formatted interfaces information
        """
        lines = ["Network Interfaces", ""]
        
        if "results" in interfaces_data and interfaces_data["results"]:
            interfaces = interfaces_data["results"]
            
            for interface in interfaces:
                status = "Up" if interface.get("status") == "up" else "Down"
                
                lines.extend([
                    f"Interface: {interface.get('name', 'Unnamed')} ({status})",
                    f"  Type: {interface.get('type', 'unknown')}",
                    f"  Mode: {interface.get('mode', 'unknown')}",
                ])
                
                if interface.get("ip"):
                    lines.append(f"  IP: {interface['ip']}")
                if interface.get("alias"):
                    lines.append(f"  Alias: {interface['alias']}")
                
                lines.append("")
            

                
        else:
            lines.append("No interfaces found")
        
        return "\n".join(lines)
    
    @staticmethod
    def vdoms(vdoms_data: Dict[str, Any]) -> str:
        """Format VDOMs list.
        
        Args:
            vdoms_data: VDOMs response from FortiGate API
            
        Returns:
            Formatted VDOMs information
        """
        lines = ["Virtual Domains (VDOMs)", ""]
        
        if "results" in vdoms_data and vdoms_data["results"]:
            vdoms = vdoms_data["results"]
            
            for vdom in vdoms:
                enabled = "Yes" if vdom.get("enabled") else "No"
                
                lines.extend([
                    f"VDOM: {vdom.get('name', 'Unnamed')} (Enabled: {enabled})",
                ])
                
                if vdom.get("comments"):
                    lines.append(f"  Comments: {vdom['comments']}")
                
                lines.append("")
                
        else:
            lines.append("No VDOMs found")
        
        return "\n".join(lines)
    
    @staticmethod
    def operation_result(operation: str, device_id: str, success: bool, 
                        details: Optional[str] = None, error: Optional[str] = None) -> str:
        """Format operation result.
        
        Args:
            operation: Operation name
            device_id: Target device ID
            success: Whether operation succeeded
            details: Additional details about the operation
            error: Error message if operation failed
            
        Returns:
            Formatted operation result
        """
        status = "SUCCESS" if success else "FAILED"
        
        lines = [
            f"Operation {status}",
            f"  Operation: {operation}",
            f"  Device: {device_id}",
            f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        
        if success and details:
            lines.extend([
                "Details:",
                f"  {details}",
                ""
            ])
        elif not success and error:
            lines.extend([
                "Error:",
                f"  {error}",
                ""
            ])
        
        return "\n".join(lines)
    
    @staticmethod
    def health_status(status: str, details: Dict[str, Any]) -> str:
        """Format health check status.

        Args:
            status: Overall health status
            details: Health check details

        Returns:
            Formatted health status
        """
        lines = [
            f"FortiGate MCP Server Health",
            f"  Status: {status.upper()}",
            f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]

        if details.get("registered_devices") is not None:
            lines.append(f"  Registered Devices: {details['registered_devices']}")

        if details.get("server_version"):
            lines.append(f"  Server Version: {details['server_version']}")

        if details.get("uptime"):
            lines.append(f"  Uptime: {details['uptime']}")

        return "\n".join(lines)

    @staticmethod
    def packet_captures(captures_data: Dict[str, Any]) -> str:
        """Format packet capture profiles list.

        Args:
            captures_data: Packet captures response from FortiGate API

        Returns:
            Formatted packet captures information
        """
        lines = ["Packet Capture Profiles", ""]

        if "results" in captures_data and captures_data["results"]:
            captures = captures_data["results"]

            for capture in captures:
                capture_id = capture.get("id", "N/A")
                interface = capture.get("interface", "N/A")
                filter_str = capture.get("filter", "none")
                max_count = capture.get("max-packet-count", "N/A")
                status = capture.get("status", "unknown")

                lines.extend([
                    f"Capture ID: {capture_id}",
                    f"  Interface: {interface}",
                    f"  Filter: {filter_str if filter_str else 'none'}",
                    f"  Max Packets: {max_count}",
                    f"  Status: {status}",
                    ""
                ])
        else:
            lines.append("No packet capture profiles found")

        return "\n".join(lines)

    @staticmethod
    def packet_capture_status(status_data: Dict[str, Any]) -> str:
        """Format packet capture status.

        Args:
            status_data: Packet capture status from FortiGate API

        Returns:
            Formatted packet capture status
        """
        lines = ["Packet Capture Status", ""]

        if "results" in status_data:
            results = status_data["results"]
            if isinstance(results, list) and results:
                results = results[0]

            lines.extend([
                f"Capture ID: {results.get('id', 'N/A')}",
                f"State: {results.get('state', 'unknown')}",
                f"Packets Captured: {results.get('packet-count', 0)}",
                f"Bytes Captured: {results.get('byte-count', 0)}",
                f"Interface: {results.get('interface', 'N/A')}",
                f"Filter: {results.get('filter', 'none') or 'none'}",
            ])

            if results.get("start-time"):
                lines.append(f"Start Time: {results['start-time']}")
            if results.get("stop-time"):
                lines.append(f"Stop Time: {results['stop-time']}")
            if results.get("file-size"):
                lines.append(f"File Size: {results['file-size']} bytes")
        else:
            lines.append("No status information available")

        return "\n".join(lines)

    @staticmethod
    def packet_capture_download(download_data: Dict[str, Any]) -> str:
        """Format packet capture download response.

        Args:
            download_data: Download data from FortiGate API

        Returns:
            Formatted download information
        """
        lines = ["Packet Capture Download", ""]

        if "results" in download_data:
            results = download_data["results"]
            if isinstance(results, list) and results:
                results = results[0]

            if results.get("file") or results.get("data"):
                lines.extend([
                    "File Available: Yes",
                    f"File Size: {results.get('size', 'Unknown')} bytes",
                    "Format: PCAP",
                    "",
                    "Note: Capture data is available for download"
                ])
            else:
                lines.append("No capture file available - capture may still be running or empty")
        else:
            lines.append("Download information not available")

        return "\n".join(lines)

    # IPSec VPN Templates
    @staticmethod
    def ipsec_phase1_list(phase1_data: Dict[str, Any]) -> str:
        """Format IPSec Phase 1 interfaces list.

        Args:
            phase1_data: Phase 1 interfaces response from FortiGate API

        Returns:
            Formatted Phase 1 tunnels information
        """
        lines = ["IPSec VPN Phase 1 Tunnels", ""]

        if "results" in phase1_data and phase1_data["results"]:
            for p1 in phase1_data["results"]:
                status = "Enabled" if p1.get("status") == "enable" else "Disabled"
                ike_version = p1.get("ike-version", "1")

                lines.extend([
                    f"Tunnel: {p1.get('name', 'Unnamed')} ({status})",
                    f"  Interface: {p1.get('interface', 'N/A')}",
                    f"  Remote Gateway: {p1.get('remote-gw', 'N/A')}",
                    f"  IKE Version: {ike_version}",
                    f"  Mode: {p1.get('mode', 'main')}",
                    f"  Proposal: {p1.get('proposal', 'N/A')}",
                    f"  DH Group: {p1.get('dhgrp', 'N/A')}",
                    f"  PSK: {'Configured' if p1.get('psksecret') else 'Not Set'}",
                ])

                if p1.get("comments"):
                    lines.append(f"  Comments: {p1['comments']}")

                lines.append("")
        else:
            lines.append("No Phase 1 tunnels configured")

        return "\n".join(lines)

    @staticmethod
    def ipsec_phase1_detail(phase1_data: Dict[str, Any], device_id: str) -> str:
        """Format detailed Phase 1 configuration.

        Args:
            phase1_data: Phase 1 detail response from FortiGate API
            device_id: Device identifier

        Returns:
            Formatted Phase 1 detail information
        """
        lines = [f"IPSec Phase 1 Detail - Device: {device_id}", ""]

        if "results" in phase1_data and phase1_data["results"]:
            p1 = phase1_data["results"]
            if isinstance(p1, list):
                p1 = p1[0] if p1 else {}

            status = "Enabled" if p1.get("status") == "enable" else "Disabled"

            lines.extend([
                "Basic Configuration",
                f"  Name: {p1.get('name', 'N/A')}",
                f"  Status: {status}",
                f"  Type: {p1.get('type', 'static')}",
                f"  Interface: {p1.get('interface', 'N/A')}",
                "",
                "Remote Peer",
                f"  Remote Gateway: {p1.get('remote-gw', 'N/A')}",
                f"  Peer Type: {p1.get('peertype', 'any')}",
                "",
                "IKE Settings",
                f"  IKE Version: {p1.get('ike-version', '1')}",
                f"  Mode: {p1.get('mode', 'main')}",
                f"  Proposal: {p1.get('proposal', 'N/A')}",
                f"  DH Group: {p1.get('dhgrp', 'N/A')}",
                f"  Local ID: {p1.get('localid', 'N/A')}",
                "",
                "Authentication",
                f"  Auth Method: {p1.get('authmethod', 'psk')}",
                f"  PSK: {'Configured' if p1.get('psksecret') else 'Not Set'}",
                "",
                "Timers",
                f"  Keylife: {p1.get('keylife', 86400)} seconds",
                f"  DPD: {p1.get('dpd', 'on-demand')}",
                f"  DPD Retry Count: {p1.get('dpd-retrycount', 3)}",
                f"  DPD Retry Interval: {p1.get('dpd-retryinterval', 10)} seconds",
            ])

            if p1.get("comments"):
                lines.extend(["", "Comments", f"  {p1['comments']}"])

        else:
            lines.append("Phase 1 tunnel not found")

        return "\n".join(lines)

    @staticmethod
    def ipsec_phase2_list(phase2_data: Dict[str, Any]) -> str:
        """Format IPSec Phase 2 interfaces list.

        Args:
            phase2_data: Phase 2 interfaces response from FortiGate API

        Returns:
            Formatted Phase 2 selectors information
        """
        lines = ["IPSec VPN Phase 2 Selectors", ""]

        if "results" in phase2_data and phase2_data["results"]:
            for p2 in phase2_data["results"]:
                status = "Enabled" if p2.get("status", "enable") == "enable" else "Disabled"

                # Extract source and destination subnets
                src_subnet = p2.get("src-subnet", "0.0.0.0/0")
                dst_subnet = p2.get("dst-subnet", "0.0.0.0/0")

                # Handle src-addr-type and dst-addr-type
                if p2.get("src-addr-type") == "name":
                    src_subnet = p2.get("src-name", src_subnet)
                if p2.get("dst-addr-type") == "name":
                    dst_subnet = p2.get("dst-name", dst_subnet)

                lines.extend([
                    f"Selector: {p2.get('name', 'Unnamed')} ({status})",
                    f"  Phase 1: {p2.get('phase1name', 'N/A')}",
                    f"  Source: {src_subnet}",
                    f"  Destination: {dst_subnet}",
                    f"  Protocol: {p2.get('protocol', '0')}",
                    f"  Proposal: {p2.get('proposal', 'N/A')}",
                    f"  PFS: {p2.get('pfs', 'enable')}",
                ])

                if p2.get("comments"):
                    lines.append(f"  Comments: {p2['comments']}")

                lines.append("")
        else:
            lines.append("No Phase 2 selectors configured")

        return "\n".join(lines)

    @staticmethod
    def ipsec_phase2_detail(phase2_data: Dict[str, Any], device_id: str) -> str:
        """Format detailed Phase 2 configuration.

        Args:
            phase2_data: Phase 2 detail response from FortiGate API
            device_id: Device identifier

        Returns:
            Formatted Phase 2 detail information
        """
        lines = [f"IPSec Phase 2 Detail - Device: {device_id}", ""]

        if "results" in phase2_data and phase2_data["results"]:
            p2 = phase2_data["results"]
            if isinstance(p2, list):
                p2 = p2[0] if p2 else {}

            lines.extend([
                "Basic Configuration",
                f"  Name: {p2.get('name', 'N/A')}",
                f"  Phase 1: {p2.get('phase1name', 'N/A')}",
                "",
                "Traffic Selectors",
                f"  Source Type: {p2.get('src-addr-type', 'subnet')}",
                f"  Source: {p2.get('src-subnet', p2.get('src-name', 'N/A'))}",
                f"  Destination Type: {p2.get('dst-addr-type', 'subnet')}",
                f"  Destination: {p2.get('dst-subnet', p2.get('dst-name', 'N/A'))}",
                f"  Protocol: {p2.get('protocol', '0')}",
                "",
                "IPSec Settings",
                f"  Proposal: {p2.get('proposal', 'N/A')}",
                f"  PFS: {p2.get('pfs', 'enable')}",
                f"  PFS DH Group: {p2.get('dhgrp', 'N/A')}",
                f"  Replay Detection: {p2.get('replay', 'enable')}",
                "",
                "Timers",
                f"  Keylife Type: {p2.get('keylife-type', 'seconds')}",
                f"  Keylife Seconds: {p2.get('keylifeseconds', 43200)}",
                f"  Keylife KB: {p2.get('keylifekbs', 5120)}",
            ])

            if p2.get("comments"):
                lines.extend(["", "Comments", f"  {p2['comments']}"])

        else:
            lines.append("Phase 2 selector not found")

        return "\n".join(lines)

    @staticmethod
    def ipsec_tunnel_status(status_data: Dict[str, Any]) -> str:
        """Format IPSec tunnel runtime status.

        Args:
            status_data: Tunnel status from FortiGate monitor API

        Returns:
            Formatted tunnel status information
        """
        lines = ["IPSec Tunnel Status", ""]

        def format_bytes(b):
            """Convert bytes to human readable format."""
            for unit in ['B', 'KB', 'MB', 'GB']:
                if b < 1024:
                    return f"{b:.2f} {unit}"
                b /= 1024
            return f"{b:.2f} TB"

        if "results" in status_data and status_data["results"]:
            for tunnel in status_data["results"]:
                name = tunnel.get("name", "Unknown")
                incoming = tunnel.get("incoming_bytes", 0)
                outgoing = tunnel.get("outgoing_bytes", 0)
                tun_status = tunnel.get("status", "unknown")

                lines.extend([
                    f"Tunnel: {name}",
                    f"  Status: {tun_status}",
                    f"  Remote Gateway: {tunnel.get('rgwy', 'N/A')}",
                    f"  Incoming: {format_bytes(incoming)}",
                    f"  Outgoing: {format_bytes(outgoing)}",
                ])

                if tunnel.get("tun_uptime"):
                    lines.append(f"  Uptime: {tunnel['tun_uptime']} seconds")

                # Add proxyid (Phase 2 selector) information
                proxyids = tunnel.get("proxyid", [])
                if proxyids:
                    lines.append("  Proxy IDs:")
                    for proxy in proxyids:
                        p_status = proxy.get("status", "N/A")
                        lines.extend([
                            f"    Proxy ID {proxy.get('proxy_id', 'N/A')}: {p_status}",
                            f"      Source: {proxy.get('proxy_src', 'N/A')}",
                            f"      Destination: {proxy.get('proxy_dst', 'N/A')}",
                        ])

                lines.append("")
        else:
            lines.append("No active IPSec tunnels")

        return "\n".join(lines)

    @staticmethod
    def ipsec_ike_gateways(ike_output: str, parsed_data: Optional[Dict[str, Any]] = None) -> str:
        """Format IKE gateway diagnostic output.

        Args:
            ike_output: Raw CLI output from diagnose vpn ike gateway list
            parsed_data: Optional parsed gateway data

        Returns:
            Formatted IKE gateway information
        """
        lines = ["IKE Gateway Status (SSH Diagnostics)", "=" * 50, ""]

        if parsed_data and parsed_data.get("gateways"):
            lines.append(f"Gateway Count: {parsed_data.get('gateway_count', 0)}")
            lines.append("")

            for gw in parsed_data["gateways"]:
                lines.extend([
                    f"Gateway: {gw.get('name', 'Unknown')}",
                ])
                # Include key fields from parsed data
                for key, value in gw.items():
                    if key not in ["name", "raw_lines"] and value:
                        lines.append(f"  {key}: {value}")
                lines.append("")

        # Always include raw output for troubleshooting
        lines.extend([
            "Raw Output:",
            "-" * 40,
            ike_output
        ])

        return "\n".join(lines)

    @staticmethod
    def ipsec_tunnel_diagnostics(tunnel_output: str, parsed_data: Optional[Dict[str, Any]] = None) -> str:
        """Format tunnel diagnostic output.

        Args:
            tunnel_output: Raw CLI output from diagnose vpn tunnel list
            parsed_data: Optional parsed tunnel data

        Returns:
            Formatted tunnel diagnostic information
        """
        lines = ["IPSec Tunnel Diagnostics (SSH)", "=" * 50, ""]

        if parsed_data and parsed_data.get("tunnels"):
            lines.append(f"Tunnel Count: {parsed_data.get('tunnel_count', 0)}")
            lines.append("")

            for tunnel in parsed_data["tunnels"]:
                lines.extend([
                    f"Tunnel: {tunnel.get('name', 'Unknown')}",
                    f"  Incoming: {tunnel.get('incoming_bytes', 0)} bytes",
                    f"  Outgoing: {tunnel.get('outgoing_bytes', 0)} bytes",
                ])
                lines.append("")

        # Always include raw output for detailed troubleshooting
        lines.extend([
            "Raw Output:",
            "-" * 40,
            tunnel_output
        ])

        return "\n".join(lines)

    @staticmethod
    def ipsec_troubleshoot_summary(
        tunnel_name: str,
        phase1_config: Optional[Dict[str, Any]] = None,
        phase2_config: Optional[Dict[str, Any]] = None,
        tunnel_status: Optional[Dict[str, Any]] = None,
        ike_output: Optional[str] = None,
        tunnel_stats: Optional[str] = None
    ) -> str:
        """Format comprehensive troubleshooting summary.

        Args:
            tunnel_name: Name of the tunnel being troubleshot
            phase1_config: Phase 1 configuration
            phase2_config: Phase 2 configuration
            tunnel_status: Tunnel runtime status
            ike_output: IKE gateway diagnostic output
            tunnel_stats: Tunnel statistics from SSH

        Returns:
            Formatted troubleshooting summary
        """
        lines = [
            f"IPSec Tunnel Troubleshooting Report: {tunnel_name}",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]

        # Phase 1 Configuration Summary
        lines.append("--- Phase 1 Configuration ---")
        if phase1_config and "results" in phase1_config and phase1_config["results"]:
            p1 = phase1_config["results"]
            if isinstance(p1, list):
                p1 = p1[0] if p1 else {}
            lines.extend([
                f"  Status: {'Enabled' if p1.get('status') == 'enable' else 'Disabled'}",
                f"  Remote Gateway: {p1.get('remote-gw', 'N/A')}",
                f"  IKE Version: {p1.get('ike-version', '1')}",
                f"  Proposal: {p1.get('proposal', 'N/A')}",
            ])
        else:
            lines.append("  Configuration not available")
        lines.append("")

        # Phase 2 Configuration Summary
        lines.append("--- Phase 2 Selectors ---")
        if phase2_config and "results" in phase2_config and phase2_config["results"]:
            for p2 in (phase2_config["results"] if isinstance(phase2_config["results"], list) else [phase2_config["results"]]):
                lines.extend([
                    f"  Selector: {p2.get('name', 'N/A')}",
                    f"    Source: {p2.get('src-subnet', 'N/A')}",
                    f"    Destination: {p2.get('dst-subnet', 'N/A')}",
                ])
        else:
            lines.append("  No selectors found")
        lines.append("")

        # Tunnel Status Summary
        lines.append("--- Tunnel Status (REST API) ---")
        if tunnel_status and "results" in tunnel_status and tunnel_status["results"]:
            for t in tunnel_status["results"]:
                if t.get("name") == tunnel_name or not tunnel_name:
                    lines.extend([
                        f"  Status: {t.get('status', 'unknown')}",
                        f"  Incoming: {t.get('incoming_bytes', 0)} bytes",
                        f"  Outgoing: {t.get('outgoing_bytes', 0)} bytes",
                    ])
                    break
        else:
            lines.append("  Status not available")
        lines.append("")

        # IKE Gateway Output
        if ike_output:
            lines.extend([
                "--- IKE Gateway Diagnostics (SSH) ---",
                ike_output[:500] + ("..." if len(ike_output) > 500 else ""),
                ""
            ])

        # Tunnel Stats Output
        if tunnel_stats:
            lines.extend([
                "--- Tunnel Statistics (SSH) ---",
                tunnel_stats[:500] + ("..." if len(tunnel_stats) > 500 else ""),
                ""
            ])

        return "\n".join(lines)
