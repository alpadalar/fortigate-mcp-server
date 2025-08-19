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
