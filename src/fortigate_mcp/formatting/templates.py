"""
Template system for FortiGate MCP response formatting.

This module provides structured templates for formatting FortiGate API responses
into human-readable and consistent output formats. Templates are organized by
resource type and operation.
"""
from typing import Dict, Any, List, Optional
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
    def _render_profile_ref(value: Any) -> str:
        """Render a FortiOS UTM profile-binding field as a human-readable name.

        These fields (av-profile, ips-sensor, webfilter-profile,
        application-list, ssl-ssh-profile) are ordinarily a plain reference
        string when profile-type is "single" and unset/empty when the
        policy uses profile-type "group" (VIS-F4, deferred -- group
        resolution is a future milestone) or has no binding at all. Handles
        the plain-string shape defensively against a dict/list-of-dict
        shape too, mirroring `_render_mappedip`'s precedent for FortiOS
        fields whose exact wire-shape has not been device-verified.

        Args:
            value: Raw profile-binding field value from the FortiGate API

        Returns:
            The bound profile's name, or "None" when absent/unresolved
        """
        if not value:
            return "None"
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return str(value.get("name", "None"))
        if isinstance(value, list) and value:
            first = value[0]
            return str(first.get("name", "None")) if isinstance(first, dict) else str(first)
        return "None"

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
            f"  Log Traffic: {policy.get('logtraffic', 'disable')}",
            f"  NAT: {'Yes' if policy.get('nat') == 'enable' else 'No'}",
        ])
        
        # Schedule -- cmdb policy responses carry this as a plain string
        # (e.g. "always"); indexing a string would render its first char.
        schedule = policy.get('schedule', 'always')
        if isinstance(schedule, str):
            schedule_name = schedule or 'always'
        elif schedule and isinstance(schedule[0], dict):
            schedule_name = schedule[0].get('name', 'always')
        else:
            schedule_name = str(schedule[0]) if schedule else 'always'
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
        utm_status = policy.get('utm-status', 'unknown')
        utm_state_label = {"enable": "ENABLED", "disable": "DISABLED"}.get(utm_status, utm_status)
        lines.extend([
            "Technical Details",
            f"  Sequence Number: {policy.get('seq-num', 'N/A')}",
            f"  Internet Service: {'Yes' if policy.get('internet-service') == 'enable' else 'No'}",
            f"  UTM Inspection (utm-status): {utm_state_label}",
            f"  Application Control: {FortiGateTemplates._render_profile_ref(policy.get('application-list'))}",
            f"  Antivirus: {FortiGateTemplates._render_profile_ref(policy.get('av-profile'))}",
            f"  Web Filter: {FortiGateTemplates._render_profile_ref(policy.get('webfilter-profile'))}",
            f"  IPS: {FortiGateTemplates._render_profile_ref(policy.get('ips-sensor'))}",
            f"  SSL/SSH Inspection: {FortiGateTemplates._render_profile_ref(policy.get('ssl-ssh-profile'))}",
        ])

        if policy.get('profile-type') == 'group':
            lines.append(
                f"  Profile Group: {policy.get('profile-group', 'unknown')} "
                "(group-managed -- per-profile detail not resolved this milestone, see VIS-F4)"
            )

        lines.append("")

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
    def _render_mappedip(mappedip: Any) -> str:
        """Render FortiOS's `mappedip` field as a human-readable string.

        FortiOS's cmdb/firewall/vip GET returns `mappedip` as a table type --
        a list of member objects like [{"range": "192.168.1.100"}] -- even
        when the VIP was created with a plain-string mappedip. Config echoes
        may still carry the plain string, so both shapes are handled.

        Args:
            mappedip: Raw `mappedip` value from the FortiGate API

        Returns:
            Comma-joined range string(s), or "N/A" when absent/empty
        """
        if isinstance(mappedip, list):
            rendered = ", ".join(
                m.get("range", str(m)) if isinstance(m, dict) else str(m)
                for m in mappedip
            )
            return rendered or "N/A"
        if mappedip is None or mappedip == "":
            return "N/A"
        return str(mappedip)

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
                mapped = FortiGateTemplates._render_mappedip(vip.get("mappedip"))
                lines.extend([
                    f"Virtual IP: {vip.get('name', 'Unnamed')}",
                    f"  External IP: {vip.get('extip', 'N/A')}",
                    f"  Mapped IP: {mapped}",
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

            mapped = FortiGateTemplates._render_mappedip(vip.get("mappedip"))
            lines.extend([
                f"Name: {vip.get('name', 'N/A')}",
                f"External IP: {vip.get('extip', 'N/A')}",
                f"Mapped IP: {mapped}",
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
                # monitor/router/ipv4 names the destination prefix `ip_mask`
                # (e.g. "0.0.0.0/0"), NOT `dst` -- that is the cmdb/router/static
                # spelling. Reading `dst` here rendered EVERY row as
                # "Route: N/A", so the tool reported a routing table in which
                # no destination was identifiable. Verified live against
                # FortiOS v7.6.7, where the union of keys over all route
                # entries is: distance, gateway, interface, ip_mask,
                # ip_version, is_tunnel_route, metric, non_rc_gateway,
                # origin, priority, tunnel_parent, type, vrf.
                lines.extend([
                    f"Route: {route.get('ip_mask', 'N/A')}",
                    f"  Gateway: {route.get('gateway', 'N/A')}",
                    f"  Interface: {route.get('interface', 'N/A')}",
                    f"  Distance: {route.get('distance', 'N/A')}",
                    f"  Metric: {route.get('metric', 'N/A')}",
                    f"  Priority: {route.get('priority', 'N/A')}",
                ])

                if route.get("type"):
                    lines.append(f"  Type: {route['type']}")

                # `origin` is the only field that separates a DHCP-learned
                # default route from an operator-configured one -- this
                # endpoint reports both as type "static". Rendered in place of
                # a former `status` branch, which could never fire: no route
                # ENTRY carries a `status` key. (`status` does exist one level
                # up, on the response envelope -- `{"status": "success",
                # "results": [...]}` -- which this function is handed as
                # `routing_data`. But the removed branch read `route[...]`,
                # not `routing_data[...]`, so it never saw that key.)
                if route.get("origin"):
                    lines.append(f"  Origin: {route['origin']}")

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
    def security_profiles(data: Dict[str, Any]) -> str:
        """Format security profile visibility across AV/IPS/web-filter/app-control.

        Args:
            data: Dict keyed by 4 fixed categories -- "antivirus", "ips",
                "webfilter", "application_control" -- each value either
                {"status": "ok", "profiles": [...]} or
                {"status": "error", "error": "<message>"}. A category key
                that is missing or falsy means it was never queried.

        Returns:
            Formatted security profiles information. A per-category
            authorization/licensing error always renders distinctly from a
            genuinely empty category -- never collapsed into the same text.
        """
        categories = [
            ("antivirus", "Antivirus Profiles"),
            ("ips", "IPS Sensors"),
            ("webfilter", "Web Filter Profiles"),
            ("application_control", "Application Control Profiles"),
        ]

        lines = ["Security Profiles", ""]

        for key, title in categories:
            category = data.get(key)

            if not category:
                lines.extend([f"{title}: not queried", ""])
                continue

            if category.get("status") == "error":
                error_message = category.get("error", "unknown error")
                lines.extend([f"{title}: query failed - {error_message}", ""])
                continue

            profiles = category.get("profiles", [])
            if not profiles:
                lines.extend([f"{title}: none configured", ""])
                continue

            lines.append(title)
            for profile in profiles:
                name = profile.get("name", "Unnamed")
                comment = profile.get("comment")
                lines.append(f"  {name} - {comment}" if comment else f"  {name}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def admin_accounts(data: Dict[str, Any]) -> str:
        """Format administrator account list (cmdb/system/admin).

        Args:
            data: Admin accounts response from FortiGate API

        Returns:
            Formatted administrator account information. Never renders the
            password/hash field -- Phase 9's Tools layer applies redaction
            before this template is reachable from any live tool call.
        """
        lines = ["Administrator Accounts", ""]

        if "results" in data and data["results"]:
            admins = data["results"]

            for admin in admins:
                name = admin.get("name", "Unnamed")
                accprofile = admin.get("accprofile", "unknown")

                trusted = False
                for i in range(1, 11):
                    host = admin.get(f"trusthost{i}")
                    if host and host != "0.0.0.0 0.0.0.0":
                        trusted = True
                        break
                trusted_text = "Yes" if trusted else "No"

                two_factor = admin.get("two-factor", "disable")
                two_factor_text = "On" if two_factor != "disable" else "Off"

                vdom_text = FortiGateTemplates._render_profile_ref(admin.get("vdom"))

                lines.extend([
                    f"Admin: {name}",
                    f"  Profile: {accprofile}",
                    f"  Trusted Hosts: {trusted_text}",
                    f"  Two-Factor: {two_factor_text}",
                    f"  VDOM: {vdom_text}",
                    "",
                ])
        else:
            lines.append("No administrator accounts configured")

        return "\n".join(lines)

    @staticmethod
    def sslvpn_settings(data: Dict[str, Any], portals_data: Optional[Dict[str, Any]] = None) -> str:
        """Format SSL-VPN settings (singleton) plus an optional bookmarks section.

        Args:
            data: SSL-VPN settings response from FortiGate API
                (cmdb/vpn.ssl/settings). `results` here is a single JSON
                object, NOT a list -- mirrors the device_status singleton
                precedent, never data["results"][0].
            portals_data: Optional SSL-VPN web portal list response
                (cmdb/vpn.ssl.web/portal) used to render a "Portal Bookmarks"
                section. Renders whatever bookmark fields (including
                logon-password/sso-password) are present, unredacted --
                Phase 9's Tools layer applies redaction before this template
                is reachable from a live tool call.

        Returns:
            Formatted SSL-VPN settings information
        """
        lines = ["SSL-VPN Settings", ""]

        if "results" not in data:
            lines.append("No SSL-VPN settings available")
            return "\n".join(lines)

        settings = data["results"]
        if isinstance(settings, list):
            settings = settings[0] if settings else {}

        if not settings:
            lines.append("No SSL-VPN settings available")
            return "\n".join(lines)

        source_interfaces = ", ".join(
            intf.get("name", "unknown") if isinstance(intf, dict) else str(intf)
            for intf in settings.get("source-interface", [])
        )
        tunnel_pools = ", ".join(
            pool.get("name", "unknown") if isinstance(pool, dict) else str(pool)
            for pool in settings.get("tunnel-ip-pools", [])
        )

        lines.extend([
            f"  Status: {settings.get('status', 'unknown')}",
            f"  Port: {settings.get('port', 'N/A')}",
            f"  Source Interface: {source_interfaces or 'N/A'}",
            f"  Tunnel IP Pools: {tunnel_pools or 'N/A'}",
            f"  Default Portal: {settings.get('default-portal', 'N/A')}",
            f"  SSL Min Proto Version: {settings.get('ssl-min-proto-ver', 'unknown')}",
            f"  Idle Timeout: {settings.get('idle-timeout', 'N/A')}",
            f"  Auth Timeout: {settings.get('auth-timeout', 'N/A')}",
            f"  Login Attempt Limit: {settings.get('login-attempt-limit', 'N/A')}",
            f"  Server Certificate: {settings.get('servercert', 'N/A')}",
            "",
        ])

        if portals_data is not None and portals_data.get("results"):
            portals = portals_data["results"]
            lines.append("Portal Bookmarks")
            for portal in portals:
                portal_name = portal.get("name", "Unnamed")
                for group in portal.get("bookmark-group", []):
                    group_name = group.get("name", "Unnamed")
                    for bookmark in group.get("bookmarks", []):
                        bm_name = bookmark.get("name", "Unnamed")
                        apptype = bookmark.get("apptype", "unknown")
                        host_or_url = bookmark.get("host") or bookmark.get("url", "N/A")
                        lines.append(
                            f"  Portal: {portal_name} / Group: {group_name} / "
                            f"Bookmark: {bm_name} ({apptype}) -> {host_or_url}"
                        )
                        # Rendered exactly as given, unredacted -- Phase 9's
                        # Tools layer applies redaction before this template
                        # is reachable from a live tool call.
                        if bookmark.get("logon-password"):
                            lines.append(f"    Logon Password: {bookmark['logon-password']}")
                        if bookmark.get("sso-password"):
                            lines.append(f"    SSO Password: {bookmark['sso-password']}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def local_in_policies(data: Dict[str, Any]) -> str:
        """Format local-in policy list (cmdb/firewall/local-in-policy, IPv4 only).

        Args:
            data: Local-in policies response from FortiGate API

        Returns:
            Formatted local-in policies information
        """
        lines = ["Local-In Policies", ""]

        if "results" in data and data["results"]:
            policies = data["results"]

            for policy in policies:
                intf_names = ", ".join(
                    intf.get("name", "unknown") if isinstance(intf, dict) else str(intf)
                    for intf in policy.get("intf", [])
                )
                srcaddr_names = ", ".join(
                    addr.get("name", "unknown") if isinstance(addr, dict) else str(addr)
                    for addr in policy.get("srcaddr", [])
                )
                dstaddr_names = ", ".join(
                    addr.get("name", "unknown") if isinstance(addr, dict) else str(addr)
                    for addr in policy.get("dstaddr", [])
                )
                service_names = ", ".join(
                    svc.get("name", "unknown") if isinstance(svc, dict) else str(svc)
                    for svc in policy.get("service", [])
                )

                lines.extend([
                    f"Policy {policy.get('policyid', 'N/A')}",
                    f"  Interface: {intf_names or 'any'}",
                    f"  Source: {srcaddr_names or 'any'}",
                    f"  Destination: {dstaddr_names or 'any'}",
                    f"  Service: {service_names or 'any'}",
                    f"  Action: {policy.get('action', 'unknown')}",
                    f"  Status: {policy.get('status', 'unknown')}",
                ])

                if policy.get("comments"):
                    lines.append(f"  Comments: {policy['comments']}")

                lines.append("")
        else:
            lines.append("No local-in policies configured")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Phase 15: config-object and monitor visibility templates
    # ------------------------------------------------------------------

    @staticmethod
    def _member_names(members: Any) -> str:
        """Render a FortiOS member list ({"name": x} dicts or plain strings)."""
        if isinstance(members, (str, dict)):
            members = [members]
        if not isinstance(members, (list, tuple)):
            return ""
        names = []
        for member in members[: FortiGateTemplates._MEMBER_CAP]:
            if isinstance(member, dict):
                names.append(str(member.get("name", "unknown")))
            else:
                names.append(str(member))
        if len(members) > FortiGateTemplates._MEMBER_CAP:
            names.append(f"... ({len(members) - FortiGateTemplates._MEMBER_CAP} more)")
        return ", ".join(names)

    # Output caps for list-style tools whose device queries are not paged.
    _LIST_CAP = 500
    _MEMBER_CAP = 200
    _FINDING_CAP = 100

    @staticmethod
    def _capped(items: List[Any], cap: int, lines: List[str], noun: str) -> List[Any]:
        """Return items[:cap]; append a truncation line to `lines` when cut."""
        if len(items) > cap:
            lines.append(f"Showing {cap} of {len(items)} {noun}; output truncated")
            lines.append("")
            return items[:cap]
        return items

    @staticmethod
    def _results_list(data: Any) -> List[Any]:
        """Return data["results"] as a list of dict entries; [] when malformed."""
        results = data.get("results") if isinstance(data, dict) else None
        if isinstance(results, dict):
            results = [results]
        if not isinstance(results, list):
            return []
        return [r for r in results if isinstance(r, dict)]

    @staticmethod
    def _group_listing(title: str, empty_text: str, data: Any) -> str:
        lines = [title, ""]
        groups = FortiGateTemplates._results_list(data)
        if not groups:
            lines.append(empty_text)
            return "\n".join(lines)
        groups = FortiGateTemplates._capped(groups, FortiGateTemplates._LIST_CAP, lines, "groups")
        for group in groups:
            members = group.get("member")
            count = len(members) if isinstance(members, list) else 0
            lines.append(f"{group.get('name', 'Unnamed')} ({count} members)")
            names = FortiGateTemplates._member_names(members)
            if names:
                lines.append(f"  Members: {names}")
            if group.get("comment"):
                lines.append(f"  Comment: {group['comment']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def address_groups(data: Dict[str, Any]) -> str:
        """Format address groups (cmdb/firewall/addrgrp)."""
        return FortiGateTemplates._group_listing(
            "Address Groups", "No address groups configured", data
        )

    @staticmethod
    def service_groups(data: Dict[str, Any]) -> str:
        """Format service groups (cmdb/firewall.service/group)."""
        return FortiGateTemplates._group_listing(
            "Service Groups", "No service groups configured", data
        )

    @staticmethod
    def schedules(data: Dict[str, Any]) -> str:
        """Format schedules from recurring/onetime/group categories.

        Args:
            data: Dict keyed "recurring", "onetime", "group"; each value
                {"status": "ok", "schedules": [...]} or
                {"status": "error", "error": "<text>"}.
        """
        categories = [
            ("recurring", "Recurring Schedules"),
            ("onetime", "One-Time Schedules"),
            ("group", "Schedule Groups"),
        ]
        lines = ["Schedules", ""]
        for key, title in categories:
            category = data.get(key) if isinstance(data, dict) else None
            if not isinstance(category, dict) or not category:
                lines.extend([f"{title}: not queried", ""])
                continue
            if category.get("status") == "error":
                lines.extend(
                    [f"{title}: query failed - {category.get('error', 'unknown error')}", ""]
                )
                continue
            items = [s for s in (category.get("schedules") or []) if isinstance(s, dict)]
            if not items:
                lines.extend([f"{title}: none configured", ""])
                continue
            lines.append(title)
            items = FortiGateTemplates._capped(
                items, FortiGateTemplates._LIST_CAP, lines, "schedules"
            )
            for item in items:
                name = item.get("name", "Unnamed")
                if key == "recurring":
                    lines.append(
                        f"  {name}: day {item.get('day') or 'N/A'}, "
                        f"start {item.get('start', 'N/A')}, end {item.get('end', 'N/A')}"
                    )
                elif key == "onetime":
                    line = (
                        f"  {name}: start {item.get('start', 'N/A')}, "
                        f"end {item.get('end', 'N/A')}"
                    )
                    if "expiration-days" in item:
                        line += f", expiration-days {item['expiration-days']}"
                    lines.append(line)
                else:
                    lines.append(
                        f"  {name}: members {FortiGateTemplates._member_names(item.get('member')) or 'none'}"
                    )
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def ip_pools(data: Dict[str, Any]) -> str:
        """Format IP pools (cmdb/firewall/ippool)."""
        lines = ["IP Pools", ""]
        pools = FortiGateTemplates._results_list(data)
        if not pools:
            lines.append("No IP pools configured")
            return "\n".join(lines)
        pools = FortiGateTemplates._capped(pools, FortiGateTemplates._LIST_CAP, lines, "pools")
        for pool in pools:
            lines.extend([
                f"{pool.get('name', 'Unnamed')}",
                f"  Type: {pool.get('type', 'unknown')}",
                f"  Range: {pool.get('startip', 'N/A')} - {pool.get('endip', 'N/A')}",
            ])
            if pool.get("source-startip") or pool.get("source-endip"):
                lines.append(
                    f"  Source range: {pool.get('source-startip', 'N/A')} - "
                    f"{pool.get('source-endip', 'N/A')}"
                )
            if pool.get("comments"):
                lines.append(f"  Comments: {pool['comments']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _named_members(value: Any, key: str) -> List[str]:
        """Names from a FortiOS table field ([{key: name}, ...]); [] when malformed."""
        if not isinstance(value, list):
            return []
        return [str(m[key]) for m in value if isinstance(m, dict) and m.get(key)]

    @staticmethod
    def zones(data: Dict[str, Any]) -> str:
        """Format firewall zones plus an interface -> zone reverse index (cmdb/system/zone)."""
        lines = ["Firewall Zones", ""]
        zones = FortiGateTemplates._results_list(data)
        if not zones:
            lines.append("No zones configured")
            return "\n".join(lines)
        zones = FortiGateTemplates._capped(zones, FortiGateTemplates._LIST_CAP, lines, "zones")
        index: Dict[str, List[str]] = {}
        for zone in zones:
            name = str(zone.get("name", "Unnamed"))
            members = FortiGateTemplates._named_members(zone.get("interface"), "interface-name")
            for member in members:
                index.setdefault(member, []).append(name)
            lines.extend([
                name,
                f"  Interfaces: {', '.join(members) if members else 'none'}",
                f"  Intrazone traffic: {zone.get('intrazone', 'N/A')}",
            ])
            if zone.get("description"):
                lines.append(f"  Description: {zone['description']}")
            lines.append("")
        lines.append("Interface to zone index")
        for iface in sorted(index):
            lines.append(f"  {iface} -> {', '.join(index[iface])}")
        return "\n".join(lines)

    @staticmethod
    def dhcp_servers(data: Dict[str, Any]) -> str:
        """Format DHCP server scopes (cmdb/system.dhcp/server). Scope config only, no leases."""
        lines = ["DHCP Servers", ""]
        servers = FortiGateTemplates._results_list(data)
        if not servers:
            lines.append("No DHCP servers configured")
            return "\n".join(lines)
        servers = FortiGateTemplates._capped(
            servers, FortiGateTemplates._LIST_CAP, lines, "DHCP servers"
        )
        for srv in servers:
            ranges = [
                f"{r.get('start-ip', 'N/A')} - {r.get('end-ip', 'N/A')}"
                for r in (srv.get("ip-range") or [])
                if isinstance(r, dict)
            ]
            dns = [
                str(srv[k]) for k in ("dns-server1", "dns-server2", "dns-server3", "dns-server4")
                if srv.get(k) and srv[k] != "0.0.0.0"
            ]
            reserved = srv.get("reserved-address")
            lines.extend([
                f"Server {srv.get('id', 'N/A')}",
                f"  Interface: {srv.get('interface', 'N/A')}",
                f"  Status: {srv.get('status', 'N/A')}",
                f"  Gateway: {srv.get('default-gateway', 'N/A')}",
                f"  Netmask: {srv.get('netmask', 'N/A')}",
                f"  IP range: {'; '.join(ranges) if ranges else 'none'}",
                f"  Lease time: {srv.get('lease-time', 'N/A')}",
                f"  DNS: {', '.join(dns) if dns else srv.get('dns-service', 'N/A')}",
            ])
            if srv.get("domain"):
                lines.append(f"  Domain: {srv['domain']}")
            if isinstance(reserved, list):
                lines.append(f"  Reserved addresses: {len(reserved)}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def central_snat_maps(data: Dict[str, Any]) -> str:
        """Format central SNAT map entries (cmdb/firewall/central-snat-map)."""
        lines = ["Central SNAT Maps", ""]
        entries = FortiGateTemplates._results_list(data)
        if not entries:
            lines.append("No central SNAT map entries configured")
            return "\n".join(lines)
        entries = FortiGateTemplates._capped(
            entries, FortiGateTemplates._LIST_CAP, lines, "entries"
        )
        names = FortiGateTemplates._member_names
        for entry in entries:
            lines.extend([
                f"Entry {entry.get('policyid', 'N/A')}",
                f"  Status: {entry.get('status', 'unknown')}",
                f"  Interfaces: {names(entry.get('srcintf')) or 'any'} -> "
                f"{names(entry.get('dstintf')) or 'any'}",
                f"  Original address: {names(entry.get('orig-addr')) or 'any'}",
                f"  Destination address: {names(entry.get('dst-addr')) or 'any'}",
                f"  Protocol: {entry.get('protocol', 'any')}",
                f"  NAT IP pool: {names(entry.get('nat-ippool')) or 'none'}",
            ])
            if entry.get("comments"):
                lines.append(f"  Comments: {entry['comments']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _shortest_interval_key(label: Any) -> int:
        """Sort key so '1-min' < '10-min' < '30-min' < '1-hour' etc."""
        text = str(label).lower()
        digits = "".join(ch for ch in text.split("-")[0] if ch.isdigit())
        number = int(digits) if digits else 10**6
        if "hour" in text:
            number *= 60
        elif "day" in text:
            number *= 1440
        return number

    @staticmethod
    def system_resources(data: Dict[str, Any]) -> str:
        """Format the latest value per resource (monitor/system/resource/usage)."""
        lines = ["System Resources", ""]
        results = data.get("results") if isinstance(data, dict) else None
        pairs: List[Any] = []
        if isinstance(results, dict):
            pairs = list(results.items())
        elif isinstance(results, list):
            for item in results:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("resource")
                    if name is not None:
                        pairs.append((name, item))
        if not pairs:
            lines.append("No resource data")
            return "\n".join(lines)
        for name, value in pairs:
            latest: Any = None
            interval = None
            if isinstance(value, list):
                buckets = [b for b in value if isinstance(b, dict) and "current" in b]
                if buckets:
                    best = min(
                        buckets,
                        key=lambda b: FortiGateTemplates._shortest_interval_key(
                            b.get("interval", "")
                        ),
                    )
                    latest = best["current"]
                    interval = best.get("interval")
            elif isinstance(value, dict):
                latest = value.get("current")
                interval = value.get("interval")
            elif isinstance(value, (int, float, str)):
                latest = value
            if latest is None:
                lines.append(f"{name}: no data")
            elif interval:
                lines.append(f"{name}: {latest} ({interval})")
            else:
                lines.append(f"{name}: {latest}")
        return "\n".join(lines)

    @staticmethod
    def license_status(data: Dict[str, Any]) -> str:
        """Format license/contract status (monitor/license/status)."""
        lines = ["License Status", ""]
        results = data.get("results") if isinstance(data, dict) else None
        entries: List[Any] = []
        if isinstance(results, dict):
            entries = list(results.items())
        elif isinstance(results, list):
            entries = [
                (item.get("name", f"entry {i + 1}"), item)
                for i, item in enumerate(results)
                if isinstance(item, dict)
            ]
        if not entries:
            lines.append("No license data")
            return "\n".join(lines)
        for name, entry in entries:
            if not isinstance(entry, dict):
                lines.append(f"{name}: {entry}")
                continue
            status = entry.get("status")
            expiry = entry.get("expires") or entry.get("expiry") or entry.get("expiration")
            if status is not None or expiry is not None:
                line = f"{name}: status {status if status is not None else 'unknown'}"
                if expiry is not None:
                    line += f", expires {expiry}"
                lines.append(line)
            else:
                scalars = [
                    f"{k}: {v}"
                    for k, v in list(entry.items())[:10]
                    if isinstance(v, (str, int, float, bool))
                ]
                lines.append(f"{name}: " + (", ".join(scalars) if scalars else "no details"))
        return "\n".join(lines)

    @staticmethod
    def ha_status(data: Dict[str, Any]) -> str:
        """Format HA peers; empty results means standalone (not an error)."""
        lines = ["HA Status", ""]
        results = data.get("results") if isinstance(data, dict) else None
        if isinstance(results, dict):
            results = [results] if results else []
        peers = [p for p in results if isinstance(p, dict)] if isinstance(results, list) else []
        if not peers:
            lines.append("Mode: standalone (no HA peers configured)")
            return "\n".join(lines)
        lines.append("Mode: HA")
        lines.append(f"Peers: {len(peers)}")
        lines.append("")
        for peer in peers:
            lines.append(f"{peer.get('hostname', 'unknown')}")
            if peer.get("serial_no") is not None:
                lines.append(f"  Serial: {peer['serial_no']}")
            if peer.get("priority") is not None:
                lines.append(f"  Priority: {peer['priority']}")
            if peer.get("role") is not None:
                lines.append(f"  Role: {peer['role']}")
            elif peer.get("primary") is not None:
                lines.append(f"  Primary: {peer['primary']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _capped_table(
        title: str, empty_text: str, rows: List[str], data: Dict[str, Any], count: int
    ) -> str:
        interface = data.get("interface")
        lines = [title, "Note: contains MAC addresses and hostnames - treat as sensitive", ""]
        if not rows:
            suffix = f" on interface {interface}" if interface else ""
            lines.append(empty_text + suffix)
            return "\n".join(lines)
        total = data.get("total")
        if isinstance(total, int) and not isinstance(total, bool) and total > count:
            lines.append(f"Showing {count} of {total} entries (limit {data.get('limit', count)})")
            lines.append("")
        lines.extend(rows)
        return "\n".join(lines)

    @staticmethod
    def arp_table(data: Dict[str, Any]) -> str:
        """Format ARP entries; data carries tool-set total/limit/interface."""
        entries = FortiGateTemplates._results_list(data)
        rows = [
            f"{e.get('ip', 'N/A')}  {e.get('mac', 'N/A')}  {e.get('interface', 'N/A')}"
            f"  age {e.get('age', 'N/A')}"
            for e in entries
        ]
        return FortiGateTemplates._capped_table(
            "ARP Table", "No ARP entries", rows, data, len(entries)
        )

    @staticmethod
    def dhcp_leases(data: Dict[str, Any]) -> str:
        """Format DHCP leases; data carries tool-set total/limit/interface."""
        entries = FortiGateTemplates._results_list(data)
        rows = []
        for e in entries:
            state = e.get("expire_time", e.get("expire", e.get("status", "N/A")))
            rows.append(
                f"{e.get('ip', 'N/A')}  {e.get('mac', 'N/A')}  {e.get('hostname') or '-'}"
                f"  {e.get('interface', 'N/A')}  {state}"
            )
        return FortiGateTemplates._capped_table(
            "DHCP Leases", "No DHCP leases", rows, data, len(entries)
        )

    # ------------------------------------------------------------------
    # Phase 16: IPsec status, firewall sessions, policy hygiene
    # ------------------------------------------------------------------

    @staticmethod
    def _subnet_text(value: Any) -> str:
        """Render proxyid selector (list of {subnet} dicts or a string)."""
        if isinstance(value, (str, dict)):
            value = [value]
        if not isinstance(value, list):
            return "N/A"
        parts = []
        for item in value:
            if isinstance(item, dict):
                parts.append(str(item.get("subnet", item.get("name", "N/A"))))
            else:
                parts.append(str(item))
        return ", ".join(parts) if parts else "N/A"

    @staticmethod
    def ipsec_tunnels(data: Dict[str, Any]) -> str:
        """Format IPsec tunnel status using an explicit field whitelist.

        Only name, remote gateway, status and proxyid selectors/bytes/status are
        ever rendered; any other key (including pre-shared keys) is dropped even
        if the payload contains it.
        """
        lines = ["IPsec Tunnels", ""]
        tunnels = FortiGateTemplates._results_list(data)
        if not tunnels:
            lines.append("No IPsec tunnels found")
            return "\n".join(lines)
        for tunnel in tunnels:
            proxyids = tunnel.get("proxyid")
            proxyids = [p for p in proxyids if isinstance(p, dict)] if isinstance(proxyids, list) else []
            status = tunnel.get("status")
            if not isinstance(status, str):
                if any(p.get("status") == "up" for p in proxyids):
                    status = "up"
                elif proxyids:
                    status = "down"
                else:
                    status = "unknown"
            lines.append(f"{tunnel.get('name', 'Unnamed')} (status: {status})")
            lines.append(f"  Remote gateway: {tunnel.get('rgwy', tunnel.get('remote_gateway', 'N/A'))}")
            if not proxyids:
                lines.append("  Phase 2 selectors: none")
            for p in proxyids:
                lines.append(
                    f"  Phase 2 {p.get('p2name', 'N/A')}: "
                    f"{FortiGateTemplates._subnet_text(p.get('proxy_src'))} -> "
                    f"{FortiGateTemplates._subnet_text(p.get('proxy_dst'))} "
                    f"[{p.get('status', 'unknown')}] "
                    f"in {p.get('incoming_bytes', 0)} B / out {p.get('outgoing_bytes', 0)} B"
                )
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def firewall_sessions(data: Dict[str, Any]) -> str:
        """Format a capped session list; data carries tool-set total/limit/filters."""
        entries = FortiGateTemplates._results_list(data)
        lines = ["Firewall Sessions", ""]
        limit = data.get("limit")
        total = data.get("total")
        returned = len(entries)
        lines.append(f"Requested up to {limit} session(s); showing {returned}")
        if data.get("truncated"):
            lines.append(
                f"Result limit of {limit} reached; more sessions may exist "
                "(narrow the filters to see others)"
            )
        filters = data.get("filters")
        if isinstance(filters, dict) and filters:
            lines.append("Filters: " + ", ".join(f"{k}={filters[k]}" for k in sorted(filters)))
        if isinstance(total, int) and not isinstance(total, bool) and total > returned:
            lines.append(f"Device reported {total} matching session(s)")
        lines.append("")
        if not entries:
            lines.append("No sessions found")
            return "\n".join(lines)
        for e in entries:
            src = e.get("saddr", e.get("srcaddr", "N/A"))
            dst = e.get("daddr", e.get("dstaddr", "N/A"))
            lines.append(
                f"{e.get('proto', 'N/A')}  {src}:{e.get('sport', '-')} -> "
                f"{dst}:{e.get('dport', '-')}  policy {e.get('policyid', 'N/A')}  "
                f"duration {e.get('duration', 'N/A')}s  expiry {e.get('expiry', 'N/A')}s"
            )
        return "\n".join(lines)

    @staticmethod
    def policy_hygiene(data: Dict[str, Any]) -> str:
        """Format the output of analysis.analyze_policy_hygiene."""
        raw_summary = data.get("summary")
        raw_findings = data.get("findings")
        summary: Dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        findings: Dict[str, Any] = raw_findings if isinstance(raw_findings, dict) else {}
        lines = ["Firewall Policy Hygiene (offline analysis of fetched configuration)", ""]
        lines.append(
            f"Policies analyzed: {summary.get('policies_analyzed', 0)} "
            f"(skipped: {summary.get('skipped', 0)})"
        )
        order = ("shadowed", "duplicate", "any_any", "permissive_any", "disabled")
        lines.append(
            "Findings: " + ", ".join(f"{k}={summary.get(k, 0)}" for k in order)
        )
        sources = data.get("sources")
        if isinstance(sources, dict):
            for name in sorted(sources):
                if sources[name] != "ok":
                    lines.append(f"Source {name}: {sources[name]} (analysis may be incomplete)")
        lines.append("")
        for key in order:
            items = findings.get(key) or []
            if not items:
                continue
            lines.append(f"{key} ({len(items)})")
            for item in items[: FortiGateTemplates._FINDING_CAP]:
                extras = ", ".join(
                    f"{k}={item[k]}" for k in sorted(item) if k != "policyid"
                )
                lines.append(f"  Policy {item.get('policyid')}" + (f": {extras}" if extras else ""))
            if len(items) > FortiGateTemplates._FINDING_CAP:
                lines.append(
                    f"  ... {len(items) - FortiGateTemplates._FINDING_CAP} more not shown"
                )
            lines.append("")
        if not any(findings.get(k) for k in order):
            lines.append("No hygiene findings")
            lines.append("")
        for note in data.get("notes") or []:
            lines.append(f"Note: {note}")
        return "\n".join(lines).rstrip()

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
            "FortiGate MCP Server Health",
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

        failed_devices = details.get("failed_devices")
        if failed_devices:
            lines.append(f"  Failed Devices: {len(failed_devices)}")
            for device_id, error in failed_devices.items():
                lines.append(f"    - {device_id}: {error}")

        return "\n".join(lines)
