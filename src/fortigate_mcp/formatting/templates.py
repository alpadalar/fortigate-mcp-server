"""
Template system for FortiGate MCP response formatting.

This module provides structured templates for formatting FortiGate API responses
into human-readable and consistent output formats. Templates are organized by
resource type and operation.
"""
from typing import Dict, Any, Optional
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
