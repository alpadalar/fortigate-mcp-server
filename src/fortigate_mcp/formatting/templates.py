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
            return "📱 No FortiGate devices configured"
        
        lines = ["📱 **FortiGate Devices**", ""]
        
        for device_id, info in devices.items():
            lines.extend([
                f"🔹 **{device_id}**",
                f"   • Host: {info['host']}:{info['port']}",
                f"   • VDOM: {info['vdom']}",
                f"   • Auth: {info['auth_method']}",
                f"   • SSL Verify: {'Yes' if info['verify_ssl'] else 'No'}",
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
        lines = [f"🖥️ **Device Status: {device_id}**", ""]
        
        if "results" in status_data:
            results = status_data["results"]
            
            lines.extend([
                f"📊 **System Information**",
                f"   • Model: {results.get('model_name', 'Unknown')} {results.get('model_number', '')}",
                f"   • Hostname: {results.get('hostname', 'Unknown')}",
                f"   • Version: {status_data.get('version', 'Unknown')}",
                f"   • Serial: {status_data.get('serial', 'Unknown')}",
                f"   • VDOM: {status_data.get('vdom', 'Unknown')}",
                ""
            ])
            
            # Add additional status info if available
            if results.get('log_disk_status'):
                lines.append(f"   • Log Disk: {results['log_disk_status']}")
            if results.get('current_time'):
                lines.append(f"   • Current Time: {results['current_time']}")
        else:
            lines.append("⚠️ No status information available")
        
        return "\n".join(lines)
    
    @staticmethod
    def firewall_policies(policies_data: Dict[str, Any]) -> str:
        """Format firewall policies list.
        
        Args:
            policies_data: Firewall policies response from FortiGate API
            
        Returns:
            Formatted firewall policies information
        """
        lines = ["🛡️ **Firewall Policies**", ""]
        
        if "results" in policies_data and policies_data["results"]:
            policies = policies_data["results"]
            
            for policy in policies[:10]:  # Limit to first 10 for readability
                status_icon = "✅" if policy.get("status") == "enable" else "❌"
                action_icon = "🟢" if policy.get("action") == "accept" else "🔴"
                
                lines.extend([
                    f"{status_icon} **Policy {policy.get('policyid', 'N/A')}** {action_icon}",
                    f"   • Name: {policy.get('name', 'Unnamed')}",
                    f"   • Source: {', '.join(policy.get('srcaddr', []))[:50]}{'...' if len(', '.join(policy.get('srcaddr', []))) > 50 else ''}",
                    f"   • Destination: {', '.join(policy.get('dstaddr', []))[:50]}{'...' if len(', '.join(policy.get('dstaddr', []))) > 50 else ''}",
                    f"   • Service: {', '.join(policy.get('service', []))[:50]}{'...' if len(', '.join(policy.get('service', []))) > 50 else ''}",
                    f"   • Action: {policy.get('action', 'unknown')}",
                    ""
                ])
            
            if len(policies) > 10:
                lines.append(f"... and {len(policies) - 10} more policies")
                
        else:
            lines.append("📝 No firewall policies found")
        
        return "\n".join(lines)
    
    @staticmethod
    def address_objects(addresses_data: Dict[str, Any]) -> str:
        """Format address objects list.
        
        Args:
            addresses_data: Address objects response from FortiGate API
            
        Returns:
            Formatted address objects information
        """
        lines = ["🏠 **Address Objects**", ""]
        
        if "results" in addresses_data and addresses_data["results"]:
            addresses = addresses_data["results"]
            
            for addr in addresses[:15]:  # Limit for readability
                type_icon = {
                    "ipmask": "🌐",
                    "iprange": "📏", 
                    "fqdn": "🔗",
                    "geography": "🗺️"
                }.get(addr.get("type", ""), "📍")
                
                lines.extend([
                    f"{type_icon} **{addr.get('name', 'Unnamed')}**",
                    f"   • Type: {addr.get('type', 'unknown')}",
                ])
                
                # Add type-specific information
                if addr.get("subnet"):
                    lines.append(f"   • Subnet: {addr['subnet']}")
                elif addr.get("start-ip") and addr.get("end-ip"):
                    lines.append(f"   • Range: {addr['start-ip']} - {addr['end-ip']}")
                elif addr.get("fqdn"):
                    lines.append(f"   • FQDN: {addr['fqdn']}")
                
                if addr.get("comment"):
                    lines.append(f"   • Comment: {addr['comment']}")
                
                lines.append("")
            
            if len(addresses) > 15:
                lines.append(f"... and {len(addresses) - 15} more address objects")
                
        else:
            lines.append("📋 No address objects found")
        
        return "\n".join(lines)
    
    @staticmethod
    def service_objects(services_data: Dict[str, Any]) -> str:
        """Format service objects list.
        
        Args:
            services_data: Service objects response from FortiGate API
            
        Returns:
            Formatted service objects information
        """
        lines = ["🔌 **Service Objects**", ""]
        
        if "results" in services_data and services_data["results"]:
            services = services_data["results"]
            
            for service in services[:15]:  # Limit for readability
                protocol = service.get("protocol", "unknown").upper()
                protocol_icon = {
                    "TCP": "🔗",
                    "UDP": "📡",
                    "ICMP": "📢"
                }.get(protocol, "⚙️")
                
                lines.extend([
                    f"{protocol_icon} **{service.get('name', 'Unnamed')}** ({protocol})",
                ])
                
                # Add protocol-specific port information
                if service.get("tcp-portrange"):
                    lines.append(f"   • TCP Ports: {service['tcp-portrange']}")
                if service.get("udp-portrange"):
                    lines.append(f"   • UDP Ports: {service['udp-portrange']}")
                
                if service.get("comment"):
                    lines.append(f"   • Comment: {service['comment']}")
                
                lines.append("")
            
            if len(services) > 15:
                lines.append(f"... and {len(services) - 15} more service objects")
                
        else:
            lines.append("📋 No service objects found")
        
        return "\n".join(lines)
    
    @staticmethod
    def static_routes(routes_data: Dict[str, Any]) -> str:
        """Format static routes list.
        
        Args:
            routes_data: Static routes response from FortiGate API
            
        Returns:
            Formatted static routes information
        """
        lines = ["🛣️ **Static Routes**", ""]
        
        if "results" in routes_data and routes_data["results"]:
            routes = routes_data["results"]
            
            for route in routes[:20]:  # Limit for readability
                status_icon = "✅" if route.get("status") == "enable" else "❌"
                
                lines.extend([
                    f"{status_icon} **Route {route.get('seq-num', 'N/A')}**",
                    f"   • Destination: {route.get('dst', '0.0.0.0/0')}",
                    f"   • Gateway: {route.get('gateway', 'N/A')}",
                    f"   • Device: {route.get('device', 'N/A')}",
                    f"   • Distance: {route.get('distance', 'N/A')}",
                ])
                
                if route.get("comment"):
                    lines.append(f"   • Comment: {route['comment']}")
                
                lines.append("")
            
            if len(routes) > 20:
                lines.append(f"... and {len(routes) - 20} more routes")
                
        else:
            lines.append("📋 No static routes found")
        
        return "\n".join(lines)
    
    @staticmethod
    def interfaces(interfaces_data: Dict[str, Any]) -> str:
        """Format interfaces list.
        
        Args:
            interfaces_data: Interfaces response from FortiGate API
            
        Returns:
            Formatted interfaces information
        """
        lines = ["🔌 **Network Interfaces**", ""]
        
        if "results" in interfaces_data and interfaces_data["results"]:
            interfaces = interfaces_data["results"]
            
            for interface in interfaces[:15]:  # Limit for readability
                status_icon = "🟢" if interface.get("status") == "up" else "🔴"
                
                lines.extend([
                    f"{status_icon} **{interface.get('name', 'Unnamed')}**",
                    f"   • Type: {interface.get('type', 'unknown')}",
                    f"   • Mode: {interface.get('mode', 'unknown')}",
                ])
                
                if interface.get("ip"):
                    lines.append(f"   • IP: {interface['ip']}")
                if interface.get("alias"):
                    lines.append(f"   • Alias: {interface['alias']}")
                
                lines.append("")
            
            if len(interfaces) > 15:
                lines.append(f"... and {len(interfaces) - 15} more interfaces")
                
        else:
            lines.append("📋 No interfaces found")
        
        return "\n".join(lines)
    
    @staticmethod
    def vdoms(vdoms_data: Dict[str, Any]) -> str:
        """Format VDOMs list.
        
        Args:
            vdoms_data: VDOMs response from FortiGate API
            
        Returns:
            Formatted VDOMs information
        """
        lines = ["🏢 **Virtual Domains (VDOMs)**", ""]
        
        if "results" in vdoms_data and vdoms_data["results"]:
            vdoms = vdoms_data["results"]
            
            for vdom in vdoms:
                status_icon = "✅" if vdom.get("enabled") else "❌"
                
                lines.extend([
                    f"{status_icon} **{vdom.get('name', 'Unnamed')}**",
                    f"   • Enabled: {'Yes' if vdom.get('enabled') else 'No'}",
                ])
                
                if vdom.get("comments"):
                    lines.append(f"   • Comments: {vdom['comments']}")
                
                lines.append("")
                
        else:
            lines.append("📋 No VDOMs found")
        
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
        status_icon = "✅" if success else "❌"
        status = "SUCCESS" if success else "FAILED"
        
        lines = [
            f"{status_icon} **Operation {status}**",
            f"   • Operation: {operation}",
            f"   • Device: {device_id}",
            f"   • Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        
        if success and details:
            lines.extend([
                "📋 **Details:**",
                f"   {details}",
                ""
            ])
        elif not success and error:
            lines.extend([
                "❗ **Error:**",
                f"   {error}",
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
        status_icon = {
            "healthy": "💚",
            "degraded": "💛", 
            "unhealthy": "❤️"
        }.get(status, "❓")
        
        lines = [
            f"{status_icon} **FortiGate MCP Server Health**",
            f"   • Status: {status.upper()}",
            f"   • Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        
        if details.get("registered_devices") is not None:
            lines.append(f"   • Registered Devices: {details['registered_devices']}")
        
        if details.get("server_version"):
            lines.append(f"   • Server Version: {details['server_version']}")
        
        if details.get("uptime"):
            lines.append(f"   • Uptime: {details['uptime']}")
        
        return "\n".join(lines)
