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
            
            for policy in policies:
                status_icon = "✅" if policy.get("status") == "enable" else "❌"
                action_icon = "🟢" if policy.get("action") == "accept" else "🔴"
                
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
                    f"{status_icon} **Policy {policy.get('policyid', 'N/A')}** {action_icon}",
                    f"   • Name: {policy.get('name', 'Unnamed')}",
                    f"   • Source: {src_text if src_text else 'any'}",
                    f"   • Destination: {dst_text if dst_text else 'any'}",
                    f"   • Service: {svc_text if svc_text else 'any'}",
                    f"   • Action: {policy.get('action', 'unknown')}",
                    ""
                ])
            

                
        else:
            lines.append("📝 No firewall policies found")
        
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
            return f"🚫 Policy not found on device {device_id}"
        
        # FortiGate API returns results as a single object for specific policy ID
        results = policy_data["results"]
        if isinstance(results, list):
            if not results:
                return f"🚫 Policy not found on device {device_id}"
            policy = results[0]  # Get first (and only) policy from list
        else:
            policy = results
        lines = [f"🔥 **Policy Detaylı Analizi - Device: {device_id}**", ""]
        
        # Basic Policy Information
        lines.extend([
            "## 📋 **Temel Bilgiler**",
            f"• **Policy ID**: {policy.get('policyid', 'N/A')}",
            f"• **Policy Adı**: {policy.get('name', 'Unnamed')}",
            f"• **Durum**: {'✅ Aktif' if policy.get('status') == 'enable' else '❌ Devre Dışı'}",
            f"• **UUID**: {policy.get('uuid', 'N/A')}",
            ""
        ])
        
        # Traffic Direction
        src_intf = policy.get('srcintf', [])
        dst_intf = policy.get('dstintf', [])
        src_intf_names = [intf.get('name', 'unknown') if isinstance(intf, dict) else str(intf) for intf in src_intf]
        dst_intf_names = [intf.get('name', 'unknown') if isinstance(intf, dict) else str(intf) for intf in dst_intf]
        
        lines.extend([
            "## 🌐 **Trafik Yönü**",
            f"• **Kaynak Interface**: {', '.join(src_intf_names)}",
            f"• **Hedef Interface**: {', '.join(dst_intf_names)}",
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
            "## 🔹 **Kaynak (Source)**",
            f"• **Adres Nesneleri**: {', '.join(src_names)}",
            f"• **Toplam Nesne Sayısı**: {len(src_names)}",
        ])
        
        # Resolve source addresses if address_objects provided
        if address_objects and "results" in address_objects:
            addr_dict = {addr["name"]: addr for addr in address_objects["results"]}
            lines.append("• **Çözümlenen Adresler**:")
            for src_name in src_names:
                if src_name in addr_dict:
                    addr = addr_dict[src_name]
                    if addr.get("subnet"):
                        lines.append(f"  - {src_name}: {addr['subnet']}")
                    elif addr.get("start-ip") and addr.get("end-ip"):
                        lines.append(f"  - {src_name}: {addr['start-ip']} - {addr['end-ip']}")
                    elif addr.get("fqdn"):
                        lines.append(f"  - {src_name}: {addr['fqdn']}")
                else:
                    lines.append(f"  - {src_name}: Çözümlenemedi")
        
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
            "## 🎯 **Hedef (Destination)**",
            f"• **Adres Nesneleri**: {', '.join(dst_names)}",
            f"• **Toplam Nesne Sayısı**: {len(dst_names)}",
        ])
        
        # Resolve destination addresses
        if address_objects and "results" in address_objects:
            lines.append("• **Çözümlenen Adresler**:")
            for dst_name in dst_names:
                if dst_name in addr_dict:
                    addr = addr_dict[dst_name]
                    if addr.get("subnet"):
                        lines.append(f"  - {dst_name}: {addr['subnet']}")
                    elif addr.get("start-ip") and addr.get("end-ip"):
                        lines.append(f"  - {dst_name}: {addr['start-ip']} - {addr['end-ip']}")
                    elif addr.get("fqdn"):
                        lines.append(f"  - {dst_name}: {addr['fqdn']}")
                else:
                    lines.append(f"  - {dst_name}: Çözümlenemedi")
        
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
            "## 🔧 **Servisler**",
            f"• **Servis Nesneleri**: {', '.join(svc_names)}",
            f"• **Toplam Servis Sayısı**: {len(svc_names)}",
        ])
        
        # Resolve services
        if service_objects and "results" in service_objects:
            svc_dict = {svc["name"]: svc for svc in service_objects["results"]}
            lines.append("• **Çözümlenen Servisler**:")
            for svc_name in svc_names:
                if svc_name in svc_dict:
                    svc = svc_dict[svc_name]
                    protocol = svc.get("protocol", "unknown").upper()
                    if svc.get("tcp-portrange"):
                        lines.append(f"  - {svc_name}: TCP {svc['tcp-portrange']}")
                    elif svc.get("udp-portrange"):
                        lines.append(f"  - {svc_name}: UDP {svc['udp-portrange']}")
                    else:
                        lines.append(f"  - {svc_name}: {protocol}")
                else:
                    lines.append(f"  - {svc_name}: Çözümlenemedi")
        
        lines.append("")
        
        # Action and Security
        action = policy.get('action', 'unknown')
        action_icon = "🟢" if action == "accept" else "🔴" if action == "deny" else "⚪"
        
        lines.extend([
            "## ⚙️ **Aksiyon ve Güvenlik**",
            f"• **Aksiyon**: {action_icon} {action.upper()}",
            f"• **Log Trafiği**: {'✅ Evet' if policy.get('logtraffic') == 'all' else '❌ Hayır'}",
            f"• **NAT**: {'✅ Evet' if policy.get('nat') == 'enable' else '❌ Hayır'}",
        ])
        
        # Schedule
        schedule = policy.get('schedule', [])
        schedule_name = schedule[0].get('name') if schedule and isinstance(schedule[0], dict) else str(schedule[0]) if schedule else 'always'
        lines.append(f"• **Zamanlama**: {schedule_name}")
        
        # Comments
        if policy.get('comments'):
            lines.extend([
                "",
                "## 💬 **Yorumlar**",
                f"```",
                f"{policy['comments']}",
                f"```"
            ])
        
        lines.append("")
        
        # Security Analysis
        risk_score, risk_factors = FortiGateTemplates._analyze_policy_security(policy)
        risk_color = "🔴" if risk_score >= 7 else "🟡" if risk_score >= 4 else "🟢"
        
        lines.extend([
            "## 🛡️ **Güvenlik Analizi**",
            f"• **Risk Skoru**: {risk_color} {risk_score}/10",
            "",
            "### ⚠️ **Risk Faktörleri**:"
        ])
        
        for factor in risk_factors:
            lines.append(f"• {factor}")
        
        lines.append("")
        
        # Recommendations
        recommendations = FortiGateTemplates._get_policy_recommendations(policy)
        if recommendations:
            lines.extend([
                "## 🔧 **İyileştirme Önerileri**",
                ""
            ])
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
        
        # Technical Details (collapsed)
        lines.extend([
            "",
            "## 🔍 **Teknik Detaylar**",
            f"• **Sequence Number**: {policy.get('seq-num', 'N/A')}",
            f"• **Internet Service**: {'✅ Evet' if policy.get('internet-service') == 'enable' else '❌ Hayır'}",
            f"• **Application Control**: {'✅ Evet' if policy.get('application-list') else '❌ Hayır'}",
            f"• **Antivirus**: {'✅ Evet' if policy.get('av-profile') else '❌ Hayır'}",
            f"• **Web Filter**: {'✅ Evet' if policy.get('webfilter-profile') else '❌ Hayır'}",
            f"• **IPS**: {'✅ Evet' if policy.get('ips-sensor') else '❌ Hayır'}",
            ""
        ])
        
        return "\n".join(lines)
    
    @staticmethod
    def _analyze_policy_security(policy: Dict[str, Any]) -> tuple[int, List[str]]:
        """Analyze policy security and return risk score and factors."""
        risk_score = 0
        risk_factors = []
        
        # Check source
        srcaddr = policy.get('srcaddr', [])
        if any(addr.get('name') == 'all' if isinstance(addr, dict) else addr == 'all' for addr in srcaddr):
            risk_score += 3
            risk_factors.append("🚨 Kaynak adres 'all' - Global erişim")
        
        # Check destination  
        dstaddr = policy.get('dstaddr', [])
        if any(addr.get('name') == 'all' if isinstance(addr, dict) else addr == 'all' for addr in dstaddr):
            risk_score += 2
            risk_factors.append("⚠️ Hedef adres 'all' - Geniş hedef erişimi")
        
        # Check service
        service = policy.get('service', [])
        if any(svc.get('name') == 'ALL' if isinstance(svc, dict) else svc == 'ALL' for svc in service):
            risk_score += 2
            risk_factors.append("⚠️ Servis 'ALL' - Tüm portlar açık")
        
        # Check logging
        if policy.get('logtraffic') != 'all':
            risk_score += 1
            risk_factors.append("📝 Log kaydı devre dışı")
        
        # Check security profiles
        if not policy.get('av-profile'):
            risk_score += 1
            risk_factors.append("🦠 Antivirus profili yok")
        
        if not policy.get('ips-sensor'):
            risk_score += 1
            risk_factors.append("🛡️ IPS sensörü yok")
        
        # Check interface types
        srcintf = policy.get('srcintf', [])
        dstintf = policy.get('dstintf', [])
        
        # WAN to LAN without proper security
        wan_to_lan = any('wan' in str(intf).lower() for intf in srcintf) and \
                    any('internal' in str(intf).lower() or 'lan' in str(intf).lower() for intf in dstintf)
        
        if wan_to_lan and not policy.get('ips-sensor'):
            risk_score += 2
            risk_factors.append("🌐 WAN'dan LAN'a erişim - IPS koruması yok")
        
        if not risk_factors:
            risk_factors.append("✅ Belirgin güvenlik riski tespit edilmedi")
        
        return min(risk_score, 10), risk_factors
    
    @staticmethod
    def _get_policy_recommendations(policy: Dict[str, Any]) -> List[str]:
        """Get security recommendations for a policy."""
        recommendations = []
        
        # Source recommendations
        srcaddr = policy.get('srcaddr', [])
        if any(addr.get('name') == 'all' if isinstance(addr, dict) else addr == 'all' for addr in srcaddr):
            recommendations.append("Kaynak adresini daha spesifik hale getirin (belirli IP aralıkları)")
        
        # Service recommendations
        service = policy.get('service', [])
        if any(svc.get('name') == 'ALL' if isinstance(svc, dict) else svc == 'ALL' for svc in service):
            recommendations.append("Servis tanımını spesifik portlarla sınırlayın")
        
        # Logging recommendations
        if policy.get('logtraffic') != 'all':
            recommendations.append("Trafik loglamasını etkinleştirin (security ve utm)")
        
        # Security profile recommendations
        if not policy.get('av-profile'):
            recommendations.append("Antivirus profili ekleyin")
        
        if not policy.get('ips-sensor'):
            recommendations.append("IPS sensörü ekleyin")
        
        if not policy.get('application-list'):
            recommendations.append("Uygulama kontrolü profili ekleyin")
        
        if not policy.get('webfilter-profile'):
            recommendations.append("Web filtreleme profili ekleyin")
        
        # NAT recommendations
        if policy.get('action') == 'accept' and not policy.get('nat'):
            dstintf = policy.get('dstintf', [])
            if any('wan' in str(intf).lower() for intf in dstintf):
                recommendations.append("İnternete çıkış için NAT'ı etkinleştirin")
        
        return recommendations
    
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
            
            for addr in addresses:
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
            
            for service in services:
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
            
            for route in routes:
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
            
            for interface in interfaces:
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
