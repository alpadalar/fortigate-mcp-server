"""
IPSec VPN troubleshooting tools for FortiGate MCP.

This module provides MCP tools for IPSec VPN operations:
- List/view IPSec Phase 1 and Phase 2 configurations
- Create/update/delete IPSec tunnel configurations
- View tunnel status and traffic statistics
- Bring tunnels up/down via SSH
- IKE gateway diagnostics via SSH
- Comprehensive tunnel troubleshooting
"""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.fortigate import FortiGateAPIError
from ..core.ssh_client import FortiGateSSHClient, FortiGateSSHError, PARAMIKO_AVAILABLE
from ..formatting.formatters import FortiGateFormatters


class IPSecTools(FortiGateTool):
    """Tools for FortiGate IPSec VPN troubleshooting and management.

    Provides comprehensive IPSec VPN functionality including configuration
    management via REST API and diagnostics via SSH CLI commands.
    """

    def _get_ssh_client(self, device_id: str) -> FortiGateSSHClient:
        """Create SSH client for a device.

        Args:
            device_id: Device identifier

        Returns:
            FortiGateSSHClient instance

        Raises:
            ValueError: If SSH is not available or credentials missing
        """
        if not PARAMIKO_AVAILABLE:
            raise ValueError("SSH diagnostics require paramiko. Install with: pip install paramiko")

        api_client = self._get_device_api(device_id)
        config = api_client.config

        if not config.username or not config.password:
            raise ValueError(f"Device {device_id} requires username/password for SSH access")

        ssh_port = getattr(config, 'ssh_port', 22)

        return FortiGateSSHClient(
            device_id=device_id,
            host=config.host,
            port=ssh_port,
            username=config.username,
            password=config.password,
            timeout=config.timeout,
            vdom=config.vdom
        )

    # ========== Phase 1 Configuration Methods (REST API) ==========

    def list_phase1_interfaces(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List all IPSec VPN Phase 1 interface configurations.

        Args:
            device_id: Device identifier
            vdom: Virtual domain (optional)

        Returns:
            Formatted list of Phase 1 tunnels
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            api_client = self._get_device_api(device_id)
            result = api_client.get_ipsec_phase1_interfaces(vdom=vdom)
            return FortiGateFormatters.format_ipsec_phase1_list(result)

        except Exception as e:
            return self._handle_error("list IPSec Phase 1 tunnels", device_id, e)

    def get_phase1_interface(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Get detailed Phase 1 interface configuration.

        Args:
            device_id: Device identifier
            name: Phase 1 interface name
            vdom: Virtual domain (optional)

        Returns:
            Formatted Phase 1 tunnel detail
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            result = api_client.get_ipsec_phase1_interface(name, vdom=vdom)
            return FortiGateFormatters.format_ipsec_phase1_detail(result, device_id)

        except Exception as e:
            return self._handle_error(f"get IPSec Phase 1 tunnel '{name}'", device_id, e)

    def create_phase1_interface(self, device_id: str, phase1_data: Dict[str, Any],
                                vdom: Optional[str] = None) -> List[Content]:
        """Create IPSec VPN Phase 1 interface.

        Args:
            device_id: Device identifier
            phase1_data: Phase 1 configuration data
            vdom: Virtual domain (optional)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(phase1_data=phase1_data)

            api_client = self._get_device_api(device_id)
            result = api_client.create_ipsec_phase1_interface(phase1_data, vdom=vdom)

            name = phase1_data.get("name", "unknown")
            return self._format_operation_result(
                f"Create IPSec Phase 1 tunnel '{name}'",
                device_id, True,
                f"Phase 1 tunnel '{name}' created successfully"
            )

        except Exception as e:
            return self._handle_error("create IPSec Phase 1 tunnel", device_id, e)

    def update_phase1_interface(self, device_id: str, name: str, phase1_data: Dict[str, Any],
                                vdom: Optional[str] = None) -> List[Content]:
        """Update IPSec VPN Phase 1 interface.

        Args:
            device_id: Device identifier
            name: Phase 1 interface name
            phase1_data: Updated configuration data
            vdom: Virtual domain (optional)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, phase1_data=phase1_data)

            api_client = self._get_device_api(device_id)
            result = api_client.update_ipsec_phase1_interface(name, phase1_data, vdom=vdom)

            return self._format_operation_result(
                f"Update IPSec Phase 1 tunnel '{name}'",
                device_id, True,
                f"Phase 1 tunnel '{name}' updated successfully"
            )

        except Exception as e:
            return self._handle_error(f"update IPSec Phase 1 tunnel '{name}'", device_id, e)

    def delete_phase1_interface(self, device_id: str, name: str,
                                vdom: Optional[str] = None) -> List[Content]:
        """Delete IPSec VPN Phase 1 interface.

        Args:
            device_id: Device identifier
            name: Phase 1 interface name
            vdom: Virtual domain (optional)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            result = api_client.delete_ipsec_phase1_interface(name, vdom=vdom)

            return self._format_operation_result(
                f"Delete IPSec Phase 1 tunnel '{name}'",
                device_id, True,
                f"Phase 1 tunnel '{name}' deleted successfully"
            )

        except Exception as e:
            return self._handle_error(f"delete IPSec Phase 1 tunnel '{name}'", device_id, e)

    # ========== Phase 2 Configuration Methods (REST API) ==========

    def list_phase2_interfaces(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List all IPSec VPN Phase 2 interface configurations.

        Args:
            device_id: Device identifier
            vdom: Virtual domain (optional)

        Returns:
            Formatted list of Phase 2 selectors
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            api_client = self._get_device_api(device_id)
            result = api_client.get_ipsec_phase2_interfaces(vdom=vdom)
            return FortiGateFormatters.format_ipsec_phase2_list(result)

        except Exception as e:
            return self._handle_error("list IPSec Phase 2 selectors", device_id, e)

    def get_phase2_interface(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Get detailed Phase 2 interface configuration.

        Args:
            device_id: Device identifier
            name: Phase 2 interface name
            vdom: Virtual domain (optional)

        Returns:
            Formatted Phase 2 selector detail
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            result = api_client.get_ipsec_phase2_interface(name, vdom=vdom)
            return FortiGateFormatters.format_ipsec_phase2_detail(result, device_id)

        except Exception as e:
            return self._handle_error(f"get IPSec Phase 2 selector '{name}'", device_id, e)

    def create_phase2_interface(self, device_id: str, phase2_data: Dict[str, Any],
                                vdom: Optional[str] = None) -> List[Content]:
        """Create IPSec VPN Phase 2 interface.

        Args:
            device_id: Device identifier
            phase2_data: Phase 2 configuration data
            vdom: Virtual domain (optional)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(phase2_data=phase2_data)

            api_client = self._get_device_api(device_id)
            result = api_client.create_ipsec_phase2_interface(phase2_data, vdom=vdom)

            name = phase2_data.get("name", "unknown")
            return self._format_operation_result(
                f"Create IPSec Phase 2 selector '{name}'",
                device_id, True,
                f"Phase 2 selector '{name}' created successfully"
            )

        except Exception as e:
            return self._handle_error("create IPSec Phase 2 selector", device_id, e)

    def update_phase2_interface(self, device_id: str, name: str, phase2_data: Dict[str, Any],
                                vdom: Optional[str] = None) -> List[Content]:
        """Update IPSec VPN Phase 2 interface.

        Args:
            device_id: Device identifier
            name: Phase 2 interface name
            phase2_data: Updated configuration data
            vdom: Virtual domain (optional)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, phase2_data=phase2_data)

            api_client = self._get_device_api(device_id)
            result = api_client.update_ipsec_phase2_interface(name, phase2_data, vdom=vdom)

            return self._format_operation_result(
                f"Update IPSec Phase 2 selector '{name}'",
                device_id, True,
                f"Phase 2 selector '{name}' updated successfully"
            )

        except Exception as e:
            return self._handle_error(f"update IPSec Phase 2 selector '{name}'", device_id, e)

    def delete_phase2_interface(self, device_id: str, name: str,
                                vdom: Optional[str] = None) -> List[Content]:
        """Delete IPSec VPN Phase 2 interface.

        Args:
            device_id: Device identifier
            name: Phase 2 interface name
            vdom: Virtual domain (optional)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            result = api_client.delete_ipsec_phase2_interface(name, vdom=vdom)

            return self._format_operation_result(
                f"Delete IPSec Phase 2 selector '{name}'",
                device_id, True,
                f"Phase 2 selector '{name}' deleted successfully"
            )

        except Exception as e:
            return self._handle_error(f"delete IPSec Phase 2 selector '{name}'", device_id, e)

    # ========== Tunnel Status Methods (REST API) ==========

    def get_tunnel_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get IPSec tunnel runtime status via REST API.

        Args:
            device_id: Device identifier
            vdom: Virtual domain (optional)

        Returns:
            Formatted tunnel status with traffic statistics
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            api_client = self._get_device_api(device_id)
            result = api_client.get_ipsec_tunnel_status(vdom=vdom)
            return FortiGateFormatters.format_ipsec_tunnel_status(result)

        except Exception as e:
            return self._handle_error("get IPSec tunnel status", device_id, e)

    # ========== SSH-based Diagnostic Methods ==========

    def diagnose_ike_gateways(self, device_id: str) -> List[Content]:
        """Get IKE gateway list with negotiation details via SSH.

        Args:
            device_id: Device identifier

        Returns:
            Formatted IKE gateway diagnostic output
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            ssh_client = self._get_ssh_client(device_id)
            try:
                raw_output = ssh_client.get_ike_gateway_list()
                parsed_data = ssh_client.parse_ike_gateway_list(raw_output)
                return FortiGateFormatters.format_ipsec_ike_gateways(raw_output, parsed_data)
            finally:
                ssh_client.disconnect()

        except Exception as e:
            return self._handle_error("diagnose IKE gateways", device_id, e)

    def diagnose_tunnels(self, device_id: str, tunnel_name: Optional[str] = None) -> List[Content]:
        """Get IPSec tunnel list with traffic statistics via SSH.

        Args:
            device_id: Device identifier
            tunnel_name: Optional specific tunnel name

        Returns:
            Formatted tunnel diagnostic output
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            ssh_client = self._get_ssh_client(device_id)
            try:
                raw_output = ssh_client.get_tunnel_list(tunnel_name)
                parsed_data = ssh_client.parse_tunnel_list(raw_output)
                return FortiGateFormatters.format_ipsec_tunnel_diagnostics(raw_output, parsed_data)
            finally:
                ssh_client.disconnect()

        except Exception as e:
            return self._handle_error("diagnose IPSec tunnels", device_id, e)

    def tunnel_up(self, device_id: str, phase1_name: str) -> List[Content]:
        """Bring up an IPSec tunnel via SSH.

        Args:
            device_id: Device identifier
            phase1_name: Name of the Phase 1 interface/tunnel

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(phase1_name=phase1_name)

            ssh_client = self._get_ssh_client(device_id)
            try:
                output = ssh_client.bring_tunnel_up(phase1_name)
                return self._format_operation_result(
                    f"Bring up IPSec tunnel '{phase1_name}'",
                    device_id, True,
                    f"Tunnel '{phase1_name}' initiated.\n\nSSH Output:\n{output}"
                )
            finally:
                ssh_client.disconnect()

        except Exception as e:
            return self._handle_error(f"bring up IPSec tunnel '{phase1_name}'", device_id, e)

    def tunnel_down(self, device_id: str, phase1_name: str) -> List[Content]:
        """Bring down an IPSec tunnel via SSH.

        Args:
            device_id: Device identifier
            phase1_name: Name of the Phase 1 interface/tunnel

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(phase1_name=phase1_name)

            ssh_client = self._get_ssh_client(device_id)
            try:
                output = ssh_client.bring_tunnel_down(phase1_name)
                return self._format_operation_result(
                    f"Bring down IPSec tunnel '{phase1_name}'",
                    device_id, True,
                    f"Tunnel '{phase1_name}' terminated.\n\nSSH Output:\n{output}"
                )
            finally:
                ssh_client.disconnect()

        except Exception as e:
            return self._handle_error(f"bring down IPSec tunnel '{phase1_name}'", device_id, e)

    def clear_ike_gateway(self, device_id: str, gateway_name: Optional[str] = None) -> List[Content]:
        """Clear IKE gateway to force renegotiation via SSH.

        Args:
            device_id: Device identifier
            gateway_name: Optional specific gateway to clear (clears all if not specified)

        Returns:
            Operation result
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            ssh_client = self._get_ssh_client(device_id)
            try:
                output = ssh_client.clear_ike_gateway(gateway_name)
                target = f"gateway '{gateway_name}'" if gateway_name else "all gateways"
                return self._format_operation_result(
                    f"Clear IKE {target}",
                    device_id, True,
                    f"IKE {target} cleared. Tunnel will renegotiate.\n\nSSH Output:\n{output}"
                )
            finally:
                ssh_client.disconnect()

        except Exception as e:
            target = gateway_name or "all"
            return self._handle_error(f"clear IKE gateway '{target}'", device_id, e)

    # ========== Combined Troubleshooting Methods ==========

    def troubleshoot_tunnel(self, device_id: str, tunnel_name: str,
                           vdom: Optional[str] = None) -> List[Content]:
        """Comprehensive IPSec tunnel troubleshooting.

        Gathers configuration and status from both REST API and SSH:
        - Phase 1 configuration
        - Phase 2 configuration
        - Tunnel status from REST API
        - IKE gateway status via SSH
        - Tunnel stats via SSH

        Args:
            device_id: Device identifier
            tunnel_name: Phase 1 tunnel name to troubleshoot
            vdom: Virtual domain (optional)

        Returns:
            Comprehensive troubleshooting report
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)
            self._validate_required_params(tunnel_name=tunnel_name)

            api_client = self._get_device_api(device_id)

            # Gather REST API data
            phase1_config = None
            phase2_config = None
            tunnel_status = None

            try:
                phase1_config = api_client.get_ipsec_phase1_interface(tunnel_name, vdom=vdom)
            except Exception:
                pass

            try:
                phase2_config = api_client.get_ipsec_phase2_interfaces(vdom=vdom)
            except Exception:
                pass

            try:
                tunnel_status = api_client.get_ipsec_tunnel_status(vdom=vdom)
            except Exception:
                pass

            # Gather SSH diagnostic data
            ike_output = None
            tunnel_stats = None

            try:
                ssh_client = self._get_ssh_client(device_id)
                try:
                    ike_output = ssh_client.get_ike_gateway_list()
                    tunnel_stats = ssh_client.get_tunnel_list(tunnel_name)
                finally:
                    ssh_client.disconnect()
            except Exception:
                pass

            return FortiGateFormatters.format_ipsec_troubleshoot(
                tunnel_name,
                phase1_config=phase1_config,
                phase2_config=phase2_config,
                tunnel_status=tunnel_status,
                ike_output=ike_output,
                tunnel_stats=tunnel_stats
            )

        except Exception as e:
            return self._handle_error(f"troubleshoot IPSec tunnel '{tunnel_name}'", device_id, e)

    def get_vpn_summary(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get complete IPSec VPN summary for a device.

        Combines Phase 1 tunnels, Phase 2 selectors, and runtime status.

        Args:
            device_id: Device identifier
            vdom: Virtual domain (optional)

        Returns:
            Comprehensive VPN summary
        """
        try:
            device_id = self._resolve_device_id(device_id)
            self._validate_device_exists(device_id)

            api_client = self._get_device_api(device_id)

            lines = [f"IPSec VPN Summary - Device: {device_id}", "=" * 60, ""]

            # Phase 1 tunnels
            try:
                phase1_data = api_client.get_ipsec_phase1_interfaces(vdom=vdom)
                p1_count = len(phase1_data.get("results", []))
                lines.append(f"Phase 1 Tunnels: {p1_count}")
                if phase1_data.get("results"):
                    for p1 in phase1_data["results"]:
                        status = "Enabled" if p1.get("status") == "enable" else "Disabled"
                        lines.append(f"  - {p1.get('name', 'N/A')} ({status}) -> {p1.get('remote-gw', 'N/A')}")
            except Exception as e:
                lines.append(f"Phase 1 Tunnels: Error - {e}")

            lines.append("")

            # Phase 2 selectors
            try:
                phase2_data = api_client.get_ipsec_phase2_interfaces(vdom=vdom)
                p2_count = len(phase2_data.get("results", []))
                lines.append(f"Phase 2 Selectors: {p2_count}")
                if phase2_data.get("results"):
                    for p2 in phase2_data["results"]:
                        src = p2.get("src-subnet", p2.get("src-name", "N/A"))
                        dst = p2.get("dst-subnet", p2.get("dst-name", "N/A"))
                        lines.append(f"  - {p2.get('name', 'N/A')} ({p2.get('phase1name', 'N/A')}): {src} <-> {dst}")
            except Exception as e:
                lines.append(f"Phase 2 Selectors: Error - {e}")

            lines.append("")

            # Tunnel status
            try:
                status_data = api_client.get_ipsec_tunnel_status(vdom=vdom)
                if status_data.get("results"):
                    lines.append("Active Tunnels:")
                    for t in status_data["results"]:
                        lines.append(f"  - {t.get('name', 'N/A')}: {t.get('status', 'unknown')} (In: {t.get('incoming_bytes', 0)}B, Out: {t.get('outgoing_bytes', 0)}B)")
                else:
                    lines.append("Active Tunnels: None")
            except Exception as e:
                lines.append(f"Active Tunnels: Error - {e}")

            formatted_text = "\n".join(lines)
            return [Content(type="text", text=formatted_text)]

        except Exception as e:
            return self._handle_error("get IPSec VPN summary", device_id, e)
