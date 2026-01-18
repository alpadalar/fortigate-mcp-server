"""
FortiManager tools for the MCP server.

This module provides MCP tools for FortiManager management:
- Device listing and status
- Policy package management
- Address and service objects
- Installation and sync operations
"""
import json
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from ..core.fortimanager import FortiManagerAPI, FortiManagerAPIError, FortiManagerManager
from ..core.logging import get_logger


class FortiManagerTool:
    """Base class for FortiManager MCP tools."""

    def __init__(self, fmg_manager: FortiManagerManager):
        """Initialize the tool.

        Args:
            fmg_manager: FortiManagerManager instance
        """
        self.fmg_manager = fmg_manager
        self.logger = get_logger(f"tools.{self.__class__.__name__.lower()}")

    def _get_manager(self, manager_id: str) -> FortiManagerAPI:
        """Get FortiManager API client.

        Args:
            manager_id: Manager identifier

        Returns:
            FortiManagerAPI instance
        """
        return self.fmg_manager.get_manager(manager_id)

    def _format_response(self, data: Any, title: Optional[str] = None) -> List[Content]:
        """Format response data into MCP content.

        Args:
            data: Data to format
            title: Optional title for the response

        Returns:
            List of Content objects
        """
        if title:
            text = f"**{title}**\n\n```json\n{json.dumps(data, indent=2, default=str)}\n```"
        else:
            text = f"```json\n{json.dumps(data, indent=2, default=str)}\n```"
        return [Content(type="text", text=text)]

    def _format_error(self, operation: str, manager_id: str, error: str) -> List[Content]:
        """Format error response.

        Args:
            operation: Operation that failed
            manager_id: Manager identifier
            error: Error message

        Returns:
            List of Content objects
        """
        text = f"""Error

{{
  "operation": "{operation}",
  "manager_id": "{manager_id}",
  "error": "{error}",
  "status": "failed"
}}"""
        return [Content(type="text", text=text)]

    def _handle_error(self, operation: str, manager_id: str, error: Exception) -> List[Content]:
        """Handle and format errors.

        Args:
            operation: Operation that failed
            manager_id: Manager identifier
            error: Exception that occurred

        Returns:
            List of Content objects
        """
        error_msg = str(error)
        self.logger.error(f"Failed to {operation} on {manager_id}: {error_msg}")

        if isinstance(error, FortiManagerAPIError):
            if error.error_code == -11:
                error_msg = "Authentication failed. Check API token or credentials."
            elif error.error_code == -6:
                error_msg = "Invalid parameter or resource not found."

        return self._format_error(operation, manager_id, error_msg)


class FortiManagerTools(FortiManagerTool):
    """FortiManager MCP tools implementation."""

    # Manager management
    def list_managers(self) -> List[Content]:
        """List registered FortiManager instances.

        Returns:
            List of Content objects with manager list
        """
        managers = self.fmg_manager.list_managers()
        if not managers:
            return [Content(type="text", text="No FortiManager instances registered")]

        lines = ["**Registered FortiManager Instances**", ""]
        for mgr_id in managers:
            lines.append(f"  - {mgr_id}")
        return [Content(type="text", text="\n".join(lines))]

    def add_manager(
        self,
        manager_id: str,
        host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = False,
        adom: str = "root"
    ) -> List[Content]:
        """Add a FortiManager instance.

        Args:
            manager_id: Unique identifier
            host: FortiManager hostname
            api_token: API token
            username: Username (if not using token)
            password: Password (if not using token)
            port: HTTPS port
            verify_ssl: Verify SSL certificates
            adom: Default ADOM

        Returns:
            List of Content objects
        """
        try:
            self.fmg_manager.add_manager(
                manager_id=manager_id,
                host=host,
                api_token=api_token,
                username=username,
                password=password,
                port=port,
                verify_ssl=verify_ssl,
                adom=adom
            )
            return [Content(type="text", text=f"FortiManager '{manager_id}' added successfully")]
        except Exception as e:
            return self._handle_error("add manager", manager_id, e)

    def remove_manager(self, manager_id: str) -> List[Content]:
        """Remove a FortiManager instance.

        Args:
            manager_id: Manager identifier

        Returns:
            List of Content objects
        """
        try:
            self.fmg_manager.remove_manager(manager_id)
            return [Content(type="text", text=f"FortiManager '{manager_id}' removed successfully")]
        except Exception as e:
            return self._handle_error("remove manager", manager_id, e)

    def test_connection(self, manager_id: str) -> List[Content]:
        """Test FortiManager connection.

        Args:
            manager_id: Manager identifier

        Returns:
            List of Content objects
        """
        try:
            fmg = self._get_manager(manager_id)
            success = fmg.test_connection()
            if success:
                return [Content(type="text", text=f"Connection to '{manager_id}' successful")]
            else:
                return [Content(type="text", text=f"Connection to '{manager_id}' failed")]
        except Exception as e:
            return self._handle_error("test connection", manager_id, e)

    # System information
    def get_system_status(self, manager_id: str) -> List[Content]:
        """Get FortiManager system status.

        Args:
            manager_id: Manager identifier

        Returns:
            List of Content objects with system status
        """
        try:
            fmg = self._get_manager(manager_id)
            status = fmg.get_system_status()
            return self._format_response(status, "FortiManager System Status")
        except Exception as e:
            return self._handle_error("get system status", manager_id, e)

    def get_adoms(self, manager_id: str) -> List[Content]:
        """Get list of Administrative Domains.

        Args:
            manager_id: Manager identifier

        Returns:
            List of Content objects with ADOMs
        """
        try:
            fmg = self._get_manager(manager_id)
            adoms = fmg.get_adoms()
            return self._format_response(adoms, "Administrative Domains")
        except Exception as e:
            return self._handle_error("get adoms", manager_id, e)

    # Device management
    def get_devices(self, manager_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get managed devices.

        Args:
            manager_id: Manager identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with devices
        """
        try:
            fmg = self._get_manager(manager_id)
            devices = fmg.get_devices(adom)
            return self._format_response(devices, "Managed Devices")
        except Exception as e:
            return self._handle_error("get devices", manager_id, e)

    def get_device_status(self, manager_id: str, device_name: str, adom: Optional[str] = None) -> List[Content]:
        """Get device status.

        Args:
            manager_id: Manager identifier
            device_name: Device name
            adom: Administrative Domain

        Returns:
            List of Content objects with device status
        """
        try:
            fmg = self._get_manager(manager_id)
            status = fmg.get_device_status(device_name, adom)
            return self._format_response(status, f"Device Status: {device_name}")
        except Exception as e:
            return self._handle_error("get device status", manager_id, e)

    def get_all_devices_status(self, manager_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get status for all managed devices.

        Args:
            manager_id: Manager identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with all device statuses
        """
        try:
            fmg = self._get_manager(manager_id)
            status = fmg.get_all_devices_status(adom)

            # Format as table
            data = status.get("data", [])
            if not data:
                return [Content(type="text", text="No devices found")]

            lines = ["**Managed Devices Status**", ""]
            lines.append("| Device | Hostname | IP | Status | Version | Platform |")
            lines.append("|--------|----------|-----|--------|---------|----------|")

            for dev in data:
                name = dev.get("name", "N/A")
                hostname = dev.get("hostname", "N/A")
                ip = dev.get("ip", "N/A")
                conn = dev.get("conn_status", "N/A")
                version = dev.get("os_ver", "N/A")
                platform = dev.get("platform_str", "N/A")

                # Connection status emoji
                status_icon = "✅" if conn == 1 else "❌"

                lines.append(f"| {name} | {hostname} | {ip} | {status_icon} | {version} | {platform} |")

            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("get all devices status", manager_id, e)

    # Policy packages
    def get_policy_packages(self, manager_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get policy packages.

        Args:
            manager_id: Manager identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with policy packages
        """
        try:
            fmg = self._get_manager(manager_id)
            packages = fmg.get_policy_packages(adom)
            return self._format_response(packages, "Policy Packages")
        except Exception as e:
            return self._handle_error("get policy packages", manager_id, e)

    def get_firewall_policies(
        self,
        manager_id: str,
        pkg_name: str,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get firewall policies from a package.

        Args:
            manager_id: Manager identifier
            pkg_name: Policy package name
            adom: Administrative Domain

        Returns:
            List of Content objects with policies
        """
        try:
            fmg = self._get_manager(manager_id)
            policies = fmg.get_firewall_policies(pkg_name, adom)
            return self._format_response(policies, f"Firewall Policies: {pkg_name}")
        except Exception as e:
            return self._handle_error("get firewall policies", manager_id, e)

    # Objects
    def get_address_objects(self, manager_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get address objects.

        Args:
            manager_id: Manager identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with address objects
        """
        try:
            fmg = self._get_manager(manager_id)
            addresses = fmg.get_address_objects(adom)
            return self._format_response(addresses, "Address Objects")
        except Exception as e:
            return self._handle_error("get address objects", manager_id, e)

    def get_service_objects(self, manager_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get service objects.

        Args:
            manager_id: Manager identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with service objects
        """
        try:
            fmg = self._get_manager(manager_id)
            services = fmg.get_service_objects(adom)
            return self._format_response(services, "Service Objects")
        except Exception as e:
            return self._handle_error("get service objects", manager_id, e)

    # Certificates
    def get_device_certificates(
        self,
        manager_id: str,
        device_name: str,
        adom: Optional[str] = None
    ) -> List[Content]:
        """Get certificates from a managed device.

        Args:
            manager_id: Manager identifier
            device_name: Device name
            adom: Administrative Domain

        Returns:
            List of Content objects with certificates
        """
        try:
            fmg = self._get_manager(manager_id)
            certs = fmg.get_certificates(device_name, adom)
            return self._format_response(certs, f"Certificates: {device_name}")
        except Exception as e:
            return self._handle_error("get certificates", manager_id, e)

    def get_all_certificates(
        self,
        manager_id: str,
        adoms: Optional[str] = None,
        filter_letsencrypt: bool = False
    ) -> List[Content]:
        """Get certificates from all managed devices.

        Scans all devices across specified ADOMs and returns certificate information
        with parsed metadata including issuer, expiry, and Let's Encrypt detection.

        Args:
            manager_id: Manager identifier
            adoms: Comma-separated list of ADOMs to scan (default: all ADOMs)
            filter_letsencrypt: Only return Let's Encrypt certificates

        Returns:
            List of Content objects with certificate report
        """
        try:
            fmg = self._get_manager(manager_id)

            # Parse ADOMs if provided
            adom_list = None
            if adoms:
                adom_list = [a.strip() for a in adoms.split(",")]

            result = fmg.get_all_certificates(
                adoms=adom_list,
                filter_letsencrypt=filter_letsencrypt,
                include_default=False
            )

            # Format as readable report
            lines = ["**Certificate Report**", ""]

            # Summary
            summary = result.get("summary", {})
            lines.append("## Summary")
            lines.append(f"- Total devices with certificates: {summary.get('total_devices', 0)}")
            lines.append(f"- Total certificates: {summary.get('total_certificates', 0)}")
            lines.append(f"- Let's Encrypt certificates: {summary.get('letsencrypt_certificates', 0)}")
            lines.append(f"- Expired certificates: {summary.get('expired_certificates', 0)}")
            lines.append(f"- Expiring within 30 days: {summary.get('expiring_soon', 0)}")
            lines.append("")

            # Device details
            lines.append("## Certificates by Device")
            lines.append("")

            for device in result.get("devices", []):
                device_name = device.get("device_name", "Unknown")
                hostname = device.get("hostname", device_name)
                adom = device.get("adom", "")
                certs = device.get("certificates", [])

                lines.append(f"### {hostname} ({device_name})")
                lines.append(f"ADOM: {adom}")
                lines.append("")

                for cert in certs:
                    name = cert.get("name", "")
                    cn = cert.get("common_name", "")
                    is_le = cert.get("is_letsencrypt", False)
                    is_expired = cert.get("is_expired", False)
                    days = cert.get("days_until_expiry")
                    valid_to = cert.get("valid_to", "")
                    issuer_o = cert.get("issuer_o", "")

                    # Status indicator
                    if is_expired:
                        status = "EXPIRED"
                    elif days is not None and days <= 30:
                        status = f"EXPIRING ({days}d)"
                    else:
                        status = "OK"

                    # Certificate type
                    cert_type = "LE" if is_le else issuer_o[:10] if issuer_o else "Unknown"

                    lines.append(f"- **{name}**")
                    lines.append(f"  - CN: {cn}")
                    lines.append(f"  - Type: {cert_type}")
                    lines.append(f"  - Expires: {valid_to} [{status}]")

                lines.append("")

            if not result.get("devices"):
                lines.append("No certificates found matching criteria.")

            return [Content(type="text", text="\n".join(lines))]
        except Exception as e:
            return self._handle_error("get all certificates", manager_id, e)

    # Installation
    def install_policy(
        self,
        manager_id: str,
        pkg_name: str,
        device_name: str,
        adom: Optional[str] = None,
        vdom: str = "root"
    ) -> List[Content]:
        """Install policy package to a device.

        Args:
            manager_id: Manager identifier
            pkg_name: Policy package name
            device_name: Target device
            adom: Administrative Domain
            vdom: Virtual Domain on device

        Returns:
            List of Content objects with result
        """
        try:
            fmg = self._get_manager(manager_id)
            result = fmg.install_policy(pkg_name, device_name, adom, vdom)
            return self._format_response(result, f"Install Policy: {pkg_name} to {device_name}")
        except Exception as e:
            return self._handle_error("install policy", manager_id, e)

    def get_install_status(self, manager_id: str, adom: Optional[str] = None) -> List[Content]:
        """Get installation status.

        Args:
            manager_id: Manager identifier
            adom: Administrative Domain

        Returns:
            List of Content objects with status
        """
        try:
            fmg = self._get_manager(manager_id)
            status = fmg.get_install_status(adom)
            return self._format_response(status, "Installation Status")
        except Exception as e:
            return self._handle_error("get install status", manager_id, e)

    # Tasks
    def get_task_status(self, manager_id: str, task_id: int) -> List[Content]:
        """Get task status.

        Args:
            manager_id: Manager identifier
            task_id: Task ID

        Returns:
            List of Content objects with task status
        """
        try:
            fmg = self._get_manager(manager_id)
            status = fmg.get_task_status(task_id)
            return self._format_response(status, f"Task Status: {task_id}")
        except Exception as e:
            return self._handle_error("get task status", manager_id, e)
