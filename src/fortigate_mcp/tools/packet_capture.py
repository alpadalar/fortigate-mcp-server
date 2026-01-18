"""
Packet capture tools for FortiGate MCP.

This module provides MCP tools for packet capture operations:
- Create/configure packet capture profiles with filters
- Start/stop packet captures
- Monitor capture status
- Download captured packets
- Clear capture data
- Timed capture with automatic analysis via SSH

Note: The capture_and_analyze tool uses SSH to run the 'diagnose sniffer packet'
CLI command, as the packet capture REST API endpoints are not available on all
FortiGate versions.
"""
import base64
import os
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.fortigate import FortiGateAPIError
from ..core.ssh_client import FortiGateSSHClient, FortiGateSSHError, PARAMIKO_AVAILABLE


class PacketCaptureTools(FortiGateTool):
    """Tools for FortiGate packet capture operations.

    Provides packet capture (sniffer) functionality for network traffic
    analysis on FortiGate devices, including Security Fabric members.

    The capture_and_analyze method uses SSH to execute the CLI 'diagnose sniffer packet'
    command, which provides more reliable access to packet capture functionality
    than the REST API on most FortiGate versions.
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
            raise ValueError("SSH capture requires paramiko. Install with: pip install paramiko")

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

    def _build_filter_string(
        self,
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None
    ) -> str:
        """Build BPF-style filter string from individual filter parameters.

        Args:
            host: Host IP filter (matches src or dst)
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            protocol: Protocol filter (tcp, udp, icmp)
            port: Port number filter

        Returns:
            BPF-style filter string
        """
        filter_parts = []

        if host:
            # Use "net" for CIDR notation (subnets), "host" for single IPs
            if "/" in host:
                filter_parts.append(f"net {host}")
            else:
                filter_parts.append(f"host {host}")
        if src_ip:
            filter_parts.append(f"src host {src_ip}")
        if dst_ip:
            filter_parts.append(f"dst host {dst_ip}")
        if port:
            filter_parts.append(f"port {port}")
        if protocol and protocol.lower() not in ("none", "any", "all", ""):
            filter_parts.append(protocol.lower())

        return " and ".join(filter_parts) if filter_parts else ""

    def list_packet_captures(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List all configured packet capture profiles.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with packet capture profiles
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            captures_data = api_client.get_packet_captures(vdom)
            return self._format_response(captures_data, "packet_captures")

        except Exception as e:
            return self._handle_error("list packet captures", device_id, e)

    def create_packet_capture(
        self,
        device_id: str,
        interface: str = "any",
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        max_packet_count: int = 10000,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Create a packet capture profile with optional filters.

        Args:
            device_id: Target device identifier
            interface: Interface to capture on (default: 'any')
            host: Host IP filter (matches src or dst)
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            protocol: Protocol filter (tcp, udp, icmp)
            port: Port number filter
            max_packet_count: Maximum packets to capture (default: 10000)
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with created capture profile info
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            # Build BPF-style filter
            filter_str = self._build_filter_string(host, src_ip, dst_ip, protocol, port)

            result = api_client.create_packet_capture(
                interface=interface,
                filter_str=filter_str if filter_str else None,
                max_packet_count=max_packet_count,
                vdom=vdom
            )

            # Extract capture ID from response
            capture_id = result.get("mkey", "unknown")

            details = f"Capture ID: {capture_id}, Interface: {interface}"
            if filter_str:
                details += f", Filter: '{filter_str}'"
            details += f", Max packets: {max_packet_count}"

            return self._format_operation_result(
                "create packet capture",
                device_id,
                True,
                details
            )

        except Exception as e:
            return self._handle_error("create packet capture", device_id, e)

    def get_packet_capture_status(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Get status of a packet capture.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with capture status
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            status_data = api_client.get_packet_capture_status(capture_id, vdom)
            return self._format_response(status_data, "packet_capture_status")

        except Exception as e:
            return self._handle_error("get packet capture status", device_id, e)

    def start_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Start a packet capture.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.start_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "start packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} started"
            )

        except Exception as e:
            return self._handle_error("start packet capture", device_id, e)

    def stop_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Stop a packet capture.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.stop_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "stop packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} stopped"
            )

        except Exception as e:
            return self._handle_error("stop packet capture", device_id, e)

    def download_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Download captured packets.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with capture data or download info
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            download_data = api_client.download_packet_capture(capture_id, vdom)
            return self._format_response(download_data, "packet_capture_download")

        except Exception as e:
            return self._handle_error("download packet capture", device_id, e)

    def delete_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Delete a packet capture profile.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.delete_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "delete packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} deleted"
            )

        except Exception as e:
            return self._handle_error("delete packet capture", device_id, e)

    def clear_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Clear captured packets from a capture profile.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.clear_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "clear packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} cleared"
            )

        except Exception as e:
            return self._handle_error("clear packet capture", device_id, e)

    def _analyze_pcap_with_tshark(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file using tshark if available.

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            Analysis results dictionary
        """
        analysis = {
            "tool": "tshark",
            "available": False,
            "summary": {},
            "conversations": [],
            "protocols": {},
            "errors": []
        }

        # Check if tshark is available
        try:
            result = subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return analysis
            analysis["available"] = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return analysis

        try:
            # Get packet count and basic stats
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "io,stat,0"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["io_stats"] = result.stdout

            # Get protocol hierarchy
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["protocol_hierarchy"] = result.stdout

            # Get conversations (top 20)
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["ip_conversations"] = result.stdout

            # Get TCP conversations
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["tcp_conversations"] = result.stdout

            # Get endpoints
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "endpoints,ip"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["ip_endpoints"] = result.stdout

        except subprocess.TimeoutExpired:
            analysis["errors"].append("tshark analysis timed out")
        except Exception as e:
            analysis["errors"].append(f"tshark analysis error: {str(e)}")

        return analysis

    def _analyze_pcap_basic(self, pcap_data: bytes) -> Dict[str, Any]:
        """Basic PCAP analysis without external tools.

        Args:
            pcap_data: Raw PCAP file data

        Returns:
            Basic analysis results
        """
        analysis = {
            "tool": "basic",
            "file_size_bytes": len(pcap_data),
            "packet_count": 0,
            "capture_info": {}
        }

        # Basic PCAP header parsing (first 24 bytes for global header)
        if len(pcap_data) >= 24:
            # Check magic number
            magic = pcap_data[:4]
            if magic == b'\xd4\xc3\xb2\xa1':  # Little-endian
                analysis["capture_info"]["format"] = "pcap (little-endian)"
                analysis["capture_info"]["byte_order"] = "little"
            elif magic == b'\xa1\xb2\xc3\xd4':  # Big-endian
                analysis["capture_info"]["format"] = "pcap (big-endian)"
                analysis["capture_info"]["byte_order"] = "big"
            elif magic == b'\x0a\x0d\x0d\x0a':  # pcapng
                analysis["capture_info"]["format"] = "pcapng"
            else:
                analysis["capture_info"]["format"] = "unknown"

            # Count packets (rough estimate based on packet headers)
            # Each packet has a 16-byte header in standard pcap
            offset = 24  # Skip global header
            packet_count = 0
            while offset < len(pcap_data) - 16:
                try:
                    # Read packet length from header (bytes 8-12, little-endian)
                    if analysis["capture_info"].get("byte_order") == "little":
                        incl_len = int.from_bytes(pcap_data[offset+8:offset+12], 'little')
                    else:
                        incl_len = int.from_bytes(pcap_data[offset+8:offset+12], 'big')

                    if incl_len <= 0 or incl_len > 65535:
                        break

                    offset += 16 + incl_len  # Header + packet data
                    packet_count += 1

                    if packet_count > 100000:  # Safety limit
                        break
                except Exception:
                    break

            analysis["packet_count"] = packet_count

        return analysis

    def capture_and_analyze(
        self,
        device_id: str,
        interface: str = "any",
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        duration_seconds: int = 120,
        max_packet_count: int = 10000,
        verbose: int = 4,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Capture traffic for a specified duration using SSH, then analyze the results.

        This method uses SSH to run the 'diagnose sniffer packet' CLI command,
        which provides reliable packet capture on all FortiGate versions. The output
        is captured and analyzed to provide traffic statistics.

        Args:
            device_id: Target device identifier or name
            interface: Interface to capture on (default: 'any')
            host: Host IP filter (matches src or dst)
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            protocol: Protocol filter (tcp, udp, icmp)
            port: Port number filter
            duration_seconds: Capture duration in seconds (default: 120 = 2 minutes)
            max_packet_count: Maximum packets to capture (0 = unlimited, default: 10000)
            verbose: Verbosity level 1-6 (default: 4 = headers with interface name)
                1 = print header of packets
                2 = print header and data from IP of packets
                3 = print header and data from Ethernet of packets
                4 = print header of packets with interface name
                5 = print header and data from IP of packets with interface name
                6 = print header and data from Ethernet of packets with interface name
            vdom: Virtual Domain (optional, uses device default)

        Returns:
            List of Content objects with capture analysis results
        """
        ssh_client = None

        try:
            resolved_device_id = self._validate_device_exists(device_id)

            # Build filter string
            filter_str = self._build_filter_string(host, src_ip, dst_ip, protocol, port)

            self.logger.info(f"Starting SSH packet capture on {device_id}")
            self.logger.info(f"Interface: {interface}, Filter: '{filter_str or 'none'}'")
            self.logger.info(f"Duration: {duration_seconds}s, Max packets: {max_packet_count}")

            # Create SSH client
            ssh_client = self._get_ssh_client(device_id)

            # Run the sniffer via SSH
            raw_output, stats = ssh_client.run_sniffer(
                interface=interface,
                filter_str=filter_str,
                verbose=verbose,
                count=max_packet_count,
                duration_seconds=duration_seconds,
                timestamp_format="a"
            )

            # Save raw output to temp file for reference
            output_path = None
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.txt',
                prefix=f'fortigate_sniffer_{resolved_device_id}_',
                delete=False
            ) as f:
                f.write(raw_output)
                output_path = f.name

            self.logger.info(f"Saved sniffer output to: {output_path}")

            # Build analysis results
            analysis_results = {
                "capture_summary": {
                    "device_id": resolved_device_id,
                    "method": "SSH (diagnose sniffer packet)",
                    "interface": stats.get("interface", interface),
                    "filter": stats.get("filter", filter_str or "none"),
                    "duration_seconds": stats.get("duration_seconds", duration_seconds),
                    "packets_captured": stats.get("packets_captured", 0),
                    "verbose_level": verbose,
                    "timestamp": datetime.now().isoformat()
                },
                "analysis": {
                    "tool": "ssh_sniffer",
                    "unique_ips": stats.get("unique_ips", []),
                    "protocols": stats.get("protocols", {}),
                    "raw_output_lines": len(raw_output.splitlines()),
                },
                "output_file": output_path
            }

            # Format output
            return self._format_ssh_capture_analysis(analysis_results, raw_output)

        except FortiGateSSHError as e:
            return self._handle_error("SSH packet capture", device_id, e)
        except Exception as e:
            return self._handle_error("capture and analyze", device_id, e)
        finally:
            if ssh_client:
                try:
                    ssh_client.disconnect()
                except Exception:
                    pass

    def _format_ssh_capture_analysis(self, results: Dict[str, Any], raw_output: str) -> List[Content]:
        """Format SSH-based capture analysis results for display.

        Args:
            results: Analysis results dictionary
            raw_output: Raw sniffer output from SSH

        Returns:
            List of Content objects with formatted analysis
        """
        lines = ["Packet Capture Analysis (SSH)", "=" * 50, ""]

        # Capture summary
        summary = results.get("capture_summary", {})
        lines.extend([
            "Capture Summary:",
            f"  Device: {summary.get('device_id', 'N/A')}",
            f"  Method: {summary.get('method', 'SSH')}",
            f"  Interface: {summary.get('interface', 'N/A')}",
            f"  Filter: {summary.get('filter', 'none')}",
            f"  Duration: {summary.get('duration_seconds', 0)} seconds",
            f"  Packets Captured: {summary.get('packets_captured', 0)}",
            f"  Verbose Level: {summary.get('verbose_level', 4)}",
            f"  Timestamp: {summary.get('timestamp', 'N/A')}",
            ""
        ])

        if results.get("output_file"):
            lines.extend([
                f"Output File: {results['output_file']}",
                ""
            ])

        # Analysis results
        analysis = results.get("analysis", {})

        if analysis.get("unique_ips"):
            lines.extend([
                "Unique IP Addresses:",
                *[f"  - {ip}" for ip in analysis["unique_ips"][:20]],  # Limit to 20
            ])
            if len(analysis["unique_ips"]) > 20:
                lines.append(f"  ... and {len(analysis['unique_ips']) - 20} more")
            lines.append("")

        if analysis.get("protocols"):
            lines.extend([
                "Protocol Summary:",
                *[f"  - {proto}: {count}" for proto, count in analysis["protocols"].items()],
                ""
            ])

        lines.append(f"Raw output: {analysis.get('raw_output_lines', 0)} lines")
        lines.append("")

        # Show sample of raw output (first 50 lines)
        output_lines = raw_output.splitlines()
        if output_lines:
            lines.extend([
                "Sample Output (first 50 lines):",
                "-" * 40,
            ])
            for line in output_lines[:50]:
                if line.strip():
                    lines.append(line)
            if len(output_lines) > 50:
                lines.append(f"... ({len(output_lines) - 50} more lines)")

        return [Content(type="text", text="\n".join(lines))]

    def _format_capture_analysis(self, results: Dict[str, Any]) -> List[Content]:
        """Format capture analysis results for display.

        Args:
            results: Analysis results dictionary

        Returns:
            List of Content objects with formatted analysis
        """
        lines = ["Packet Capture Analysis", "=" * 50, ""]

        # Capture summary
        summary = results.get("capture_summary", {})
        lines.extend([
            "Capture Summary:",
            f"  Device: {summary.get('device_id', 'N/A')}",
            f"  Capture ID: {summary.get('capture_id', 'N/A')}",
            f"  Interface: {summary.get('interface', 'N/A')}",
            f"  Filter: {summary.get('filter', 'none')}",
            f"  Duration: {summary.get('duration_seconds', 0)} seconds",
            f"  Packets Captured: {summary.get('packets_captured', 0)}",
            f"  Bytes Captured: {summary.get('bytes_captured', 0)}",
            f"  Timestamp: {summary.get('timestamp', 'N/A')}",
            ""
        ])

        if results.get("pcap_file"):
            lines.extend([
                f"PCAP File: {results['pcap_file']}",
                ""
            ])

        # Analysis results
        analysis = results.get("analysis", {})
        if analysis.get("error"):
            lines.extend([
                "Analysis Error:",
                f"  {analysis['error']}",
                ""
            ])
        elif analysis.get("tool") == "tshark":
            lines.extend([
                "Analysis (tshark):",
                "-" * 40,
                ""
            ])

            if analysis.get("summary", {}).get("io_stats"):
                lines.extend([
                    "I/O Statistics:",
                    analysis["summary"]["io_stats"],
                    ""
                ])

            if analysis.get("summary", {}).get("protocol_hierarchy"):
                lines.extend([
                    "Protocol Hierarchy:",
                    analysis["summary"]["protocol_hierarchy"],
                    ""
                ])

            if analysis.get("summary", {}).get("ip_conversations"):
                lines.extend([
                    "IP Conversations:",
                    analysis["summary"]["ip_conversations"],
                    ""
                ])

            if analysis.get("summary", {}).get("tcp_conversations"):
                lines.extend([
                    "TCP Conversations:",
                    analysis["summary"]["tcp_conversations"],
                    ""
                ])

            if analysis.get("summary", {}).get("ip_endpoints"):
                lines.extend([
                    "IP Endpoints:",
                    analysis["summary"]["ip_endpoints"],
                    ""
                ])

            if analysis.get("errors"):
                lines.extend([
                    "Analysis Warnings:",
                    *[f"  - {err}" for err in analysis["errors"]],
                    ""
                ])

        elif analysis.get("tool") == "basic":
            lines.extend([
                "Analysis (basic):",
                "-" * 40,
                f"  File Size: {analysis.get('file_size_bytes', 0)} bytes",
                f"  Packet Count: {analysis.get('packet_count', 0)}",
                f"  Format: {analysis.get('capture_info', {}).get('format', 'unknown')}",
                ""
            ])
            if analysis.get("note"):
                lines.append(f"  Note: {analysis['note']}")
                lines.append("")

        if summary.get("cleaned_up"):
            lines.append("Capture profile has been cleaned up.")
        elif summary.get("cleaned_up") is False:
            lines.append("Warning: Failed to clean up capture profile.")

        return [Content(type="text", text="\n".join(lines))]

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for packet capture tools."""
        return {
            "name": "packet_capture_tools",
            "description": "FortiGate packet capture and sniffer tools",
            "operations": [
                {
                    "name": "list_packet_captures",
                    "description": "List all packet capture profiles",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_packet_capture",
                    "description": "Create a packet capture profile with filters",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "interface", "type": "string", "required": False, "default": "any"},
                        {"name": "host", "type": "string", "required": False},
                        {"name": "src_ip", "type": "string", "required": False},
                        {"name": "dst_ip", "type": "string", "required": False},
                        {"name": "protocol", "type": "string", "required": False},
                        {"name": "port", "type": "integer", "required": False},
                        {"name": "max_packet_count", "type": "integer", "required": False, "default": 10000},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_packet_capture_status",
                    "description": "Get status of a packet capture",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "start_packet_capture",
                    "description": "Start a packet capture",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "stop_packet_capture",
                    "description": "Stop a packet capture",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "download_packet_capture",
                    "description": "Download captured packets",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_packet_capture",
                    "description": "Delete a packet capture profile",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "clear_packet_capture",
                    "description": "Clear captured packets",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "capture_and_analyze",
                    "description": "Capture traffic via SSH using 'diagnose sniffer packet' CLI command",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "interface", "type": "string", "required": False, "default": "any"},
                        {"name": "host", "type": "string", "required": False},
                        {"name": "src_ip", "type": "string", "required": False},
                        {"name": "dst_ip", "type": "string", "required": False},
                        {"name": "protocol", "type": "string", "required": False},
                        {"name": "port", "type": "integer", "required": False},
                        {"name": "duration_seconds", "type": "integer", "required": False, "default": 120},
                        {"name": "max_packet_count", "type": "integer", "required": False, "default": 10000},
                        {"name": "verbose", "type": "integer", "required": False, "default": 4},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
