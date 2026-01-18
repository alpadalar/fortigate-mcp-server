"""
SSH client for FortiGate CLI operations.

This module provides SSH-based access to FortiGate CLI commands that are not
available via the REST API, such as packet capture (diagnose sniffer packet).
"""
import io
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

from ..core.logging import get_logger


class FortiGateSSHError(Exception):
    """Exception raised for FortiGate SSH errors."""

    def __init__(self, message: str, device_id: str = None):
        self.message = message
        self.device_id = device_id
        super().__init__(self.message)


class FortiGateSSHClient:
    """SSH client for FortiGate CLI operations.

    Provides methods for executing CLI commands on FortiGate devices,
    particularly for operations not available via REST API like packet capture.
    """

    def __init__(
        self,
        device_id: str,
        host: str,
        port: int = 22,
        username: str = None,
        password: str = None,
        timeout: int = 30,
        vdom: str = "root"
    ):
        """Initialize the SSH client.

        Args:
            device_id: Identifier for this device
            host: FortiGate hostname or IP
            port: SSH port (default: 22)
            username: SSH username
            password: SSH password
            timeout: Connection timeout in seconds
            vdom: Default VDOM for operations
        """
        if not PARAMIKO_AVAILABLE:
            raise FortiGateSSHError("paramiko is not installed. Install with: pip install paramiko")

        self.device_id = device_id
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.vdom = vdom
        self.logger = get_logger(f"ssh.{device_id}")

        self._client: Optional[paramiko.SSHClient] = None
        self._shell: Optional[paramiko.Channel] = None

    def connect(self) -> None:
        """Establish SSH connection to FortiGate."""
        if self._client is not None:
            return

        self.logger.info(f"Connecting to {self.host}:{self.port} via SSH")

        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self._client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            self.logger.info(f"SSH connection established to {self.host}")

        except paramiko.AuthenticationException as e:
            raise FortiGateSSHError(f"SSH authentication failed: {e}", self.device_id)
        except paramiko.SSHException as e:
            raise FortiGateSSHError(f"SSH connection error: {e}", self.device_id)
        except Exception as e:
            raise FortiGateSSHError(f"Failed to connect: {e}", self.device_id)

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._shell:
            self._shell.close()
            self._shell = None

        if self._client:
            self._client.close()
            self._client = None
            self.logger.info(f"SSH connection closed to {self.host}")

    def execute_command(self, command: str, timeout: int = 30) -> str:
        """Execute a CLI command and return output.

        Args:
            command: CLI command to execute
            timeout: Command timeout in seconds

        Returns:
            Command output as string
        """
        self.connect()

        self.logger.debug(f"Executing command: {command}")

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout
            )

            output = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')

            if error and "command parse error" in error.lower():
                raise FortiGateSSHError(f"Command error: {error}", self.device_id)

            return output

        except paramiko.SSHException as e:
            raise FortiGateSSHError(f"Command execution failed: {e}", self.device_id)

    def run_sniffer(
        self,
        interface: str = "any",
        filter_str: str = "",
        verbose: int = 4,
        count: int = 0,
        duration_seconds: int = 120,
        timestamp_format: str = "a"
    ) -> Tuple[str, Dict[str, Any]]:
        """Run packet sniffer and capture output.

        Executes: diagnose sniffer packet <interface> '<filter>' <verbose> <count> <timestamp>

        Args:
            interface: Interface to capture on (default: "any")
            filter_str: BPF-style filter (e.g., "host 192.168.1.1 and port 443")
            verbose: Verbosity level 1-6 (default: 4)
                1 = print header of packets
                2 = print header and data from IP of packets
                3 = print header and data from Ethernet of packets
                4 = print header of packets with interface name
                5 = print header and data from IP of packets with interface name
                6 = print header and data from Ethernet of packets with interface name
            count: Number of packets to capture (0 = unlimited until timeout)
            duration_seconds: How long to run capture (default: 120 seconds)
            timestamp_format: Timestamp format (default: "a" = absolute UTC)
                l = local time
                a = absolute UTC

        Returns:
            Tuple of (raw_output, parsed_stats)
        """
        self.connect()

        # Build command
        # diagnose sniffer packet <interface> '<filter>' <verbose> <count> <timestamp>
        if filter_str:
            cmd = f"diagnose sniffer packet {interface} '{filter_str}' {verbose} {count} {timestamp_format}"
        else:
            cmd = f"diagnose sniffer packet {interface} '' {verbose} {count} {timestamp_format}"

        self.logger.info(f"Starting packet capture: {cmd}")
        self.logger.info(f"Capture will run for {duration_seconds} seconds")

        output_lines = []
        packet_count = 0
        start_time = time.time()

        try:
            # Use invoke_shell for interactive command that needs to be interrupted
            self._shell = self._client.invoke_shell()
            self._shell.settimeout(5)  # Read timeout

            # Clear any initial banner/prompt
            time.sleep(1)
            while self._shell.recv_ready():
                self._shell.recv(4096)

            # Send the sniffer command
            self._shell.send(cmd + "\n")
            time.sleep(0.5)

            # Collect output until duration expires or count reached
            while (time.time() - start_time) < duration_seconds:
                if count > 0 and packet_count >= count:
                    self.logger.info(f"Reached packet count limit: {count}")
                    break

                try:
                    if self._shell.recv_ready():
                        chunk = self._shell.recv(8192).decode('utf-8', errors='replace')
                        output_lines.append(chunk)

                        # Count packets in output (lines starting with timestamp or interface)
                        new_packets = len(re.findall(r'^\d+\.\d+\.\d+\.\d+|^port\d+|^any\s', chunk, re.MULTILINE))
                        packet_count += new_packets

                        if new_packets > 0:
                            self.logger.debug(f"Captured {packet_count} packets so far...")
                    else:
                        time.sleep(0.1)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.warning(f"Read error: {e}")
                    break

            # Stop the sniffer by sending Ctrl+C
            self.logger.info("Stopping packet capture...")
            self._shell.send("\x03")  # Ctrl+C
            time.sleep(1)

            # Collect any remaining output
            while self._shell.recv_ready():
                chunk = self._shell.recv(8192).decode('utf-8', errors='replace')
                output_lines.append(chunk)

        except Exception as e:
            self.logger.error(f"Sniffer error: {e}")
            raise FortiGateSSHError(f"Packet capture failed: {e}", self.device_id)
        finally:
            if self._shell:
                self._shell.close()
                self._shell = None

        raw_output = "".join(output_lines)
        elapsed = time.time() - start_time

        # Parse statistics from output
        stats = self._parse_sniffer_output(raw_output, elapsed)
        stats["interface"] = interface
        stats["filter"] = filter_str or "none"
        stats["duration_seconds"] = int(elapsed)

        self.logger.info(f"Capture complete: {stats.get('packets_captured', 0)} packets in {int(elapsed)}s")

        return raw_output, stats

    def _parse_sniffer_output(self, output: str, duration: float) -> Dict[str, Any]:
        """Parse sniffer output to extract statistics.

        Args:
            output: Raw sniffer output
            duration: Capture duration in seconds

        Returns:
            Dictionary with parsed statistics
        """
        stats = {
            "packets_captured": 0,
            "bytes_captured": 0,
            "unique_ips": set(),
            "protocols": {},
            "conversations": [],
            "errors": []
        }

        # Count packets - look for lines that appear to be packet headers
        # FortiGate sniffer output format varies by verbosity level
        # Level 4+ includes interface name: "port1 in 192.168.1.1 -> 8.8.8.8: ..."
        packet_patterns = [
            r'(?:port\d+|any|wan\d*|lan\d*|dmz\d*|internal\d*)\s+(?:in|out)\s+(\d+\.\d+\.\d+\.\d+)\s*[->]+\s*(\d+\.\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+\.\d+)[.:]\d+\s*[->]+\s*(\d+\.\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)',
        ]

        for pattern in packet_patterns:
            matches = re.findall(pattern, output)
            for match in matches:
                stats["packets_captured"] += 1
                if len(match) >= 2:
                    stats["unique_ips"].add(match[0])
                    stats["unique_ips"].add(match[1])

        # Look for protocol indicators
        if "icmp" in output.lower():
            stats["protocols"]["ICMP"] = stats["protocols"].get("ICMP", 0) + output.lower().count("icmp")
        if "tcp" in output.lower():
            stats["protocols"]["TCP"] = stats["protocols"].get("TCP", 0) + output.lower().count(" tcp ")
        if "udp" in output.lower():
            stats["protocols"]["UDP"] = stats["protocols"].get("UDP", 0) + output.lower().count(" udp ")

        # Look for summary line at end
        summary_match = re.search(r'(\d+)\s+packets\s+received', output)
        if summary_match:
            stats["packets_captured"] = int(summary_match.group(1))

        # Convert set to list for JSON serialization
        stats["unique_ips"] = list(stats["unique_ips"])

        return stats

    def test_connection(self) -> bool:
        """Test SSH connection.

        Returns:
            True if connection successful
        """
        try:
            self.connect()
            output = self.execute_command("get system status", timeout=10)
            return "Hostname:" in output or "Version:" in output
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
        finally:
            self.disconnect()

    # IPSec VPN diagnostic commands
    def get_ike_gateway_list(self, timeout: int = 30) -> str:
        """Get IKE gateway list with negotiation details.

        Command: diagnose vpn ike gateway list

        Returns:
            Raw CLI output showing IKE gateway status
        """
        return self.execute_command("diagnose vpn ike gateway list", timeout=timeout)

    def get_tunnel_list(self, tunnel_name: Optional[str] = None, timeout: int = 30) -> str:
        """Get IPSec tunnel list with traffic statistics.

        Command: diagnose vpn tunnel list [name <tunnel>]

        Args:
            tunnel_name: Optional specific tunnel name to query
            timeout: Command timeout

        Returns:
            Raw CLI output showing tunnel status and stats
        """
        if tunnel_name:
            return self.execute_command(f"diagnose vpn tunnel list name {tunnel_name}", timeout=timeout)
        return self.execute_command("diagnose vpn tunnel list", timeout=timeout)

    def bring_tunnel_up(self, phase1_name: str, timeout: int = 30) -> str:
        """Bring up an IPSec tunnel.

        Command: diagnose vpn tunnel up <phase1_name>

        Args:
            phase1_name: Name of the Phase 1 interface/tunnel
            timeout: Command timeout

        Returns:
            CLI output indicating tunnel initiation
        """
        self.logger.info(f"Bringing up tunnel: {phase1_name}")
        return self.execute_command(f"diagnose vpn tunnel up {phase1_name}", timeout=timeout)

    def bring_tunnel_down(self, phase1_name: str, timeout: int = 30) -> str:
        """Bring down an IPSec tunnel.

        Command: diagnose vpn tunnel down <phase1_name>

        Args:
            phase1_name: Name of the Phase 1 interface/tunnel
            timeout: Command timeout

        Returns:
            CLI output indicating tunnel teardown
        """
        self.logger.info(f"Bringing down tunnel: {phase1_name}")
        return self.execute_command(f"diagnose vpn tunnel down {phase1_name}", timeout=timeout)

    def clear_ike_gateway(self, gateway_name: Optional[str] = None, timeout: int = 30) -> str:
        """Clear IKE gateway to force renegotiation.

        Command: diagnose vpn ike gateway clear [name <gateway>]

        Args:
            gateway_name: Optional specific gateway to clear (clears all if not specified)
            timeout: Command timeout

        Returns:
            CLI output
        """
        if gateway_name:
            self.logger.info(f"Clearing IKE gateway: {gateway_name}")
            return self.execute_command(f"diagnose vpn ike gateway clear name {gateway_name}", timeout=timeout)
        self.logger.info("Clearing all IKE gateways")
        return self.execute_command("diagnose vpn ike gateway clear", timeout=timeout)

    def parse_ike_gateway_list(self, output: str) -> Dict[str, Any]:
        """Parse diagnose vpn ike gateway list output.

        Args:
            output: Raw CLI output from get_ike_gateway_list()

        Returns:
            Parsed gateway information
        """
        gateways = []
        current_gateway = None

        for line in output.split('\n'):
            line = line.strip()

            # Look for gateway name lines
            name_match = re.match(r'^name:\s*(.+)$', line, re.IGNORECASE)
            if name_match:
                if current_gateway:
                    gateways.append(current_gateway)
                current_gateway = {"name": name_match.group(1).strip(), "raw_lines": []}

            if current_gateway:
                current_gateway["raw_lines"].append(line)

                # Parse common fields
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip().lower().replace(" ", "_")
                    value = value.strip()
                    if key and value and key != "name":
                        current_gateway[key] = value

        if current_gateway:
            gateways.append(current_gateway)

        return {
            "gateway_count": len(gateways),
            "gateways": gateways
        }

    def parse_tunnel_list(self, output: str) -> Dict[str, Any]:
        """Parse diagnose vpn tunnel list output.

        Args:
            output: Raw CLI output from get_tunnel_list()

        Returns:
            Parsed tunnel information with statistics
        """
        tunnels = []
        current_tunnel = None

        for line in output.split('\n'):
            line = line.strip()

            # Look for tunnel/gateway name indicators
            name_match = re.match(r'^name:\s*(.+)$', line, re.IGNORECASE)
            if name_match:
                if current_tunnel:
                    tunnels.append(current_tunnel)
                current_tunnel = {
                    "name": name_match.group(1).strip(),
                    "raw_lines": [],
                    "incoming_bytes": 0,
                    "outgoing_bytes": 0
                }

            if current_tunnel:
                current_tunnel["raw_lines"].append(line)

                # Parse statistics
                in_match = re.search(r'incoming\s*:\s*(\d+)', line, re.IGNORECASE)
                if in_match:
                    current_tunnel["incoming_bytes"] = int(in_match.group(1))

                out_match = re.search(r'outgoing\s*:\s*(\d+)', line, re.IGNORECASE)
                if out_match:
                    current_tunnel["outgoing_bytes"] = int(out_match.group(1))

                # Parse common key:value pairs
                if ":" in line:
                    key, _, value = line.partition(":")
                    key = key.strip().lower().replace(" ", "_").replace("-", "_")
                    value = value.strip()
                    if key and value and key not in ["name", "incoming", "outgoing"]:
                        current_tunnel[key] = value

        if current_tunnel:
            tunnels.append(current_tunnel)

        return {
            "tunnel_count": len(tunnels),
            "tunnels": tunnels
        }


# Import socket for timeout exception
import socket
