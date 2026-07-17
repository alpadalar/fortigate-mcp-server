"""
Main STDIO server implementation for FortiGate MCP.

This module implements the core MCP server for FortiGate integration, providing:
- Configuration loading and validation
- Logging setup
- FortiGate API connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown

The server exposes a set of tools for managing FortiGate resources including:
- Device management
- Firewall policy operations
- Network object management
- Routing configuration
"""
import os
import sys
import signal
from typing import Optional

from fastmcp import FastMCP

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools
from .registry import register_tools

class FortiGateMCPServer:
    """Main server class for FortiGate MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)

        # Collect boot-time device secrets so the redaction filter can
        # scrub them from any log line before the first handler is even
        # created. HTTP bearer tokens (AuthConfig.api_tokens) are
        # registered too: a config file shared with the HTTP transport
        # must not leak its auth tokens through the stdio server's logs.
        secrets: set = set()
        for device_config in self.config.fortigate.devices.values():
            if device_config.api_token:
                secrets.add(device_config.api_token.get_secret_value())
            if device_config.password:
                secrets.add(device_config.password.get_secret_value())
        for api_token in self.config.auth.api_tokens:
            if api_token:
                secrets.add(api_token.get_secret_value())

        self.logger = setup_logging(self.config.logging, secrets=secrets)

        if self.config.rate_limiting.enabled:
            self.logger.warning(
                "rate_limiting.enabled is true, but rate limiting is NOT "
                "enforced in this release -- the setting is parsed and ignored"
            )

        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
        # Initialize tools
        self.device_tools = DeviceTools(self.fortigate_manager)
        self.firewall_tools = FirewallTools(self.fortigate_manager)
        self.network_tools = NetworkTools(self.fortigate_manager)
        self.routing_tools = RoutingTools(self.fortigate_manager)
        self.virtual_ip_tools = VirtualIPTools(self.fortigate_manager)
        
        # Initialize MCP server
        self.mcp = FastMCP("FortiGateMCP")
        self._tests_passed: Optional[bool] = None
        register_tools(self.mcp, self, transport="stdio")

    def start(self) -> None:
        """Start the MCP server."""
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                self.logger.info("Running startup tests...")
                connection_results = self.fortigate_manager.test_all_connections()
                self._tests_passed = all(connection_results.values())
                if not self._tests_passed:
                    failed_devices = [
                        device_id for device_id, ok in connection_results.items() if not ok
                    ]
                    self.logger.warning(
                        f"Startup connection tests failed for devices: {failed_devices}"
                    )

            self.logger.info("Starting FortiGate MCP server...")
            anyio.run(self.mcp.run_stdio_async)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            sys.exit(1)

def server_main() -> None:
    """Entry point for running the stdio FortiGate MCP server."""
    config_path = os.getenv("FORTIGATE_MCP_CONFIG")
    if not config_path:
        print("FORTIGATE_MCP_CONFIG environment variable must be set", file=sys.stderr)
        sys.exit(1)

    try:
        server = FortiGateMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    server_main()
