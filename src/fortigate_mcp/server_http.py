"""
HTTP-based MCP server implementation for FortiGate MCP.

This module provides an HTTP transport layer for the MCP server,
supporting HTTP transport for web-based integrations and external access.
"""

import os
import sys
import signal
from typing import Optional

# The official SDK's embedded FastMCP engine has neither custom_route() nor
# http_app() -- a fallback to that engine can never produce this HTTP
# server and would only defer failure to a confusing runtime
# AttributeError deep inside build_http_app(). fastmcp is a pinned direct
# dependency, so a missing package here means a genuinely broken
# environment -- fail loudly at import time instead.
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.responses import JSONResponse

from .config.loader import load_config
from .core.logging import setup_logging
from .core.fortigate import FortiGateManager
from .middleware.auth import AuthMiddleware
from .middleware.trace import TraceMiddleware
from .registry import register_tools
from .tools.device import DeviceTools
from .tools.firewall import FirewallTools
from .tools.network import NetworkTools
from .tools.routing import RoutingTools
from .tools.virtual_ip import VirtualIPTools

class FortiGateMCPHTTPServer:
    """
    HTTP-based MCP server for FortiGate management.

    This server supports:
    - HTTP transport for web integration
    - Authentication is enforced by a pure-ASGI Bearer-token middleware
      (middleware/auth.py::AuthMiddleware) when AuthConfig.require_auth is
      True (default False -- unauthenticated by default; run only on
      trusted networks). GET/HEAD /health stays token-exempt for liveness
      probes even when require_auth is True.
    - Rate limiting is not currently enforced (RateLimitConfig is parsed
      but never checked)
    - CORS is not configured (AuthConfig.allowed_origins is parsed but not
      applied; no CORS middleware exists in this codebase)
    """
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8814,
                 path: str = "/fortigate-mcp"):
        """
        Initialize the HTTP MCP server.
        
        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        # Load and validate configuration
        self.config = load_config(config_path)

        # Collect boot-time device secrets so the redaction filter can
        # scrub them from any log line before the first handler is even
        # created. HTTP bearer tokens (AuthConfig.api_tokens) are covered
        # by the same filter as device secrets (T-04-12).
        secrets: set = set()
        for device_config in self.config.fortigate.devices.values():
            if device_config.api_token:
                secrets.add(device_config.api_token.get_secret_value())
            if device_config.password:
                secrets.add(device_config.password.get_secret_value())
        for api_token in self.config.auth.api_tokens:
            if api_token:
                secrets.add(api_token.get_secret_value())

        # Setup logging
        self.logger = setup_logging(self.config.logging, secrets=secrets)

        if self.config.rate_limiting.enabled:
            self.logger.warning(
                "rate_limiting.enabled is true, but rate limiting is NOT "
                "enforced in this release -- the setting is parsed and ignored"
            )

        self.host = host
        self.port = port
        self.path = path
        
        # Initialize core components
        self.fortigate_manager = FortiGateManager(
            self.config.fortigate.devices, 
            self.config.auth
        )
        
        # Test connection on startup
        self._test_initial_connection()
        
        # Initialize tools
        self.device_tools = DeviceTools(self.fortigate_manager)
        self.firewall_tools = FirewallTools(self.fortigate_manager)
        self.network_tools = NetworkTools(self.fortigate_manager)
        self.routing_tools = RoutingTools(self.fortigate_manager)
        self.virtual_ip_tools = VirtualIPTools(self.fortigate_manager)
        
        # Initialize FastMCP
        self.mcp = FastMCP("FortiGateMCP-HTTP")

        # Register tools from the shared registry (CONS-01)
        register_tools(self.mcp, self, transport="http")

        # HTTP-level readiness route for E2E/liveness polling (CONS-02).
        # Distinct from the MCP tool literally named "health" registered
        # above by register_tools()'s http-only branch -- that tool is only
        # reachable via a full MCP JSON-RPC session, while this is a plain
        # GET endpoint. Must be registered before any build_http_app()/
        # http_app() call: custom routes bake into mcp._additional_http_routes,
        # which http_app() reads at construction time.
        @self.mcp.custom_route("/health", methods=["GET"])
        async def health(request):
            # HTTP status stays 200 even when devices are degraded: this
            # route is a process-liveness probe (is the server up and able
            # to answer at all), not a readiness probe. A load balancer
            # treating a 5xx/4xx here as "take this instance out of
            # rotation" would be wrong -- the process itself is healthy
            # even if a FortiGate device is unreachable.
            #
            # Minimal body by design: this route stays token-exempt even
            # when require_auth is True, so it must not disclose device
            # IDs, device counts, or raw initialization error strings to
            # unauthenticated callers. Device-level detail
            # (registered_devices / failed_devices) lives behind the
            # authenticated "health" MCP tool instead.
            failed_devices = self.fortigate_manager.failed_devices
            return JSONResponse(
                {"status": "degraded" if failed_devices else "healthy"}
            )

    def _test_initial_connection(self) -> None:
        """Test initial FortiGate connection."""
        try:
            self.logger.info("Testing initial FortiGate connections...")
            devices = self.fortigate_manager.list_devices()
            
            for device_id in devices:
                try:
                    api_client = self.fortigate_manager.get_device(device_id)
                    success = api_client.test_connection()
                    if success:
                        self.logger.info(f"Successfully connected to device: {device_id}")
                    else:
                        self.logger.warning(f"Connection test failed for device: {device_id}")
                except Exception as e:
                    self.logger.error(f"Connection test error for device {device_id}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Initial connection test error: {e}")

    def build_http_app(self):
        """THE single ASGI app factory.

        ``run()`` and the E2E test fixture (``tests/conftest.py``) both call
        this -- never construct a second, separate ``http_app()`` anywhere.

        Middleware ordering contract (enforced): Trace is OUTERMOST (first
        in the list), Auth is next, applied only when
        ``config.auth.require_auth`` is True. Trace stays outermost so the
        trace-header canary still appears on a 401 response, proving the
        middleware stack attached even when Auth denies a request. If CORS
        is ever added, it goes outermost of all (ahead of Trace) so an
        unauthenticated CORS preflight OPTIONS is answered before Auth can
        401 it. Uses the ``Middleware([...])`` list ONLY -- never FastMCP's
        own middleware-registration method, which prepends (LIFO order) and
        would invert this ordering.
        """
        middleware = [Middleware(TraceMiddleware)]
        if self.config.auth.require_auth:
            # AuthConfig.api_tokens are SecretStr -- unwrap once here, at
            # the single point of consumption, so the middleware compares
            # plain token values.
            middleware.append(
                Middleware(
                    AuthMiddleware,
                    api_tokens=[
                        token.get_secret_value()
                        for token in self.config.auth.api_tokens
                    ],
                )
            )
        return self.mcp.http_app(path=self.path, middleware=middleware)

    def run(self) -> None:
        """
        Start the HTTP MCP server.

        Runs the server with HTTP transport on the configured
        host and port.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting FortiGate MCP HTTP server on {self.host}:{self.port}{self.path}")
            self.logger.info(f"Registered devices: {len(self.fortigate_manager.devices)}")

            # Build the single ASGI app and serve it via a manual uvicorn
            # server (instead of FastMCP's mcp.run(transport="http", ...)
            # convenience wrapper) so run() and the E2E fixture serve the
            # IDENTICAL app object produced by build_http_app().
            app = self.build_http_app()
            import uvicorn
            uvicorn.Server(
                uvicorn.Config(
                    app,
                    host=self.host,
                    port=self.port,
                    log_level="info",
                    lifespan="on",
                )
            ).run()
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            sys.exit(1)


class FortiGateMCPCommand:
    """
    Command runner for FortiGate MCP HTTP server.
    
    This class can be used as a standalone command runner.
    """
    
    help = "FortiGate MCP HTTP Server"
    
    def __init__(self):
        self.server = None
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8814,
            help='Server port (default: 8814)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/fortigate-mcp',
            help='HTTP path (default: /fortigate-mcp)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('FORTIGATE_MCP_CONFIG')
        
        self.server = FortiGateMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8814),
            path=options.get('path', '/fortigate-mcp')
        )
        
        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='FortiGate MCP HTTP Server')
    command = FortiGateMCPCommand()
    command.add_arguments(parser)
    
    args = parser.parse_args()
    options = vars(args)
    
    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
