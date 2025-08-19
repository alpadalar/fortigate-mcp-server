"""
FortiGate MCP - A Model Context Protocol server for FortiGate management.

This package provides a comprehensive MCP server implementation for managing
FortiGate devices through their REST API. It offers both HTTP and STDIO transports
for integration with MCP-compatible clients like Cursor IDE.

Key features:
- Device management and configuration
- Firewall policy operations
- Network object management  
- Routing configuration
- System monitoring and health checks

The server supports multiple transport modes:
- STDIO: For direct integration with MCP clients
- HTTP: For web-based and external integrations
"""

__version__ = "1.0.0"
__author__ = "FortiGate MCP Team"
__email__ = "support@fortimcp.dev"

from .server import FortiGateMCPServer
from .server_http import FortiGateMCPHTTPServer

__all__ = [
    "FortiGateMCPServer", 
    "FortiGateMCPHTTPServer",
]
