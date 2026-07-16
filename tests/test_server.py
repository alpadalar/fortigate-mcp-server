"""
Tests for the stdio MCP server (FortiGateMCPServer).

Covers regression fixes for the known stdio-server bugs cataloged in
Phase 1 (Stability Baseline): construction NameError, sync/async
dispatch mismatches, and dict-payload forwarding.
"""

import asyncio

from src.fortigate_mcp.server import FortiGateMCPServer


def test_stdio_server_constructs_successfully(tmp_config_path):
    """FortiGateMCPServer constructs without exception and registers 30 tools."""
    server = FortiGateMCPServer(tmp_config_path)

    assert server is not None
    tools = asyncio.run(server.mcp.list_tools())
    assert len(tools) == 30
