#!/bin/bash
# Start FortiGate MCP Server (STDIO mode for Cursor integration)

set -e

# Set config path
export FORTIGATE_MCP_CONFIG="$(pwd)/config/config.json"

# Check if config exists
if [ ! -f "$FORTIGATE_MCP_CONFIG" ]; then
    echo "Error: Configuration file not found at $FORTIGATE_MCP_CONFIG"
    echo "Please create config.json from config.example.json"
    exit 1
fi

echo "Starting FortiGate MCP Server (STDIO mode)..."
echo "Config: $FORTIGATE_MCP_CONFIG"
echo ""

# Run with uv
exec uv run python -m src.fortigate_mcp.server
