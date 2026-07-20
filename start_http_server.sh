#!/bin/bash
# Start FortiGate MCP HTTP Server

set -e

# Default values
# Loopback by default: the shipped config has auth.require_auth=false, and an
# unauthenticated HTTP server must never bind wider than 127.0.0.1. Set
# MCP_HTTP_HOST explicitly (with auth.require_auth=true) for a wider bind.
HOST="${MCP_HTTP_HOST:-127.0.0.1}"
PORT="${MCP_HTTP_PORT:-8814}"
PATH="${MCP_HTTP_PATH:-/fortigate-mcp}"
CONFIG="${FORTIGATE_MCP_CONFIG:-$(pwd)/config/config.json}"

# Check if config exists
if [ ! -f "$CONFIG" ]; then
    echo "Error: Configuration file not found at $CONFIG"
    echo "Please create config.json from config.example.json"
    exit 1
fi

echo "Starting FortiGate MCP HTTP Server..."
echo "Host: $HOST"
echo "Port: $PORT"
echo "Path: $PATH"
echo "Config: $CONFIG"
echo ""

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Run the server
exec python -m src.fortigate_mcp.server_http \
    --host "$HOST" \
    --port "$PORT" \
    --path "$PATH" \
    --config "$CONFIG"
