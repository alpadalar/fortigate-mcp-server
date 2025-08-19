#!/bin/bash
# Start FortiGate MCP HTTP Server

set -e

# Default values
HOST="${MCP_HTTP_HOST:-0.0.0.0}"
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
