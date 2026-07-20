# FortiGate MCP Server

FortiGate MCP Server - A comprehensive Model Context Protocol (MCP) server for managing FortiGate devices. This project provides programmatic access to FortiGate devices and enables integration with MCP-compatible clients such as Claude Desktop, Claude Code, and Cursor.

## 🚀 Features

FortiGate MCP Server exposes 33 unique tools, 61 total tool-surface registrations across stdio (30) and HTTP (31) transports; 3 create-tools have transport-specific parameter shapes. Covered areas:

- **Device Management**: Add, remove, and test connections to FortiGate devices
- **Firewall Management**: List, create, update, and delete firewall rules
- **Network Management**: Manage address and service objects
- **Routing Management**: Manage static routes and interfaces
- **Virtual IP Management**: Manage virtual IPs (VIP/DNAT)
- **HTTP Transport**: MCP protocol over HTTP using FastMCP
- **Docker Support**: Easy installation and deployment
- **MCP Client Integration**: Works with Claude Desktop, Claude Code, Cursor, and other MCP-compatible clients

## 📋 Requirements

- Python 3.11+
- `uv` package manager (recommended) or `pip`
- Access to FortiGate device
- API token or username/password

## 🛠️ Installation

### 1. Clone the Project

```bash
git clone https://github.com/alpadalar/fortigate-mcp-server.git
cd fortigate-mcp-server
```

### 2. Install Dependencies

```bash
# Using uv (recommended) - installs the locked, reproducible dependency set
uv sync --locked

# Or using pip
pip install -e .
```

### 3. Configuration

Create your local config from the committed example (`config/config.json` is gitignored and does
not exist on a fresh clone):

```bash
cp config/config.example.json config/config.json
```

Then edit `config/config.json`:

```json
{
  "server": {
    "allow_writes": false
  },
  "fortigate": {
    "devices": {
      "default": {
        "host": "192.168.1.1",
        "port": 443,
        "username": "admin",
        "password": "your_password",
        "api_token": "your-api-token",
        "vdom": "root",
        "verify_ssl": true,
        "timeout": 30
      }
    }
  },
  "logging": {
    "level": "INFO",
    "file": "./logs/fortigate_mcp.log"
  }
}
```

## 🚀 Usage

### Start HTTP Server

```bash
# Start with script
./start_http_server.sh

# Or manually
python -m src.fortigate_mcp.server_http \
  --host 127.0.0.1 \
  --port 8814 \
  --path /fortigate-mcp \
  --config config/config.json
```

Use `--host 0.0.0.0` only if you need access from other machines on the network AND have
`auth.require_auth=true` configured in `config/config.json`; otherwise keep `127.0.0.1` —
unauthenticated HTTP should never bind wider than loopback.

### Run with Docker

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f fortigate-mcp-server
```

## 🔧 MCP Client Integration

FortiGate MCP Server works with any MCP-compatible client. Verified, ready-to-use config examples
are provided for Claude Desktop, Claude Code, and Cursor:

- [`examples/claude_desktop_config.stdio.json`](examples/claude_desktop_config.stdio.json) — Claude Desktop, stdio transport (recommended)
- [`examples/claude_desktop_config.http.json`](examples/claude_desktop_config.http.json) — Claude Desktop, HTTP transport via the `mcp-remote` bridge
- [`examples/claude_code_mcp.json`](examples/claude_code_mcp.json) — Claude Code project-scope `.mcp.json` (stdio and HTTP entries)
- [`examples/cursor_mcp_config.json`](examples/cursor_mcp_config.json) — Cursor MCP configuration

Every stdio example in this project launches the server via `uv run --directory <path> python -m
src.fortigate_mcp.server` instead of a bare `python -m ...` command. This matters because
GUI-launched MCP clients (like Claude Desktop) commonly start commands from a directory other than
the repo root — the explicit `--directory` flag makes the invocation working-directory
independent, so it keeps working regardless of where the client process happens to start from.

### Claude Code (`.mcp.json`)

Add a project-scope `.mcp.json` at your repository root (see
`examples/claude_code_mcp.json` for the full file, including the HTTP entry):

```json
{
  "mcpServers": {
    "fortigate-mcp-stdio": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "${CLAUDE_PROJECT_DIR}", "python", "-m", "src.fortigate_mcp.server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "${CLAUDE_PROJECT_DIR}/config/config.json"
      }
    }
  }
}
```

Or register the HTTP transport via the Claude Code CLI:

```bash
claude mcp add --transport http fortigate-mcp http://127.0.0.1:8814/fortigate-mcp --header "Authorization: Bearer <token>"
```

`--header` is only needed when `auth.require_auth=true` is set in `config/config.json`.

### Claude Desktop

Claude Desktop's native config schema validates stdio servers only. Use
`examples/claude_desktop_config.stdio.json` for the stdio transport (recommended). For the HTTP
transport, `examples/claude_desktop_config.http.json` bridges to this server through the
community `mcp-remote` npm package (`npx -y mcp-remote ...`) — this package is not vetted or
installed by this project; inspect it yourself before running it, since `npx` fetches and
executes third-party code on your behalf.

### Cursor

See `examples/cursor_mcp_config.json` for a working stdio configuration.

## 📚 API Commands

### Device Management

- `list_devices` - List registered devices
- `get_device_status` - Get device status
- `test_device_connection` - Test connection
- `add_device` - Add new device
- `remove_device` - Remove device
- `discover_vdoms` - Discover VDOMs

### Firewall Management

- `list_firewall_policies` - List firewall rules
- `create_firewall_policy` - Create new rule
- `update_firewall_policy` - Update rule
- `delete_firewall_policy` - Delete rule

### Network Management

- `list_address_objects` - List address objects
- `create_address_object` - Create address object
- `list_service_objects` - List service objects
- `create_service_object` - Create service object

### Virtual IP Management

- `list_virtual_ips` - List virtual IPs
- `create_virtual_ip` - Create virtual IP
- `update_virtual_ip` - Update virtual IP
- `get_virtual_ip_detail` - Get virtual IP detail
- `delete_virtual_ip` - Delete virtual IP

### Routing Management

- `list_static_routes` - List static routes
- `create_static_route` - Create static route
- `update_static_route` - Update static route
- `delete_static_route` - Delete static route
- `get_static_route_detail` - Get static route detail
- `get_routing_table` - Get routing table
- `list_interfaces` - List interfaces
- `get_interface_status` - Get interface status

### System Commands

- `health` - Health check
- `test_connection` - Connection test
- `get_schema_info` - Schema information

## 🧪 Testing

### Run Tests

```bash
# One-time setup: test dependencies (pytest, pytest-cov, respx, pyyaml) live in the
# dev/test extras — the plain `uv sync --locked` from the install step does not install them
uv sync --locked --all-extras

# Quick run with coverage disabled (a bare -q only reduces verbosity;
# without --no-cov the coverage gate from pyproject.toml addopts still runs)
uv run pytest -q --no-cov

# Full suite with coverage (--cov-fail-under=67 enforced per pyproject.toml)
uv run pytest

# Run specific test files
uv run pytest tests/test_device_manager.py
uv run pytest tests/test_fortigate_api.py
uv run pytest tests/test_tools.py

# Verbose output
uv run pytest -v

# Detailed error information
uv run pytest --tb=long
```

### Test Categories

- **Unit Tests**: Test individual components and functions
- **Coverage**: Code coverage reporting with HTML output

### Manual Testing

The `/health` route lives at the app root, is exempt from Bearer-token auth, and works with
plain `curl`:

```bash
# Liveness probe
curl http://127.0.0.1:8814/health
```

The MCP protocol itself cannot be exercised with a bare `curl` POST: the streamable-HTTP
transport requires an `initialize` handshake, session management, and `tools/call` framing.
Use a real MCP client for protocol-level testing — for example `fastmcp.Client`:

```bash
uv run python - <<'PY'
import asyncio
from fastmcp import Client

async def main():
    # Trailing slash matches the mount convention; the non-slash form 307-redirects
    async with Client("http://127.0.0.1:8814/fortigate-mcp/") as client:
        tools = await client.list_tools()
        print(f"{len(tools)} tools registered")
        result = await client.call_tool("health", {})
        print(result.content[0].text)

asyncio.run(main())
PY
```

Alternatively, bridge with `npx -y mcp-remote http://127.0.0.1:8814/fortigate-mcp` or use the
MCP Inspector.

## 📁 Project Structure

```
fortigate-mcp-server/
├── src/
│   └── fortigate_mcp/
│       ├── __init__.py
│       ├── server.py               # STDIO MCP server
│       ├── server_http.py          # HTTP MCP server
│       ├── config/                 # Configuration management
│       ├── core/                   # Core components
│       ├── tools/                  # MCP tools
│       └── formatting/             # Response formatting
├── config/
│   ├── config.json                # Main configuration (gitignored, created from example)
│   └── config.example.json        # Example configuration
├── examples/
│   ├── claude_desktop_config.stdio.json  # Claude Desktop, stdio transport
│   ├── claude_desktop_config.http.json   # Claude Desktop, HTTP via mcp-remote
│   ├── claude_code_mcp.json               # Claude Code .mcp.json
│   └── cursor_mcp_config.json             # Cursor MCP config
├── logs/                          # Log files
├── tests/                         # Test files
├── docker-compose.yml             # Docker compose
├── Dockerfile                     # Docker image
├── start_server.sh                # STDIO startup script
├── start_http_server.sh           # HTTP startup script
└── README.md                      # This file
```

## 🔍 Troubleshooting

### Common Issues

1. **Connection Error**
   - Ensure FortiGate device is accessible
   - Verify API token or username/password
   - If you see SSL certificate errors, install the FortiGate device's certificate as trusted (or
     replace it with a CA-signed certificate) — do not disable certificate verification.
     `verify_ssl` defaults to `true` and must stay `true`; see SECURITY.md for the rationale.

2. **Port Conflict**
   - Ensure port 8814 is available
   - Change port using `--port` parameter

3. **Configuration Error**
   - Ensure `config.json` is properly formatted
   - Check JSON syntax

4. **MCP Client Connection Issue**
   - Ensure the server is running
   - Verify the config file path and URL are correct
   - Restart the MCP client (Claude Desktop / Claude Code / Cursor)

### Logs

Check logs using:

```bash
# HTTP server logs
tail -f logs/fortigate_mcp.log

# Docker logs
docker-compose logs -f fortigate-mcp-server
```

## 🔒 Security

### Implemented Controls

1. **Write protection (default: read-only)**
   - Write and destructive tools are rejected unless explicitly enabled via
     `server.allow_writes: true` in config, or the `FORTIGATE_MCP_ALLOW_WRITES=1` environment
     variable

2. **TLS certificate verification (default: on)**
   - Config-loaded devices verify TLS certificates by default (`verify_ssl: true`)

3. **Bearer-token authentication (optional, default: off)**
   - Available via `auth.require_auth` / `auth.api_tokens`; unauthenticated by default — run only
     on trusted networks when disabled

4. **Secret redaction**
   - API tokens and passwords are stored as `SecretStr` and are never written to logs

### Known Limitations

- Rate limiting is parsed from config but **not enforced** — do not rely on it as a working
  control.
- Unauthenticated HTTP (the default) should bind to `127.0.0.1` (loopback) only; binding to
  `0.0.0.0` for wider network access requires enabling Bearer auth
  (`auth.require_auth=true`) plus network-level controls (firewall rules, VPN, reverse-proxy
  allowlists).

See [SECURITY.md](SECURITY.md) for the full threat model and known limitations.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## 🙏 Acknowledgments

- [FastMCP](https://gofastmcp.com/) - For MCP HTTP transport
- [FortiGate API](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/109229/rest-api) - For FortiGate integration

## 📞 Support

For issues:
- Use the [Issues](https://github.com/alpadalar/fortigate-mcp-server/issues) page
- Check the documentation
- Review the logs

---

**Note**: This project has been tested with FortiGate devices. Please perform comprehensive testing before using in production.
