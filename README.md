<p align="center">
  <img src="https://img.shields.io/badge/FortiGate-MCP%20Server-blue?style=for-the-badge&logo=fortinet&logoColor=white" alt="FortiGate MCP Server"/>
</p>

<h1 align="center">FortiGate MCP Server</h1>

<p align="center">
  <strong>A production-ready Model Context Protocol (MCP) server for managing FortiGate firewalls</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/MCP-1.0-green?style=flat-square" alt="MCP 1.0"/>
  <img src="https://img.shields.io/badge/async-httpx-orange?style=flat-square" alt="Async httpx"/>
  <img src="https://img.shields.io/badge/tests-117%20passed-brightgreen?style=flat-square" alt="Tests"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License"/>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#available-tools">Tools</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#security">Security</a> &bull;
  <a href="#testing">Testing</a>
</p>

---

## Overview

FortiGate MCP Server exposes FortiGate firewall management capabilities through the [Model Context Protocol](https://modelcontextprotocol.io/), enabling AI assistants and MCP-compatible tools to programmatically manage firewall policies, network objects, routing, and device configurations.

Built with **fully async Python**, persistent HTTP connection pooling, and security-first defaults.

## Features

**Device Management**
- Multi-device support with concurrent management
- API token and basic authentication
- Connection testing and health monitoring
- VDOM discovery and per-VDOM operations

**Firewall Policy Management**
- Full CRUD for firewall policies
- Policy detail with address/service object resolution
- VDOM-scoped operations

**Network Object Management**
- Address objects (subnet, IP range, FQDN)
- Service objects (TCP/UDP/SCTP with port ranges)

**Virtual IP Management**
- NAT/DNAT virtual IPs
- Port forwarding configuration
- Protocol-specific VIP rules

**Routing**
- Static route CRUD operations
- Routing table inspection
- Interface listing and status monitoring

**Infrastructure**
- Fully async API client with `httpx.AsyncClient` connection pooling
- STDIO and HTTP transport modes
- Pydantic configuration models with validation
- Structured logging with API call tracing
- Rate limiting support

## Quick Start

### Prerequisites

- Python 3.11+
- Access to a FortiGate device with API enabled
- API token (recommended) or admin credentials

### Installation

```bash
git clone https://github.com/Aprazor/fortigate-mcp-server.git
cd fortigate-mcp-server

python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

pip install -e .
```

### Configuration

Create a configuration file (e.g., `config/config.json`):

```json
{
  "fortigate": {
    "devices": {
      "fw-primary": {
        "host": "192.168.1.1",
        "port": 443,
        "api_token": "your-api-token-here",
        "vdom": "root",
        "verify_ssl": true,
        "timeout": 30
      }
    }
  },
  "server": {
    "name": "fortigate-mcp-server",
    "host": "0.0.0.0",
    "port": 8814
  },
  "auth": {
    "require_auth": false,
    "allowed_origins": []
  },
  "logging": {
    "level": "INFO",
    "console": true
  }
}
```

### Run the Server

**STDIO mode** (for direct MCP client integration):

```bash
export FORTIGATE_MCP_CONFIG=config/config.json
python -m src.fortigate_mcp.server
```

**HTTP mode** (for web-based access):

```bash
python -m src.fortigate_mcp.server_http \
  --host 0.0.0.0 \
  --port 8814 \
  --config config/config.json
```

### MCP Client Integration

**Claude Desktop / Claude Code** (`~/.claude/mcp_servers.json`):

```json
{
  "mcpServers": {
    "fortigate": {
      "command": "python",
      "args": ["-m", "src.fortigate_mcp.server"],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/path/to/config.json"
      }
    }
  }
}
```

**Cursor IDE** (`~/.cursor/mcp_servers.json`):

```json
{
  "mcpServers": {
    "FortiGateMCP": {
      "url": "http://localhost:8814/fortigate-mcp/",
      "transport": "http"
    }
  }
}
```

## Available Tools

### Device Management (6 tools)

| Tool | Description |
|------|-------------|
| `list_devices` | List all registered FortiGate devices |
| `get_device_status` | Get system status for a device |
| `test_device_connection` | Test connectivity to a device |
| `add_device` | Register a new FortiGate device |
| `remove_device` | Remove a registered device |
| `discover_vdoms` | Discover Virtual Domains on a device |

### Firewall Policy Management (5 tools)

| Tool | Description |
|------|-------------|
| `list_firewall_policies` | List all firewall policies |
| `create_firewall_policy` | Create a new firewall policy |
| `update_firewall_policy` | Update an existing policy |
| `get_firewall_policy_detail` | Get policy with resolved objects |
| `delete_firewall_policy` | Delete a firewall policy |

### Network Object Management (4 tools)

| Tool | Description |
|------|-------------|
| `list_address_objects` | List firewall address objects |
| `create_address_object` | Create address object (subnet/range/FQDN) |
| `list_service_objects` | List firewall service objects |
| `create_service_object` | Create service object (TCP/UDP/SCTP) |

### Virtual IP Management (5 tools)

| Tool | Description |
|------|-------------|
| `list_virtual_ips` | List virtual IP configurations |
| `create_virtual_ip` | Create VIP with optional port forwarding |
| `update_virtual_ip` | Update virtual IP configuration |
| `get_virtual_ip_detail` | Get detailed VIP information |
| `delete_virtual_ip` | Delete a virtual IP |

### Routing Management (8 tools)

| Tool | Description |
|------|-------------|
| `list_static_routes` | List configured static routes |
| `create_static_route` | Create a new static route |
| `update_static_route` | Update an existing static route |
| `delete_static_route` | Delete a static route |
| `get_static_route_detail` | Get detailed route information |
| `get_routing_table` | Get the active routing table |
| `list_interfaces` | List network interfaces |
| `get_interface_status` | Get interface operational status |

### System Tools (2 tools)

| Tool | Description |
|------|-------------|
| `health_check` | Server health and device connectivity status |
| `get_server_info` | Server version and configuration info |

## Architecture

```
fortigate-mcp-server/
├── src/fortigate_mcp/
│   ├── server.py                # STDIO MCP server (FastMCP)
│   ├── server_http.py           # HTTP MCP server (FastMCP)
│   ├── config/
│   │   ├── loader.py            # Configuration file loading
│   │   └── models.py            # Pydantic config models
│   ├── core/
│   │   ├── fortigate.py         # Async API client + device manager
│   │   └── logging.py           # Structured logging setup
│   ├── tools/
│   │   ├── base.py              # Base tool class (error handling, formatting)
│   │   ├── definitions.py       # Tool description constants
│   │   ├── device.py            # Device management tools
│   │   ├── firewall.py          # Firewall policy tools
│   │   ├── network.py           # Address/service object tools
│   │   ├── routing.py           # Routing and interface tools
│   │   └── virtual_ip.py        # Virtual IP tools
│   └── formatting/
│       ├── formatters.py        # MCP content formatters
│       └── templates.py         # Response templates
└── tests/
    ├── conftest.py              # Shared fixtures (AsyncMock)
    ├── test_config.py           # Configuration model tests
    ├── test_device_manager.py   # Device manager lifecycle tests
    ├── test_fortigate_api.py    # Async API client tests
    ├── test_formatting.py       # Response formatting tests
    └── test_tools.py            # Tool integration tests
```

### Design Principles

- **Fully async**: All API calls use `httpx.AsyncClient` with persistent connection pooling per device
- **Security by default**: SSL verification enabled, empty CORS origins, no wildcard defaults
- **Clean separation**: Config models, API client, tool logic, and formatting are independent layers
- **Error categorization**: FortiGate API errors are mapped to user-friendly messages with HTTP status awareness

## Security

This server is designed with security-first defaults:

| Setting | Default | Description |
|---------|---------|-------------|
| `verify_ssl` | `true` | SSL certificate verification enabled |
| `allowed_origins` | `[]` | No CORS origins allowed (explicit opt-in) |
| `require_auth` | `false` | MCP server authentication (enable for production) |

**Recommendations for production:**

- Use **API tokens** instead of username/password authentication
- Keep `verify_ssl: true` unless testing with self-signed certificates
- Set explicit `allowed_origins` when using HTTP transport
- Enable `require_auth` with configured API tokens for the MCP server itself
- Run the server on a trusted network or behind a reverse proxy
- Use environment variables for sensitive configuration values

## Testing

The project includes 117 tests covering the full async stack:

```bash
# Run all tests
python -m pytest

# Run with verbose output
python -m pytest -v

# Run specific test module
python -m pytest tests/test_tools.py

# Run with coverage report
python -m pytest --cov=src --cov-report=html
```

### Test Coverage

| Module | Coverage |
|--------|----------|
| Config models | Security defaults, validation, Pydantic models |
| API client | Async HTTP, connection pooling, error handling |
| Device manager | Lifecycle (add/remove/list), async operations |
| Tool classes | All CRUD operations, VDOM support, error paths |
| Formatting | Templates, content rendering, edge cases |

## Troubleshooting

**Connection refused**
- Verify the FortiGate device is reachable and the API is enabled
- Check that the port (default 443) is not blocked by network firewalls

**Authentication failed (401)**
- Verify your API token is valid and has appropriate permissions
- For basic auth, confirm the username/password are correct

**SSL certificate error**
- For self-signed certificates in lab environments, set `verify_ssl: false`
- For production, install a valid certificate on the FortiGate device

**VDOM not found**
- Use `discover_vdoms` to list available VDOMs on the device
- Ensure the VDOM name matches exactly (case-sensitive)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`python -m pytest`)
5. Commit your changes (`git commit -m 'Add my feature'`)
6. Push to your branch (`git push origin feature/my-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification
- [FastMCP](https://gofastmcp.com/) - Python MCP server framework
- [FortiGate REST API](https://docs.fortinet.com/) - FortiGate API documentation
- [httpx](https://www.python-httpx.org/) - Async HTTP client
