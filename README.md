# FortiGate MCP Server

FortiGate MCP Server - A comprehensive Model Context Protocol (MCP) server for managing FortiGate devices. This project provides programmatic access to FortiGate devices and enables integration with MCP-compatible tools like Cursor.

## 🚀 Features

- **Device Management**: Add, remove, and test connections to FortiGate devices
- **Firewall Management**: List, create, update, and delete firewall rules
- **Network Management**: Manage address and service objects
- **Routing Management**: Manage static routes and interfaces
- **HTTP Transport**: MCP protocol over HTTP using FastMCP
- **Docker Support**: Easy installation and deployment
- **Cursor Integration**: Full integration with Cursor IDE

## 📋 Requirements

- Python 3.8+
- Access to FortiGate device
- API token or username/password

## 🛠️ Installation

### 1. Clone the Project

```bash
git clone <repository-url>
cd fortigate-mcp-server
```

### 2. Install Dependencies

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

Edit the `config/config.json` file:

```json
{
  "fortigate": {
    "devices": {
      "default": {
        "host": "192.168.1.1",
        "port": 443,
        "username": "admin",
        "password": "password",
        "api_token": "your-api-token",
        "vdom": "root",
        "verify_ssl": false,
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
  --host 0.0.0.0 \
  --port 8814 \
  --path /fortigate-mcp \
  --config config/config.json
```

### Run with Docker

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f fortigate-mcp-server
```

## 🔧 Cursor MCP Integration

### 1. Cursor MCP Configuration

Edit `~/.cursor/mcp_servers.json` in Cursor:

#### Option 1: Command Connection

```json
{
  "mcpServers": {
    "fortigate-mcp": {
      "command": "python",
      "args": [
        "-m",
        "src.fortigate_mcp.server_http",
        "--host",
        "0.0.0.0",
        "--port",
        "8814",
        "--path",
        "/fortigate-mcp",
        "--config",
        "/path/to/your/config.json"
      ],
      "env": {
        "FORTIGATE_MCP_CONFIG": "/path/to/your/config.json"
      }
    }
  }
}
```

#### Option 2: URL Connection (Recommended)

```json
{
  "mcpServers": {
    "FortiGateMCP": {
      "url": "http://0.0.0.0:8814/fortigate-mcp/",
      "transport": "http"
    }
  }
}
```

### 2. Using in Cursor

To use FortiGate MCP in Cursor:

1. **Start the server:**
```bash
cd /media/workspace/fortigate-mcp-server
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --path /fortigate-mcp --config config/config.json
```

2. **Restart Cursor**
3. **Ensure MCP server is running**
4. **Use FortiGate commands in Cursor**

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
# Run all unit tests (default)
python -m pytest

# Run with coverage
python -m pytest --cov=src --cov-report=html

# Run specific test categories
python -m pytest tests/test_device_manager.py
python -m pytest tests/test_fortigate_api.py
python -m pytest tests/test_tools.py

# Run integration tests (requires server running)
python integration_tests.py

# Run only unit tests (default)
python -m pytest tests/

# Run with verbose output
python -m pytest -v

# Run with detailed error information
python -m pytest --tb=long
```

### Test Categories

- **Unit Tests**: Test individual components and functions
- **Integration Tests**: Test HTTP server functionality (requires server running)
- **Coverage**: Code coverage reporting with HTML output

### HTTP Server Test

```bash
# Run test script
python test_http_server.py
```

### Manual Testing

```bash
# Health check
curl -X POST http://localhost:8814/fortigate-mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "health", "params": {}}'

# List devices
curl -X POST http://localhost:8814/fortigate-mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "list_devices", "params": {}}'
```

## 📁 Project Structure

```
fortigate-mcp-server/
├── src/
│   └── fortigate_mcp/
│       ├── __init__.py
│       ├── server_http.py          # HTTP MCP server
│       ├── config/                 # Configuration management
│       ├── core/                   # Core components
│       ├── tools/                  # MCP tools
│       └── formatting/             # Response formatting
├── config/
│   ├── config.json                # Main configuration
│   └── config.example.json        # Example configuration
├── examples/
│   └── cursor_mcp_config.json     # Cursor MCP config
├── logs/                          # Log files
├── tests/                         # Test files
├── docker-compose.yml             # Docker compose
├── Dockerfile                     # Docker image
├── start_http_server.sh           # Startup script
├── test_http_server.py            # Test script
└── README.md                      # This file
```

## 🔍 Troubleshooting

### Common Issues

1. **Connection Error**
   - Ensure FortiGate device is accessible
   - Verify API token or username/password
   - Use `verify_ssl: false` for SSL certificate issues

2. **Port Conflict**
   - Ensure port 8814 is available
   - Change port using `--port` parameter

3. **Configuration Error**
   - Ensure `config.json` is properly formatted
   - Check JSON syntax

4. **Cursor MCP Connection Issue**
   - Ensure server is running
   - Verify URL is correct
   - Restart Cursor

### Logs

Check logs using:

```bash
# HTTP server logs
tail -f logs/fortigate_mcp.log

# Docker logs
docker-compose logs -f fortigate-mcp-server
```

## 🔒 Security

### Recommendations

1. **Use API Tokens**
   - Use API tokens instead of username/password
   - Store tokens securely

2. **SSL Certificate**
   - Use SSL certificates in production
   - Set `verify_ssl: true`

3. **Network Security**
   - Run MCP server only on secure networks
   - Restrict access with firewall rules

4. **Rate Limiting**
   - Enable rate limiting
   - Limit API calls

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
- [Cursor](https://cursor.sh/) - For MCP support

## 📞 Support

For issues:
- Use the [Issues](https://github.com/your-repo/issues) page
- Check the documentation
- Review the logs

---

**Note**: This project has been tested with FortiGate devices. Please perform comprehensive testing before using in production.
