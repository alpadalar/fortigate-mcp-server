# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FortiGate MCP Server is a Model Context Protocol (MCP) server for managing FortiGate firewall devices, FortiManager, and FortiAnalyzer. It exposes FortiGate/FortiManager/FortiAnalyzer REST API operations as MCP tools for integration with AI assistants and automation systems like Cursor IDE.

## Common Commands

```bash
# Install dependencies (using uv - recommended)
uv sync
uv sync --extra dev    # Include dev dependencies

# Or with pip
pip install -e ".[dev]"

# Run tests
python -m pytest                           # All tests with coverage
python -m pytest tests/test_tools.py       # Single test file
python -m pytest -k "test_list_devices"    # Single test by name
python -m pytest --no-cov                  # Skip coverage
python -m pytest -m unit                   # Only unit tests
python -m pytest -m integration            # Only integration tests

# Linting
black src tests                            # Format code
isort src tests                            # Sort imports
flake8 src tests                           # Lint
mypy src                                   # Type check

# Start server
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --config config/config.json

# Integration tests (requires running server)
python integration_tests.py

# Docker
docker-compose up -d
```

## Architecture

### Server Layer
Two server implementations share the same tool infrastructure:
- `server.py` - STDIO transport for CLI/pipe integration, uses `mcp.run_stdio_async()`
- `server_http.py` - HTTP transport for web integration, uses `mcp.run(transport="http")`

Both instantiate `FortiGateMCPServer`/`FortiGateMCPHTTPServer` which:
1. Loads config via `config/loader.py` → validates with Pydantic models in `config/models.py`
2. Creates `FortiGateManager` with configured devices
3. Creates `FortiManagerManager` for FortiManager integration (dynamic registration)
4. Creates `FortiAnalyzerManager` for FortiAnalyzer integration (dynamic registration)
5. Instantiates tool classes (`DeviceTools`, `FirewallTools`, `FortiAnalyzerTools`, etc.)
6. Registers MCP tools via `@self.mcp.tool()` decorators

### Core Layer (`core/`)
- `FortiGateManager` - Multi-device manager, maintains dict of `FortiGateAPI` instances by device_id
- `FortiGateAPI` - Single device client, wraps all FortiGate REST API calls via `_make_request()`
- `FortiManagerManager` / `FortiManagerAPI` - FortiManager JSON-RPC client for central management
- `FortiAnalyzerManager` / `FortiAnalyzerAPI` - FortiAnalyzer JSON-RPC client for log/analytics
- `ACMEClient` - Let's Encrypt certificate management via ACME protocol
- `CloudflareDNS` - DNS-01 challenge handler for ACME via Cloudflare API
- FortiGate API base URL pattern: `https://{host}:{port}/api/v2/{endpoint}`
- FortiManager/FortiAnalyzer API base URL: `https://{host}:{port}/jsonrpc`
- Auth: Bearer token (`api_token`) or Basic auth (`username/password`)

### Tools Layer (`tools/`)
All FortiGate tools inherit from `FortiGateTool` base class which provides:
- `_get_device_api(device_id)` - Get API client for device
- `_format_response(data, resource_type)` - Format API responses via `FortiGateFormatters`
- `_handle_error(operation, device_id, error)` - Standardized error handling with HTTP status code mapping
- `_execute_with_logging()` - Async execution wrapper with timing

Tool categories map to FortiGate API endpoints:
| Tool Class | API Endpoints |
|------------|---------------|
| `DeviceTools` | `monitor/system/status`, `cmdb/system/vdom` |
| `FirewallTools` | `cmdb/firewall/policy` |
| `NetworkTools` | `cmdb/firewall/address`, `cmdb/firewall.service/custom` |
| `RoutingTools` | `cmdb/router/static`, `monitor/router/ipv4` |
| `VirtualIPTools` | `cmdb/firewall/vip` |
| `CertificateTools` | `cmdb/certificate/local`, `cmdb/certificate/ca`, `cmdb/certificate/remote`, `cmdb/certificate/crl` |
| `FabricTools` | Security Fabric topology, HA cluster status, SDN connectors |
| `ACMETools` | Let's Encrypt certificate automation via DNS-01 challenge |
| `PacketCaptureTools` | SSH-based `diagnose sniffer packet` CLI command for packet capture |
| `FortiManagerTools` | Central device/policy management (uses `FortiManagerTool` base class) |
| `FortiAnalyzerTools` | Log search, reports, FortiView analytics, alerts (uses `FortiAnalyzerTool` base class) |

### Device Name Resolution
The base class supports device name aliases via `DEVICE_NAME_MAP` in `tools/base.py`. Users can reference devices by friendly name (e.g., "NLFMFW1A") instead of device_id (e.g., "default"). Resolution is case-insensitive.

### Configuration
Config is loaded from JSON file specified by `--config` flag or `FORTIGATE_MCP_CONFIG` env var.
Root model: `Config` in `config/models.py` containing:
- `server` - Host/port/name
- `fortigate.devices` - Dict of `FortiGateDeviceConfig` keyed by device_id
- `fortimanager` - FortiManager connection config (optional)
- `acme` - ACME/Let's Encrypt settings (optional)
- `auth` - MCP server auth (not FortiGate auth)
- `logging` - Log level/format/file
- `rate_limiting` - Request throttling

### Environment Variables
- `FORTIGATE_MCP_CONFIG` - Path to config file
- `CLOUDFLARE_API_TOKEN` - Cloudflare API token for ACME DNS-01 challenges
- `ACME_EMAIL` - Contact email for Let's Encrypt account
- `ACME_ACCOUNT_KEY_PATH` - Path to ACME account key (defaults to `~/.acme/account.key`)

### Response Formatting (`formatting/`)
`FortiGateFormatters` class provides specialized formatters for each resource type, converting API responses to human-readable MCP `TextContent` objects.

## Key Patterns

- All device operations require `device_id` parameter to select which FortiGate to target
- Optional `vdom` parameter on most operations (defaults to device's configured vdom)
- HTTP server tests device connections on startup via `_test_initial_connection()`
- Tool descriptions in `tools/definitions.py` are used for MCP tool registration
- FortiManager tools use separate `FortiManagerTool` base class with `FortiManagerManager`
- FortiAnalyzer tools use separate `FortiAnalyzerTool` base class with `FortiAnalyzerManager`

## FortiGate REST API Reference

The server wraps FortiGate's REST API v2. Key endpoint patterns:

| Type | URL Pattern | Purpose |
|------|-------------|---------|
| CMDB | `/api/v2/cmdb/{section}/{subsection}` | Configuration (CRUD operations) |
| Monitor | `/api/v2/monitor/{section}/{subsection}` | Runtime data and statistics |

Common CMDB paths used by this server:
- `firewall/policy` - Firewall rules
- `firewall/address` - Address objects
- `firewall.service/custom` - Service objects
- `router/static` - Static routes
- `firewall/vip` - Virtual IPs
- `system/interface` - Network interfaces
- `system/vdom` - Virtual domains
- `certificate/local` - Local/device certificates
- `certificate/ca` - CA certificates
- `certificate/remote` - Remote certificates
- `certificate/crl` - Certificate revocation lists
- `system/csf` - Security Fabric configuration
- `system/sniffer` - Packet capture profiles

Monitor paths for packet capture:
- `monitor/system/sniffer` - Capture status
- `monitor/system/sniffer/start` - Start capture
- `monitor/system/sniffer/stop` - Stop capture
- `monitor/system/sniffer/download` - Download PCAP
- `monitor/system/sniffer/clear` - Clear captured packets

All requests include `?vdom={vdom}` query parameter.

## Packet Capture (SSH-based)

The `capture_and_analyze` tool uses SSH to run the FortiGate CLI command `diagnose sniffer packet`:

**Why SSH?** The REST API packet capture endpoints (`monitor/system/sniffer`) are not available on all FortiGate versions. SSH provides reliable access across all versions.

**How it works:**
1. Connects to FortiGate via SSH using device credentials (username/password required)
2. Executes `diagnose sniffer packet <interface> '<filter>' <verbose> <count> <timestamp>`
3. Captures output for configurable duration (default: 2 minutes)
4. Saves raw sniffer output to temp file (e.g., `/tmp/fortigate_sniffer_default_xxx.txt`)
5. Parses output to extract unique IPs, protocols, and packet statistics

**Configuration:**
- Device config must include `username` and `password` for SSH access
- Optional `ssh_port` in device config (default: 22)
- Requires `paramiko` package: `pip install paramiko`

**Verbosity levels:**
- 1 = packet headers
- 2 = headers + IP data
- 3 = headers + Ethernet data
- 4 = headers with interface name (default)
- 5 = headers + IP data with interface name
- 6 = headers + Ethernet data with interface name

**BPF-style filters supported:**
- `host <ip>` - match source or destination IP
- `src host <ip>` - match source IP
- `dst host <ip>` - match destination IP
- `port <port>` - match source or destination port
- `tcp`, `udp`, `icmp` - protocol filters
- Multiple filters combined with "and"

## FortiAnalyzer Integration

FortiAnalyzer uses the same JSON-RPC API pattern as FortiManager. Instances are registered dynamically at runtime (not via config file).

### Dynamic Registration

```python
# Register a FortiAnalyzer instance via MCP tool
faz_add_analyzer(
    analyzer_id="faz1",
    host="192.168.1.100",
    api_token="your-api-token",  # or username/password
    adom="root"
)
```

### FortiAnalyzer API Endpoints

All requests go to `https://{host}:{port}/jsonrpc` using JSON-RPC protocol.

| Endpoint | Purpose |
|----------|---------|
| `/sys/login/user` | Session authentication |
| `/sys/logout` | End session |
| `/sys/status` | System status |
| `/dvmdb/adom` | List ADOMs |
| `/dvmdb/adom/{adom}/device` | Devices reporting logs |
| `/logview/adom/{adom}/logsearch` | Search logs |
| `/logview/adom/{adom}/logstats` | Log statistics |
| `/logview/adom/{adom}/logfields/{type}` | Available log fields |
| `/report/adom/{adom}/config/report` | Report templates |
| `/report/adom/{adom}/run` | Execute report |
| `/fortiview/adom/{adom}/{view}/run` | FortiView analytics |
| `/eventmgmt/adom/{adom}/alerts` | Alert management |

### FortiAnalyzer Tools (24 tools)

**Analyzer Management:**
- `faz_list_analyzers` - List registered instances
- `faz_add_analyzer` - Add new instance
- `faz_remove_analyzer` - Remove instance
- `faz_test_connection` - Test connectivity

**System Information:**
- `faz_get_system_status` - System status
- `faz_get_adoms` - List ADOMs

**Device Management:**
- `faz_get_devices` - Devices reporting logs
- `faz_get_device_status` - Device log status

**Log Operations:**
- `faz_search_logs` - Search with filters (traffic, event, security)
- `faz_get_log_stats` - Log volume statistics
- `faz_get_log_fields` - Available fields per log type
- `faz_get_raw_logs` - Raw log data

**Report Operations:**
- `faz_list_reports` - Report templates
- `faz_run_report` - Execute report (async)
- `faz_get_report_status` - Check report progress
- `faz_download_report` - Download completed report

**FortiView Analytics:**
- `faz_get_fortiview` - Dashboard data
- `faz_get_threat_stats` - Threat statistics
- `faz_get_top_sources` - Top traffic sources
- `faz_get_top_destinations` - Top destinations
- `faz_get_top_applications` - Top applications

**Event Management:**
- `faz_get_event_summary` - Event counts
- `faz_list_alerts` - Active alerts
- `faz_acknowledge_alert` - Acknowledge alert

### Time Range Syntax

Log/analytics tools support flexible time ranges:
- Relative: `"1h"`, `"24h"`, `"7d"`, `"30d"`
- Keywords: `"today"`, `"yesterday"`
- Default: last 1 hour

### Log Types

Supported log types for search operations:
- `traffic` - Traffic logs (default)
- `event` - System event logs
- `security` - Security logs (IPS, AV, Web Filter)
- `app-ctrl` - Application control
- `webfilter` - Web filtering
- `ips` - Intrusion prevention
- `virus` - Antivirus

## MCP Protocol Notes

This server implements the Model Context Protocol using FastMCP:
- Tools return `List[TextContent]` (via `mcp.types.TextContent`)
- JSON-RPC 2.0 message format over STDIO or HTTP transport
- Tool schemas auto-generated from Python type annotations and `Field()` descriptions
- Errors returned as `{"isError": true}` in tool results, not protocol-level errors
