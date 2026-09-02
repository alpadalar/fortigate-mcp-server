# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | :white_check_mark: |

This project follows a **latest-only** support policy: only the most recent `1.0.x` release
line receives security fixes. There is no LTS or backport commitment.

## Reporting a Vulnerability

Please report security vulnerabilities using **GitHub Private Vulnerability Reporting**
(the Security Advisories tab):

https://github.com/alpadalar/fortigate-mcp-server/security/advisories/new

**Do not open a public GitHub issue for security reports.** Private Vulnerability Reporting
lets you share details, proof-of-concept steps, and affected versions with the maintainer
privately, so a fix can be prepared and coordinated before the report becomes visible to
other users.

We will acknowledge new reports and work with you on remediation and disclosure timing.

## What Can This Server Do To Your Firewall

This MCP server exposes **34 unique tools**, registered as **63 total tool-surface
registrations across the stdio (31 tools) and HTTP (32 tools) transports** (three
create-tools — `create_address_object`, `create_service_object`, `create_static_route` —
have transport-specific parameter shapes and are therefore counted once per transport; every
other tool name is schema-identical across both transports). Each tool operates against
whichever FortiGate device(s) are registered with this server — via `config/config.json` at
startup, or via the `add_device` tool at runtime — using the credentials configured for that
device. This server has no independent authorization model of its own beyond what a
device's own FortiGate account already permits.

Depending on which tools an MCP client (or the human directing it) chooses to invoke, and
whether write/destructive tools are enabled (see "Implemented Security Controls" below),
this server can read firewall configuration and device status, and can create, modify, or
delete firewall policies, address objects, service objects, static routes, and virtual IPs
on any registered device. Treat any MCP client with access to this server as having the same
operational capability as a human operator holding the configured FortiGate account's
permissions.

### Tool Risk Classification
| Tool | Risk |
|---|---|
| `list_devices` | read |
| `get_device_status` | read |
| `test_device_connection` | read |
| `discover_vdoms` | read |
| `list_firewall_policies` | read |
| `get_firewall_policy_detail` | read |
| `list_address_objects` | read |
| `list_service_objects` | read |
| `list_static_routes` | read |
| `get_routing_table` | read |
| `list_interfaces` | read |
| `get_interface_status` | read |
| `list_dhcp_leases` | read |
| `get_static_route_detail` | read |
| `list_virtual_ips` | read |
| `get_virtual_ip_detail` | read |
| `health_check` | read |
| `get_server_info` | read |
| `test_connection` | read |
| `health` | read |
| `get_schema_info` | read |
| `add_device` | write |
| `create_firewall_policy` | write |
| `update_firewall_policy` | write |
| `create_address_object` | write |
| `create_service_object` | write |
| `update_static_route` | write |
| `create_static_route` | write |
| `create_virtual_ip` | write |
| `update_virtual_ip` | write |
| `remove_device` | destructive |
| `delete_firewall_policy` | destructive |
| `delete_static_route` | destructive |
| `delete_virtual_ip` | destructive |

**Read-only tools** (20) only retrieve information — device status, firewall policies,
address/service objects, routes, interfaces, virtual IPs, and server health/schema data.
They never modify FortiGate device state and are never subject to the write gate described
below.

**Write tools** (9) create new objects (policies, address/service objects, routes, virtual
IPs, or a newly-registered device) or modify existing ones on the target FortiGate device.
They are rejected by default unless the write gate is explicitly enabled (see below).

**Destructive tools** (4) permanently remove objects from the target device or unregister a
device from this server's in-memory registry (`remove_device`, and the `delete_*` tools).
Like write tools, they are rejected by default unless the write gate is explicitly enabled.

## Implemented Security Controls

**Dispatch-layer read-only gate (SEC-01).** Every write and destructive tool is wrapped by
`registry.py`'s `_gate()` helper at registration time. Unless `server.allow_writes=true` in
the loaded config, or the `FORTIGATE_MCP_ALLOW_WRITES=1` environment variable is set, calling
any write/destructive tool raises a protocol-level `ToolError` (`CallToolResult.is_error=True`)
instead of touching the device — this server ships **read-only by default**.

**TLS certificate verification (SEC-04).** `FortiGateDeviceConfig.verify_ssl` defaults to
`true` for every device loaded from a config file: config-file-loaded devices verify the
target FortiGate's TLS certificate unless an operator explicitly opts out per device. See
"Known Security Limitations" below for a documented exception on the `add_device` MCP tool.

**Bearer-token authentication (SEC-05).** When `auth.require_auth=true` in the loaded
config, the pure-ASGI `AuthMiddleware` (`middleware/auth.py`) enforces that every HTTP
request carries a valid `Authorization: Bearer <token>` header matching one of
`auth.api_tokens`, using constant-time comparison (`hmac.compare_digest`) against every
configured token so match position never leaks via timing. `require_auth` defaults to
`false` (unauthenticated by default) — run the HTTP transport only on trusted networks when
authentication is disabled. `GET`/`HEAD /health` stays token-exempt even when
`require_auth=true`, so liveness probes keep working without a token.

**Secrets are never logged in cleartext.** Device passwords, API tokens, and HTTP bearer
tokens are stored as Pydantic `SecretStr` fields (never printed by `repr()`/`model_dump()`),
**and** a handler-level `TokenRedactionFilter` (`core/logging.py`) actively scrubs every
registered secret value out of rendered log messages and exception tracebacks before they
reach any console or file handler — the type alone does not guarantee redaction; the filter
is what actually enforces it at the point log records are written.

**Network exposure guidance.** Unauthenticated HTTP is this server's default mode
(`auth.require_auth=false`). In that mode, bind the HTTP transport to `127.0.0.1` (loopback)
only — never expose an unauthenticated server on `0.0.0.0` or any routable interface.
Binding to `0.0.0.0` for wider network access requires first enabling Bearer authentication
(`auth.require_auth=true` with at least one configured `auth.api_tokens` entry), plus
network-level controls (firewall rules, a VPN, or a reverse-proxy allowlist) as
defense-in-depth on top of application-level auth.

## Known Security Limitations

**`add_device` runtime TLS verification exception (accepted, byte-frozen contract).** The
`add_device` MCP tool's `verify_ssl` parameter keeps a schema default of `false` — the
opposite of the config-file default described above — because the MCP tool surface (tool
names and parameter schemas) is a byte-frozen contract for this release line
(`tests/fixtures/tool_schemas_stdio.json` / `tool_schemas_http.json`, golden-guarded), and
changing that parameter's default would alter the generated `inputSchema` and break the
golden snapshot. **What this means in practice:** a device added at runtime via `add_device`
without explicitly passing `verify_ssl=true` is connected to with TLS certificate
verification **disabled**. **How to mitigate:** operators and MCP clients must always pass
`verify_ssl=true` explicitly when calling `add_device` if TLS verification is required for
that device. Devices loaded from `config/config.json` at startup are unaffected — they
default to `verify_ssl=true` already. This exception will be revisited only as part of a
future major version that is allowed to change the tool parameter schema.

**Rate limiting is parsed but not enforced.** `rate_limiting.enabled` and related
`RateLimitConfig` fields are parsed from configuration and validated, but no code path in
this codebase actually checks or enforces them. Do not rely on rate limiting as a working
control in this release line.

**CORS is parsed but not applied.** `auth.allowed_origins` is parsed from configuration, but
no CORS middleware exists anywhere in this codebase — the setting currently has no effect.

**Runtime-added devices are not persisted.** Devices registered at runtime via the
`add_device` MCP tool exist only in this process's in-memory registry
(`FortiGateManager.devices`) and are lost on restart; they are never written back to
`config/config.json`.
