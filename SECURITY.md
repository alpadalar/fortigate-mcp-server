# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x: |

This project follows a **latest-only** support policy: only the most recent `1.2.x` release
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

This MCP server exposes **50 unique tools**, registered as **95 total tool-surface
registrations across the stdio (47 tools) and HTTP (48 tools) transports** (three
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
| `get_static_route_detail` | read |
| `list_virtual_ips` | read |
| `get_virtual_ip_detail` | read |
| `health_check` | read |
| `get_server_info` | read |
| `test_connection` | read |
| `health` | read |
| `get_schema_info` | read |
| `list_security_profiles` | read |
| `list_admins` | read |
| `get_sslvpn_settings` | read |
| `list_local_in_policies` | read |
| `list_address_groups` | read |
| `list_service_groups` | read |
| `list_schedules` | read |
| `list_ip_pools` | read |
| `list_central_snat_maps` | read |
| `get_system_resources` | read |
| `get_license_status` | read |
| `get_ha_status` | read |
| `get_arp_table` | read |
| `list_dhcp_leases` | read |
| `get_ipsec_tunnel_status` | read |
| `list_firewall_sessions` | read |
| `analyze_policy_hygiene` | read |
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

**Read-only tools** (37) only retrieve information — device status, firewall policies,
address/service objects, routes, interfaces, virtual IPs, server health/schema data, and the
v1.1 visibility additions (security profiles, admin accounts, SSL-VPN settings, local-in
policies) and the v1.2 additions (address/service groups, schedules, IP pools,
central SNAT maps, system resources, license status, HA status, ARP table, DHCP leases,
IPsec tunnel status, firewall sessions, policy hygiene analysis). They never modify FortiGate device state and are never subject to the write gate
described below.

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

**API-response secret-field redaction.** Secret-shaped fields in FortiGate API responses —
password hashes, PSKs (`psksecret`/`psksecret-remote`), private keys, numbered
`ssh-public-key*` entries, and SSL-VPN bookmark credentials (`logon-password`,
`sso-password`) — are replaced with a redaction marker by `redact_sensitive_fields`
(`src/fortigate_mcp/validation.py`), a key-name deny-list applied at the Tools layer to
`list_admins` and `get_sslvpn_settings` output before any response text is formatted, and
proven non-vacuously in `tests/test_security_admin_tools.py`. The deny-list is fail-open by
accepted design: only enumerated field names are redacted, so a future FortiOS field with an
unrecognized name would pass through unredacted until the deny-list is extended.

**Network exposure guidance.** Unauthenticated HTTP is this server's default mode
(`auth.require_auth=false`). In that mode, bind the HTTP transport to `127.0.0.1` (loopback)
only — never expose an unauthenticated server on `0.0.0.0` or any routable interface.
Binding to `0.0.0.0` for wider network access requires first enabling Bearer authentication
(`auth.require_auth=true` with at least one configured `auth.api_tokens` entry), plus
network-level controls (firewall rules, a VPN, or a reverse-proxy allowlist) as
defense-in-depth on top of application-level auth.

## Authentication Guidance for FortiGate Devices

**Prefer a REST API token.** Configure each device with `api_token` (a REST API administrator
bound to a restricted `accprofile` and trusted hosts) rather than `username`/`password`.
Tokens are never exchanged for a cookie session, can be scoped and revoked independently, and
are redacted from this server's logs.

**Password/session login is deprecated on FortiOS 7.6+ (unofficial).** Community reports
(unofficial, not confirmed by Fortinet documentation) state that from FortiOS 7.6.3 the
`/logincheck` endpoint no longer returns a usable session cookie, and that password
authentication is deprecated on 7.6.x and later. Treat username/password devices on 7.6+ as
unsupported and use an API token.

**FG-IR-24-268 (FortiOS 7.4.0-7.4.3).** Fortinet PSIRT advisory FG-IR-24-268 ("Insertion of
sensitive information into log file") describes API token exposure in REST API logs on
FortiOS 7.4.0 through 7.4.3, fixed in 7.4.4 and later. Run a fixed FortiOS release on any
device this server connects to with an API token. This is a FortiOS issue, not a defect of
this server.

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

**`list_admins` output is reconnaissance-sensitive on unauthenticated HTTP.** Admin account
names, `accprofile`, and trusted-host scope — even with secret fields (password hash, PSK,
private keys) redacted — are useful to an attacker profiling this server's operator surface,
since they reveal who administers the target FortiGate and how broadly each account is
scoped. This is an accepted-posture advisory, not a defect: secret-shaped fields
(password hashes, PSKs, private keys, SSH public keys) are stripped from `list_admins` and
`get_sslvpn_settings` responses by the Tools layer's `redact_sensitive_fields` before any
output is formatted (see "API-response secret-field redaction" under Implemented Security
Controls above; `src/fortigate_mcp/validation.py`, proven in
`tests/test_security_admin_tools.py`). **How to
mitigate:** set `auth.require_auth=true` (with at least one configured `auth.api_tokens`
entry) before binding the HTTP transport to any non-loopback interface.

**ARP, DHCP-lease, and HA-status output is network-reconnaissance-sensitive.** `get_arp_table`,
`list_dhcp_leases`, and `get_ha_status` expose MAC addresses, client hostnames/IPs, and HA peer
serial numbers and hostnames, which map the internal network for an attacker. This is an
accepted-posture advisory (same as `list_admins`), not a defect. `list_firewall_sessions`
(live source/destination IPs; capped at 200, default 20) and `analyze_policy_hygiene` (policy and
object names) are in the same class, and `get_ipsec_tunnel_status` never returns pre-shared keys.
The ARP, DHCP and session tools are output-capped. The HTTP transport is unauthenticated by default (`auth.require_auth=false`):
set `auth.require_auth=true` (with at least one `auth.api_tokens` entry) or keep the bind on
loopback before exposing it. The Phase 15 monitor/cmdb response shapes are validated against
fixtures only; live-device verification items are tracked for the release checklist.
