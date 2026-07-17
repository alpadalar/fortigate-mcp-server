# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-17

First public release.

### Added

- Canonical per-tool risk classification (`RISK_CLASSIFICATION`) and a dispatch-layer
  read-only gate for write/destructive MCP tools (SEC-01/SEC-02)
- Shared MCP tool registry (`registry.py`) consolidating stdio and HTTP tool registration
  into a single source of truth (CONS-01)
- respx-based mock HTTP test harness for `FortiGateAPI` boundary tests (CONS-03)
- Live end-to-end test harness exercising the real ASGI app over a pre-bound socket (CONS-02)
- Golden MCP tool-surface schema snapshot freezing tool name and parameter schema across both
  transports (STAB-04)
- Pure-ASGI Bearer-token authentication middleware for the HTTP transport (SEC-05)
- Centralized host/port/vdom/identifier validators applied at every REST call site
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and GitHub issue/PR templates
- Four verified MCP client configuration examples: Claude Desktop (stdio and HTTP), Claude
  Code, and Cursor

### Changed

- `FortiGateDeviceConfig.verify_ssl` now defaults to `true` for devices loaded from a config
  file (SEC-04)
- `mcp` and `fastmcp` dependencies pinned to verified PyPI release bands
  (`mcp>=1.23.0,<2.0`, `fastmcp>=2.11,<3`)
- The stdio server now shares one tool registry with the HTTP server instead of duplicating
  ~30 hand-written tool registrations
- README.md and HTTP_MCP_GUIDE.md rewritten to describe only verified, evidence-based
  behavior (uv-first install, loopback-bind guidance for unauthenticated HTTP, no unverified
  claims)
- pytest configuration consolidated entirely into `pyproject.toml`; coverage gate calibrated
  to a real measured baseline

### Fixed

- The stdio server's async/sync tool-registration mismatch, where awaiting synchronous tool
  methods raised `TypeError` at call time
- Dict-vs-individual-field parameter signature drift on the three create-tools
  (`create_address_object`, `create_service_object`, `create_static_route`)
- A broken package entry point (`pyproject.toml` referenced a non-existent `src.main:main`)
- The Dockerfile's stale `COPY pytest.ini .` line, which broke `docker build` after
  `pytest.ini` was deleted
- A `.dockerignore` gap that allowed the gitignored, secrets-bearing `config/config.json` to
  be copied into built Docker images

### Security

- Bearer-token HTTP authentication enforcement with constant-time token comparison (SEC-05)
- Token and password redaction in logs via a handler-level log filter (CONF-03)
- TLS certificate verification enabled by default for config-loaded devices (SEC-04)
- Dispatch-layer read-only gate: write and destructive MCP tools are rejected unless
  explicitly enabled via `server.allow_writes` or `FORTIGATE_MCP_ALLOW_WRITES` (SEC-01)
