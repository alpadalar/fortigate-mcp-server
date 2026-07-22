# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Four GitHub Actions workflows (`test.yml`, `lint.yml`, `security.yml`, `release.yml`),
  each with every `uses:` action pinned to a live-verified 40-character commit SHA and
  each proven hosted-green with a real run on `origin/main` (CI-01, CI-02, CI-03, CI-04)
- A tag-safe release/publish workflow (`release.yml`) that gates GHCR's `:latest` tag on
  the actual triggering event (`flavor: latest=auto` only on real tag pushes, never on
  `workflow_dispatch`), proven via a hosted dry run on both trigger paths before any real
  semver tag was ever pushed (CI-05)
- Four HTTP-200-verified README badges (Test, Lint, Security, Release), added only after
  each referenced workflow had a real hosted-green (or hosted-verified dry-run, for
  `release.yml`) run, with a hygiene test guarding that every badge references a workflow
  file that actually exists on disk (CI-06)

### Changed

- `ruff` added as a pinned lint dependency and calibrated clean against its built-in
  default rule set across `src/` and `tests/`; `mypy src/` now exits 0 under the
  pre-existing strict `[tool.mypy]` config, with zero strictness dialed back (CI-02)
- Dockerfile now installs via `uv sync --locked --no-dev --no-editable` instead of an
  unlocked `uv pip install --system -e .`, so the built image's dependency graph is
  byte-identical to the audited `uv.lock` (CI-05)

### Security

- `fastmcp` dependency ceiling raised from `>=2.11,<3` to `>=3.2.0` (resolved 3.4.0),
  remediating CVE-2026-32871 (GHSA-vv7q-7jx5-f767, `OpenAPIProvider` SSRF/path-traversal).
  The full local test suite (469 tests) and the byte-frozen golden MCP tool-schema
  snapshot both pass unchanged on the new version (CI-03)

## [1.0.0] - Pending (not yet tagged)

Prepared for the first public release. This version has been assembled and
tested on `main` but no `v1.0.0` git tag has been pushed yet, and no image
has been published to GHCR under this version -- tagging is a separate,
deliberate operator decision (a `v*` tag triggers the production release
workflow). The content below reflects what is ready to ship once that tag
is pushed.

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

### Removed

- The undocumented optional nginx reverse-proxy profile in `docker-compose.yml` (and its
  `nginx/nginx.conf`): when activated, it published ports 80/443 on all host interfaces and
  proxied straight to the default-unauthenticated MCP backend over the internal Docker
  network, bypassing the compose file's loopback-only publish; its TLS server block was
  entirely commented out and no release document referenced the profile. A repository
  hygiene test now requires every compose publish spec to bind 127.0.0.1.

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
- FortiGate API token rotated on the live device (Plan 05-01, primary mitigation); the
  dangling pre-rotation commits, kept alive only by leftover filter-branch backup refs, were
  removed from local git history via refs/original cleanup and git gc (Plan 05-04, secondary
  hygiene), without ever fetching from or altering origin/main (REL-06). GitHub's server-side
  cache of the pre-rotation commit may still resolve it by direct SHA indefinitely (documented,
  accepted residual risk).
