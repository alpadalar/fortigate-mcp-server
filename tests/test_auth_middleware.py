"""Unit + wiring tests for ``AuthMiddleware`` (SEC-05).

Covers, against a minimal hand-built Starlette downstream app wrapped
directly in ``AuthMiddleware`` (via ``httpx.ASGITransport``):

- Reject-before-compare: missing/malformed/empty credentials never reach
  ``hmac.compare_digest`` (proven with a counting spy).
- No-short-circuit comparison: every configured token is compared exactly
  once for a non-empty candidate, even when the first token matches.
- Fail-closed filtering of empty/whitespace-only configured tokens.
- Method-scoped GET/HEAD /health exemption (a POST to /health is NOT
  exempt).
- Non-"http" ASGI scope passthrough.
- 401 response bodies never contain a configured token substring.
- ``AuthConfig`` field/model validator invariants (config/models.py).

Test data convention: obviously-fake, "-not-real"-suffixed token literals
only, matching this repo's existing convention (see test_config_strict.py).
"""

import hmac
import json
import os
import tempfile
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.applications import Starlette

from src.fortigate_mcp.config.models import AuthConfig
from src.fortigate_mcp.core import logging as core_logging
from src.fortigate_mcp.middleware import auth as auth_module
from src.fortigate_mcp.middleware.auth import AuthMiddleware
from fastmcp.server.http import RequestContextMiddleware
from src.fortigate_mcp.middleware.trace import TraceMiddleware
from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer


async def _root(request):
    return PlainTextResponse("ok")


async def _health(request):
    return PlainTextResponse("healthy")


def _downstream_app() -> Starlette:
    """Minimal downstream app: "/" and "/health" (multi-method, so a
    non-GET/HEAD /health request that reaches the app would prove the
    method-scoped exemption is broken rather than being masked by a
    405 from the downstream router itself)."""
    return Starlette(
        routes=[
            Route("/", _root, methods=["GET"]),
            Route("/health", _health, methods=["GET", "HEAD", "POST"]),
        ]
    )


def _wrapped_client(api_tokens) -> httpx.AsyncClient:
    app = AuthMiddleware(_downstream_app(), api_tokens=api_tokens)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _spy_compare_digest(monkeypatch):
    """Patch hmac.compare_digest (as seen through the middleware module's
    ``import hmac``) with a call-recording wrapper that still delegates to
    the real implementation, and return the list of recorded calls."""
    calls = []
    real_compare = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(auth_module.hmac, "compare_digest", spy)
    return calls


class TestRejectBeforeCompare:
    async def test_missing_header_denied_without_compare(self, monkeypatch):
        calls = _spy_compare_digest(monkeypatch)
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.get("/")
        assert response.status_code == 401
        assert calls == []

    @pytest.mark.parametrize(
        "header_value",
        ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer    ", "bearerx good-token-not-real"],
    )
    async def test_malformed_header_denied_without_compare(self, monkeypatch, header_value):
        calls = _spy_compare_digest(monkeypatch)
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.get("/", headers={"Authorization": header_value})
        assert response.status_code == 401
        assert calls == []

    async def test_empty_or_whitespace_configured_tokens_deny_without_compare(self, monkeypatch):
        calls = _spy_compare_digest(monkeypatch)
        async with _wrapped_client(["", "   "]) as client:
            no_header = await client.get("/")
            with_header = await client.get(
                "/", headers={"Authorization": "Bearer anything-not-real"}
            )
        assert no_header.status_code == 401
        assert with_header.status_code == 401
        assert calls == []


class TestTokenComparison:
    async def test_correct_token_allows_request(self):
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.get(
                "/", headers={"Authorization": "Bearer good-token-not-real"}
            )
        assert response.status_code == 200
        assert response.text == "ok"

    async def test_wrong_non_empty_token_denied_no_leak(self):
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.get(
                "/", headers={"Authorization": "Bearer wrong-token-not-real"}
            )
        assert response.status_code == 401
        assert "good-token-not-real" not in response.text

    async def test_partial_empty_token_filtered_good_token_still_works(self):
        async with _wrapped_client(["", "good-token-not-real"]) as client:
            no_header = await client.get("/")
            good = await client.get(
                "/", headers={"Authorization": "Bearer good-token-not-real"}
            )
        assert no_header.status_code == 401
        assert good.status_code == 200

    async def test_multi_token_comparison_runs_for_every_token_no_short_circuit(
        self, monkeypatch
    ):
        calls = _spy_compare_digest(monkeypatch)
        tokens = ["good-token-not-real", "second-token-not-real", "third-token-not-real"]
        async with _wrapped_client(tokens) as client:
            response = await client.get(
                "/", headers={"Authorization": "Bearer good-token-not-real"}
            )
        assert response.status_code == 200
        # First token matches, but every configured token is still compared
        # exactly once -- no `any(...)` early-exit.
        assert len(calls) == len(tokens)

    async def test_duplicate_authorization_headers_first_honored(self):
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.get(
                "/",
                headers=[
                    ("Authorization", "Bearer wrong-token-not-real"),
                    ("Authorization", "Bearer good-token-not-real"),
                ],
            )
        assert response.status_code == 401


class TestHealthExemption:
    async def test_health_get_bypasses_auth(self):
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.get("/health")
        assert response.status_code == 200

    async def test_health_head_bypasses_auth(self):
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.head("/health")
        assert response.status_code == 200

    async def test_health_post_does_not_bypass_auth(self):
        async with _wrapped_client(["good-token-not-real"]) as client:
            response = await client.post("/health")
        assert response.status_code == 401


class TestScopePassthrough:
    async def test_non_http_scope_passes_through_untouched(self):
        observed = {}

        async def downstream(scope, receive, send):
            observed["scope_type"] = scope["type"]

        middleware = AuthMiddleware(downstream, api_tokens=["good-token-not-real"])

        async def receive():
            return {"type": "lifespan.startup"}

        async def send(message):
            pass

        await middleware({"type": "lifespan"}, receive, send)
        assert observed["scope_type"] == "lifespan"


class TestAuthConfigValidators:
    def test_rejects_empty_token(self):
        with pytest.raises(ValidationError):
            AuthConfig(require_auth=False, api_tokens=[""])

    def test_rejects_whitespace_only_token(self):
        with pytest.raises(ValidationError):
            AuthConfig(require_auth=False, api_tokens=["   "])

    def test_rejects_control_character_token(self):
        with pytest.raises(ValidationError):
            AuthConfig(require_auth=False, api_tokens=["good-token-not-real\r\n"])

    def test_rejects_require_auth_true_with_no_tokens(self):
        with pytest.raises(ValidationError):
            AuthConfig(require_auth=True, api_tokens=[])

    def test_default_require_auth_false_with_empty_tokens_is_valid(self):
        config = AuthConfig()
        assert config.require_auth is False
        assert config.api_tokens == []

    def test_require_auth_true_with_valid_token_is_valid(self):
        config = AuthConfig(require_auth=True, api_tokens=["good-token-not-real"])
        assert config.require_auth is True
        assert config.api_tokens == ["good-token-not-real"]

    def test_validation_error_never_echoes_token_value(self):
        secret_shaped = "totally-secret-value-not-real"
        with pytest.raises(ValidationError) as excinfo:
            AuthConfig(require_auth=False, api_tokens=[secret_shaped + "\r\n"])
        assert secret_shaped not in str(excinfo.value)


# --- Task 2: build_http_app() wiring proofs against server_http.py itself ---


def _build_http_server(require_auth: bool, api_tokens) -> FortiGateMCPHTTPServer:
    """Construct a real FortiGateMCPHTTPServer with zero socket access,
    mirroring tests/test_tool_schema_snapshot.py::_build_servers's
    tempfile-config + _test_initial_connection no-op patch pattern."""
    config = {
        "server": {"host": "0.0.0.0", "port": 8814, "name": "test", "version": "1.0.0"},
        "fortigate": {
            "devices": {
                "default": {
                    "host": "198.51.100.10",
                    "api_token": "test-token-not-real",
                    "vdom": "root",
                    "verify_ssl": False,
                    "timeout": 1,
                }
            }
        },
        "auth": {
            "require_auth": require_auth,
            "api_tokens": api_tokens,
            "allowed_origins": ["*"],
        },
        "logging": {"level": "INFO", "console": True},
    }
    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="auth_wiring_config_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    try:
        with patch.object(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None):
            return FortiGateMCPHTTPServer(config_path=config_path)
    finally:
        os.unlink(config_path)


class TestBuildHttpAppWiring:
    """Structural proofs against server_http.py's build_http_app() itself.

    Note: fastmcp's own ``http_app()`` unconditionally appends
    ``RequestContextMiddleware`` AFTER whatever list ``build_http_app()``
    passes it (verified live this session against the installed fastmcp
    2.11.3) -- it is not something build_http_app() adds itself. The
    equality assertions below pin the full observed order (our own
    middleware plus fastmcp's own addition) rather than a bare membership
    check, so a regression in EITHER our wiring or fastmcp's own append
    behavior is caught.
    """

    def test_require_auth_true_wires_trace_then_auth_in_order(self):
        server = _build_http_server(True, ["wiring-test-token-not-real"])
        app = server.build_http_app()
        classes = [m.cls for m in app.user_middleware]
        assert classes == [TraceMiddleware, AuthMiddleware, RequestContextMiddleware]

    def test_require_auth_false_wires_trace_only(self):
        server = _build_http_server(False, [])
        app = server.build_http_app()
        classes = [m.cls for m in app.user_middleware]
        assert AuthMiddleware not in classes
        assert classes == [TraceMiddleware, RequestContextMiddleware]

    def test_require_auth_true_registers_token_for_redaction(self):
        _build_http_server(True, ["wiring-test-token-not-real"])
        assert "wiring-test-token-not-real" in core_logging._redaction_filter._secrets
