"""Live end-to-end HTTP harness proving the ``build_http_app`` factory seam
(CONS-02).

Three independent proofs:

1. Behavioral middleware proof -- a real HTTP response served over a real
   TCP socket on 127.0.0.1 carries ``X-FortiGate-MCP-Trace``.
2. Structural middleware proof on THE SERVED APP -- ``TraceMiddleware`` sits
   in the ``user_middleware`` list of the EXACT app object the fixture
   handed to uvicorn (the yielded ``app``), never a second, freshly
   constructed factory product.
3. Real MCP protocol E2E -- a ``fastmcp.Client`` completes a full session
   (initialize + ``tools/list`` + a harmless ``tools/call``) against the
   live ``/fortigate-mcp`` mount, proving the manually-assembled MCP mount,
   lifespan, and session manager all survived the ``run()`` refactor.

``run()``'s delegation to the factory is proven separately and behaviorally
via monkeypatching -- replacing brittle source-string inspection with a
captured-argument assertion.
"""

import asyncio
import signal

import httpx
import uvicorn
from fastmcp import Client
from unittest.mock import patch

from src.fortigate_mcp.middleware.trace import TraceMiddleware
from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer


def test_health_route_returns_200(live_server):
    """The live /health route (registered before the factory builds the
    app) responds 200 over a real socket."""
    base_url, _server, _app = live_server
    response = httpx.get(base_url + "/health", timeout=5, trust_env=False)
    assert response.status_code == 200


def test_trace_header_present_on_served_app(live_server):
    """THE live behavioral proof: TraceMiddleware, registered inside the
    factory, actually executes on the served app and stamps every HTTP
    response -- not just a unit-tested ASGI callable in isolation."""
    base_url, _server, _app = live_server
    response = httpx.get(base_url + "/health", timeout=5, trust_env=False)
    assert response.headers.get("X-FortiGate-MCP-Trace") == "build_http_app"


def test_trace_middleware_class_present_on_the_served_app(live_server):
    """Structural proof on THE SERVED instance: never call the factory
    again here -- that would construct a second app and reopen the drift
    blind spot this phase exists to close. Inspect the exact object the
    fixture already handed to uvicorn."""
    _base_url, _server, app = live_server
    middleware_classes = [m.cls for m in app.user_middleware]
    assert TraceMiddleware in middleware_classes


async def _mcp_session_probe(base_url):
    """Drive a real MCP protocol session over streamable HTTP against the
    live /fortigate-mcp mount. Trailing slash matches fastmcp's mount
    convention; the client follows any 307 redirect from the non-slash
    form."""
    async with Client(f"{base_url}/fortigate-mcp/") as client:
        tools = await client.list_tools()
        result = await client.call_tool("list_devices", {})
        return tools, result


def test_mcp_protocol_session_against_live_server(live_server):
    """/health alone cannot prove the manually assembled MCP mount,
    lifespan, and session manager survived the manual-uvicorn run()
    refactor. A real fastmcp.Client session -- session initialize,
    tools/list, and one harmless tools/call -- exercises that entire path
    end-to-end."""
    base_url, _server, _app = live_server
    tools, result = asyncio.run(_mcp_session_probe(base_url))
    assert len(tools) == 35
    assert "default" in result.content[0].text


def test_unauthenticated_request_denied_with_trace_header_on_401(live_server_auth_required):
    """The live ordering proof: TraceMiddleware (outermost) still stamps
    the trace header on a 401 produced by AuthMiddleware (inner), and the
    denial body never contains the configured token."""
    base_url, _server, _app = live_server_auth_required
    response = httpx.get(base_url + "/fortigate-mcp/", timeout=5, trust_env=False)
    assert response.status_code == 401
    assert "e2e-test-token-not-real" not in response.text
    assert response.headers.get("X-FortiGate-MCP-Trace") == "build_http_app"


def test_wrong_token_denied_on_live_server(live_server_auth_required):
    """A wrong non-empty Bearer token is rejected 401 by the real served app."""
    base_url, _server, _app = live_server_auth_required
    response = httpx.get(
        base_url + "/fortigate-mcp/",
        timeout=5,
        trust_env=False,
        headers={"Authorization": "Bearer wrong-token-not-real"},
    )
    assert response.status_code == 401


def test_health_remains_reachable_without_token_when_auth_required(live_server_auth_required):
    """GET /health stays token-exempt even on a require_auth=True live server."""
    base_url, _server, _app = live_server_auth_required
    response = httpx.get(base_url + "/health", timeout=5, trust_env=False)
    assert response.status_code == 200


async def _mcp_session_probe_with_auth(base_url):
    """Same protocol probe as ``_mcp_session_probe``, but authenticated:
    passing a plain str for ``auth`` wraps it in fastmcp's BearerAuth
    automatically (verified live this session against
    fastmcp/client/transports.py's ``_set_auth``)."""
    async with Client(
        f"{base_url}/fortigate-mcp/", auth="e2e-test-token-not-real"
    ) as client:
        tools = await client.list_tools()
        result = await client.call_tool("list_devices", {})
        return tools, result


def test_mcp_protocol_session_with_bearer_token_against_live_server(
    live_server_auth_required,
):
    """A real fastmcp.Client session with the correct Bearer token
    completes tools/list and a tools/call against the require_auth=True
    live server."""
    base_url, _server, _app = live_server_auth_required
    tools, result = asyncio.run(_mcp_session_probe_with_auth(base_url))
    assert len(tools) == 35
    assert "default" in result.content[0].text


def test_run_serves_the_factory_app(tmp_config_path, monkeypatch):
    """Behavioral run()-delegation proof, replacing brittle source-string
    inspection: monkeypatch build_http_app() to a sentinel and uvicorn to
    capture what it is constructed with, then prove run() passes the
    factory's exact return value through, unmodified."""
    with patch.object(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None):
        server = FortiGateMCPHTTPServer(
            config_path=tmp_config_path,
            host="127.0.0.1",
            port=0,
            path="/fortigate-mcp",
        )

    sentinel = object()
    monkeypatch.setattr(server, "build_http_app", lambda: sentinel)

    captured = {}

    class _FakeConfig:
        def __init__(self, app, **kwargs):
            captured["app"] = app

    class _FakeServer:
        def __init__(self, config):
            pass

        def run(self):
            captured["ran"] = True

    monkeypatch.setattr(uvicorn, "Config", _FakeConfig)
    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    # run() installs SIGINT/SIGTERM handlers -- neutralize so this test does
    # not mutate global process signal-handler state.
    monkeypatch.setattr(signal, "signal", lambda *a, **k: None)

    server.run()

    assert captured["app"] is sentinel
    assert captured.get("ran") is True
