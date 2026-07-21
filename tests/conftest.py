"""
Pytest configuration and fixtures
"""

import json
import os
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from typing import Optional

import pytest
import asyncio
import httpx
import uvicorn
from unittest.mock import MagicMock, patch

from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig
from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer
from tests.support.fake_fortigate import fortigate_router


@pytest.fixture
def fortigate_manager():
    """FortiGate manager fixture"""
    auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
    devices = {}
    manager = FortiGateManager(devices, auth_config)
    yield manager
    # Cleanup
    manager.devices.clear()


@pytest.fixture
def mock_fortigate_api():
    """Mock FortiGate API fixture"""
    mock_api = MagicMock(spec=FortiGateAPI)
    mock_api.device_id = "test_device"
    
    # Mock config attribute
    mock_config = MagicMock()
    mock_config.host = "192.168.1.1"
    mock_config.vdom = "root"
    mock_api.config = mock_config
    
    mock_api.auth_method = "basic"
    
    # Default return values
    mock_api.get_system_status.return_value = {
        "hostname": "FortiGate",
        "version": "v7.0.0",
        "status": "ok"
    }
    
    mock_api.get_vdoms.return_value = {
        "results": [
            {"name": "root", "enabled": True}
        ]
    }
    
    mock_api.get_interfaces.return_value = {
        "results": [
            {"name": "port1", "status": "up"},
            {"name": "port2", "status": "down"}
        ]
    }
    
    mock_api.get_firewall_policies.return_value = {
        "results": [
            {"policyid": 1, "name": "Allow_HTTP", "action": "accept"}
        ]
    }
    
    mock_api.get_address_objects.return_value = {
        "results": [
            {"name": "test_addr", "subnet": "192.168.1.0/24"}
        ]
    }
    
    mock_api.get_service_objects.return_value = {
        "results": [
            {"name": "HTTP", "tcp-portrange": "80"}
        ]
    }
    
    mock_api.get_static_routes.return_value = {
        "results": [
            {"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}
        ]
    }
    
    mock_api.test_connection.return_value = True
    
    return mock_api


@pytest.fixture
def sample_policy_data():
    """Sample policy data fixture"""
    return {
        "name": "Test_Policy",
        "srcintf": [{"name": "port1"}],
        "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "service": [{"name": "ALL"}],
        "action": "accept",
        "schedule": "always",
        "comments": "Test policy created by pytest"
    }


@pytest.fixture
def sample_address_data():
    """Sample address object data fixture"""
    return {
        "name": "test_address",
        "subnet": "192.168.1.0/24",
        "comments": "Test address object"
    }


@pytest.fixture
def sample_service_data():
    """Sample service object data fixture"""
    return {
        "name": "test_service",
        "protocol": "TCP/UDP/SCTP",
        "tcp-portrange": "8080",
        "comments": "Test service object"
    }


@pytest.fixture
def sample_route_data():
    """Sample static route data fixture"""
    return {
        "dst": "10.0.0.0/8",
        "gateway": "192.168.1.1",
        "device": "port1",
        "comment": "Test static route"
    }


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def tmp_config_path(tmp_path):
    """Temp FORTIGATE_MCP_CONFIG-compatible JSON file for server-construction tests.

    Uses an RFC 5737 TEST-NET-2 address and an obviously-fake token so no
    future contributor mistakes fixture data for a real credential. Timeout
    is kept low (1s, not 30s) so any future network-touching construction
    fails fast against the unroutable TEST-NET-2 address.
    """
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
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
                "auth": {"require_auth": False, "api_tokens": [], "allowed_origins": ["*"]},
                "logging": {"level": "INFO", "console": True},
            }
        )
    )
    yield str(config_file)


# Two supported styles for consuming the respx FortiGate mock harness:
# - `fake_fortigate_router` (below): ACTIVE fixture, enters the router
#   context for the whole test -- use when a single router instance
#   covers the entire test body.
# - `fortigate_router()` called explicitly inside a `with` block: use
#   when per-test scoping (a fresh router per assertion) reads better.
@pytest.fixture
def fake_fortigate_router():
    """Active respx router fixture (calls cleared once context exits)."""
    router = fortigate_router()
    with router:
        yield router


@pytest.fixture
def device_config():
    """Sample device configuration fixture"""
    return FortiGateDeviceConfig(
        host="192.168.1.1",
        username="admin",
        password="password",
        vdom="root",
        verify_ssl=False,
        timeout=30,
        port=443
    )


@contextmanager
def run_live_server(require_auth: bool = False, api_tokens: Optional[list] = None):
    """Serve the EXACT ``build_http_app()`` output over a real 127.0.0.1
    TCP socket, in a daemon thread, and yield ``(base_url, server, app)``.

    Correctness properties this fixture guarantees:

    - TOCTOU port race: the listening socket is bound here, ONCE, and
      handed directly to uvicorn's ``run()`` via its ``sockets`` kwarg --
      no probe-then-rebind window for another process to steal the port.
    - Unverified thread termination: teardown asserts the daemon thread is
      no longer alive after ``should_exit`` + ``join``, instead of merely
      joining and hoping.
    - mkstemp descriptor leak: the descriptor returned by
      ``tempfile.mkstemp`` is consumed via ``os.fdopen`` (matching
      ``tests/test_tool_schema_snapshot.py::_build_servers``), never left
      open.
    - httpx proxy-env inheritance: the readiness poll uses
      ``trust_env=False`` so an ambient ``HTTP_PROXY`` can never hijack
      loopback traffic during the poll.
    - Served-app identity: ``build_http_app()`` is called exactly once
      here; the SAME object is both served by uvicorn and yielded to
      tests, so structural middleware checks never construct a second app.

    ``load_config`` rejects an empty device set ("At least one FortiGate
    device must be configured"), so this fixture reuses the standard
    one-RFC-5737-device config shape from ``tmp_config_path`` and patches
    ``FortiGateMCPHTTPServer._test_initial_connection`` to a no-op during
    construction (same technique as
    ``tests/test_tool_schema_snapshot.py::_build_servers``, line 107) so
    E2E startup performs zero FortiGate network I/O.

    Args:
        require_auth: threaded into the temp config's ``auth.require_auth``
            (default False, matching every pre-existing caller of this
            function -- the default-unauthenticated live server).
        api_tokens: threaded into the temp config's ``auth.api_tokens``
            (default ``[]`` when None, matching every pre-existing caller).
    """
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
            "api_tokens": api_tokens or [],
            "allowed_origins": ["*"],
        },
        "logging": {"level": "INFO", "console": True},
    }
    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="e2e_config_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)

    # Pre-bind an OS-assigned ephemeral port on loopback ONLY -- never
    # "0.0.0.0" and never read from an environment variable. The socket is
    # NOT closed here; it is handed straight to uvicorn below so no other
    # process can race us for the port between probe and bind.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    uv = None
    thread = None
    sock_owned_by_uvicorn = False
    try:
        with patch.object(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None):
            server = FortiGateMCPHTTPServer(
                config_path=config_path,
                host="127.0.0.1",
                port=port,
                path="/fortigate-mcp",
            )
        # Built EXACTLY ONCE: this same object is served by uvicorn AND
        # yielded to tests for structural inspection.
        app = server.build_http_app()

        uv = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="error",
                lifespan="on",
            )
        )
        thread = threading.Thread(target=lambda: uv.run(sockets=[sock]), daemon=True)
        sock_owned_by_uvicorn = True
        thread.start()

        base_url = f"http://127.0.0.1:{port}"
        ready = False
        for _ in range(200):
            try:
                # trust_env=False: an ambient HTTP_PROXY must never hijack
                # loopback traffic during the readiness poll.
                response = httpx.get(base_url + "/health", timeout=0.5, trust_env=False)
                if response.status_code == 200:
                    ready = True
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.03)
        if not ready:
            raise RuntimeError("live E2E server did not become ready in time")

        yield base_url, server, app
    finally:
        if uv is not None:
            uv.should_exit = True
        if thread is not None:
            thread.join(timeout=5)
            assert not thread.is_alive(), "uvicorn E2E thread failed to terminate within 5s"
        # uvicorn owns and closes sockets passed to run(sockets=...) on
        # shutdown once thread.start() has actually handed it off. If
        # construction/build_http_app() raised before that hand-off,
        # `sock` was never given to uvicorn and must be closed here to
        # avoid leaking the bound file descriptor.
        if not sock_owned_by_uvicorn:
            sock.close()
        try:
            os.unlink(config_path)
        except OSError:
            pass


@pytest.fixture(scope="module")
def live_server():
    """Module-scoped live uvicorn E2E server -- amortizes startup cost
    across every test in ``tests/test_e2e_http.py``. Yields
    ``(base_url, server, app)``.

    ``require_auth`` stays at its default False -- the default,
    unauthenticated live server proving SEC-05 changed nothing about the
    pre-existing behavior every test in this module already relies on."""
    with run_live_server() as ctx:
        yield ctx


@pytest.fixture(scope="module")
def live_server_auth_required():
    """Module-scoped live uvicorn E2E server with ``require_auth=True`` and
    a single configured Bearer token, proving SEC-05's HTTP auth
    enforcement against a real served app (not a hand-built stand-in).
    Yields ``(base_url, server, app)``."""
    with run_live_server(
        require_auth=True, api_tokens=["e2e-test-token-not-real"]
    ) as ctx:
        yield ctx
