"""Gap-filling offline tests for the HTTP server (server_http.py)."""
import json
import signal
import sys
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

import src.fortigate_mcp.server_http as sh
from src.fortigate_mcp.server_http import (
    FortiGateMCPCommand,
    FortiGateMCPHTTPServer,
    main,
)


_ORIG_TIC = FortiGateMCPHTTPServer._test_initial_connection


def _config(tmp_path, **extra):
    data = {
        "fortigate": {"devices": {"d1": {
            "host": "198.51.100.10", "api_token": "tok-not-real", "timeout": 1}}},
        **extra,
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    return str(p)


@pytest.fixture
def make(monkeypatch, tmp_path):
    monkeypatch.setattr(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None)

    def _make(**extra):
        return FortiGateMCPHTTPServer(_config(tmp_path, **extra), host="127.0.0.1", port=1, path="/m")
    return _make


def test_defaults_are_loopback(make):
    s = make()
    assert (s.host, s.port, s.path) == ("127.0.0.1", 1, "/m")


def test_rate_limit_warning_and_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None)
    data = {
        "fortigate": {"devices": {"d1": {
            "host": "198.51.100.10", "username": "u", "password": "pw-not-real", "timeout": 1}}},
        "auth": {"require_auth": True, "api_tokens": ["bearer-not-real"]},
        "rate_limiting": {"enabled": True},
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    s = FortiGateMCPHTTPServer(str(p))
    assert (s.host, s.port, s.path) == ("127.0.0.1", 8814, "/fortigate-mcp")


def test_health_healthy_and_degraded(make):
    s = make()
    with TestClient(s.build_http_app()) as c:
        assert c.get("/health").json() == {"status": "healthy"}
        s.fortigate_manager.failed_devices = {"d1": "err"}
        assert c.get("/health").json() == {"status": "degraded"}


def test_auth_middleware_applied_when_required(make):
    s = make(auth={"require_auth": True, "api_tokens": ["bearer-not-real"]})
    names = [m.cls.__name__ for m in s.build_http_app().user_middleware]
    assert names.index("TraceMiddleware") < names.index("AuthMiddleware")


def test_no_auth_middleware_by_default(make):
    names = [m.cls.__name__ for m in make().build_http_app().user_middleware]
    assert "AuthMiddleware" not in names and "TraceMiddleware" in names


def test_initial_connection_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None)
    s = FortiGateMCPHTTPServer(_config(tmp_path))
    s.logger = MagicMock()
    ok, bad, err = MagicMock(), MagicMock(), MagicMock()
    ok.test_connection.return_value = True
    bad.test_connection.return_value = False
    err.test_connection.side_effect = RuntimeError("down")
    s.fortigate_manager = MagicMock()
    s.fortigate_manager.list_devices.return_value = ["ok", "bad", "err"]
    s.fortigate_manager.get_device.side_effect = lambda d: {"ok": ok, "bad": bad, "err": err}[d]
    _ORIG_TIC(s)
    assert s.logger.info.call_count >= 2
    s.logger.warning.assert_called_once()
    s.logger.error.assert_called_once()


def test_initial_connection_outer_error(make):
    s = make()
    s.logger = MagicMock()
    s.fortigate_manager = MagicMock()
    s.fortigate_manager.list_devices.side_effect = RuntimeError("x")
    _ORIG_TIC(s)
    s.logger.error.assert_called_once()


def test_run_serves_via_uvicorn(make, monkeypatch):
    import uvicorn
    s = make()
    monkeypatch.setattr(signal, "signal", MagicMock())
    server_cls = MagicMock()
    monkeypatch.setattr(uvicorn, "Server", server_cls)
    monkeypatch.setattr(uvicorn, "Config", MagicMock())
    s.run()
    server_cls.return_value.run.assert_called_once()
    kwargs = uvicorn.Config.call_args.kwargs
    assert kwargs["host"] == "127.0.0.1" and kwargs["port"] == 1
    handler = signal.signal.call_args_list[0].args[1]
    with pytest.raises(SystemExit) as ei:
        handler(signal.SIGTERM, None)
    assert ei.value.code == 0


def test_run_error_exits_1(make, monkeypatch):
    import uvicorn
    s = make()
    monkeypatch.setattr(signal, "signal", MagicMock())
    monkeypatch.setattr(uvicorn, "Config", MagicMock(side_effect=RuntimeError("x")))
    with pytest.raises(SystemExit) as ei:
        s.run()
    assert ei.value.code == 1


def test_command_handle_passes_options(monkeypatch):
    ctor = MagicMock()
    monkeypatch.setattr(sh, "FortiGateMCPHTTPServer", ctor)
    monkeypatch.delenv("FORTIGATE_MCP_CONFIG", raising=False)
    cmd = FortiGateMCPCommand()
    cmd.handle(host="0.0.0.0", port=9, path="/p", config="/c.json")
    ctor.assert_called_once_with(config_path="/c.json", host="0.0.0.0", port=9, path="/p")
    ctor.return_value.run.assert_called_once()


def test_command_handle_defaults_and_env(monkeypatch):
    ctor = MagicMock()
    monkeypatch.setattr(sh, "FortiGateMCPHTTPServer", ctor)
    monkeypatch.setenv("FORTIGATE_MCP_CONFIG", "/env.json")
    FortiGateMCPCommand().handle()
    ctor.assert_called_once_with(
        config_path="/env.json", host="127.0.0.1", port=8814, path="/fortigate-mcp")


def test_main_parses_args(monkeypatch):
    ctor = MagicMock()
    monkeypatch.setattr(sh, "FortiGateMCPHTTPServer", ctor)
    monkeypatch.setattr(sys, "argv", ["x", "--port", "9999", "--config", "/c.json"])
    main()
    assert ctor.call_args.kwargs["port"] == 9999
    assert ctor.call_args.kwargs["host"] == "127.0.0.1"


@pytest.mark.parametrize("exc,code", [(KeyboardInterrupt(), 0), (RuntimeError("bad"), 1)])
def test_main_errors(monkeypatch, exc, code):
    monkeypatch.setattr(sh, "FortiGateMCPHTTPServer", MagicMock(side_effect=exc))
    monkeypatch.setattr(sys, "argv", ["x", "--config", "c"])
    with pytest.raises(SystemExit) as ei:
        main()
    assert ei.value.code == code
