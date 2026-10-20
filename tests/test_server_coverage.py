"""Gap-filling offline tests for the stdio server (server.py)."""
import json
import signal
import sys
from unittest.mock import MagicMock

import pytest

import src.fortigate_mcp.server as srv
from src.fortigate_mcp.server import FortiGateMCPServer, server_main


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
def server(tmp_path):
    return FortiGateMCPServer(_config(tmp_path))


def test_rate_limit_warning_and_password_secret(tmp_path):
    data = {
        "fortigate": {"devices": {"d1": {
            "host": "198.51.100.10", "username": "u", "password": "pw-not-real",
            "timeout": 1}}},
        "auth": {"require_auth": False, "api_tokens": ["bearer-not-real"]},
        "rate_limiting": {"enabled": True},
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(data))
    s = FortiGateMCPServer(str(p))
    assert s.config.rate_limiting.enabled


class _Anyio:
    def __init__(self, exc=None):
        self.exc = exc
        self.ran = None

    def run(self, fn):
        self.ran = fn
        if self.exc:
            raise self.exc


@pytest.fixture
def stub_start(monkeypatch):
    import anyio
    stub = _Anyio()
    monkeypatch.setattr(anyio, "run", stub.run)
    monkeypatch.setattr(signal, "signal", MagicMock())
    return stub


def test_start_runs_stdio(server, stub_start, monkeypatch):
    monkeypatch.delenv("RUN_TESTS_ON_START", raising=False)
    server.start()
    assert stub_start.ran == server.mcp.run_stdio_async
    assert signal.signal.call_count == 2


def test_start_startup_tests_all_pass(server, stub_start, monkeypatch):
    monkeypatch.setenv("RUN_TESTS_ON_START", "1")
    server.fortigate_manager.test_all_connections = MagicMock(return_value={"d1": True})
    server.start()
    assert server._tests_passed is True


def test_start_startup_tests_fail_warns(server, stub_start, monkeypatch):
    monkeypatch.setenv("RUN_TESTS_ON_START", "yes")
    server.fortigate_manager.test_all_connections = MagicMock(return_value={"d1": False})
    server.logger = MagicMock()
    server.start()
    assert server._tests_passed is False
    assert "d1" in server.logger.warning.call_args.args[0]


def test_start_error_exits_1(server, monkeypatch):
    import anyio
    monkeypatch.setattr(signal, "signal", MagicMock())
    monkeypatch.setattr(anyio, "run", _Anyio(RuntimeError("x")).run)
    with pytest.raises(SystemExit) as ei:
        server.start()
    assert ei.value.code == 1


def test_signal_handler_exits_0(server, stub_start):
    server.start()
    handler = signal.signal.call_args_list[0].args[1]
    with pytest.raises(SystemExit) as ei:
        handler(signal.SIGINT, None)
    assert ei.value.code == 0


def test_main_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["fortigate-mcp-server", "--version"])
    with pytest.raises(SystemExit) as ei:
        server_main()
    assert ei.value.code == 0
    assert "fortigate-mcp-server" in capsys.readouterr().out


def test_main_requires_config(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["x"])
    monkeypatch.delenv("FORTIGATE_MCP_CONFIG", raising=False)
    with pytest.raises(SystemExit) as ei:
        server_main()
    assert ei.value.code == 1
    assert "FORTIGATE_MCP_CONFIG" in capsys.readouterr().err


def test_main_starts_server(monkeypatch, tmp_path):
    fake = MagicMock()
    ctor = MagicMock(return_value=fake)
    monkeypatch.setattr(srv, "FortiGateMCPServer", ctor)
    monkeypatch.setattr(sys, "argv", ["x", "--config", "/some/cfg.json"])
    server_main()
    ctor.assert_called_once_with("/some/cfg.json")
    fake.start.assert_called_once()


def test_main_env_config(monkeypatch):
    ctor = MagicMock()
    monkeypatch.setattr(srv, "FortiGateMCPServer", ctor)
    monkeypatch.setattr(sys, "argv", ["x"])
    monkeypatch.setenv("FORTIGATE_MCP_CONFIG", "/env/cfg.json")
    server_main()
    ctor.assert_called_once_with("/env/cfg.json")


@pytest.mark.parametrize("exc,code", [(KeyboardInterrupt(), 0), (RuntimeError("bad"), 1)])
def test_main_errors(monkeypatch, exc, code, capsys):
    monkeypatch.setattr(srv, "FortiGateMCPServer", MagicMock(side_effect=exc))
    monkeypatch.setattr(sys, "argv", ["x", "--config", "c"])
    with pytest.raises(SystemExit) as ei:
        server_main()
    assert ei.value.code == code
