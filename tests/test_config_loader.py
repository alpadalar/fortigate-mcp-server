"""Offline tests for config.loader.load_config and create_example_config."""
import json

import pytest

from src.fortigate_mcp.config.loader import create_example_config, load_config

DEVICE = {"host": "198.51.100.10", "api_token": "test-token-not-real"}


def _write(tmp_path, data):
    p = tmp_path / "c.json"
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return str(p)


def _cfg(devices=None, **extra):
    return {"fortigate": {"devices": {"d1": DEVICE} if devices is None else devices}, **extra}


def test_valid_file(tmp_path):
    cfg = load_config(_write(tmp_path, _cfg()))
    assert "d1" in cfg.fortigate.devices


def test_path_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("FORTIGATE_MCP_CONFIG", _write(tmp_path, _cfg()))
    assert "d1" in load_config().fortigate.devices


def test_no_path_raises(monkeypatch):
    monkeypatch.delenv("FORTIGATE_MCP_CONFIG", raising=False)
    with pytest.raises(ValueError, match="Configuration path"):
        load_config()


def test_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nope.json"))


def test_malformed_json(tmp_path):
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_config(_write(tmp_path, "{not json"))


def test_unreadable_path_is_valueerror(tmp_path):
    with pytest.raises(ValueError, match="Failed to load"):
        load_config(str(tmp_path))  # a directory


@pytest.mark.parametrize("data,msg", [
    ([1, 2], "must be a JSON object"),
    ({}, "'fortigate' section"),
    ({"fortigate": {}}, "'devices' section"),
    ({"fortigate": {"devices": {}}}, "At least one"),
    ({"fortigate": {"devices": []}}, "At least one"),
    ({"fortigate": {"devices": {"d": "x"}}}, "must be an object"),
    ({"fortigate": {"devices": {"d": {"api_token": "t"}}}}, "'host' field"),
    ({"fortigate": {"devices": {"d": {"host": "h"}}}}, "api_token"),
    ({"fortigate": {"devices": {"d": {"host": "h", "username": "u"}}}}, "api_token"),
])
def test_structure_rejections(tmp_path, data, msg):
    with pytest.raises(ValueError, match=msg):
        load_config(_write(tmp_path, data))


def test_validation_error_hides_secret_input(tmp_path):
    data = _cfg(server={"port": "not-a-port-SECRETVALUE"})
    with pytest.raises(ValueError) as ei:
        load_config(_write(tmp_path, data))
    assert "Configuration validation failed" in str(ei.value)
    assert "SECRETVALUE" not in str(ei.value)
    assert ei.value.__cause__ is None


def test_unexpected_exception_is_generic(tmp_path, monkeypatch):
    import src.fortigate_mcp.config.loader as loader

    def boom(**_):
        raise RuntimeError("leak-me")

    monkeypatch.setattr(loader, "Config", boom)
    with pytest.raises(ValueError, match="unexpected error") as ei:
        load_config(_write(tmp_path, _cfg()))
    assert "leak-me" not in str(ei.value)


def test_example_config_loads_roundtrip(tmp_path):
    example = create_example_config()
    assert example["server"]["port"] == 8814
    cfg = load_config(_write(tmp_path, example))
    assert set(cfg.fortigate.devices) == set(example["fortigate"]["devices"])
