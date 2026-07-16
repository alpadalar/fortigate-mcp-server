"""
Strict-mode config regression tests (CONF-01/CONF-02/CONF-03).

Covers:
- extra="forbid" rejection at the top level AND nested inside
  fortigate.devices.<id> (extra=forbid does not cascade to nested model
  references -- verified by RESEARCH.md -- so every model needs its own
  strict base; StrictConfigModel is that shared base).
- Pydantic model-boundary validation for host/vdom/port/timeout.
- SecretStr masking in str()/repr()/f-string.
- The shipped config/config.example.json still loads unmodified.
- The ADVERSARIAL CONF-01+CONF-03 coupling proof: a rejected field's value
  IS a token-shaped secret, and it must never surface through str(e),
  repr(e), a fully formatted traceback, or a retained __cause__.

Test data convention: RFC 5737 TEST-NET-2 hosts (198.51.100.x) and
"test-token-not-real"-prefixed literals only -- never anything that could
be mistaken for a real credential.
"""

import json
import traceback
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.fortigate_mcp.config.loader import load_config
from src.fortigate_mcp.config.models import Config


def _repo_root() -> Path:
    """Resolve the repository root from this test file's location."""
    return Path(__file__).resolve().parent.parent


def _base_config_dict() -> dict:
    """A minimal, strict-mode-valid config dict for building test variants."""
    return {
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


def test_rejects_unknown_top_level_field():
    """An unknown top-level config key is rejected under strict mode."""
    data = _base_config_dict()
    data["bogus_top_level"] = True

    with pytest.raises(ValidationError):
        Config(**data)


def test_rejects_unknown_nested_device_field():
    """An unknown field nested inside fortigate.devices.<id> is rejected too.

    Regression guard for Pitfall 1: extra=forbid on the root model alone
    does NOT cascade to nested model references -- every model needs its
    own strict base (StrictConfigModel).
    """
    data = _base_config_dict()
    data["fortigate"]["devices"]["default"]["apitoken"] = "typo"

    with pytest.raises(ValidationError):
        Config(**data)


def test_example_config_still_valid():
    """The shipped config/config.example.json loads unmodified under strict mode."""
    example_path = _repo_root() / "config" / "config.example.json"

    config = load_config(str(example_path))

    assert "default" in config.fortigate.devices
    assert "backup" in config.fortigate.devices


@pytest.mark.parametrize(
    "field, value",
    [
        ("port", True),
        ("port", "443"),
        ("port", 70000),
        ("port", 0),
        ("timeout", 0),
    ],
)
def test_port_and_timeout_bounds_rejected(field, value):
    """Bool/string ports, out-of-range ports, and non-positive timeouts are rejected.

    port uses a mode="before" validator so lax coercion (bool->int,
    "443"->443) cannot slip a value past the check.
    """
    data = _base_config_dict()
    data["fortigate"]["devices"]["default"][field] = value

    with pytest.raises(ValidationError):
        Config(**data)


def test_rejected_value_containing_token_never_leaks(tmp_path):
    """ADVERSARIAL: the REJECTED field's value IS the token marker.

    Unlike a non-adversarial test that puts the token in a valid field
    while rejection happens elsewhere, this makes the extra_forbidden
    error's own input value the marker -- proving the loader's handling
    survives even when the leak vector is maximally hostile.
    """
    marker = "test-token-not-real-SECRET-MARKER"
    data = _base_config_dict()
    data["fortigate"]["devices"]["default"]["bogus_extra_field"] = marker

    config_file = tmp_path / "adversarial-config.json"
    config_file.write_text(json.dumps(data))

    with pytest.raises(ValueError) as exc_info:
        load_config(str(config_file))

    assert marker not in str(exc_info.value)
    assert marker not in repr(exc_info.value)

    formatted_traceback = "".join(
        traceback.format_exception(
            type(exc_info.value), exc_info.value, exc_info.value.__traceback__
        )
    )
    assert marker not in formatted_traceback
    assert exc_info.value.__cause__ is None


def test_device_host_rejected_at_model_boundary():
    """A malformed host (path traversal shape) is rejected at the model boundary."""
    data = _base_config_dict()
    data["fortigate"]["devices"]["default"]["host"] = "../bad"

    with pytest.raises(ValidationError):
        Config(**data)


def test_device_vdom_rejected_at_model_boundary():
    """A malformed vdom (space-containing) is rejected at the model boundary."""
    data = _base_config_dict()
    data["fortigate"]["devices"]["default"]["vdom"] = "bad vdom"

    with pytest.raises(ValidationError):
        Config(**data)


def test_secretstr_masks_in_str_repr_fstring():
    """api_token is a SecretStr that masks in str()/repr()/direct f-string interpolation."""
    data = _base_config_dict()
    config = Config(**data)
    device = config.fortigate.devices["default"]

    assert "test-token-not-real" not in str(device)
    assert "test-token-not-real" not in repr(device)
    assert f"{device.api_token}" == "**********"


def test_unknown_exception_fallback_is_generic(monkeypatch, tmp_path):
    """An unknown (non-ValidationError) exception during Config construction
    produces a generic message with zero interpolation of the original text."""
    data = _base_config_dict()
    config_file = tmp_path / "valid-config.json"
    config_file.write_text(json.dumps(data))

    class _ExplodingConfig:
        def __init__(self, **kwargs):
            raise RuntimeError("boom-with-test-token-not-real")

    monkeypatch.setattr("src.fortigate_mcp.config.loader.Config", _ExplodingConfig)

    with pytest.raises(ValueError) as exc_info:
        load_config(str(config_file))

    assert "boom" not in str(exc_info.value)
    assert "test-token-not-real" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
