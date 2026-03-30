"""
Configuration model tests - validates security defaults and validation.
"""

import pytest
from pydantic import ValidationError

from src.fortigate_mcp.config.models import (
    FortiGateDeviceConfig,
    FortiGateConfig,
    AuthConfig,
    LoggingConfig,
    ServerConfig,
    RateLimitConfig,
    Config,
    DeviceCommandParams,
    PolicyParams,
    AddressObjectParams,
    ServiceObjectParams,
    RouteParams,
)


class TestFortiGateDeviceConfig:
    """Tests for device configuration model."""

    def test_minimal_config(self):
        """Test minimal device config with just host."""
        config = FortiGateDeviceConfig(host="10.0.0.1")
        assert config.host == "10.0.0.1"
        assert config.port == 443
        assert config.vdom == "root"
        assert config.timeout == 30

    def test_ssl_verify_default_true(self):
        """Test that SSL verification defaults to True (security fix)."""
        config = FortiGateDeviceConfig(host="10.0.0.1")
        assert config.verify_ssl is True

    def test_ssl_verify_explicit_false(self):
        """Test that SSL verification can be explicitly disabled."""
        config = FortiGateDeviceConfig(host="10.0.0.1", verify_ssl=False)
        assert config.verify_ssl is False

    def test_full_config(self):
        """Test full device config with all fields."""
        config = FortiGateDeviceConfig(
            host="10.0.0.1",
            port=8443,
            username="admin",
            password="secret",
            api_token="mytoken",
            vdom="production",
            verify_ssl=True,
            timeout=60
        )
        assert config.port == 8443
        assert config.username == "admin"
        assert config.vdom == "production"
        assert config.timeout == 60


class TestAuthConfig:
    """Tests for authentication configuration model."""

    def test_default_auth_config(self):
        """Test default auth config has secure defaults."""
        config = AuthConfig()
        assert config.require_auth is False
        assert config.api_tokens == []

    def test_cors_default_empty(self):
        """Test that CORS allowed_origins defaults to empty list (security fix)."""
        config = AuthConfig()
        assert config.allowed_origins == []

    def test_custom_auth_config(self):
        """Test custom auth configuration."""
        config = AuthConfig(
            require_auth=True,
            api_tokens=["token1", "token2"],
            allowed_origins=["https://app.example.com"]
        )
        assert config.require_auth is True
        assert len(config.api_tokens) == 2
        assert config.allowed_origins == ["https://app.example.com"]


class TestServerConfig:
    """Tests for server configuration model."""

    def test_default_server_config(self):
        """Test default server config."""
        config = ServerConfig()
        assert config.host == "0.0.0.0"
        assert config.port == 8814
        assert config.name == "fortigate-mcp-server"
        assert config.version == "1.0.0"


class TestLoggingConfig:
    """Tests for logging configuration model."""

    def test_default_logging_config(self):
        """Test default logging config."""
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.file is None
        assert config.console is True


class TestRateLimitConfig:
    """Tests for rate limit configuration model."""

    def test_default_rate_limit(self):
        """Test default rate limit settings."""
        config = RateLimitConfig()
        assert config.enabled is True
        assert config.max_requests_per_minute == 60
        assert config.burst_size == 10


class TestFortiGateConfig:
    """Tests for FortiGate config container."""

    def test_devices_config(self):
        """Test FortiGate config with devices."""
        config = FortiGateConfig(
            devices={
                "fw1": FortiGateDeviceConfig(host="10.0.0.1"),
                "fw2": FortiGateDeviceConfig(host="10.0.0.2")
            }
        )
        assert len(config.devices) == 2
        assert "fw1" in config.devices
        assert "fw2" in config.devices


class TestParameterModels:
    """Tests for tool parameter models."""

    def test_device_command_params(self):
        """Test device command parameters."""
        params = DeviceCommandParams(device_id="fw1")
        assert params.device_id == "fw1"

    def test_policy_params_minimal(self):
        """Test minimal policy parameters."""
        params = PolicyParams(device_id="fw1")
        assert params.policy_id is None
        assert params.vdom is None

    def test_policy_params_full(self):
        """Test full policy parameters."""
        params = PolicyParams(device_id="fw1", policy_id="5", vdom="test")
        assert params.policy_id == "5"
        assert params.vdom == "test"

    def test_address_object_params(self):
        """Test address object parameters."""
        params = AddressObjectParams(device_id="fw1", name="test_addr")
        assert params.name == "test_addr"

    def test_service_object_params(self):
        """Test service object parameters."""
        params = ServiceObjectParams(device_id="fw1", name="HTTP")
        assert params.name == "HTTP"

    def test_route_params(self):
        """Test route parameters."""
        params = RouteParams(device_id="fw1", vdom="custom")
        assert params.vdom == "custom"
