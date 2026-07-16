"""
Configuration models for the FortiGate MCP server.

This module defines Pydantic models for configuration validation:
- FortiGate connection settings
- Authentication credentials
- Logging configuration
- Tool-specific parameter models

The models provide:
- Type validation
- Default values
- Field descriptions
- Required vs optional field handling
"""
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from ..validation import validate_host, validate_port, validate_vdom


class StrictConfigModel(BaseModel):
    """Base for all configuration models: rejects unknown fields and hides
    raw input values in validation errors (defense-in-depth for
    secret-bearing fields)."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class FortiGateDeviceConfig(StrictConfigModel):
    """Model for individual FortiGate device configuration.

    Defines the required and optional parameters for
    connecting to a specific FortiGate device.

    Coercion policy: port must be a JSON integer (strings and booleans
    rejected pre-coercion); other fields follow Pydantic lax coercion,
    which is acceptable because none of them is interpolated into a REST
    path without further validation.
    """
    host: str = Field(description="FortiGate IP address or hostname")
    port: int = Field(default=443, description="HTTPS port (default: 443)")
    username: Optional[str] = Field(default=None, description="Username for authentication")
    password: Optional[SecretStr] = Field(default=None, description="Password for authentication")
    api_token: Optional[SecretStr] = Field(default=None, description="API token for authentication")
    vdom: str = Field(default="root", description="Virtual Domain name")
    verify_ssl: bool = Field(default=False, description="SSL certificate verification")
    timeout: int = Field(default=30, gt=0, description="Request timeout in seconds")

    @field_validator("host")
    @classmethod
    def _validate_host(cls, v: str) -> str:
        return validate_host(v)

    @field_validator("vdom")
    @classmethod
    def _validate_vdom(cls, v: str) -> str:
        return validate_vdom(v)

    @field_validator("port", mode="before")
    @classmethod
    def _validate_port(cls, v: int) -> int:
        return validate_port(v)

class FortiGateConfig(StrictConfigModel):
    """Model for FortiGate devices configuration.

    Contains configuration for multiple FortiGate devices.
    Each device is identified by a unique key.
    """
    devices: Dict[str, FortiGateDeviceConfig] = Field(
        description="Dictionary of FortiGate devices keyed by device ID"
    )

class AuthConfig(StrictConfigModel):
    """Authentication configuration for the MCP server's HTTP transport.

    NOT YET ENFORCED: these fields are parsed and stored but never checked
    at the transport layer -- the HTTP server is unauthenticated by
    default (require_auth defaults to False; run only on trusted
    networks). Bearer-token enforcement is planned for Phase 4 (SEC-05)
    on top of Phase 3's app factory. See the CONF-04 decision record.
    """
    require_auth: bool = Field(default=False, description="Whether authentication is required")
    api_tokens: List[str] = Field(default_factory=list, description="Valid API tokens")
    allowed_origins: List[str] = Field(default=["*"], description="CORS allowed origins")

class LoggingConfig(StrictConfigModel):
    """Model for logging configuration.

    Defines logging parameters with sensible defaults.
    Supports both file and console logging with
    customizable format and log levels.
    """
    level: str = Field(default="INFO", description="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    file: Optional[str] = Field(default=None, description="Log file path (None for console only)")
    console: bool = Field(default=True, description="Enable console logging")

class ServerConfig(StrictConfigModel):
    """Model for server configuration.

    Defines server runtime parameters including
    network binding and performance settings.
    """
    host: str = Field(default="0.0.0.0", description="Server bind address")
    port: int = Field(default=8814, ge=1, le=65535, description="Server port")
    name: str = Field(default="fortigate-mcp-server", description="Server name")
    version: str = Field(default="1.0.0", description="Server version")

class RateLimitConfig(StrictConfigModel):
    """Rate limiting configuration.

    NOT YET ENFORCED: parsed but never checked anywhere in the codebase.
    Enforcement is a Phase 4 candidate. See SECURITY roadmap.
    """
    enabled: bool = Field(default=True, description="Enable rate limiting")
    max_requests_per_minute: int = Field(default=60, description="Maximum requests per minute")
    burst_size: int = Field(default=10, description="Burst request allowance")

class Config(StrictConfigModel):
    """Root configuration model.

    Combines all configuration models into a single validated
    configuration object. Provides the complete server configuration.
    """
    server: ServerConfig = Field(default_factory=ServerConfig)
    fortigate: FortiGateConfig = Field(description="FortiGate devices configuration")
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)

# Parameter models for tool validation
class DeviceCommandParams(BaseModel):
    """Parameters for device commands."""
    device_id: str = Field(description="FortiGate device ID")

class PolicyParams(BaseModel):
    """Parameters for firewall policy operations."""
    device_id: str = Field(description="FortiGate device ID")
    policy_id: Optional[str] = Field(default=None, description="Policy ID for specific operations")
    vdom: Optional[str] = Field(default=None, description="Virtual Domain (uses device default if not specified)")

class AddressObjectParams(BaseModel):
    """Parameters for address object operations."""
    device_id: str = Field(description="FortiGate device ID")
    name: Optional[str] = Field(default=None, description="Address object name")
    vdom: Optional[str] = Field(default=None, description="Virtual Domain")

class ServiceObjectParams(BaseModel):
    """Parameters for service object operations."""
    device_id: str = Field(description="FortiGate device ID")
    name: Optional[str] = Field(default=None, description="Service object name")
    vdom: Optional[str] = Field(default=None, description="Virtual Domain")

class RouteParams(BaseModel):
    """Parameters for routing operations."""
    device_id: str = Field(description="FortiGate device ID")
    vdom: Optional[str] = Field(default=None, description="Virtual Domain")
