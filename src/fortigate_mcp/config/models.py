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
from pydantic import BaseModel, Field

class FortiGateDeviceConfig(BaseModel):
    """Model for individual FortiGate device configuration.

    Defines the required and optional parameters for
    connecting to a specific FortiGate device.
    """
    host: str = Field(description="FortiGate IP address or hostname")
    port: int = Field(default=443, description="HTTPS port (default: 443)")
    ssh_port: int = Field(default=22, description="SSH port for CLI access (default: 22)")
    username: Optional[str] = Field(default=None, description="Username for authentication")
    password: Optional[str] = Field(default=None, description="Password for authentication")
    api_token: Optional[str] = Field(default=None, description="API token for authentication")
    vdom: str = Field(default="root", description="Virtual Domain name")
    verify_ssl: bool = Field(default=False, description="SSL certificate verification")
    timeout: int = Field(default=30, description="Request timeout in seconds")

class FortiGateConfig(BaseModel):
    """Model for FortiGate devices configuration.
    
    Contains configuration for multiple FortiGate devices.
    Each device is identified by a unique key.
    """
    devices: Dict[str, FortiGateDeviceConfig] = Field(
        description="Dictionary of FortiGate devices keyed by device ID"
    )

class AuthConfig(BaseModel):
    """Model for authentication configuration.
    
    Defines authentication parameters for the MCP server itself.
    Used for HTTP transport authentication if enabled.
    """
    require_auth: bool = Field(default=False, description="Whether authentication is required")
    api_tokens: List[str] = Field(default_factory=list, description="Valid API tokens")
    allowed_origins: List[str] = Field(default=["*"], description="CORS allowed origins")

class LoggingConfig(BaseModel):
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

class ServerConfig(BaseModel):
    """Model for server configuration.
    
    Defines server runtime parameters including
    network binding and performance settings.
    """
    host: str = Field(default="0.0.0.0", description="Server bind address")
    port: int = Field(default=8814, description="Server port")
    name: str = Field(default="fortigate-mcp-server", description="Server name")
    version: str = Field(default="1.0.0", description="Server version")

class RateLimitConfig(BaseModel):
    """Model for rate limiting configuration.

    Defines rate limiting parameters to prevent
    API abuse and ensure stable performance.
    """
    enabled: bool = Field(default=True, description="Enable rate limiting")
    max_requests_per_minute: int = Field(default=60, description="Maximum requests per minute")
    burst_size: int = Field(default=10, description="Burst request allowance")

class ACMEConfig(BaseModel):
    """Model for ACME/Let's Encrypt configuration.

    Defines configuration for automated certificate issuance
    using Let's Encrypt with Cloudflare DNS validation.
    """
    enabled: bool = Field(default=False, description="Enable ACME certificate management")
    email: Optional[str] = Field(default=None, description="Contact email for Let's Encrypt account")
    staging: bool = Field(default=False, description="Use Let's Encrypt staging environment")
    account_key_path: Optional[str] = Field(default=None, description="Path to store ACME account key")
    cloudflare_api_token: Optional[str] = Field(default=None, description="Cloudflare API token for DNS validation")
    default_key_type: str = Field(default="rsa", description="Default key type (rsa or ec)")
    default_key_size: int = Field(default=2048, description="Default key size for RSA keys")

class Config(BaseModel):
    """Root configuration model.

    Combines all configuration models into a single validated
    configuration object. Provides the complete server configuration.
    """
    server: ServerConfig = Field(default_factory=ServerConfig)
    fortigate: FortiGateConfig = Field(description="FortiGate devices configuration")
    auth: AuthConfig = Field(default_factory=AuthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    acme: ACMEConfig = Field(default_factory=ACMEConfig)

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
