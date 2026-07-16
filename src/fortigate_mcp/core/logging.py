"""
Logging configuration for FortiGate MCP server.

This module provides centralized logging setup with support for:
- Multiple log levels
- File and console output
- Structured log formatting
- Component-specific loggers
"""
import logging
import logging.handlers
import sys
import threading
from typing import Iterable, Optional, Set

from ..config.models import LoggingConfig
from ..validation import scrub_secrets


class TokenRedactionFilter(logging.Filter):
    """Redact known secrets and Bearer-pattern tokens from log records.

    Attach to HANDLERS, not loggers — ancestor-logger filters are not
    re-run for records propagated from child loggers; handlers receive
    those records directly. A filter added directly to the root logger
    object would silently never see records emitted by
    ``get_logger("tools...")`` and similar child loggers, because
    Python's logging propagation delivers the record straight to every
    ancestor HANDLER without re-invoking ancestor logger-level filters.

    Thread safety: `register()` never mutates `self._secrets` in place --
    it always rebinds the attribute to a brand-new set built under a lock.
    `filter()` reads `self._secrets` with a single attribute access (no
    lock needed there: CPython single-reference reads/writes are atomic
    under the GIL), so a concurrent `register()` call can never be
    observed mid-mutation by `scrub_secrets()`'s internal iteration --
    `filter()` either sees the old set object or the new one, never a
    partially-updated one. This closes a reproducible
    `RuntimeError: Set changed size during iteration` under concurrent
    add_device calls racing arbitrary concurrent logging (every log call
    reaches this filter).
    """

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._secrets: Set[str] = set()

    def register(self, secrets: Iterable[Optional[str]]) -> None:
        """Add secrets to the redaction registry. Never removes entries."""
        with self._lock:
            self._secrets = self._secrets | {s for s in secrets if s}

    def filter(self, record: logging.LogRecord) -> bool:
        # Single atomic reference read -- see thread-safety note above.
        secrets_snapshot = self._secrets

        # Scrub the rendered message. record.args is cleared afterward so
        # Formatter.format() does not re-interpolate the original (already
        # substituted into msg above) args over the redacted text.
        msg = record.getMessage()
        record.msg = scrub_secrets(msg, secrets_snapshot)
        record.args = None

        # Scrub exception tracebacks too: Formatter.format() uses a
        # pre-set record.exc_text instead of re-formatting record.exc_info,
        # so pre-computing and scrubbing exc_text here is what keeps a
        # secret embedded in an exception message from leaking through
        # the appended traceback.
        if record.exc_info and not record.exc_text:
            record.exc_text = scrub_secrets(
                logging.Formatter().formatException(record.exc_info), secrets_snapshot
            )
            record.exc_info = None

        return True


# Module-level shared filter instance: setup_logging() attaches this same
# instance to every handler it creates, so register_secrets() (called at
# boot and at runtime by DeviceTools.add_device) updates redaction for
# every handler without needing a re-attachment pass.
_redaction_filter = TokenRedactionFilter()


def register_secrets(secrets: Iterable[Optional[str]]) -> None:
    """Register secrets with the shared redaction filter.

    Safe to call before or after setup_logging(); safe to call multiple
    times (e.g. once per runtime add_device call). Secrets are only ever
    added, never removed.
    """
    _redaction_filter.register(secrets)


def _attach_redaction(handler: logging.Handler) -> logging.Handler:
    """Attach the shared redaction filter to a handler.

    Single choke point for handler-level filter attachment — every
    handler setup_logging() creates must be routed through this helper
    so a future handler cannot be added without redaction coverage.
    """
    handler.addFilter(_redaction_filter)
    return handler


def setup_logging(config: LoggingConfig, secrets: Optional[set] = None) -> logging.Logger:
    """Setup logging configuration for the FortiGate MCP server.

    Configures logging based on the provided configuration:
    - Sets global log level
    - Configures console and/or file output
    - Sets up formatters for structured output
    - Creates component-specific loggers
    - Attaches a shared TokenRedactionFilter to every handler created

    Args:
        config: LoggingConfig object containing logging settings
        secrets: optional iterable of known secret values to register with
            the redaction filter before any handler is created

    Returns:
        Logger instance for the main application

    Example:
        config = LoggingConfig(level="INFO", file="server.log", console=True)
        logger = setup_logging(config, secrets={"my-api-token"})
        logger.info("Server starting...")
    """
    if secrets:
        register_secrets(secrets)

    # Clear any existing handlers to avoid duplication
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # Set global log level
    log_level = getattr(logging, config.level.upper(), logging.INFO)
    root_logger.setLevel(log_level)

    # Create formatter
    formatter = logging.Formatter(
        config.format,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Setup console logging if enabled
    # NOTE: must never target sys.stdout — the stdio MCP transport
    # (mcp.server.stdio.stdio_server) writes JSON-RPC framing directly to
    # stdout, so any plain-text log line written there corrupts the
    # protocol stream. Route console logging to stderr instead.
    if config.console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(_attach_redaction(console_handler))

    # Setup file logging if specified
    if config.file:
        try:
            # Create directory if it doesn't exist
            import os
            log_dir = os.path.dirname(config.file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            # Use rotating file handler to prevent large log files
            file_handler = logging.handlers.RotatingFileHandler(
                config.file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(_attach_redaction(file_handler))
        except Exception as e:
            # If file logging fails, log to console
            console_logger = logging.getLogger("fortigate-mcp.logging")
            console_logger.warning(f"Failed to setup file logging: {e}")

    # Create and return main application logger
    logger = logging.getLogger("fortigate-mcp.main")

    # Set specific log levels for component loggers
    _setup_component_loggers(log_level)

    return logger

def _setup_component_loggers(log_level: int) -> None:
    """Setup component-specific loggers with appropriate levels.
    
    Configures loggers for different components of the system:
    - Core components (FortiGate API, device management)
    - Tools (firewall, network, routing)
    - HTTP transport
    - External libraries
    
    Args:
        log_level: Base log level to use for all components
    """
    # Component loggers with same level as main
    component_loggers = [
        "fortigate-mcp.core",
        "fortigate-mcp.tools",
        "fortigate-mcp.device",
        "fortigate-mcp.firewall",
        "fortigate-mcp.network",
        "fortigate-mcp.routing",
        "fortigate-mcp.server",
        "fortigate-mcp.http"
    ]
    
    for logger_name in component_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(log_level)
    
    # External library loggers - set to WARNING to reduce noise
    external_loggers = [
        "httpx",
        "uvicorn",
        "fastapi",
        "urllib3"
    ]
    
    for logger_name in external_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific component.
    
    Creates a logger with the fortigate-mcp prefix and the specified name.
    This ensures consistent naming across all components.
    
    Args:
        name: Component name (e.g., "device", "firewall", "tools.base")
        
    Returns:
        Logger instance for the component
        
    Example:
        logger = get_logger("device.manager")
        logger.info("Device manager initialized")
    """
    return logging.getLogger(f"fortigate-mcp.{name}")

def log_api_call(logger: logging.Logger, method: str, url: str, 
                 status_code: Optional[int] = None, 
                 duration_ms: Optional[float] = None) -> None:
    """Log FortiGate API calls with structured information.
    
    Provides consistent logging for all FortiGate API interactions:
    - Request method and URL
    - Response status code
    - Request duration
    - Error information if applicable
    
    Args:
        logger: Logger instance to use
        method: HTTP method (GET, POST, PUT, DELETE)
        url: Request URL
        status_code: HTTP status code (if response received)
        duration_ms: Request duration in milliseconds
        
    Example:
        log_api_call(logger, "GET", "/api/v2/cmdb/firewall/policy", 200, 150.5)
    """
    msg_parts = [f"{method} {url}"]
    
    if status_code is not None:
        msg_parts.append(f"-> {status_code}")
    
    if duration_ms is not None:
        msg_parts.append(f"({duration_ms:.1f}ms)")
    
    message = " ".join(msg_parts)
    
    if status_code and status_code >= 400:
        logger.warning(f"API call failed: {message}")
    else:
        logger.debug(f"API call: {message}")

def log_tool_call(logger: logging.Logger, tool_name: str, 
                  device_id: str, success: bool, 
                  duration_ms: Optional[float] = None,
                  error: Optional[str] = None) -> None:
    """Log MCP tool calls with structured information.
    
    Provides consistent logging for all MCP tool executions:
    - Tool name and target device
    - Success/failure status
    - Execution duration
    - Error details if applicable
    
    Args:
        logger: Logger instance to use
        tool_name: Name of the MCP tool
        device_id: Target FortiGate device ID
        success: Whether the tool execution succeeded
        duration_ms: Tool execution duration in milliseconds
        error: Error message if execution failed
        
    Example:
        log_tool_call(logger, "get_firewall_policies", "default", True, 250.0)
    """
    status = "SUCCESS" if success else "FAILED"
    msg_parts = [f"Tool {tool_name} on device {device_id}: {status}"]
    
    if duration_ms is not None:
        msg_parts.append(f"({duration_ms:.1f}ms)")
    
    if error:
        msg_parts.append(f"- {error}")
    
    message = " ".join(msg_parts)
    
    if success:
        logger.info(message)
    else:
        logger.error(message)
