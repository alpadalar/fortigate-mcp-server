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
from typing import Optional
from ..config.models import LoggingConfig

def setup_logging(config: LoggingConfig) -> logging.Logger:
    """Setup logging configuration for the FortiGate MCP server.
    
    Configures logging based on the provided configuration:
    - Sets global log level
    - Configures console and/or file output
    - Sets up formatters for structured output
    - Creates component-specific loggers
    
    Args:
        config: LoggingConfig object containing logging settings
        
    Returns:
        Logger instance for the main application
        
    Example:
        config = LoggingConfig(level="INFO", file="server.log", console=True)
        logger = setup_logging(config)
        logger.info("Server starting...")
    """
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
    if config.console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
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
            root_logger.addHandler(file_handler)
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
