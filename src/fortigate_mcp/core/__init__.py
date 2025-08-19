"""Core functionality for FortiGate MCP."""

from .logging import setup_logging
from .fortigate import FortiGateManager

__all__ = [
    "setup_logging",
    "FortiGateManager"
]
