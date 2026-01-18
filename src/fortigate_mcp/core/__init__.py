"""Core functionality for FortiGate MCP."""

from .logging import setup_logging
from .fortigate import FortiGateManager
from .ssh_client import FortiGateSSHClient, FortiGateSSHError, PARAMIKO_AVAILABLE
from .fortianalyzer import FortiAnalyzerAPI, FortiAnalyzerAPIError, FortiAnalyzerManager

__all__ = [
    "setup_logging",
    "FortiGateManager",
    "FortiGateSSHClient",
    "FortiGateSSHError",
    "PARAMIKO_AVAILABLE",
    "FortiAnalyzerAPI",
    "FortiAnalyzerAPIError",
    "FortiAnalyzerManager",
]
