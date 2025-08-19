"""
Pytest configuration and fixtures
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig


@pytest.fixture
def fortigate_manager():
    """FortiGate manager fixture"""
    auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
    devices = {}
    manager = FortiGateManager(devices, auth_config)
    yield manager
    # Cleanup
    manager.devices.clear()


@pytest.fixture
def mock_fortigate_api():
    """Mock FortiGate API fixture"""
    mock_api = MagicMock(spec=FortiGateAPI)
    mock_api.device_id = "test_device"
    
    # Mock config attribute
    mock_config = MagicMock()
    mock_config.host = "192.168.1.1"
    mock_config.vdom = "root"
    mock_api.config = mock_config
    
    mock_api.auth_method = "basic"
    
    # Default return values
    mock_api.get_system_status.return_value = {
        "hostname": "FortiGate",
        "version": "v7.0.0",
        "status": "ok"
    }
    
    mock_api.get_vdoms.return_value = {
        "results": [
            {"name": "root", "enabled": True}
        ]
    }
    
    mock_api.get_interfaces.return_value = {
        "results": [
            {"name": "port1", "status": "up"},
            {"name": "port2", "status": "down"}
        ]
    }
    
    mock_api.get_firewall_policies.return_value = {
        "results": [
            {"policyid": 1, "name": "Allow_HTTP", "action": "accept"}
        ]
    }
    
    mock_api.get_address_objects.return_value = {
        "results": [
            {"name": "test_addr", "subnet": "192.168.1.0/24"}
        ]
    }
    
    mock_api.get_service_objects.return_value = {
        "results": [
            {"name": "HTTP", "tcp-portrange": "80"}
        ]
    }
    
    mock_api.get_static_routes.return_value = {
        "results": [
            {"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}
        ]
    }
    
    mock_api.test_connection.return_value = True
    
    return mock_api


@pytest.fixture
def sample_policy_data():
    """Sample policy data fixture"""
    return {
        "name": "Test_Policy",
        "srcintf": [{"name": "port1"}],
        "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "service": [{"name": "ALL"}],
        "action": "accept",
        "schedule": "always",
        "comments": "Test policy created by pytest"
    }


@pytest.fixture
def sample_address_data():
    """Sample address object data fixture"""
    return {
        "name": "test_address",
        "subnet": "192.168.1.0/24",
        "comments": "Test address object"
    }


@pytest.fixture
def sample_service_data():
    """Sample service object data fixture"""
    return {
        "name": "test_service",
        "protocol": "TCP/UDP/SCTP",
        "tcp-portrange": "8080",
        "comments": "Test service object"
    }


@pytest.fixture
def sample_route_data():
    """Sample static route data fixture"""
    return {
        "dst": "10.0.0.0/8",
        "gateway": "192.168.1.1",
        "device": "port1",
        "comment": "Test static route"
    }


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def device_config():
    """Sample device configuration fixture"""
    return FortiGateDeviceConfig(
        host="192.168.1.1",
        username="admin",
        password="password",
        vdom="root",
        verify_ssl=False,
        timeout=30,
        port=443
    )
