"""
MCP Tools tests
"""

import pytest
from unittest.mock import MagicMock, patch

from src.fortigate_mcp.tools.device import DeviceTools
from src.fortigate_mcp.tools.firewall import FirewallTools
from src.fortigate_mcp.tools.network import NetworkTools
from src.fortigate_mcp.tools.routing import RoutingTools
from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI
from src.fortigate_mcp.config.models import AuthConfig


class TestDeviceTools:
    """Device Tools test sınıfı"""
    
    def setup_method(self):
        """Her test öncesi çalışan setup metodu"""
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        self.fortigate_manager = FortiGateManager({}, auth_config)
        self.device_tools = DeviceTools(self.fortigate_manager)
    
    def test_list_devices_empty(self):
        """Boş cihaz listesi testi"""
        result = self.device_tools.list_devices()
        
        assert "devices" in result[0].text
        assert "No FortiGate devices configured" in result[0].text
    
    def test_list_devices_with_devices(self):
        """Cihazları olan liste testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.device_tools.list_devices()
        
        assert "Registered FortiGate Devices" in result[0].text
        assert "test_device" in result[0].text
    
    def test_get_device_status_success(self):
        """Başarılı cihaz durumu alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_system_status.return_value = {"hostname": "FortiGate", "version": "v7.0.0"}
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.device_tools.get_device_status("test_device")
        
        assert "Device Status" in result[0].text
        assert "test_device" in result[0].text
        mock_api.get_system_status.assert_called_once()
    
    def test_get_device_status_not_found(self):
        """Olmayan cihaz durumu alma testi"""
        result = self.device_tools.get_device_status("nonexistent_device")
        
        assert "Error" in result[0].text
        assert "not found" in result[0].text
    
    def test_test_device_connection_success(self):
        """Başarılı bağlantı testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.test_connection.return_value = True
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.device_tools.test_device_connection("test_device")
        
        assert "Connection Test" in result[0].text
        assert "CONNECTED" in result[0].text
        mock_api.test_connection.assert_called_once()
    
    def test_add_device_success(self):
        """Başarılı cihaz ekleme testi"""
        result = self.device_tools.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        assert "added" in result[0].text
        assert "test_device" in result[0].text
        assert "test_device" in self.fortigate_manager.devices
    
    def test_remove_device_success(self):
        """Başarılı cihaz kaldırma testi"""
        # Önce cihaz ekle
        self.fortigate_manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        result = self.device_tools.remove_device("test_device")
        
        assert "removed" in result[0].text
        assert "test_device" not in self.fortigate_manager.devices


class TestFirewallTools:
    """Firewall Tools test sınıfı"""
    
    def setup_method(self):
        """Her test öncesi çalışan setup metodu"""
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        self.fortigate_manager = FortiGateManager({}, auth_config)
        self.firewall_tools = FirewallTools(self.fortigate_manager)
    
    def test_list_firewall_policies_success(self):
        """Başarılı firewall policy listesi alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_firewall_policies.return_value = {
            "results": [{"policyid": 1, "name": "Test_Policy"}]
        }
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.firewall_tools.list_policies("test_device")
        
        assert "Firewall Policies" in result[0].text
        assert "Test_Policy" in result[0].text
        mock_api.get_firewall_policies.assert_called_once()
    
    def test_create_firewall_policy_success(self):
        """Başarılı firewall policy oluşturma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.create_firewall_policy.return_value = {"status": "success"}
        self.fortigate_manager.devices["test_device"] = mock_api
        
        policy_data = {
            "name": "Test_Policy",
            "srcintf": [{"name": "port1"}],
            "dstintf": [{"name": "port2"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "ALL"}],
            "action": "accept"
        }
        
        result = self.firewall_tools.create_policy("test_device", policy_data)
        
        assert "created" in result[0].text
        mock_api.create_firewall_policy.assert_called_once_with(policy_data, vdom=None)


class TestNetworkTools:
    """Network Tools test sınıfı"""
    
    def setup_method(self):
        """Her test öncesi çalışan setup metodu"""
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        self.fortigate_manager = FortiGateManager({}, auth_config)
        self.network_tools = NetworkTools(self.fortigate_manager)
    
    def test_list_address_objects_success(self):
        """Başarılı address object listesi alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_address_objects.return_value = {
            "results": [{"name": "test_addr", "subnet": "192.168.1.0/24"}]
        }
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.network_tools.list_address_objects("test_device")
        
        assert "Address Objects" in result[0].text
        assert "test_addr" in result[0].text
        mock_api.get_address_objects.assert_called_once()
    
    def test_create_address_object_success(self):
        """Başarılı address object oluşturma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.create_address_object.return_value = {"status": "success"}
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.network_tools.create_address_object(
            device_id="test_device",
            name="test_addr",
            address_type="subnet",
            address="192.168.1.0/24"
        )
        
        assert "created" in result[0].text
        mock_api.create_address_object.assert_called_once()


class TestRoutingTools:
    """Routing Tools test sınıfı"""
    
    def setup_method(self):
        """Her test öncesi çalışan setup metodu"""
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        self.fortigate_manager = FortiGateManager({}, auth_config)
        self.routing_tools = RoutingTools(self.fortigate_manager)
    
    def test_list_static_routes_success(self):
        """Başarılı static route listesi alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_static_routes.return_value = {
            "results": [{"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}]
        }
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.routing_tools.list_static_routes("test_device")
        
        assert "Static Routes" in result[0].text
        assert "10.0.0.0/8" in result[0].text
        mock_api.get_static_routes.assert_called_once()
    
    def test_create_static_route_success(self):
        """Başarılı static route oluşturma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.create_static_route.return_value = {"status": "success"}
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.routing_tools.create_static_route(
            device_id="test_device",
            dst="10.0.0.0/8",
            gateway="192.168.1.1"
        )
        
        assert "created" in result[0].text
        mock_api.create_static_route.assert_called_once()
