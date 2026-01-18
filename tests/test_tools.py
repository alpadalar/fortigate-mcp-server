"""
MCP Tools tests
"""

import pytest
from unittest.mock import MagicMock, patch

from src.fortigate_mcp.tools.device import DeviceTools
from src.fortigate_mcp.tools.firewall import FirewallTools
from src.fortigate_mcp.tools.network import NetworkTools
from src.fortigate_mcp.tools.routing import RoutingTools
from src.fortigate_mcp.tools.fabric import FabricTools
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
        
        assert "Connection test successful" in result[0].text or "Connection Test" in result[0].text
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
    
    def test_get_policy_detail_success(self):
        """Başarılı policy detay alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_firewall_policy_detail.return_value = {
            "results": {
                "policyid": 35,
                "name": "WAN->ManDown-Project",
                "srcintf": [{"name": "wan1"}],
                "dstintf": [{"name": "internal"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "Yartu-1-TCP"}, {"name": "Yartu-1-UDP"}],
                "service": [{"name": "ALL"}],
                "action": "accept",
                "status": "enable"
            }
        }
        mock_api.get_address_objects.return_value = {
            "results": [{"name": "all", "subnet": "0.0.0.0 0.0.0.0"}]
        }
        mock_api.get_service_objects.return_value = {
            "results": [{"name": "ALL", "protocol": "TCP/UDP/SCTP"}]
        }
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.firewall_tools.get_policy_detail("test_device", "35")
        
        assert "Policy Detail" in result[0].text
        assert "35" in result[0].text
        assert "WAN->ManDown-Project" in result[0].text
        mock_api.get_firewall_policy_detail.assert_called_once_with("35", vdom=None)
        mock_api.get_address_objects.assert_called_once()
        mock_api.get_service_objects.assert_called_once()
    
    def test_get_policy_detail_not_found(self):
        """Olmayan policy detay alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_firewall_policy_detail.side_effect = Exception("Policy not found")
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.firewall_tools.get_policy_detail("test_device", "999")
        
        assert "Error" in result[0].text
        assert "not found" in result[0].text.lower()
    
    def test_delete_firewall_policy_success(self):
        """Başarılı firewall policy silme testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.delete_firewall_policy.return_value = {"status": "success"}
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.firewall_tools.delete_policy("test_device", "35")
        
        assert "deleted" in result[0].text
        assert "35" in result[0].text
        mock_api.delete_firewall_policy.assert_called_once_with("35", vdom=None)


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
    
    def test_list_service_objects_success(self):
        """Başarılı service object listesi alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_service_objects.return_value = {
            "results": [{"name": "HTTP", "tcp-portrange": "80"}]
        }
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.network_tools.list_service_objects("test_device")
        
        assert "Service Objects" in result[0].text
        assert "HTTP" in result[0].text
        mock_api.get_service_objects.assert_called_once()
    
    def test_create_service_object_success(self):
        """Başarılı service object oluşturma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.create_service_object.return_value = {"status": "success"}
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.network_tools.create_service_object(
            device_id="test_device",
            name="test_service",
            service_type="TCP/UDP/SCTP",
            protocol="TCP",
            port="8080"
        )
        
        assert "created" in result[0].text
        mock_api.create_service_object.assert_called_once()


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
    
    def test_list_interfaces_success(self):
        """Başarılı interface listesi alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_interfaces.return_value = {
            "results": [{"name": "port1", "status": "up"}]
        }
        self.fortigate_manager.devices["test_device"] = mock_api
        
        result = self.routing_tools.list_interfaces("test_device")
        
        assert "Interfaces" in result[0].text
        assert "port1" in result[0].text
        mock_api.get_interfaces.assert_called_once()
    
    def test_get_interface_status_success(self):
        """Başarılı interface durumu alma testi"""
        # Mock cihaz ekle
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_interface_status.return_value = {
            "results": {"name": "port1", "status": "up", "ip": "192.168.1.1"}
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.routing_tools.get_interface_status("test_device", "port1")

        assert "port1" in result[0].text
        mock_api.get_interface_status.assert_called_once_with("port1", vdom=None)


class TestFabricTools:
    """Security Fabric Tools test class"""

    def setup_method(self):
        """Setup method called before each test"""
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        self.fortigate_manager = FortiGateManager({}, auth_config)
        self.fabric_tools = FabricTools(self.fortigate_manager)

    def test_get_security_fabric_config_success(self):
        """Test successful security fabric config retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_security_fabric_config.return_value = {
            "results": {
                "status": "enable",
                "group-name": "test-fabric",
                "upstream-ip": "10.0.0.1"
            }
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_security_fabric_config("test_device")

        assert len(result) > 0
        mock_api.get_security_fabric_config.assert_called_once()

    def test_get_security_fabric_config_not_found(self):
        """Test fabric config retrieval for non-existent device"""
        result = self.fabric_tools.get_security_fabric_config("nonexistent_device")

        assert "Error" in result[0].text
        assert "not found" in result[0].text

    def test_get_security_fabric_status_success(self):
        """Test successful security fabric status retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_security_fabric_status.return_value = {
            "results": {
                "upstream": [],
                "downstream": [
                    {"name": "downstream-fw", "ip": "10.0.0.2"}
                ]
            }
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_security_fabric_status("test_device")

        assert len(result) > 0
        mock_api.get_security_fabric_status.assert_called_once()

    def test_get_fabric_devices_success(self):
        """Test successful fabric devices retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_fabric_devices.return_value = {
            "results": [
                {"name": "fabric-device-1", "device-ip": "10.0.0.3"}
            ]
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_fabric_devices("test_device")

        assert len(result) > 0
        mock_api.get_fabric_devices.assert_called_once()

    def test_get_fabric_connectors_success(self):
        """Test successful fabric connectors retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_fabric_connectors.return_value = {
            "results": [
                {"name": "azure-connector", "type": "azure"}
            ]
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_fabric_connectors("test_device")

        assert len(result) > 0
        mock_api.get_fabric_connectors.assert_called_once()

    def test_get_ha_status_success(self):
        """Test successful HA status retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_ha_status.return_value = {
            "results": [
                {"serial_no": "FG123456", "priority": 200, "role": "master"}
            ]
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_ha_status("test_device")

        assert len(result) > 0
        mock_api.get_ha_status.assert_called_once()

    def test_get_ha_config_success(self):
        """Test successful HA config retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_ha_config.return_value = {
            "results": {
                "group-name": "HA-Cluster",
                "mode": "a-p",
                "priority": 200
            }
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_ha_config("test_device")

        assert len(result) > 0
        mock_api.get_ha_config.assert_called_once()

    def test_get_fabric_topology_success(self):
        """Test successful fabric topology retrieval"""
        # Add mock device
        mock_api = MagicMock(spec=FortiGateAPI)
        mock_api.device_id = "test_device"
        mock_api.get_security_fabric_config.return_value = {
            "results": {"status": "enable", "group-name": "test-fabric"}
        }
        mock_api.get_security_fabric_status.return_value = {
            "results": {"downstream": []}
        }
        mock_api.get_fabric_devices.return_value = {
            "results": []
        }
        mock_api.get_ha_config.return_value = {
            "results": {"mode": "standalone"}
        }
        mock_api.get_ha_status.return_value = {
            "results": []
        }
        self.fortigate_manager.devices["test_device"] = mock_api

        result = self.fabric_tools.get_fabric_topology("test_device")

        assert len(result) > 0
        mock_api.get_security_fabric_config.assert_called_once()
        mock_api.get_security_fabric_status.assert_called_once()
        mock_api.get_fabric_devices.assert_called_once()
        mock_api.get_ha_config.assert_called_once()
        mock_api.get_ha_status.assert_called_once()

    def test_get_schema_info(self):
        """Test schema info retrieval"""
        schema = self.fabric_tools.get_schema_info()

        assert schema["name"] == "fabric_tools"
        assert "operations" in schema
        assert len(schema["operations"]) == 7  # All 7 fabric operations
