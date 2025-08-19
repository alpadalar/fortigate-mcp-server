"""
FortiGate Manager tests
"""

import pytest
from unittest.mock import patch, MagicMock

from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI, FortiGateAPIError
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig


class TestFortiGateManager:
    """FortiGate Manager sınıfı için test sınıfı"""
    
    def setup_method(self):
        """Her test öncesi çalışan setup metodu"""
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        self.manager = FortiGateManager({}, auth_config)
    
    def test_add_device_success(self):
        """Başarılı cihaz ekleme testi"""
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        assert "test_device" in self.manager.devices
        assert isinstance(self.manager.devices["test_device"], FortiGateAPI)
    
    def test_add_device_duplicate(self):
        """Duplicate cihaz ekleme testi"""
        # İlk cihazı ekle
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        # Aynı ID ile tekrar eklemeye çalış
        with pytest.raises(ValueError, match="already exists"):
            self.manager.add_device(
                device_id="test_device",
                host="192.168.1.2",
                username="admin",
                password="password"
            )
    
    def test_remove_device_success(self):
        """Başarılı cihaz kaldırma testi"""
        # Önce cihaz ekle
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        # Cihazı kaldır
        self.manager.remove_device("test_device")
        
        assert "test_device" not in self.manager.devices
    
    def test_remove_device_not_found(self):
        """Olmayan cihaz kaldırma testi"""
        with pytest.raises(ValueError, match="not found"):
            self.manager.remove_device("nonexistent_device")
    
    def test_list_devices_empty(self):
        """Boş cihaz listesi testi"""
        result = self.manager.list_devices()
        
        assert result == []
    
    def test_list_devices_with_devices(self):
        """Cihazları olan liste testi"""
        # İki cihaz ekle
        self.manager.add_device(
            device_id="test_device1",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        self.manager.add_device(
            device_id="test_device2",
            host="192.168.1.2",
            username="admin",
            password="password"
        )
        
        result = self.manager.list_devices()
        
        assert len(result) == 2
        assert "test_device1" in result
        assert "test_device2" in result
    
    def test_get_device_success(self):
        """Başarılı cihaz alma testi"""
        # Cihaz ekle
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        
        # Cihazı al
        device = self.manager.get_device("test_device")
        
        assert isinstance(device, FortiGateAPI)
        assert device.device_id == "test_device"
    
    def test_get_device_not_found(self):
        """Olmayan cihaz alma testi"""
        with pytest.raises(ValueError, match="not found"):
            self.manager.get_device("nonexistent_device")
    
    def test_test_all_connections(self, mock_fortigate_api):
        """Tüm bağlantıları test etme"""
        # Mock cihaz ekle
        self.manager.devices["test_device"] = mock_fortigate_api
        
        result = self.manager.test_all_connections()
        
        assert "test_device" in result
        assert result["test_device"] is True
