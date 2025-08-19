"""
FortiGate API tests
"""

import pytest
from unittest.mock import patch, MagicMock
import httpx

from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateAPIError
from src.fortigate_mcp.config.models import FortiGateDeviceConfig


class TestFortiGateAPI:
    """FortiGate API sınıfı için test sınıfı"""
    
    def setup_method(self):
        """Her test öncesi çalışan setup metodu"""
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            username="admin",
            password="password",
            vdom="root"
        )
        self.api = FortiGateAPI("test_device", config)
    
    def test_init_with_credentials(self):
        """Username/password ile başlatma testi"""
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        api = FortiGateAPI("test_device", config)
        
        assert api.device_id == "test_device"
        assert api.config.host == "192.168.1.1"
        assert api.config.username == "admin"
        assert api.config.password == "password"
        assert api.auth_method == "basic"
        assert api.config.vdom == "root"
    
    def test_init_with_token(self):
        """API token ile başlatma testi"""
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            api_token="test_token"
        )
        api = FortiGateAPI("test_device", config)
        
        assert api.device_id == "test_device"
        assert api.config.host == "192.168.1.1"
        assert api.headers["Authorization"] == "Bearer test_token"
        assert api.auth_method == "token"
    
    def test_init_no_auth(self):
        """Kimlik doğrulama bilgisi olmadan başlatma testi"""
        config = FortiGateDeviceConfig(host="192.168.1.1")
        
        with pytest.raises(ValueError, match="Either api_token or username/password must be provided"):
            FortiGateAPI("test_device", config)
    
    def test_make_request_success(self):
        """Başarılı API request testi"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success", "results": []}
        
        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response
            
            result = self.api._make_request("GET", "monitor/system/status")
            
            assert result == {"status": "success", "results": []}
            mock_client.request.assert_called_once()
    
    def test_make_request_api_error(self):
        """API error response testi"""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.text = "Bad Request"
        
        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response
            
            with pytest.raises(FortiGateAPIError) as exc_info:
                self.api._make_request("GET", "invalid/endpoint")
            
            assert "API request failed: 400" in str(exc_info.value)
            assert exc_info.value.status_code == 400
    
    def test_make_request_network_error(self):
        """Network error testi"""
        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.side_effect = httpx.RequestError("Connection failed")
            
            with pytest.raises(FortiGateAPIError) as exc_info:
                self.api._make_request("GET", "monitor/system/status")
            
            assert "Network error" in str(exc_info.value)
    
    def test_test_connection_success(self):
        """Başarılı bağlantı testi"""
        with patch.object(self.api, 'get_system_status') as mock_status:
            mock_status.return_value = {"status": "ok"}
            
            result = self.api.test_connection()
            
            assert result is True
            mock_status.assert_called_once()
    
    def test_test_connection_failure(self):
        """Başarısız bağlantı testi"""
        with patch.object(self.api, 'get_system_status') as mock_status:
            mock_status.side_effect = Exception("Connection failed")
            
            result = self.api.test_connection()
            
            assert result is False
    
    def test_get_system_status(self):
        """Sistem durumu alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"hostname": "FortiGate", "version": "v7.0.0"}
            
            result = self.api.get_system_status()
            
            assert result == {"hostname": "FortiGate", "version": "v7.0.0"}
            mock_request.assert_called_once_with("GET", "monitor/system/status", vdom=None)
    
    def test_get_vdoms(self):
        """VDOM listesi alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"name": "root"}]}
            
            result = self.api.get_vdoms()
            
            assert result == {"results": [{"name": "root"}]}
            mock_request.assert_called_once_with("GET", "cmdb/system/vdom")
    
    def test_get_interfaces(self):
        """Interface listesi alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"name": "port1"}]}
            
            result = self.api.get_interfaces()
            
            assert result == {"results": [{"name": "port1"}]}
            mock_request.assert_called_once_with("GET", "cmdb/system/interface", vdom=None)
    
    def test_get_firewall_policies(self):
        """Firewall policy listesi alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"policyid": 1}]}
            
            result = self.api.get_firewall_policies()
            
            assert result == {"results": [{"policyid": 1}]}
            mock_request.assert_called_once_with("GET", "cmdb/firewall/policy", vdom=None)
    
    def test_get_address_objects(self):
        """Address object listesi alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"name": "test_addr"}]}
            
            result = self.api.get_address_objects()
            
            assert result == {"results": [{"name": "test_addr"}]}
            mock_request.assert_called_once_with("GET", "cmdb/firewall/address", vdom=None)
    
    def test_get_service_objects(self):
        """Service object listesi alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"name": "HTTP"}]}
            
            result = self.api.get_service_objects()
            
            assert result == {"results": [{"name": "HTTP"}]}
            mock_request.assert_called_once_with("GET", "cmdb/firewall.service/custom", vdom=None)
    
    def test_get_static_routes(self):
        """Static route listesi alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"dst": "10.0.0.0/8"}]}
            
            result = self.api.get_static_routes()
            
            assert result == {"results": [{"dst": "10.0.0.0/8"}]}
            mock_request.assert_called_once_with("GET", "cmdb/router/static", vdom=None)
    
    def test_get_routing_table(self):
        """Routing table alma testi"""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"results": [{"dst": "0.0.0.0/0"}]}
            
            result = self.api.get_routing_table()
            
            assert result == {"results": [{"dst": "0.0.0.0/0"}]}
            mock_request.assert_called_once_with("GET", "monitor/router/ipv4", vdom=None)
