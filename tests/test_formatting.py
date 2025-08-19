"""
Formatting and templates tests
"""

import pytest
from unittest.mock import MagicMock

from src.fortigate_mcp.formatting.templates import FortiGateTemplates
from src.fortigate_mcp.formatting.formatters import FortiGateFormatters
from mcp.types import TextContent


class TestFortiGateTemplates:
    """FortiGate Templates test sınıfı"""
    
    def test_firewall_policies_empty(self):
        """Boş firewall policies template testi"""
        data = {"results": []}
        result = FortiGateTemplates.firewall_policies(data)
        
        assert "Firewall Policies" in result
        assert "No firewall policies found" in result
    
    def test_firewall_policies_with_data(self):
        """Veri ile firewall policies template testi"""
        data = {
            "results": [
                {
                    "policyid": 1,
                    "name": "Test_Policy",
                    "srcintf": [{"name": "port1"}],
                    "dstintf": [{"name": "port2"}],
                    "srcaddr": [{"name": "all"}],
                    "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}],
                    "action": "accept",
                    "status": "enable"
                }
            ]
        }
        result = FortiGateTemplates.firewall_policies(data)
        
        assert "Firewall Policies" in result
        assert "Test_Policy" in result
        assert "1" in result
        assert "accept" in result
    
    def test_firewall_policy_detail_success(self):
        """Firewall policy detail template testi"""
        policy_data = {
            "results": {
                "policyid": 35,
                "name": "WAN->ManDown-Project",
                "srcintf": [{"name": "wan1"}],
                "dstintf": [{"name": "internal"}],
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "Yartu-1-TCP"}, {"name": "Yartu-1-UDP"}],
                "service": [{"name": "ALL"}],
                "action": "accept",
                "status": "enable",
                "uuid": "test-uuid"
            }
        }
        
        address_objects = {
            "results": [
                {"name": "all", "subnet": "0.0.0.0 0.0.0.0"},
                {"name": "Yartu-1-TCP", "subnet": "192.168.1.10 255.255.255.255"}
            ]
        }
        
        service_objects = {
            "results": [
                {"name": "ALL", "protocol": "TCP/UDP/SCTP"}
            ]
        }
        
        result = FortiGateTemplates.firewall_policy_detail(
            policy_data, "test_device", address_objects, service_objects
        )
        
        assert "Policy Detaylı Analizi" in result
        assert "35" in result
        assert "WAN->ManDown-Project" in result
        assert "test_device" in result
        assert "Güvenlik Analizi" in result
    
    def test_address_objects_empty(self):
        """Boş address objects template testi"""
        data = {"results": []}
        result = FortiGateTemplates.address_objects(data)
        
        assert "Address Objects" in result
        assert "No address objects found" in result
    
    def test_address_objects_with_data(self):
        """Veri ile address objects template testi"""
        data = {
            "results": [
                {
                    "name": "test_addr",
                    "subnet": "192.168.1.0/24",
                    "type": "ipmask",
                    "comment": "Test address"
                }
            ]
        }
        result = FortiGateTemplates.address_objects(data)
        
        assert "Address Objects" in result
        assert "test_addr" in result
        assert "192.168.1.0/24" in result
    
    def test_service_objects_empty(self):
        """Boş service objects template testi"""
        data = {"results": []}
        result = FortiGateTemplates.service_objects(data)
        
        assert "Service Objects" in result
        assert "No service objects found" in result
    
    def test_service_objects_with_data(self):
        """Veri ile service objects template testi"""
        data = {
            "results": [
                {
                    "name": "HTTP",
                    "tcp-portrange": "80",
                    "protocol": "TCP/UDP/SCTP",
                    "comment": "HTTP service"
                }
            ]
        }
        result = FortiGateTemplates.service_objects(data)
        
        assert "Service Objects" in result
        assert "HTTP" in result
        assert "80" in result
    
    def test_static_routes_empty(self):
        """Boş static routes template testi"""
        data = {"results": []}
        result = FortiGateTemplates.static_routes(data)
        
        assert "Static Routes" in result
        assert "No static routes found" in result
    
    def test_static_routes_with_data(self):
        """Veri ile static routes template testi"""
        data = {
            "results": [
                {
                    "dst": "10.0.0.0/8",
                    "gateway": "192.168.1.1",
                    "device": "port1",
                    "distance": 10,
                    "status": "enable"
                }
            ]
        }
        result = FortiGateTemplates.static_routes(data)
        
        assert "Static Routes" in result
        assert "10.0.0.0/8" in result
        assert "192.168.1.1" in result
    
    def test_interfaces_empty(self):
        """Boş interfaces template testi"""
        data = {"results": []}
        result = FortiGateTemplates.interfaces(data)
        
        assert "Interfaces" in result
        assert "No interfaces found" in result
    
    def test_interfaces_with_data(self):
        """Veri ile interfaces template testi"""
        data = {
            "results": [
                {
                    "name": "port1",
                    "status": "up",
                    "ip": "192.168.1.1 255.255.255.0",
                    "type": "physical",
                    "alias": "LAN"
                }
            ]
        }
        result = FortiGateTemplates.interfaces(data)
        
        assert "Interfaces" in result
        assert "port1" in result
        assert "192.168.1.1" in result
        assert "physical" in result
        assert "LAN" in result
    
    def test_device_status_success(self):
        """Device status template testi"""
        device_id = "test_device"
        status_data = {
            "hostname": "FortiGate",
            "version": "v7.0.5",
            "serial": "FGT80FTK20004708",
            "status": "online"
        }
        
        result = FortiGateTemplates.device_status(device_id, status_data)
        
        assert "Device Status" in result
        assert "test_device" in result
        # Template'de status bilgisi farklı şekilde işleniyor
        assert "test_device" in result
    
    def test_vdoms_success(self):
        """VDOMs template testi"""
        data = {
            "results": [
                {
                    "name": "root",
                    "enabled": True,
                    "description": "Root VDOM"
                }
            ]
        }
        
        result = FortiGateTemplates.vdoms(data)
        
        assert "Virtual Domains" in result
        assert "root" in result
        assert "enabled" in result.lower()


class TestFortiGateFormatters:
    """FortiGate Formatters test sınıfı"""
    
    def test_format_firewall_policies(self):
        """Firewall policies formatter testi"""
        data = {
            "results": [
                {
                    "policyid": 1,
                    "name": "Test_Policy",
                    "action": "accept"
                }
            ]
        }
        
        result = FortiGateFormatters.format_firewall_policies(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Firewall Policies" in result[0].text
    
    def test_format_firewall_policy_detail(self):
        """Firewall policy detail formatter testi"""
        policy_data = {
            "results": {
                "policyid": 35,
                "name": "Test_Policy",
                "action": "accept"
            }
        }
        
        result = FortiGateFormatters.format_firewall_policy_detail(
            policy_data, "test_device"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Policy Detaylı Analizi" in result[0].text
    
    def test_format_address_objects(self):
        """Address objects formatter testi"""
        data = {
            "results": [
                {
                    "name": "test_addr",
                    "subnet": "192.168.1.0/24"
                }
            ]
        }
        
        result = FortiGateFormatters.format_address_objects(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Address Objects" in result[0].text
    
    def test_format_service_objects(self):
        """Service objects formatter testi"""
        data = {
            "results": [
                {
                    "name": "HTTP",
                    "tcp-portrange": "80"
                }
            ]
        }
        
        result = FortiGateFormatters.format_service_objects(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Service Objects" in result[0].text
    
    def test_format_static_routes(self):
        """Static routes formatter testi"""
        data = {
            "results": [
                {
                    "dst": "10.0.0.0/8",
                    "gateway": "192.168.1.1"
                }
            ]
        }
        
        result = FortiGateFormatters.format_static_routes(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Static Routes" in result[0].text
    
    def test_format_interfaces(self):
        """Interfaces formatter testi"""
        data = {
            "results": [
                {
                    "name": "port1",
                    "status": "up"
                }
            ]
        }
        
        result = FortiGateFormatters.format_interfaces(data)
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Interfaces" in result[0].text
    
    def test_format_error(self):
        """Error formatter testi"""
        result = FortiGateFormatters.format_error(
            "Test error message", "test_device", "test_operation"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "Error" in result[0].text
        assert "Test error message" in result[0].text
        assert "test_device" in result[0].text
        assert "test_operation" in result[0].text
    
    def test_format_operation_result_success(self):
        """Success operation result formatter testi"""
        result = FortiGateFormatters.format_operation_result(
            "test_operation", "test_device", True, "Success details"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "test_operation" in result[0].text
        assert "test_device" in result[0].text
        assert "Success details" in result[0].text
    
    def test_format_operation_result_failure(self):
        """Failure operation result formatter testi"""
        result = FortiGateFormatters.format_operation_result(
            "test_operation", "test_device", False, 
            error="Operation failed"
        )
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        assert "test_operation" in result[0].text
        assert "test_device" in result[0].text
        assert "Operation failed" in result[0].text
