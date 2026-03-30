"""
MCP Tools tests - async tool implementations.
"""

import pytest
from unittest.mock import AsyncMock

from src.fortigate_mcp.tools.device import DeviceTools
from src.fortigate_mcp.tools.firewall import FirewallTools
from src.fortigate_mcp.tools.network import NetworkTools
from src.fortigate_mcp.tools.routing import RoutingTools
from src.fortigate_mcp.tools.virtual_ip import VirtualIPTools


class TestDeviceTools:
    """Device Tools tests - all async."""

    @pytest.fixture(autouse=True)
    def setup(self, fortigate_manager):
        self.fortigate_manager = fortigate_manager
        self.device_tools = DeviceTools(fortigate_manager)

    @pytest.mark.asyncio
    async def test_list_devices_empty(self):
        """Test listing when no devices configured."""
        result = await self.device_tools.list_devices()

        assert "No FortiGate devices configured" in result[0].text

    @pytest.mark.asyncio
    async def test_list_devices_with_devices(self, mock_fortigate_api):
        """Test listing registered devices."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.device_tools.list_devices()

        assert "Registered FortiGate Devices" in result[0].text
        assert "test_device" in result[0].text

    @pytest.mark.asyncio
    async def test_get_device_status_success(self, mock_fortigate_api):
        """Test getting device status."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.device_tools.get_device_status("test_device")

        assert "Device Status" in result[0].text
        assert "test_device" in result[0].text
        mock_fortigate_api.get_system_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_device_status_not_found(self):
        """Test getting status for nonexistent device."""
        result = await self.device_tools.get_device_status("nonexistent_device")

        assert "Error" in result[0].text
        assert "not found" in result[0].text

    @pytest.mark.asyncio
    async def test_test_device_connection_success(self, mock_fortigate_api):
        """Test successful connection test."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.device_tools.test_device_connection("test_device")

        assert "Connection test successful" in result[0].text
        mock_fortigate_api.test_connection.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_device_connection_failure(self, mock_fortigate_api):
        """Test failed connection test."""
        mock_fortigate_api.test_connection = AsyncMock(return_value=False)
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.device_tools.test_device_connection("test_device")

        assert "Connection test failed" in result[0].text

    @pytest.mark.asyncio
    async def test_add_device_success(self):
        """Test successfully adding a device."""
        result = await self.device_tools.add_device(
            device_id="new_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )

        assert "added" in result[0].text
        assert "new_device" in result[0].text
        assert "new_device" in self.fortigate_manager.devices

    @pytest.mark.asyncio
    async def test_add_device_duplicate(self, mock_fortigate_api):
        """Test adding a device that already exists."""
        self.fortigate_manager.devices["existing"] = mock_fortigate_api

        result = await self.device_tools.add_device(
            device_id="existing",
            host="192.168.1.1",
            username="admin",
            password="password"
        )

        assert "already exists" in result[0].text

    @pytest.mark.asyncio
    async def test_remove_device_success(self, mock_fortigate_api):
        """Test successfully removing a device."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.device_tools.remove_device("test_device")

        assert "removed" in result[0].text
        assert "test_device" not in self.fortigate_manager.devices

    @pytest.mark.asyncio
    async def test_remove_device_not_found(self):
        """Test removing nonexistent device."""
        result = await self.device_tools.remove_device("nonexistent")

        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_discover_vdoms(self, mock_fortigate_api):
        """Test VDOM discovery."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.device_tools.discover_vdoms("test_device")

        assert "Virtual Domains" in result[0].text
        mock_fortigate_api.get_vdoms.assert_called_once()


class TestFirewallTools:
    """Firewall Tools tests - all async."""

    @pytest.fixture(autouse=True)
    def setup(self, fortigate_manager):
        self.fortigate_manager = fortigate_manager
        self.firewall_tools = FirewallTools(fortigate_manager)

    @pytest.mark.asyncio
    async def test_list_policies(self, mock_fortigate_api):
        """Test listing firewall policies."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.firewall_tools.list_policies("test_device")

        assert "Firewall Policies" in result[0].text
        mock_fortigate_api.get_firewall_policies.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_policy(self, mock_fortigate_api, sample_policy_data):
        """Test creating a firewall policy."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.firewall_tools.create_policy("test_device", sample_policy_data)

        assert "created" in result[0].text
        mock_fortigate_api.create_firewall_policy.assert_called_once_with(sample_policy_data, vdom=None)

    @pytest.mark.asyncio
    async def test_update_policy(self, mock_fortigate_api):
        """Test updating a firewall policy."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api
        update_data = {"action": "deny"}

        result = await self.firewall_tools.update_policy("test_device", "5", update_data)

        assert "updated" in result[0].text
        mock_fortigate_api.update_firewall_policy.assert_called_once_with("5", update_data, vdom=None)

    @pytest.mark.asyncio
    async def test_get_policy_detail(self, mock_fortigate_api):
        """Test getting policy detail with address/service resolution."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.firewall_tools.get_policy_detail("test_device", "35")

        assert "Policy Detail" in result[0].text
        mock_fortigate_api.get_firewall_policy_detail.assert_called_once_with("35", vdom=None)
        mock_fortigate_api.get_address_objects.assert_called_once()
        mock_fortigate_api.get_service_objects.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_policy_detail_not_found(self, mock_fortigate_api):
        """Test getting detail for nonexistent policy."""
        mock_fortigate_api.get_firewall_policy_detail = AsyncMock(
            side_effect=Exception("Policy not found")
        )
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.firewall_tools.get_policy_detail("test_device", "999")

        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_delete_policy(self, mock_fortigate_api):
        """Test deleting a firewall policy."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.firewall_tools.delete_policy("test_device", "35")

        assert "deleted" in result[0].text
        mock_fortigate_api.delete_firewall_policy.assert_called_once_with("35", vdom=None)

    @pytest.mark.asyncio
    async def test_list_policies_device_not_found(self):
        """Test listing policies for nonexistent device."""
        result = await self.firewall_tools.list_policies("nonexistent")

        assert "Error" in result[0].text
        assert "not found" in result[0].text

    @pytest.mark.asyncio
    async def test_create_policy_with_vdom(self, mock_fortigate_api, sample_policy_data):
        """Test creating policy with explicit VDOM."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.firewall_tools.create_policy("test_device", sample_policy_data, vdom="custom_vdom")

        mock_fortigate_api.create_firewall_policy.assert_called_once_with(sample_policy_data, vdom="custom_vdom")


class TestNetworkTools:
    """Network Tools tests - all async."""

    @pytest.fixture(autouse=True)
    def setup(self, fortigate_manager):
        self.fortigate_manager = fortigate_manager
        self.network_tools = NetworkTools(fortigate_manager)

    @pytest.mark.asyncio
    async def test_list_address_objects(self, mock_fortigate_api):
        """Test listing address objects."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.network_tools.list_address_objects("test_device")

        assert "Address Objects" in result[0].text
        assert "test_addr" in result[0].text
        mock_fortigate_api.get_address_objects.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_address_object(self, mock_fortigate_api):
        """Test creating an address object."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.network_tools.create_address_object(
            device_id="test_device",
            name="test_addr",
            address_type="subnet",
            address="192.168.1.0/24"
        )

        assert "created" in result[0].text
        mock_fortigate_api.create_address_object.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_service_objects(self, mock_fortigate_api):
        """Test listing service objects."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.network_tools.list_service_objects("test_device")

        assert "Service Objects" in result[0].text
        assert "HTTP" in result[0].text
        mock_fortigate_api.get_service_objects.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_service_object(self, mock_fortigate_api):
        """Test creating a service object."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.network_tools.create_service_object(
            device_id="test_device",
            name="test_svc",
            service_type="TCP/UDP/SCTP",
            protocol="TCP",
            port="8080"
        )

        assert "created" in result[0].text
        mock_fortigate_api.create_service_object.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_address_objects_device_not_found(self):
        """Test listing address objects for nonexistent device."""
        result = await self.network_tools.list_address_objects("nonexistent")

        assert "Error" in result[0].text


class TestRoutingTools:
    """Routing Tools tests - all async."""

    @pytest.fixture(autouse=True)
    def setup(self, fortigate_manager):
        self.fortigate_manager = fortigate_manager
        self.routing_tools = RoutingTools(fortigate_manager)

    @pytest.mark.asyncio
    async def test_list_static_routes(self, mock_fortigate_api):
        """Test listing static routes."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.list_static_routes("test_device")

        assert "Static Routes" in result[0].text
        assert "10.0.0.0/8" in result[0].text
        mock_fortigate_api.get_static_routes.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_static_route(self, mock_fortigate_api):
        """Test creating a static route."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.create_static_route(
            device_id="test_device",
            dst="10.0.0.0/8",
            gateway="192.168.1.1"
        )

        assert "created" in result[0].text
        mock_fortigate_api.create_static_route.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_interfaces(self, mock_fortigate_api):
        """Test listing interfaces."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.list_interfaces("test_device")

        assert "Interfaces" in result[0].text
        mock_fortigate_api.get_interfaces.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_interface_status(self, mock_fortigate_api):
        """Test getting interface status."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.get_interface_status("test_device", "port1")

        assert "port1" in result[0].text
        mock_fortigate_api.get_interface_status.assert_called_once_with("port1", vdom=None)

    @pytest.mark.asyncio
    async def test_get_routing_table(self, mock_fortigate_api):
        """Test getting routing table."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.get_routing_table("test_device")

        assert len(result) > 0
        assert result[0].text is not None
        mock_fortigate_api.get_routing_table.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_static_route(self, mock_fortigate_api):
        """Test updating a static route."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api
        route_data = {"gateway": "192.168.2.1"}

        result = await self.routing_tools.update_static_route("test_device", "1", route_data)

        assert "updated" in result[0].text
        mock_fortigate_api.update_static_route.assert_called_once_with("1", route_data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_static_route(self, mock_fortigate_api):
        """Test deleting a static route."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.delete_static_route("test_device", "1")

        assert "deleted" in result[0].text
        mock_fortigate_api.delete_static_route.assert_called_once_with("1", vdom=None)

    @pytest.mark.asyncio
    async def test_get_static_route_detail(self, mock_fortigate_api):
        """Test getting static route detail."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.routing_tools.get_static_route_detail("test_device", "1")

        assert len(result) > 0
        assert result[0].text is not None
        mock_fortigate_api.get_static_route_detail.assert_called_once_with("1", vdom=None)


class TestVirtualIPTools:
    """Virtual IP Tools tests - all async."""

    @pytest.fixture(autouse=True)
    def setup(self, fortigate_manager):
        self.fortigate_manager = fortigate_manager
        self.vip_tools = VirtualIPTools(fortigate_manager)

    @pytest.mark.asyncio
    async def test_list_virtual_ips(self, mock_fortigate_api):
        """Test listing virtual IPs."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.vip_tools.list_virtual_ips("test_device")

        assert len(result) > 0
        assert result[0].text is not None
        mock_fortigate_api.get_virtual_ips.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_virtual_ip(self, mock_fortigate_api):
        """Test creating a virtual IP."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.vip_tools.create_virtual_ip(
            device_id="test_device",
            name="test_vip",
            extip="1.2.3.4",
            mappedip="10.0.0.1",
            extintf="wan1"
        )

        assert "created" in result[0].text
        mock_fortigate_api.create_virtual_ip.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_virtual_ip(self, mock_fortigate_api):
        """Test updating a virtual IP."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api
        update_data = {"extip": "5.6.7.8"}

        result = await self.vip_tools.update_virtual_ip("test_device", "test_vip", update_data)

        assert "updated" in result[0].text
        mock_fortigate_api.update_virtual_ip.assert_called_once_with("test_vip", update_data, vdom=None)

    @pytest.mark.asyncio
    async def test_get_virtual_ip_detail(self, mock_fortigate_api):
        """Test getting virtual IP detail."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.vip_tools.get_virtual_ip_detail("test_device", "test_vip")

        assert len(result) > 0
        assert result[0].text is not None
        mock_fortigate_api.get_virtual_ip_detail.assert_called_once_with("test_vip", vdom=None)

    @pytest.mark.asyncio
    async def test_delete_virtual_ip(self, mock_fortigate_api):
        """Test deleting a virtual IP."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.vip_tools.delete_virtual_ip("test_device", "test_vip")

        assert "deleted" in result[0].text
        mock_fortigate_api.delete_virtual_ip.assert_called_once_with("test_vip", vdom=None)

    @pytest.mark.asyncio
    async def test_list_virtual_ips_device_not_found(self):
        """Test listing VIPs for nonexistent device."""
        result = await self.vip_tools.list_virtual_ips("nonexistent")

        assert "Error" in result[0].text

    @pytest.mark.asyncio
    async def test_create_virtual_ip_with_port_forward(self, mock_fortigate_api):
        """Test creating VIP with port forwarding."""
        self.fortigate_manager.devices["test_device"] = mock_fortigate_api

        result = await self.vip_tools.create_virtual_ip(
            device_id="test_device",
            name="web_vip",
            extip="1.2.3.4",
            mappedip="10.0.0.1",
            extintf="wan1",
            portforward="enable",
            protocol="tcp",
            extport="443",
            mappedport="8443"
        )

        assert "created" in result[0].text
        # Verify the VIP data includes port forwarding details
        call_args = mock_fortigate_api.create_virtual_ip.call_args
        vip_data = call_args[0][0]
        assert vip_data["portforward"] == "enable"
        assert vip_data["extport"] == "443"
        assert vip_data["mappedport"] == "8443"
