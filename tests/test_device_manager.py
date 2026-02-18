"""
FortiGate Manager tests - device lifecycle and async operations.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI, FortiGateAPIError
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig


class TestFortiGateManager:
    """FortiGate Manager tests."""

    @pytest.fixture(autouse=True)
    def setup(self, auth_config):
        self.manager = FortiGateManager({}, auth_config)

    def test_add_device_success(self):
        """Test successful device addition."""
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )

        assert "test_device" in self.manager.devices
        assert isinstance(self.manager.devices["test_device"], FortiGateAPI)

    def test_add_device_duplicate_raises(self):
        """Test adding duplicate device raises ValueError."""
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )

        with pytest.raises(ValueError, match="already exists"):
            self.manager.add_device(
                device_id="test_device",
                host="192.168.1.2",
                username="admin",
                password="password"
            )

    def test_add_device_with_token(self):
        """Test adding device with API token auth."""
        self.manager.add_device(
            device_id="token_device",
            host="192.168.1.1",
            api_token="my_token"
        )

        assert "token_device" in self.manager.devices
        assert self.manager.devices["token_device"].auth_method == "token"

    @pytest.mark.asyncio
    async def test_remove_device_success(self, mock_fortigate_api):
        """Test successful async device removal."""
        self.manager.devices["test_device"] = mock_fortigate_api

        await self.manager.remove_device("test_device")

        assert "test_device" not in self.manager.devices
        mock_fortigate_api.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_device_not_found_raises(self):
        """Test removing nonexistent device raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            await self.manager.remove_device("nonexistent_device")

    def test_list_devices_empty(self):
        """Test listing devices when none registered."""
        result = self.manager.list_devices()
        assert result == []

    def test_list_devices_with_devices(self):
        """Test listing multiple registered devices."""
        self.manager.add_device(
            device_id="device1",
            host="192.168.1.1",
            username="admin",
            password="pass"
        )
        self.manager.add_device(
            device_id="device2",
            host="192.168.1.2",
            username="admin",
            password="pass"
        )

        result = self.manager.list_devices()

        assert len(result) == 2
        assert "device1" in result
        assert "device2" in result

    def test_get_device_success(self):
        """Test getting a registered device."""
        self.manager.add_device(
            device_id="test_device",
            host="192.168.1.1",
            username="admin",
            password="password"
        )

        device = self.manager.get_device("test_device")

        assert isinstance(device, FortiGateAPI)
        assert device.device_id == "test_device"

    def test_get_device_not_found_raises(self):
        """Test getting nonexistent device raises ValueError."""
        with pytest.raises(ValueError, match="not found"):
            self.manager.get_device("nonexistent_device")

    @pytest.mark.asyncio
    async def test_test_all_connections(self, mock_fortigate_api):
        """Test testing all device connections."""
        self.manager.devices["test_device"] = mock_fortigate_api

        result = await self.manager.test_all_connections()

        assert "test_device" in result
        assert result["test_device"] is True

    @pytest.mark.asyncio
    async def test_test_all_connections_with_failure(self, mock_fortigate_api):
        """Test all connections when one fails."""
        mock_fortigate_api.test_connection = AsyncMock(side_effect=Exception("fail"))
        self.manager.devices["test_device"] = mock_fortigate_api

        result = await self.manager.test_all_connections()

        assert result["test_device"] is False

    @pytest.mark.asyncio
    async def test_close_all(self, mock_fortigate_api):
        """Test closing all device connections."""
        mock_api2 = MagicMock()
        mock_api2.close = AsyncMock()

        self.manager.devices["dev1"] = mock_fortigate_api
        self.manager.devices["dev2"] = mock_api2

        await self.manager.close_all()

        mock_fortigate_api.close.assert_called_once()
        mock_api2.close.assert_called_once()

    def test_init_with_device_configs(self, auth_config):
        """Test manager initialization with pre-defined device configs."""
        devices = {
            "fw1": FortiGateDeviceConfig(
                host="192.168.1.1",
                api_token="token1",
                verify_ssl=False
            )
        }
        manager = FortiGateManager(devices, auth_config)

        assert "fw1" in manager.devices
        assert isinstance(manager.devices["fw1"], FortiGateAPI)
