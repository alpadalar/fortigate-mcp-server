"""
FortiGate API tests - async client with connection pooling.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx

from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateAPIError
from src.fortigate_mcp.config.models import FortiGateDeviceConfig


class TestFortiGateAPIInit:
    """Tests for FortiGateAPI initialization."""

    def test_init_with_credentials(self):
        """Test initialization with username/password."""
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            username="admin",
            password="password"
        )
        api = FortiGateAPI("test_device", config)

        assert api.device_id == "test_device"
        assert api.config.host == "192.168.1.1"
        assert api.auth_method == "basic"
        assert api.config.vdom == "root"
        assert isinstance(api._client, httpx.AsyncClient)

    def test_init_with_token(self):
        """Test initialization with API token."""
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            api_token="test_token"
        )
        api = FortiGateAPI("test_device", config)

        assert api.device_id == "test_device"
        assert api.headers["Authorization"] == "Bearer test_token"
        assert api.auth_method == "token"

    def test_init_no_auth_raises(self):
        """Test initialization without authentication raises ValueError."""
        config = FortiGateDeviceConfig(host="192.168.1.1")

        with pytest.raises(ValueError, match="Either api_token or username/password must be provided"):
            FortiGateAPI("test_device", config)

    def test_init_creates_async_client(self):
        """Test that init creates a persistent httpx.AsyncClient."""
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            api_token="test_token",
            verify_ssl=False,
            timeout=60
        )
        api = FortiGateAPI("test_device", config)

        assert isinstance(api._client, httpx.AsyncClient)

    def test_base_url_construction(self):
        """Test base URL is constructed correctly."""
        config = FortiGateDeviceConfig(
            host="10.0.0.1",
            port=8443,
            api_token="token"
        )
        api = FortiGateAPI("dev", config)

        assert api.base_url == "https://10.0.0.1:8443/api/v2"


class TestFortiGateAPIAsync:
    """Tests for async FortiGateAPI methods."""

    @pytest.fixture(autouse=True)
    def setup(self):
        config = FortiGateDeviceConfig(
            host="192.168.1.1",
            username="admin",
            password="password",
            vdom="root",
            verify_ssl=False
        )
        self.api = FortiGateAPI("test_device", config)

    @pytest.mark.asyncio
    async def test_close(self):
        """Test async client close."""
        with patch.object(self.api._client, 'aclose', new_callable=AsyncMock) as mock_close:
            await self.api.close()
            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager protocol."""
        with patch.object(self.api._client, 'aclose', new_callable=AsyncMock):
            async with self.api as api:
                assert api is self.api

    @pytest.mark.asyncio
    async def test_make_request_success(self):
        """Test successful API request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success", "results": []}

        with patch.object(self.api._client, 'request', new_callable=AsyncMock, return_value=mock_response):
            result = await self.api._make_request("GET", "monitor/system/status")

            assert result == {"status": "success", "results": []}

    @pytest.mark.asyncio
    async def test_make_request_api_error(self):
        """Test API error response raises FortiGateAPIError."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.text = "Bad Request"

        with patch.object(self.api._client, 'request', new_callable=AsyncMock, return_value=mock_response):
            with pytest.raises(FortiGateAPIError) as exc_info:
                await self.api._make_request("GET", "invalid/endpoint")

            assert "API request failed: 400" in str(exc_info.value)
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_make_request_network_error(self):
        """Test network error raises FortiGateAPIError."""
        with patch.object(
            self.api._client, 'request',
            new_callable=AsyncMock,
            side_effect=httpx.RequestError("Connection failed")
        ):
            with pytest.raises(FortiGateAPIError) as exc_info:
                await self.api._make_request("GET", "monitor/system/status")

            assert "Network error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_make_request_vdom_parameter(self):
        """Test that vdom parameter is passed correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}

        with patch.object(self.api._client, 'request', new_callable=AsyncMock, return_value=mock_response) as mock_req:
            await self.api._make_request("GET", "cmdb/firewall/policy", vdom="custom_vdom")

            call_kwargs = mock_req.call_args
            assert call_kwargs.kwargs["params"]["vdom"] == "custom_vdom"

    @pytest.mark.asyncio
    async def test_test_connection_success(self):
        """Test successful connection test."""
        with patch.object(self.api, 'get_system_status', new_callable=AsyncMock, return_value={"status": "ok"}):
            result = await self.api.test_connection()
            assert result is True

    @pytest.mark.asyncio
    async def test_test_connection_failure(self):
        """Test failed connection test."""
        with patch.object(self.api, 'get_system_status', new_callable=AsyncMock, side_effect=Exception("Connection failed")):
            result = await self.api.test_connection()
            assert result is False

    @pytest.mark.asyncio
    async def test_get_system_status(self):
        """Test get_system_status calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"hostname": "FG"}) as mock:
            result = await self.api.get_system_status()
            assert result == {"hostname": "FG"}
            mock.assert_called_once_with("GET", "monitor/system/status", vdom=None)

    @pytest.mark.asyncio
    async def test_get_vdoms(self):
        """Test get_vdoms calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            result = await self.api.get_vdoms()
            mock.assert_called_once_with("GET", "cmdb/system/vdom")

    @pytest.mark.asyncio
    async def test_get_interfaces(self):
        """Test get_interfaces calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_interfaces()
            mock.assert_called_once_with("GET", "cmdb/system/interface", vdom=None)

    @pytest.mark.asyncio
    async def test_get_firewall_policies(self):
        """Test get_firewall_policies calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_firewall_policies()
            mock.assert_called_once_with("GET", "cmdb/firewall/policy", vdom=None)

    @pytest.mark.asyncio
    async def test_create_firewall_policy(self):
        """Test create_firewall_policy sends POST with data."""
        policy_data = {"name": "test", "action": "accept"}
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"status": "success"}) as mock:
            await self.api.create_firewall_policy(policy_data)
            mock.assert_called_once_with("POST", "cmdb/firewall/policy", data=policy_data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_firewall_policy(self):
        """Test delete_firewall_policy sends DELETE."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"status": "success"}) as mock:
            await self.api.delete_firewall_policy("5")
            mock.assert_called_once_with("DELETE", "cmdb/firewall/policy/5", vdom=None)

    @pytest.mark.asyncio
    async def test_get_address_objects(self):
        """Test get_address_objects calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_address_objects()
            mock.assert_called_once_with("GET", "cmdb/firewall/address", vdom=None)

    @pytest.mark.asyncio
    async def test_get_service_objects(self):
        """Test get_service_objects calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_service_objects()
            mock.assert_called_once_with("GET", "cmdb/firewall.service/custom", vdom=None)

    @pytest.mark.asyncio
    async def test_get_static_routes(self):
        """Test get_static_routes calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_static_routes()
            mock.assert_called_once_with("GET", "cmdb/router/static", vdom=None)

    @pytest.mark.asyncio
    async def test_get_routing_table(self):
        """Test get_routing_table calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_routing_table()
            mock.assert_called_once_with("GET", "monitor/router/ipv4", vdom=None)

    @pytest.mark.asyncio
    async def test_get_virtual_ips(self):
        """Test get_virtual_ips calls correct endpoint."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"results": []}) as mock:
            await self.api.get_virtual_ips()
            mock.assert_called_once_with("GET", "cmdb/firewall/vip", vdom=None)

    @pytest.mark.asyncio
    async def test_create_virtual_ip(self):
        """Test create_virtual_ip sends POST."""
        vip_data = {"name": "test_vip", "extip": "1.2.3.4"}
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"status": "success"}) as mock:
            await self.api.create_virtual_ip(vip_data)
            mock.assert_called_once_with("POST", "cmdb/firewall/vip", data=vip_data, vdom=None)

    @pytest.mark.asyncio
    async def test_delete_virtual_ip(self):
        """Test delete_virtual_ip sends DELETE."""
        with patch.object(self.api, '_make_request', new_callable=AsyncMock, return_value={"status": "success"}) as mock:
            await self.api.delete_virtual_ip("test_vip")
            mock.assert_called_once_with("DELETE", "cmdb/firewall/vip/test_vip", vdom=None)
