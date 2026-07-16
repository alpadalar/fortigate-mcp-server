"""
FortiGate API tests
"""

import pytest
from unittest.mock import patch, MagicMock
import httpx

from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateAPIError, FortiGateManager
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig
from src.fortigate_mcp.tools.firewall import FirewallTools


# 13 identifier-bearing FortiGateAPI methods x their expected dispatch shape:
# (method_name, valid_id, expected_verb, expected_endpoint, extra_positional_args)
ENDPOINT_MATRIX = [
    ("update_firewall_policy", "1", "PUT", "cmdb/firewall/policy/1", ({},)),
    ("get_firewall_policy_detail", "1", "GET", "cmdb/firewall/policy/1", ()),
    ("delete_firewall_policy", "1", "DELETE", "cmdb/firewall/policy/1", ()),
    ("update_address_object", "obj1", "PUT", "cmdb/firewall/address/obj1", ({},)),
    ("delete_address_object", "obj1", "DELETE", "cmdb/firewall/address/obj1", ()),
    ("update_service_object", "obj1", "PUT", "cmdb/firewall.service/custom/obj1", ({},)),
    ("delete_service_object", "obj1", "DELETE", "cmdb/firewall.service/custom/obj1", ()),
    ("update_static_route", "1", "PUT", "cmdb/router/static/1", ({},)),
    ("delete_static_route", "1", "DELETE", "cmdb/router/static/1", ()),
    ("get_static_route_detail", "1", "GET", "cmdb/router/static/1", ()),
    ("update_virtual_ip", "obj1", "PUT", "cmdb/firewall/vip/obj1", ({},)),
    ("delete_virtual_ip", "obj1", "DELETE", "cmdb/firewall/vip/obj1", ()),
    ("get_virtual_ip_detail", "obj1", "GET", "cmdb/firewall/vip/obj1", ()),
]

# Injection-shaped corpus: path traversal, CRLF, query/fragment characters, space.
INJECTION_CORPUS = ["../", "%0d%0a", "?", "#", "bad name", "bad\r\nname"]


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
        assert api.config.password.get_secret_value() == "password"
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

    def test_get_interface_status_uses_params_and_allows_vlan_names(self):
        """VLAN subinterface names with dots (e.g. port1.100) must pass, and
        the value must reach FortiGate via httpx params= (not a raw query
        string)."""
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"status": "up"}

            result = self.api.get_interface_status("port1.100")

            assert result == {"status": "up"}
            mock_request.assert_called_once_with(
                "GET", "monitor/system/interface", params={"interface": "port1.100"}, vdom=None
            )

    def test_get_interface_status_rejects_injection(self):
        """Injection-shaped interface names raise before any request."""
        with pytest.raises(ValueError):
            self.api.get_interface_status("../")

    def test_make_request_rejects_empty_vdom(self):
        """An explicit empty-string vdom override must be rejected, never
        silently swapped for the device default."""
        with pytest.raises(ValueError):
            self.api._make_request("GET", "monitor/system/status", vdom="")

    def test_make_request_rejects_invalid_vdom(self):
        with pytest.raises(ValueError):
            self.api._make_request("GET", "monitor/system/status", vdom="bad vdom!")

    def test_make_request_none_vdom_falls_back_to_config_default(self):
        """vdom=None still resolves to the validated config default ('root')."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}

        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response

            self.api._make_request("GET", "monitor/system/status", vdom=None)

            _, call_kwargs = mock_client.request.call_args
            assert call_kwargs["params"]["vdom"] == "root"

    def test_base_url_ipv6_bracketed(self):
        config = FortiGateDeviceConfig(
            host="2001:db8::1",
            api_token="test-token-not-real",
        )
        api = FortiGateAPI("test_device", config)

        assert api.base_url == "https://[2001:db8::1]:443/api/v2"

    def test_base_url_ipv4_unchanged(self):
        config = FortiGateDeviceConfig(
            host="198.51.100.10",
            api_token="test-token-not-real",
        )
        api = FortiGateAPI("test_device", config)

        assert api.base_url == "https://198.51.100.10:443/api/v2"


class TestFortiGateAPIInjectionRejection:
    """Negative proof: EVERY one of the 13 identifier-bearing FortiGateAPI
    methods rejects EVERY corpus value before any HTTP request is attempted
    (13 methods x 6 corpus values = 78 parametrized cases)."""

    def setup_method(self):
        config = FortiGateDeviceConfig(
            host="198.51.100.10",
            api_token="test-token-not-real",
            vdom="root",
        )
        self.api = FortiGateAPI("test_device", config)

    @pytest.mark.parametrize(
        "method_name,valid_id,expected_verb,expected_endpoint,extra_args", ENDPOINT_MATRIX
    )
    @pytest.mark.parametrize("bad_value", INJECTION_CORPUS)
    def test_rejects_injection(
        self, bad_value, method_name, valid_id, expected_verb, expected_endpoint, extra_args
    ):
        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None

            method = getattr(self.api, method_name)
            with pytest.raises(ValueError):
                method(bad_value, *extra_args)

            mock_client.request.assert_not_called()


class TestFortiGateAPIDispatchShape:
    """Positive proof: EVERY one of the 13 identifier-bearing FortiGateAPI
    methods issues the exact expected HTTP verb against the exact expected
    validated endpoint path -- no site can silently escape with a wrong
    prefix, wrong verb, or unvalidated identifier."""

    def setup_method(self):
        config = FortiGateDeviceConfig(
            host="198.51.100.10",
            api_token="test-token-not-real",
            vdom="root",
        )
        self.api = FortiGateAPI("test_device", config)

    @pytest.mark.parametrize(
        "method_name,valid_id,expected_verb,expected_endpoint,extra_args", ENDPOINT_MATRIX
    )
    def test_dispatch_shape(
        self, method_name, valid_id, expected_verb, expected_endpoint, extra_args
    ):
        with patch.object(self.api, '_make_request') as mock_request:
            mock_request.return_value = {"status": "success"}

            method = getattr(self.api, method_name)
            method(valid_id, *extra_args)

            called_args = mock_request.call_args.args
            assert called_args[0] == expected_verb
            assert called_args[1] == expected_endpoint


class TestFortiGateAPITokenLeak:
    """Adversarial proof (CONF-03): the device's own secret is deliberately
    embedded in each untrusted text source (httpx exception message, JSON
    error body, plain-text error body) and proven absent from the resulting
    FortiGateAPIError -- including at the tool-layer MCP-content surface."""

    FAKE_TOKEN = "test-token-not-real"

    def setup_method(self):
        config = FortiGateDeviceConfig(
            host="198.51.100.10",
            api_token=self.FAKE_TOKEN,
            vdom="root",
        )
        self.api = FortiGateAPI("test_device", config)

    def test_network_error_message_scrubbed(self):
        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.side_effect = httpx.RequestError(
                f"Connection failed; request had Authorization: Bearer {self.FAKE_TOKEN}"
            )

            with pytest.raises(FortiGateAPIError) as exc_info:
                self.api._make_request("GET", "monitor/system/status")

            assert self.FAKE_TOKEN not in str(exc_info.value)
            assert self.FAKE_TOKEN not in repr(exc_info.value)
            assert "***REDACTED***" in str(exc_info.value)

    def test_json_error_body_scrubbed(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": f"invalid token {self.FAKE_TOKEN} supplied"
        }
        mock_response.text = "unused"

        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response

            with pytest.raises(FortiGateAPIError) as exc_info:
                self.api._make_request("GET", "monitor/system/status")

            assert self.FAKE_TOKEN not in str(exc_info.value)
            assert self.FAKE_TOKEN not in repr(exc_info.value)
            assert "***REDACTED***" in str(exc_info.value)
            assert exc_info.value.status_code == 400

    def test_text_error_body_scrubbed(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.side_effect = ValueError("not json")
        mock_response.text = f"server error: echo Bearer {self.FAKE_TOKEN}"

        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response

            with pytest.raises(FortiGateAPIError) as exc_info:
                self.api._make_request("GET", "monitor/system/status")

            assert self.FAKE_TOKEN not in str(exc_info.value)
            assert "***REDACTED***" in str(exc_info.value)

    def test_tool_layer_error_output_scrubbed_end_to_end(self):
        auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
        manager = FortiGateManager({}, auth_config)
        manager.devices["dev"] = self.api
        firewall_tools = FirewallTools(manager)

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "error": f"invalid token {self.FAKE_TOKEN} supplied"
        }
        mock_response.text = "unused"

        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response

            result = firewall_tools.delete_policy("dev", "1")

        combined_text = "\n".join(content.text for content in result)
        assert self.FAKE_TOKEN not in combined_text

    def test_unexpected_exception_scrubbed_and_wrapped(self):
        """WR-02 regression: an exception that is neither httpx.RequestError
        nor a FortiGateAPIError raised inside the try block (e.g. an
        unexpected error on the success-path response.json() call) must
        still be scrubbed and wrapped in a FortiGateAPIError -- not
        propagate raw all the way to the MCP tool-response layer, which has
        no TokenRedactionFilter fallback of its own."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = RuntimeError(
            f"unexpected parse failure, saw Bearer {self.FAKE_TOKEN}"
        )

        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None
            mock_client.request.return_value = mock_response

            with pytest.raises(FortiGateAPIError) as exc_info:
                self.api._make_request("GET", "monitor/system/status")

            assert self.FAKE_TOKEN not in str(exc_info.value)
            assert "***REDACTED***" in str(exc_info.value)
            assert exc_info.value.device_id == "test_device"

    def test_full_request_cycle_logs_never_contain_token(self, caplog):
        """Regression guard for the current clean state of log_api_call
        (log_api_call never logs headers today)."""
        caplog.set_level("DEBUG")

        mock_success = MagicMock()
        mock_success.status_code = 200
        mock_success.json.return_value = {"status": "success"}

        mock_error = MagicMock()
        mock_error.status_code = 400
        mock_error.json.return_value = {"error": "generic failure"}
        mock_error.text = "generic failure"

        with patch('httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.__enter__.return_value = mock_client
            mock_client.__exit__.return_value = None

            mock_client.request.return_value = mock_success
            self.api._make_request("GET", "monitor/system/status")

            mock_client.request.return_value = mock_error
            with pytest.raises(FortiGateAPIError):
                self.api._make_request("GET", "monitor/system/status")

        assert self.FAKE_TOKEN not in caplog.text
