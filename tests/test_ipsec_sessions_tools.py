"""Wire-level (respx) tests for get_ipsec_tunnel_status and list_firewall_sessions (Phase 16)."""
import httpx
import pytest
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.monitor import MonitorTools
from src.fortigate_mcp.tools.vpn import VPNTools
from tests.support.fake_fortigate import load_fixture

BASE_URL = "https://198.51.100.10:443/api/v2"
IPSEC_PATH = "/monitor/vpn/ipsec"
SESSION_PATH = "/monitor/firewall/session"
NOT_SUPPORTED = "not supported on this FortiOS version"
PSK_SENTINELS = [
    "FAKE-PSK-SENTINEL-TOP-1", "FAKE-PSK-SENTINEL-TOP-2",
    "FAKE-PSK-SENTINEL-NESTED-1", "FAKE-PSK-SENTINEL-NESTED-2",
    "FAKE-PSK-SENTINEL-UNLISTED-1", "FAKE-PSK-SENTINEL-UNLISTED-2",
]


def _manager():
    config = FortiGateDeviceConfig(host="198.51.100.10", api_token="test-token-not-real",
                                   vdom="root")
    manager = FortiGateManager(
        {}, AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
    )
    manager.devices["test_device"] = FortiGateAPI("test_device", config)
    return manager


def _router():
    return respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True)


class TestIpsecTunnelStatus:
    def setup_method(self):
        self.tools = VPNTools(_manager())

    def test_renders_tunnels_and_proxyids(self):
        with _router() as router:
            router.get(IPSEC_PATH).mock(
                return_value=httpx.Response(200, json=load_fixture("vpn_ipsec_status.json"))
            )
            text = self.tools.get_ipsec_tunnel_status(device_id="test_device")[0].text
        assert "SITE-B (status: up)" in text and "SITE-C (status: down)" in text
        assert "Remote gateway: 203.0.113.20" in text
        assert "10.1.0.0/24 -> 10.2.0.0/24 [up]" in text
        assert "in 123456 B / out 654321 B" in text

    def test_psk_never_rendered_non_vacuous(self):
        raw = str(load_fixture("vpn_ipsec_status.json"))
        # Vacuity guard: every sentinel really is present in the raw payload.
        for sentinel in PSK_SENTINELS:
            assert sentinel in raw
        with _router() as router:
            router.get(IPSEC_PATH).mock(
                return_value=httpx.Response(200, json=load_fixture("vpn_ipsec_status.json"))
            )
            text = self.tools.get_ipsec_tunnel_status(device_id="test_device")[0].text
        for sentinel in PSK_SENTINELS:
            assert sentinel not in text
        for key in ("psksecret", "psk", "preshared"):
            assert key not in text.lower()

    def test_formatter_whitelist_drops_unlisted_secret_key_even_without_redaction(self):
        """Defence in depth: 'preshared-key' is not in the redaction deny-list."""
        from src.fortigate_mcp.formatting.templates import FortiGateTemplates

        text = FortiGateTemplates.ipsec_tunnels(load_fixture("vpn_ipsec_status.json"))
        assert "FAKE-PSK-SENTINEL" not in text

    def test_vdom_override_forwarded(self):
        with _router() as router:
            route = router.get(IPSEC_PATH).mock(
                return_value=httpx.Response(200, json={"results": []})
            )
            text = self.tools.get_ipsec_tunnel_status(device_id="test_device", vdom="vd1")[0].text
            assert route.calls.last.request.url.params["vdom"] == "vd1"
        assert "No IPsec tunnels found" in text

    def test_404_maps_to_not_supported(self):
        with _router() as router:
            router.get(IPSEC_PATH).mock(
                return_value=httpx.Response(404, json=load_fixture("error_404.json"))
            )
            text = self.tools.get_ipsec_tunnel_status(device_id="test_device")[0].text
        assert NOT_SUPPORTED in text and "raw-device-text-xyz" not in text

    @pytest.mark.parametrize("status,expected", [(401, "Authentication failed"),
                                                 (403, "Permission denied")])
    def test_auth_errors_render_fixed_text(self, status, expected):
        with _router() as router:
            router.get(IPSEC_PATH).mock(
                return_value=httpx.Response(status, json=load_fixture("error_401.json"))
            )
            text = self.tools.get_ipsec_tunnel_status(device_id="test_device")[0].text
        assert expected in text and "test-token-not-real" not in text

    def test_unknown_device_is_structured_error(self):
        text = self.tools.get_ipsec_tunnel_status(device_id="nope")[0].text
        assert "failed" in text.lower()


class TestFirewallSessions:
    def setup_method(self):
        self.tools = MonitorTools(_manager())

    def _serve(self, router):
        return router.get(SESSION_PATH).mock(
            return_value=httpx.Response(200, json=load_fixture("firewall_session_list.json"))
        )

    def test_fixture_exceeds_cap(self):
        assert len(load_fixture("firewall_session_list.json")["results"]) == 250

    def test_default_count_is_20_and_truncated(self):
        with _router() as router:
            route = self._serve(router)
            text = self.tools.list_firewall_sessions(device_id="test_device")[0].text
            assert route.calls.last.request.url.params["count"] == "20"
        assert "Requested up to 20 session(s); showing 20" in text
        assert "Result limit of 20 reached" in text
        assert text.count("policy 3") == 20

    def test_max_count_200_sent_and_enforced_client_side(self):
        with _router() as router:
            route = self._serve(router)
            text = self.tools.list_firewall_sessions(device_id="test_device", count=200)[0].text
            assert route.calls.last.request.url.params["count"] == "200"
        assert "showing 200" in text and text.count("policy 3") == 200

    @pytest.mark.parametrize("count", [0, -1, 201, 500, True, "20"])
    def test_invalid_count_rejected_without_http(self, count):
        with _router() as router:
            route = self._serve(router)
            text = self.tools.list_firewall_sessions(device_id="test_device", count=count)[0].text
            assert not route.called
        assert "count must be" in text

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"srcaddr": "192.0.2.1 "}, {"srcaddr": "192.0.2.1&x=1"}, {"dstaddr": "a b"},
            {"dstaddr": "'1.1.1.1'"}, {"srcaddr": "1.1.1.1\n"}, {"dstaddr": "example.com"},
            {"srcport": 0}, {"dstport": 70000}, {"srcport": "80"},
            {"proto": "tcp&evil=1"}, {"proto": "tcp udp"}, {"proto": 0}, {"proto": "999"},
        ],
    )
    def test_bad_filters_rejected_with_no_http_call(self, kwargs):
        with _router() as router:
            route = self._serve(router)
            text = self.tools.list_firewall_sessions(device_id="test_device", **kwargs)[0].text
            assert not route.called
        assert "failed" in text.lower()

    def test_valid_filters_in_outbound_query(self):
        with _router() as router:
            route = self._serve(router)
            self.tools.list_firewall_sessions(
                device_id="test_device", srcaddr="192.0.2.5", dstaddr="198.51.100.50",
                srcport=20005, dstport=443, proto="TCP", count=5,
            )
            params = route.calls.last.request.url.params
        assert params["srcaddr"] == "192.0.2.5" and params["dstaddr"] == "198.51.100.50"
        assert params["srcport"] == "20005" and params["dstport"] == "443"
        assert params["protocol"] == "tcp" and params["count"] == "5"

    def test_details_wrapped_results_supported(self):
        wrapped = {"results": {"summary": {}, "details": load_fixture(
            "firewall_session_list.json")["results"][:3]}}
        with _router() as router:
            router.get(SESSION_PATH).mock(return_value=httpx.Response(200, json=wrapped))
            text = self.tools.list_firewall_sessions(device_id="test_device")[0].text
        assert "showing 3" in text and "Result limit" not in text

    def test_empty_results(self):
        with _router() as router:
            router.get(SESSION_PATH).mock(return_value=httpx.Response(200, json={"results": []}))
            text = self.tools.list_firewall_sessions(device_id="test_device")[0].text
        assert "No sessions found" in text

    def test_404_maps_to_not_supported(self):
        with _router() as router:
            router.get(SESSION_PATH).mock(
                return_value=httpx.Response(404, json=load_fixture("error_404.json"))
            )
            text = self.tools.list_firewall_sessions(device_id="test_device")[0].text
        assert NOT_SUPPORTED in text and "raw-device-text-xyz" not in text

    @pytest.mark.parametrize("status,expected", [(401, "Authentication failed"),
                                                 (403, "Permission denied")])
    def test_auth_errors_render_fixed_text(self, status, expected):
        with _router() as router:
            router.get(SESSION_PATH).mock(
                return_value=httpx.Response(status, json=load_fixture("error_401.json"))
            )
            text = self.tools.list_firewall_sessions(device_id="test_device")[0].text
        assert expected in text and "test-token-not-real" not in text
