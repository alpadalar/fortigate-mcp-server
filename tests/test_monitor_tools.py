"""Wire-level (respx) tests for MonitorTools (Phase 15, plan 15-04)."""
import httpx
import pytest
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.monitor import MonitorTools
from tests.support.fake_fortigate import load_fixture

BASE_URL = "https://198.51.100.10:443/api/v2"
SECRET = "ENC_FAKE_NOT_REAL_PLACEHOLDER"
NOT_SUPPORTED = "not supported on this FortiOS version"

# (method, endpoint, fixture, resource type)
TOOLS = [
    ("get_system_resources", "/monitor/system/resource/usage", "system_resource_usage.json",
     "system_resources"),
    ("get_license_status", "/monitor/license/status", "license_status.json", "license_status"),
    ("get_ha_status", "/monitor/system/ha-peer", "ha_peer.json", "ha_status"),
    ("get_arp_table", "/monitor/network/arp", "arp_table.json", "arp_table"),
    ("list_dhcp_leases", "/monitor/system/dhcp", "dhcp_leases.json", "dhcp_leases"),
]
IDS = [t[0] for t in TOOLS]
CAPPED = [t for t in TOOLS if t[0] in ("get_arp_table", "list_dhcp_leases")]
CAPPED_IDS = [t[0] for t in CAPPED]


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


class TestMonitorTools:
    def setup_method(self):
        self.tools = MonitorTools(_manager())

    def test_system_resources_latest_only(self):
        with _router() as router:
            router.get(TOOLS[0][1]).mock(
                return_value=httpx.Response(200, json=load_fixture(TOOLS[0][2]))
            )
            text = self.tools.get_system_resources(device_id="test_device")[0].text
        assert "cpu: 12 (1-min)" in text and "mem: 41 (1-min)" in text
        assert "session: 1234" in text and "setup_rate: 7" in text
        assert "historical" not in text and "62" not in text

    def test_license_status(self):
        with _router() as router:
            router.get(TOOLS[1][1]).mock(
                return_value=httpx.Response(200, json=load_fixture(TOOLS[1][2]))
            )
            text = self.tools.get_license_status(device_id="test_device")[0].text
        assert "forticare: status licensed, expires 2027-03-01" in text
        assert "ips: status expired" in text

    def test_ha_peers(self):
        with _router() as router:
            router.get(TOOLS[2][1]).mock(
                return_value=httpx.Response(200, json=load_fixture("ha_peer.json"))
            )
            text = self.tools.get_ha_status(device_id="test_device")[0].text
        assert "Mode: HA" in text and "fw-a" in text and "FGVMEVFAKE0000002" in text

    def test_ha_standalone_is_not_an_error(self):
        with _router() as router:
            router.get(TOOLS[2][1]).mock(
                return_value=httpx.Response(200, json=load_fixture("ha_peer_standalone.json"))
            )
            text = self.tools.get_ha_status(device_id="test_device")[0].text
        assert "Mode: standalone" in text
        assert "error" not in text.lower() and "failed" not in text.lower()

    def test_ha_404_is_unsupported_not_standalone(self):
        with _router() as router:
            router.get(TOOLS[2][1]).mock(
                return_value=httpx.Response(404, json=load_fixture("error_404.json"))
            )
            text = self.tools.get_ha_status(device_id="test_device")[0].text
        assert NOT_SUPPORTED in text and "standalone" not in text

    @pytest.mark.parametrize("method,path,fixture,rtype", TOOLS, ids=IDS)
    def test_redaction_non_vacuous(self, method, path, fixture, rtype):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            seen = []
            orig = self.tools._format_response

            def spy(data, resource_type=None, **kw):
                seen.append((data, resource_type))
                return orig(data, resource_type, **kw)

            self.tools._format_response = spy  # type: ignore[method-assign]
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert SECRET not in text
        assert seen and seen[0][1] == rtype
        assert "***REDACTED***" in str(seen[0][0])

    @pytest.mark.parametrize("method,path,fixture,rtype", TOOLS, ids=IDS)
    def test_404_401_vdom(self, method, path, fixture, rtype):
        with _router() as router:
            router.get(path).mock(
                return_value=httpx.Response(404, json=load_fixture("error_404.json"))
            )
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert NOT_SUPPORTED in text and "raw-device-text-xyz" not in text
        with _router() as router:
            router.get(path).mock(
                return_value=httpx.Response(401, json=load_fixture("error_401.json"))
            )
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert "Authentication failed" in text
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            getattr(self.tools, method)(device_id="test_device", vdom="vd1")
            assert router.calls.last.request.url.params["vdom"] == "vd1"

    @pytest.mark.parametrize("method", IDS)
    def test_unknown_device(self, method):
        text = getattr(self.tools, method)(device_id="nope")[0].text
        assert "nope" in text and "failed" in text


class TestMonitorCappedTables:
    def setup_method(self):
        self.tools = MonitorTools(_manager())

    @pytest.mark.parametrize("method,path,fixture,rtype", CAPPED, ids=CAPPED_IDS)
    def test_interface_filter(self, method, path, fixture, rtype):
        with _router() as router:
            route = router.get(path).mock(
                return_value=httpx.Response(200, json=load_fixture(fixture))
            )
            text = getattr(self.tools, method)(device_id="test_device", interface="port1")[0].text
            # Single GET, no extra query params beyond vdom.
            assert route.call_count == 1
            assert set(router.calls.last.request.url.params.keys()) == {"vdom"}
        assert "port1" in text and "port2.100" not in text
        assert "Showing" not in text  # 4 entries, below default cap

    @pytest.mark.parametrize("method,path,fixture,rtype", CAPPED, ids=CAPPED_IDS)
    def test_limit_caps_and_reports_total(self, method, path, fixture, rtype):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            text = getattr(self.tools, method)(device_id="test_device", limit=2)[0].text
        assert "Showing 2 of 7 entries (limit 2)" in text
        assert "treat as sensitive" in text
        assert text.count("10.") == 2

    @pytest.mark.parametrize("method,path,fixture,rtype", CAPPED, ids=CAPPED_IDS)
    def test_total_is_post_filter(self, method, path, fixture, rtype):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            text = getattr(self.tools, method)(
                device_id="test_device", interface="port1", limit=1)[0].text
        assert "Showing 1 of 4 entries (limit 1)" in text

    @pytest.mark.parametrize("method,path,fixture,rtype", CAPPED, ids=CAPPED_IDS)
    def test_unknown_interface_mentions_filter(self, method, path, fixture, rtype):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            text = getattr(self.tools, method)(device_id="test_device", interface="port9")[0].text
        assert "No " in text and "port9" in text

    @pytest.mark.parametrize("method,path,fixture,rtype", CAPPED, ids=CAPPED_IDS)
    @pytest.mark.parametrize("kwargs", [
        {"limit": 501}, {"limit": 0}, {"limit": -3}, {"limit": "5"}, {"limit": True},
        {"limit": 2.5}, {"interface": "port1;rm"}, {"interface": "../x"}, {"interface": ""},
    ])
    def test_bad_args_make_no_request(self, method, path, fixture, rtype, kwargs):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            text = getattr(self.tools, method)(device_id="test_device", **kwargs)[0].text
            assert router.calls.call_count == 0
        assert "failed" in text

    @pytest.mark.parametrize("method,path,fixture,rtype", CAPPED, ids=CAPPED_IDS)
    def test_non_list_results_tolerated(self, method, path, fixture, rtype):
        with _router() as router:
            router.get(path).mock(
                return_value=httpx.Response(200, json={"status": "success", "results": "weird"})
            )
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert "No " in text


def test_schema_info_lists_five_operations():
    info = MonitorTools(_manager()).get_schema_info()
    assert info["name"] == "monitor_tools"
    assert [o["name"] for o in info["operations"]] == [
        "get_system_resources", "get_license_status", "get_ha_status",
        "get_arp_table", "list_dhcp_leases",
    ]
    arp = info["operations"][3]
    assert [p["name"] for p in arp["parameters"]] == ["device_id", "vdom", "interface", "limit"]
