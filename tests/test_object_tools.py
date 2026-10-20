"""Wire-level (respx) tests for ObjectTools (Phase 15, plan 15-03)."""
import httpx
import pytest
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.objects import ObjectTools
from tests.support.fake_fortigate import load_fixture

BASE_URL = "https://198.51.100.10:443/api/v2"
SECRET = "ENC_FAKE_NOT_REAL_PLACEHOLDER"
NOT_SUPPORTED = "not supported on this FortiOS version"

# (tool method, endpoint, fixture, resource type, expected names in output)
SINGLE = [
    ("list_address_groups", "/cmdb/firewall/addrgrp", "address_group_list.json",
     "address_groups", ["GRP-SERVERS", "SRV-WEB", "SRV-DB"]),
    ("list_service_groups", "/cmdb/firewall.service/group", "service_group_list.json",
     "service_groups", ["GRP-WEB", "HTTP", "HTTPS"]),
    ("list_ip_pools", "/cmdb/firewall/ippool", "ippool_list.json",
     "ip_pools", ["POOL-OUT", "203.0.113.10", "POOL-FIXED"]),
    ("list_central_snat_maps", "/cmdb/firewall/central-snat-map", "central_snat_map_list.json",
     "central_snat_maps", ["Entry 1", "LAN-NET", "POOL-OUT"]),
]
IDS = [s[0] for s in SINGLE]


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


class TestObjectTools:
    def setup_method(self):
        self.tools = ObjectTools(_manager())

    @pytest.mark.parametrize("method,path,fixture,rtype,names", SINGLE, ids=IDS)
    def test_renders_and_redacts(self, method, path, fixture, rtype, names):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            seen = []
            orig = self.tools._format_response

            def spy(data, resource_type=None, **kw):
                seen.append((data, resource_type))
                return orig(data, resource_type, **kw)

            self.tools._format_response = spy  # type: ignore[method-assign]
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        for name in names:
            assert name in text
        assert SECRET not in text
        # Non-vacuous: the data handed to the formatter was redacted (fails if redact removed).
        assert seen and seen[0][1] == rtype
        assert "***REDACTED***" in str(seen[0][0])
        assert SECRET not in str(seen[0][0])

    @pytest.mark.parametrize("method,path,fixture,rtype,names", SINGLE, ids=IDS)
    def test_empty_results(self, method, path, fixture, rtype, names):
        with _router() as router:
            router.get(path).mock(
                return_value=httpx.Response(200, json={"status": "success", "results": []})
            )
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert "No " in text

    @pytest.mark.parametrize("method,path,fixture,rtype,names", SINGLE, ids=IDS)
    def test_404_and_401(self, method, path, fixture, rtype, names):
        with _router() as router:
            router.get(path).mock(
                return_value=httpx.Response(404, json=load_fixture("error_404.json"))
            )
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert NOT_SUPPORTED in text
        assert "raw-device-text-xyz" not in text
        with _router() as router:
            router.get(path).mock(
                return_value=httpx.Response(401, json=load_fixture("error_401.json"))
            )
            text = getattr(self.tools, method)(device_id="test_device")[0].text
        assert "Authentication failed" in text
        assert NOT_SUPPORTED not in text

    @pytest.mark.parametrize("method,path,fixture,rtype,names", SINGLE, ids=IDS)
    def test_vdom_reaches_query(self, method, path, fixture, rtype, names):
        with _router() as router:
            router.get(path).mock(return_value=httpx.Response(200, json=load_fixture(fixture)))
            getattr(self.tools, method)(device_id="test_device", vdom="vd1")
            assert router.calls.last.request.url.params["vdom"] == "vd1"

    @pytest.mark.parametrize("method", IDS + ["list_schedules"])
    def test_unknown_device_returns_error_response(self, method):
        text = getattr(self.tools, method)(device_id="nope")[0].text
        assert "nope" in text and "failed" in text

    def test_invalid_vdom_returns_error_response(self):
        text = self.tools.list_ip_pools(device_id="test_device", vdom="../x")[0].text
        assert "failed" in text


SCHEDULE_PATHS = {
    "recurring": "/cmdb/firewall.schedule/recurring",
    "onetime": "/cmdb/firewall.schedule/onetime",
    "group": "/cmdb/firewall.schedule/group",
}
SCHEDULE_FIXTURES = {
    "recurring": "schedule_recurring_list.json",
    "onetime": "schedule_onetime_list.json",
    "group": "schedule_group_list.json",
}


def _mock_schedules(router, overrides=None):
    overrides = overrides or {}
    for key, path in SCHEDULE_PATHS.items():
        resp = overrides.get(key) or httpx.Response(200, json=load_fixture(SCHEDULE_FIXTURES[key]))
        router.get(path).mock(return_value=resp)


class TestListSchedules:
    def setup_method(self):
        self.tools = ObjectTools(_manager())

    def test_all_three_render_and_redact(self):
        with _router() as router:
            _mock_schedules(router)
            text = self.tools.list_schedules(device_id="test_device")[0].text
        assert "BUSINESS-HOURS: day monday" in text and "08:00" in text
        assert "MAINT-WINDOW: start 22:00 2026/11/01" in text
        assert "SCHED-ALL: members BUSINESS-HOURS, MAINT-WINDOW" in text
        assert SECRET not in text

    def test_403_degrades_one_category(self):
        forbidden = httpx.Response(
            403, json={"status": "error", "http_status": 403, "error": "Forbidden raw"}
        )
        with _router() as router:
            _mock_schedules(router, {"onetime": forbidden})
            text = self.tools.list_schedules(device_id="test_device")[0].text
        assert "One-Time Schedules: query failed - permission denied" in text
        assert "none configured" not in text
        assert "BUSINESS-HOURS" in text and "SCHED-ALL" in text
        assert "Forbidden raw" not in text

    def test_404_degrades_one_category(self):
        nf = httpx.Response(404, json=load_fixture("error_404.json"))
        with _router() as router:
            _mock_schedules(router, {"group": nf})
            text = self.tools.list_schedules(device_id="test_device")[0].text
        assert f"Schedule Groups: query failed - {NOT_SUPPORTED}" in text
        assert "BUSINESS-HOURS" in text and "MAINT-WINDOW" in text
        assert "raw-device-text-xyz" not in text

    def test_network_failure_propagates_to_outer_handler(self):
        with _router() as router:
            route = router.get(SCHEDULE_PATHS["recurring"]).mock(
                side_effect=httpx.ConnectError("down")
            )
            other = router.get(SCHEDULE_PATHS["onetime"]).mock(
                return_value=httpx.Response(200, json={"results": []})
            )
            text = self.tools.list_schedules(device_id="test_device")[0].text
            assert route.called and not other.called
        assert "failed" in text and "Schedules" not in text.split("\n")[0]


def test_schema_info_lists_five_operations():
    info = ObjectTools(_manager()).get_schema_info()
    assert info["name"] == "object_tools"
    assert [o["name"] for o in info["operations"]] == [
        "list_address_groups", "list_service_groups", "list_schedules",
        "list_ip_pools", "list_central_snat_maps",
    ]
    for op in info["operations"]:
        assert [p["name"] for p in op["parameters"]] == ["device_id", "vdom"]
