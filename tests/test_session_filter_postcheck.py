"""list_firewall_sessions: device-side json_filter on monitor/firewall/sessions, legacy
fallback, and client-side re-check of filters the device ignored."""
import json

import httpx
import pytest
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.monitor import MonitorTools, _session_matches
from tests.support.fake_fortigate import load_fixture

BASE_URL = "https://198.51.100.10:443/api/v2"
SESSIONS_PATH = "/monitor/firewall/sessions"
LEGACY_PATH = "/monitor/firewall/session"
IGNORED_WARNING = "WARNING: the device did not apply the filters"


def _tools():
    config = FortiGateDeviceConfig(host="198.51.100.10", api_token="test-token-not-real",
                                   vdom="root")
    manager = FortiGateManager(
        {}, AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
    )
    manager.devices["test_device"] = FortiGateAPI("test_device", config)
    return MonitorTools(manager)


def _router():
    return respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True)


def _wrapped(details, matched_count=None):
    summary = {"matched_count": len(details) if matched_count is None else matched_count,
               "session_count": 20000}
    return {"results": {"summary": summary, "details": details}}


def _session(saddr="10.193.103.16", sport=43174, daddr="10.115.38.57", dport=6013,
             proto="tcp"):
    return {"proto": proto, "saddr": saddr, "sport": sport, "daddr": daddr, "dport": dport,
            "policyid": 164, "duration": 10, "expiry": 3600}


class TestSessionMatches:
    def test_all_filters_must_match(self):
        entry = _session()
        assert _session_matches(entry, {"dstaddr": "10.115.38.57", "dstport": "6013"})
        assert not _session_matches(entry, {"dstaddr": "10.115.38.57", "dstport": "6067"})
        assert not _session_matches(entry, {"srcaddr": "192.0.2.2"})

    def test_protocol_name_and_number_are_equivalent(self):
        assert _session_matches({"proto": "6"}, {"protocol": "tcp"})
        assert _session_matches({"proto": "TCP"}, {"protocol": "6"})
        assert not _session_matches({"proto": "udp"}, {"protocol": "tcp"})

    def test_missing_field_does_not_match(self):
        assert not _session_matches({"saddr": "192.0.2.1"}, {"dstport": "443"})

    def test_alternate_key_names(self):
        assert _session_matches({"dstaddr": "198.51.100.50"}, {"dstaddr": "198.51.100.50"})


class TestJsonFilterRequest:
    def test_post_with_method_override_and_json_filter(self):
        with _router() as router:
            route = router.post(SESSIONS_PATH).mock(
                return_value=httpx.Response(200, json=_wrapped([_session()], matched_count=3))
            )
            text = _tools().list_firewall_sessions(
                device_id="test_device", dstaddr="10.115.38.57", dstport=6013,
                srcaddr="10.193.103.16", srcport=43174, count=5,
            )[0].text
            request = route.calls.last.request
        assert request.headers["X-HTTP-Method-Override"] == "GET"
        assert request.headers["Authorization"] == "Bearer test-token-not-real"
        params = request.url.params
        assert params["ip_version"] == "ipv4" and params["start"] == "0"
        assert params["count"] == "5" and params["summary"] == "true"
        assert params["vdom"] == "root"
        groups = json.loads(request.content)["json_filter"]
        sent = {g["filters"][0]["key"]: g["filters"][0]["pattern"] for g in groups}
        assert sent == {"srcaddr": "10.193.103.16", "dstaddr": "10.115.38.57",
                        "srcport": "43174", "dstport": "6013"}
        assert all(g["filters"][0]["operator"] == "exact" for g in groups)
        assert "Device reported 3 session(s) matching the filters" in text
        assert IGNORED_WARNING not in text
        assert "10.193.103.16:43174 -> 10.115.38.57:6013" in text

    def test_protocol_is_not_sent_device_side_and_is_applied_locally(self):
        details = [_session(), _session(proto="udp", dport=53, daddr="10.115.38.57")]
        with _router() as router:
            route = router.post(SESSIONS_PATH).mock(
                return_value=httpx.Response(200, json=_wrapped(details))
            )
            text = _tools().list_firewall_sessions(
                device_id="test_device", dstaddr="10.115.38.57", proto="tcp"
            )[0].text
            groups = json.loads(route.calls.last.request.content)["json_filter"]
        assert [g["filters"][0]["key"] for g in groups] == ["dstaddr"]
        assert IGNORED_WARNING not in text
        assert "protocol filtered by the server" in text
        assert ":6013" in text and ":53 " not in text

    def test_no_filters_sends_empty_json_filter(self):
        with _router() as router:
            route = router.post(SESSIONS_PATH).mock(
                return_value=httpx.Response(200, json=_wrapped([_session()]))
            )
            _tools().list_firewall_sessions(device_id="test_device")
            body = json.loads(route.calls.last.request.content)
        assert body == {"json_filter": []}

    def test_ipv6_address_uses_v6_key_and_ip_version(self):
        with _router() as router:
            route = router.post(SESSIONS_PATH).mock(
                return_value=httpx.Response(200, json=_wrapped([]))
            )
            _tools().list_firewall_sessions(device_id="test_device", dstaddr="2001:db8::1")
            request = route.calls.last.request
        assert request.url.params["ip_version"] == "ipv6"
        groups = json.loads(request.content)["json_filter"]
        assert groups[0]["filters"][0]["key"] == "dstaddr6"


class TestLegacyFallback:
    @pytest.mark.parametrize("status", [404, 405])
    def test_falls_back_to_legacy_get(self, status):
        with _router() as router:
            router.post(SESSIONS_PATH).mock(return_value=httpx.Response(status, json={}))
            legacy = router.get(LEGACY_PATH).mock(
                return_value=httpx.Response(200, json={"results": [_session()]})
            )
            text = _tools().list_firewall_sessions(
                device_id="test_device", dstaddr="10.115.38.57"
            )[0].text
            assert legacy.called
            assert legacy.calls.last.request.url.params["dstaddr"] == "10.115.38.57"
        assert "10.193.103.16:43174 -> 10.115.38.57:6013" in text

    def test_permission_error_does_not_fall_back(self):
        with _router() as router:
            router.post(SESSIONS_PATH).mock(
                return_value=httpx.Response(403, json=load_fixture("error_401.json"))
            )
            legacy = router.get(LEGACY_PATH).mock(
                return_value=httpx.Response(200, json={"results": []})
            )
            text = _tools().list_firewall_sessions(device_id="test_device")[0].text
            assert not legacy.called
        assert "Permission denied" in text and "test-token-not-real" not in text


class TestFiltersIgnoredByDevice:
    def _list(self, payload, **kwargs):
        with _router() as router:
            router.post(SESSIONS_PATH).mock(return_value=httpx.Response(200, json=payload))
            return _tools().list_firewall_sessions(device_id="test_device", **kwargs)[0].text

    def test_unfiltered_device_response_is_filtered_and_flagged(self):
        # The fixture alternates tcp/443 and udp/53 sessions: the device "ignored" the filters.
        text = self._list(load_fixture("firewall_session_list.json"),
                          count=20, dstport=53, proto="udp")
        assert IGNORED_WARNING in text
        assert "-> 198.51.100.50:53" in text
        assert ":443" not in text.split(IGNORED_WARNING)[1]
        assert "Requested up to 20 session(s); showing 20" in text
        assert "matching the filters" not in text

    def test_no_matching_session_is_not_conclusive(self):
        text = self._list(load_fixture("firewall_session_list.json"),
                          count=20, dstaddr="10.115.38.55", dstport=6067)
        assert IGNORED_WARNING in text
        assert "does NOT prove it does not exist" in text
        assert "No sessions found" in text

    def test_without_filters_nothing_is_dropped(self):
        text = self._list(load_fixture("firewall_session_list.json"), count=20)
        assert IGNORED_WARNING not in text
        assert "showing 20" in text
