"""Unit tests for the pure policy hygiene analysis module (Phase 16)."""
import copy
import json

import httpx
import respx

from src.fortigate_mcp.analysis.policy_hygiene import analyze_policy_hygiene
from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.firewall import FirewallTools
from tests.support.fake_fortigate import load_fixture


def pol(pid, src="all", dst="all", svc="ALL", action="accept", status="enable",
        srcintf="lan", dstintf="wan", **extra):
    def mem(v):
        return [{"name": x} for x in (v if isinstance(v, list) else [v])]

    d = {
        "policyid": pid, "status": status, "action": action,
        "srcintf": mem(srcintf), "dstintf": mem(dstintf),
        "srcaddr": mem(src), "dstaddr": mem(dst), "service": mem(svc),
        "schedule": "always",
    }
    d.update(extra)
    return d


def grp(name, members):
    return {"name": name, "member": [{"name": m} for m in members]}


def run(policies, addresses=None, groups=None):
    return analyze_policy_hygiene(policies, addresses or [], groups or [])


def ids(result, key):
    return [f["policyid"] for f in result["findings"][key]]


class TestCategories:
    def test_disabled(self):
        r = run([pol(1, src="A", dst="B", svc="HTTP", status="disable")])
        assert ids(r, "disabled") == [1]
        assert r["summary"]["disabled"] == 1

    def test_any_any_positive_and_negative(self):
        r = run([pol(1), pol(2, src="A"), pol(3, action="deny")])
        assert ids(r, "any_any") == [1]
        assert ids(r, "permissive_any") == [2]

    def test_permissive_any_destination_side(self):
        r = run([pol(5, src="A", dst="all")])
        assert r["findings"]["permissive_any"] == [{"policyid": 5, "any_side": "destination"}]

    def test_any_any_needs_service_all(self):
        r = run([pol(1, svc="HTTP")])
        assert ids(r, "any_any") == [] and ids(r, "permissive_any") == []

    def test_duplicate(self):
        r = run([pol(1, src="A", dst="B", svc="HTTP"), pol(2, src="A", dst="B", svc="HTTP")])
        assert r["findings"]["duplicate"] == [{"policyid": 2, "duplicate_of": 1}]
        assert ids(r, "shadowed") == []

    def test_shadowed_by_wider_earlier(self):
        r = run([pol(1, src="all", dst="B", svc="ALL", action="deny"),
                 pol(2, src="A", dst="B", svc="HTTP")])
        assert r["findings"]["shadowed"] == [
            {"policyid": 2, "shadowed_by": 1, "earlier_action": "deny", "action": "accept"}
        ]

    def test_not_shadowed_when_earlier_narrower(self):
        r = run([pol(1, src="A", dst="B", svc="HTTP"), pol(2, src="all", dst="B", svc="ALL")])
        assert ids(r, "shadowed") == []

    def test_not_shadowed_when_interface_differs(self):
        r = run([pol(1, dst="B", dstintf="wan"), pol(2, src="A", dst="B", dstintf="dmz")])
        assert ids(r, "shadowed") == []

    def test_clean_set_has_no_findings(self):
        r = run([pol(1, src="A", dst="B", svc="HTTP"), pol(2, src="C", dst="D", svc="DNS")])
        assert all(not v for v in r["findings"].values())
        assert r["notes"] == []


class TestGroupsAndRobustness:
    def test_group_member_shadowed_by_group(self):
        r = run(
            [pol(1, src="GRP", dst="B", svc="ALL"), pol(2, src="A1", dst="B", svc="HTTP")],
            groups=[grp("GRP", ["A1", "A2"])],
        )
        assert ids(r, "shadowed") == [2]

    def test_nested_group(self):
        r = run(
            [pol(1, src="OUTER", dst="B"), pol(2, src="A1", dst="B", svc="HTTP")],
            groups=[grp("OUTER", ["INNER"]), grp("INNER", ["A1"])],
        )
        assert ids(r, "shadowed") == [2]

    def test_group_cycle_terminates_with_note(self):
        r = run(
            [pol(1, src="G1", dst="B", svc="HTTP")],
            groups=[grp("G1", ["G2", "A"]), grp("G2", ["G1"])],
        )
        assert any("cycle" in n for n in r["notes"])

    def test_all_address_object_treated_as_all(self):
        r = run([pol(1, src="EVERYTHING", dst="EVERYTHING")],
                addresses=[{"name": "EVERYTHING", "subnet": "0.0.0.0 0.0.0.0"}])
        assert ids(r, "any_any") == [1]

    def test_complex_earlier_policy_never_shadows(self):
        r = run([pol(1, src="all", dst="B", **{"srcaddr-negate": "enable"}),
                 pol(2, src="A", dst="B", svc="HTTP")])
        assert ids(r, "shadowed") == []
        r = run([pol(1, src="all", dst="B", users=[{"name": "bob"}]),
                 pol(2, src="A", dst="B", svc="HTTP")])
        assert ids(r, "shadowed") == []

    def test_schedule_mismatch_blocks_shadow(self):
        r = run([pol(1, src="all", dst="B", schedule="work"), pol(2, src="A", dst="B")])
        assert ids(r, "shadowed") == []

    def test_malformed_entries_skipped_with_notes(self):
        r = run([None, "x", {"status": "enable"}, {"policyid": True}, pol(7)])
        assert r["summary"]["policies_analyzed"] == 1
        assert r["summary"]["skipped"] == 4
        assert ids(r, "any_any") == [7]

    def test_non_list_inputs_do_not_raise(self):
        r = analyze_policy_hygiene(None, "bad", {"x": 1})
        assert r["summary"]["policies_analyzed"] == 0
        assert r["notes"]

    def test_missing_keys_tolerated(self):
        r = run([{"policyid": 3}])
        assert r["summary"]["policies_analyzed"] == 1

    def test_deterministic_and_key_order_independent(self):
        policies = [pol(1, src="all", dst="B", action="deny"),
                    pol(2, src="A", dst="B", svc="HTTP"), pol(3, status="disable"), pol(10)]
        first = json.dumps(run(policies), sort_keys=False)
        assert first == json.dumps(run(copy.deepcopy(policies)), sort_keys=False)
        shuffled = [dict(reversed(list(p.items()))) for p in policies]
        assert first == json.dumps(run(shuffled), sort_keys=False)

    def test_findings_sorted_numerically(self):
        r = run([pol(10, status="disable"), pol(9, status="disable"), pol(100, status="disable")])
        assert ids(r, "disabled") == [9, 10, 100]


# ---------------------------------------------------------------------------
# Fixture-driven and tool-level tests (Plan 16-03)
# ---------------------------------------------------------------------------

BASE_URL = "https://198.51.100.10:443/api/v2"
POLICY_PATH = "/cmdb/firewall/policy"
ADDRESS_PATH = "/cmdb/firewall/address"
ADDRGRP_PATH = "/cmdb/firewall/addrgrp"


def _fx(name):
    return load_fixture(name)["results"]


def _fixture_result():
    return analyze_policy_hygiene(
        _fx("firewall_policy_hygiene.json"),
        _fx("firewall_address_hygiene.json"),
        _fx("firewall_addrgrp_hygiene.json"),
    )


class TestFixtureDriven:
    def test_each_category_has_positive_and_negative_neighbor(self):
        r = _fixture_result()
        assert r["findings"]["shadowed"] == [
            {"policyid": 2, "shadowed_by": 1, "earlier_action": "deny", "action": "accept"},
            {"policyid": 9, "shadowed_by": 8, "earlier_action": "accept", "action": "accept"},
        ]
        assert r["findings"]["duplicate"] == [{"policyid": 4, "duplicate_of": 3}]
        assert ids(r, "any_any") == [5]
        assert r["findings"]["permissive_any"] == [{"policyid": 6, "any_side": "source"}]
        assert ids(r, "disabled") == [7]
        # Negative neighbors: 3 (same dst as its duplicate but first), 8, 10 are clean.
        flagged = {f["policyid"] for v in r["findings"].values() for f in v}
        assert not ({3, 8, 10, 1} & flagged)
        assert r["summary"]["policies_analyzed"] == 10 and r["summary"]["skipped"] == 1

    def test_group_cycle_noted_and_malformed_skipped(self):
        r = _fixture_result()
        assert any("GRP-CYC-1" in n for n in r["notes"])
        assert any("malformed" in n for n in r["notes"])

    def test_byte_identical_twice_and_shuffled_keys(self):
        first = json.dumps(_fixture_result())
        assert first == json.dumps(_fixture_result())
        policies = [
            dict(reversed(list(p.items()))) if isinstance(p, dict) else p
            for p in _fx("firewall_policy_hygiene.json")
        ]
        groups = [dict(reversed(list(g.items()))) for g in _fx("firewall_addrgrp_hygiene.json")]
        shuffled = analyze_policy_hygiene(policies, _fx("firewall_address_hygiene.json"), groups)
        assert first == json.dumps(shuffled)

    def test_clean_policy_set_yields_empty_findings(self):
        clean = [p for p in _fx("firewall_policy_hygiene.json")
                 if isinstance(p, dict) and p["policyid"] in (3, 10)]
        r = analyze_policy_hygiene(
            clean, _fx("firewall_address_hygiene.json"), _fx("firewall_addrgrp_hygiene.json")
        )
        assert all(not v for v in r["findings"].values())


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


def _serve(router, addr=None, grp=None, policy=None):
    router.get(POLICY_PATH).mock(
        return_value=policy or httpx.Response(200, json=load_fixture("firewall_policy_hygiene.json"))
    )
    router.get(ADDRESS_PATH).mock(
        return_value=addr or httpx.Response(200, json=load_fixture("firewall_address_hygiene.json"))
    )
    router.get(ADDRGRP_PATH).mock(
        return_value=grp or httpx.Response(200, json=load_fixture("firewall_addrgrp_hygiene.json"))
    )


class TestAnalyzePolicyHygieneTool:
    def setup_method(self):
        self.tools = FirewallTools(_manager())

    def test_output_has_expected_ids_and_summary(self):
        with _router() as router:
            _serve(router)
            text = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert "Policies analyzed: 10 (skipped: 1)" in text
        assert "shadowed=2, duplicate=1, any_any=1, permissive_any=1, disabled=1" in text
        assert "Policy 2: action=accept, earlier_action=deny, shadowed_by=1" in text
        assert "Policy 4: duplicate_of=3" in text
        assert "any_any (1)\n  Policy 5" in text
        assert "Policy 6: any_side=source" in text
        assert "disabled (1)\n  Policy 7" in text
        assert "Source" not in text

    def test_deterministic_across_calls(self):
        with _router() as router:
            _serve(router)
            a = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
            b = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert a == b

    def test_addrgrp_403_degrades_with_fixed_text(self):
        forbidden = httpx.Response(403, json={"status": "error", "error": "Forbidden raw-xyz"})
        with _router() as router:
            _serve(router, grp=forbidden)
            text = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert "Source addrgrp: permission denied (analysis may be incomplete)" in text
        assert "Forbidden raw-xyz" not in text
        # Policy-only findings still appear; group-resolved shadowing (9) cannot.
        assert "Policy 2:" in text and "Policy 4:" in text and "Policy 9:" not in text

    def test_address_404_degrades_with_fixed_text(self):
        nf = httpx.Response(404, json=load_fixture("error_404.json"))
        with _router() as router:
            _serve(router, addr=nf)
            text = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert "Source address: endpoint not found" in text
        assert "raw-device-text-xyz" not in text

    def test_policy_404_maps_to_not_supported(self):
        with _router() as router:
            _serve(router, policy=httpx.Response(404, json=load_fixture("error_404.json")))
            text = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert "not supported on this FortiOS version" in text
        assert "raw-device-text-xyz" not in text

    def test_network_failure_on_subfetch_propagates(self):
        with _router() as router:
            router.get(POLICY_PATH).mock(
                return_value=httpx.Response(200, json=load_fixture("firewall_policy_hygiene.json"))
            )
            router.get(ADDRESS_PATH).mock(side_effect=httpx.ConnectError("down"))
            text = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert "failed" in text.lower() and "Policies analyzed" not in text

    def test_policy_403_renders_fixed_text(self):
        with _router() as router:
            _serve(router, policy=httpx.Response(403, json={"error": "Forbidden raw-xyz"}))
            text = self.tools.analyze_policy_hygiene(device_id="test_device")[0].text
        assert "Permission denied" in text and "raw-xyz" not in text


def test_tool_through_registered_mcp_session(tmp_config_path):
    """End-to-end through the registry (stdio server + in-memory MCP client)."""
    import asyncio

    from fastmcp import Client

    from src.fortigate_mcp.server import FortiGateMCPServer

    server = FortiGateMCPServer(tmp_config_path)

    async def call():
        async with Client(server.mcp) as client:
            return await client.call_tool("analyze_policy_hygiene", {"device_id": "default"})

    with respx.mock(base_url=BASE_URL, assert_all_called=False, assert_all_mocked=True) as router:
        _serve(router)
        result = asyncio.run(call())
    assert "Policy 5" in result.content[0].text and "shadowed=2" in result.content[0].text


class TestReviewRegressions:
    """17-REVIEW fixes: false shadow/any_any claims and capped output."""

    def test_application_match_never_shadows(self):
        earlier = pol(1, application=[{"name": "HTTP"}])
        later = pol(2)
        assert ids(run([earlier, later]), "shadowed") == []

    def test_url_category_and_srcaddr6_not_duplicates(self):
        a = pol(1, **{"url-category": [{"id": 5}]})
        b = pol(2)
        assert ids(run([a, b]), "duplicate") == []

    def test_negated_later_policy_not_shadowed_by_name_subset(self):
        earlier = pol(1, src=["a", "b"])
        later = pol(2, src="a", **{"srcaddr-negate": "enable"})
        assert ids(run([earlier, later]), "shadowed") == []

    def test_negated_later_policy_shadowed_by_match_all(self):
        earlier = pol(1, src="all")
        later = pol(2, src="a", **{"srcaddr-negate": "enable"})
        assert ids(run([earlier, later]), "shadowed") == [2]

    def test_negated_all_all_not_any_any(self):
        p = pol(1, **{"srcaddr-negate": "enable"})
        assert ids(run([p]), "any_any") == []


def test_policy_hygiene_template_caps_findings():
    from src.fortigate_mcp.formatting.templates import FortiGateTemplates

    data = {
        "summary": {"disabled": 150},
        "findings": {"disabled": [{"policyid": i} for i in range(150)]},
    }
    text = FortiGateTemplates.policy_hygiene(data)
    assert "Policy 99" in text and "Policy 100" not in text
    assert "50 more not shown" in text


def test_group_template_caps_entries_and_members():
    from src.fortigate_mcp.formatting.templates import FortiGateTemplates

    data = {"results": [
        {"name": f"g{i}", "member": [{"name": f"m{j}"} for j in range(300)] if i == 0 else []}
        for i in range(600)
    ]}
    text = FortiGateTemplates.address_groups(data)
    assert "Showing 500 of 600 groups" in text
    assert "g499" in text and "g500" not in text
    assert "(100 more)" in text
