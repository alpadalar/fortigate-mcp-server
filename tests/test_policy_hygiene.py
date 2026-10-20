"""Unit tests for the pure policy hygiene analysis module (Phase 16)."""
import copy
import json

from src.fortigate_mcp.analysis.policy_hygiene import analyze_policy_hygiene


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
