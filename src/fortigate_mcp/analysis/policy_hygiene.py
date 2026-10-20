"""Pure firewall policy hygiene analysis.

`analyze_policy_hygiene(policies, addresses, addrgrps)` operates on plain
dicts as returned by FortiOS cmdb endpoints. It performs no I/O, imports
nothing from `core` or `tools`, and is deterministic: findings are sorted by
policy id and independent of dict key order.

Findings (policy order is list order, as FortiGate evaluates by sequence):
    shadowed        An earlier enabled policy provably matches every packet the
                    later policy matches, so the later one never takes effect.
    duplicate       Two policies have an identical match tuple and action.
    any_any         Enabled accept policy with srcaddr all, dstaddr all and
                    service ALL.
    permissive_any  Enabled accept policy with service ALL where exactly one of
                    srcaddr/dstaddr is all.
    disabled        Policy with status disable.

Accuracy limits (deliberately conservative -- no false "shadowed" claims):
    * Address relations are decided from names only: "all", name equality and
      address-group membership (groups expanded recursively with a cycle
      guard). IP/subnet arithmetic is NOT performed, so a policy shadowed only
      through overlapping subnets is not reported. An address object whose
      subnet is 0.0.0.0/0 is treated as "all".
    * Service and interface relations are name-based ("ALL"/"any" or equality);
      service groups are not expanded.
    * An earlier policy that uses negated match fields, user/group matches or
      internet-service matches, or a non-"always" schedule different from the
      later policy's, is never considered to shadow anything.
    * Malformed entries are skipped and reported in `notes`.
"""

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

_ALL_ADDR = {"all", "any"}
_ALL_SERVICE = {"all"}  # compared lowercase
_ALL_INTF = {"any"}
_NEGATE_KEYS = ("srcaddr-negate", "dstaddr-negate", "service-negate")
_EXTRA_MATCH_KEYS = (
    "users",
    "groups",
    "fsso-groups",
    "internet-service",
    "internet-service-src",
    "internet-service-name",
    "internet-service-src-name",
)
_FINDING_KEYS = ("shadowed", "duplicate", "any_any", "permissive_any", "disabled")


def _names(value: Any) -> FrozenSet[str]:
    """Extract names from a FortiOS member list ({"name": x} dicts or strings)."""
    if isinstance(value, (str, dict)):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return frozenset()
    out: Set[str] = set()
    for item in value:
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name:
                out.add(name)
        elif isinstance(item, str) and item:
            out.add(item)
    return frozenset(out)


def _pid_key(pid: Any) -> Tuple[int, str]:
    try:
        return (0, f"{int(pid):012d}")
    except (TypeError, ValueError):
        return (1, str(pid))


def _enabled(flag: Any) -> bool:
    return isinstance(flag, str) and flag.lower() == "enable"


def _expand_groups(
    addrgrps: Iterable[Any], notes: Set[str]
) -> Dict[str, FrozenSet[str]]:
    """Map group name -> set of leaf (non-group) member names, cycle-safe."""
    direct: Dict[str, FrozenSet[str]] = {}
    for grp in addrgrps:
        if isinstance(grp, dict) and isinstance(grp.get("name"), str):
            direct[grp["name"]] = _names(grp.get("member"))

    def resolve(name: str, stack: Tuple[str, ...]) -> FrozenSet[str]:
        if name in stack:
            notes.add(f"address group cycle detected involving '{name}'")
            return frozenset()
        leaves: Set[str] = set()
        for member in direct.get(name, frozenset()):
            if member in direct:
                leaves |= resolve(member, stack + (name,))
            else:
                leaves.add(member)
        return frozenset(leaves)

    return {name: resolve(name, ()) for name in sorted(direct)}


def _all_address_names(addresses: Iterable[Any]) -> FrozenSet[str]:
    """Address objects that match everything (0.0.0.0/0)."""
    out: Set[str] = set()
    for addr in addresses:
        if not isinstance(addr, dict) or not isinstance(addr.get("name"), str):
            continue
        subnet = addr.get("subnet")
        if isinstance(subnet, str) and subnet.split() in (["0.0.0.0", "0.0.0.0"], ["0.0.0.0/0"]):
            out.add(addr["name"])
    return frozenset(out)


@dataclass
class _Policy:
    pid: Any
    enabled: bool
    action: str
    srcintf: FrozenSet[str]
    dstintf: FrozenSet[str]
    src: FrozenSet[str]
    dst: FrozenSet[str]
    service: FrozenSet[str]
    schedule: str
    complex_match: bool
    raw_key: str


def _normalize(
    raw: Dict[str, Any],
    groups: Dict[str, FrozenSet[str]],
    all_names: FrozenSet[str],
) -> Optional[_Policy]:
    pid = raw.get("policyid")
    if pid is None or isinstance(pid, bool) or not isinstance(pid, (int, str)):
        return None
    status = raw.get("status", "enable")
    enabled = not (isinstance(status, str) and status.lower() == "disable")
    action_raw = raw.get("action", "deny")
    action = action_raw.lower() if isinstance(action_raw, str) else "deny"
    srcintf = _names(raw.get("srcintf"))
    dstintf = _names(raw.get("dstintf"))
    service = frozenset(n.lower() for n in _names(raw.get("service")))
    sched = raw.get("schedule", "always")
    schedule = sched if isinstance(sched, str) else "always"

    def expand(value: Any) -> FrozenSet[str]:
        leaves: Set[str] = set()
        for name in _names(value):
            if name in groups:
                leaves |= groups[name]
            else:
                leaves.add(name)
        if any(n.lower() in _ALL_ADDR or n in all_names for n in leaves):
            return frozenset({"all"})
        return frozenset(leaves)

    src = expand(raw.get("srcaddr"))
    dst = expand(raw.get("dstaddr"))
    complex_match = any(_enabled(raw.get(k)) for k in _NEGATE_KEYS) or any(
        bool(_names(raw.get(k))) or _enabled(raw.get(k)) for k in _EXTRA_MATCH_KEYS
    )
    raw_key = repr(
        (
            sorted(srcintf), sorted(dstintf), sorted(src), sorted(dst),
            sorted(service), schedule, action,
            sorted(
                (k, repr(raw.get(k))) for k in _NEGATE_KEYS + _EXTRA_MATCH_KEYS if raw.get(k)
            ),
        )
    )
    return _Policy(
        pid, enabled, action, srcintf, dstintf, src, dst, service, schedule,
        complex_match, raw_key,
    )


def _covers(big: FrozenSet[str], small: FrozenSet[str], universe: Set[str]) -> bool:
    """True if `big` provably matches everything `small` matches (name-based)."""
    if not small:
        return False  # empty/unknown match: cannot prove anything
    if big & universe:
        return True
    return small <= big


def _is_all_addr(s: FrozenSet[str]) -> bool:
    return "all" in s


def _is_all_service(s: FrozenSet[str]) -> bool:
    return bool(s & _ALL_SERVICE)


def analyze_policy_hygiene(
    policies: Any, addresses: Any = None, addrgrps: Any = None
) -> Dict[str, Any]:
    """Analyze policies for shadowing, duplicates, any-any rules and disabled entries.

    Args:
        policies: list of cmdb firewall/policy dicts, in evaluation order.
        addresses: list of cmdb firewall/address dicts (used to detect 0.0.0.0/0 objects).
        addrgrps: list of cmdb firewall/addrgrp dicts (expanded recursively).

    Returns:
        {"summary": {...counts...}, "findings": {category: [ ... ]}, "notes": [...]}
        All lists are sorted deterministically by policy id.
    """
    notes: Set[str] = set()
    pol_list = policies if isinstance(policies, list) else []
    if not isinstance(policies, list):
        notes.add("policies input was not a list; nothing analyzed")
    addr_list = addresses if isinstance(addresses, list) else []
    grp_list = addrgrps if isinstance(addrgrps, list) else []

    groups = _expand_groups(grp_list, notes)
    all_names = _all_address_names(addr_list)

    parsed: List[_Policy] = []
    skipped = 0
    for idx, raw in enumerate(pol_list):
        pol = _normalize(raw, groups, all_names) if isinstance(raw, dict) else None
        if pol is None:
            skipped += 1
            notes.add(f"skipped malformed policy entry at position {idx}")
            continue
        parsed.append(pol)

    findings: Dict[str, List[Dict[str, Any]]] = {k: [] for k in _FINDING_KEYS}
    seen_keys: Dict[str, Any] = {}
    for i, pol in enumerate(parsed):
        if not pol.enabled:
            findings["disabled"].append({"policyid": pol.pid})
            continue

        if pol.action == "accept" and _is_all_service(pol.service):
            src_all, dst_all = _is_all_addr(pol.src), _is_all_addr(pol.dst)
            if src_all and dst_all:
                findings["any_any"].append({"policyid": pol.pid})
            elif src_all or dst_all:
                findings["permissive_any"].append(
                    {"policyid": pol.pid, "any_side": "source" if src_all else "destination"}
                )

        if pol.raw_key in seen_keys:
            findings["duplicate"].append(
                {"policyid": pol.pid, "duplicate_of": seen_keys[pol.raw_key]}
            )
            continue
        seen_keys[pol.raw_key] = pol.pid

        for earlier in parsed[:i]:
            if not earlier.enabled or earlier.complex_match:
                continue
            if earlier.schedule != "always" and earlier.schedule != pol.schedule:
                continue
            if (
                _covers(earlier.srcintf, pol.srcintf, _ALL_INTF)
                and _covers(earlier.dstintf, pol.dstintf, _ALL_INTF)
                and _covers(earlier.src, pol.src, {"all"})
                and _covers(earlier.dst, pol.dst, {"all"})
                and _covers(earlier.service, pol.service, _ALL_SERVICE)
            ):
                findings["shadowed"].append(
                    {
                        "policyid": pol.pid,
                        "shadowed_by": earlier.pid,
                        "earlier_action": earlier.action,
                        "action": pol.action,
                    }
                )
                break

    for key in _FINDING_KEYS:
        findings[key].sort(key=lambda f: _pid_key(f["policyid"]))

    summary: Dict[str, int] = {
        "policies_analyzed": len(parsed),
        "skipped": skipped,
    }
    for key in _FINDING_KEYS:
        summary[key] = len(findings[key])
    return {"summary": summary, "findings": findings, "notes": sorted(notes)}
