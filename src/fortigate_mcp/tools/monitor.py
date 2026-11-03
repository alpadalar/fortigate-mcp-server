"""Monitor visibility tools (resources, license, HA, ARP, DHCP) for FortiGate MCP."""
from typing import Any, Callable, Dict, List, Optional
from mcp_types import TextContent as Content
from .base import FortiGateTool
from ..validation import (
    redact_sensitive_fields,
    validate_interface_name,
    validate_result_limit,
    validate_session_filters,
)

# Result cap shared by get_arp_table and list_dhcp_leases.
DEFAULT_RESULT_LIMIT = 100
MAX_RESULT_LIMIT = 500

# Result cap for list_firewall_sessions.
SESSION_DEFAULT_COUNT = 20
SESSION_MAX_COUNT = 200

# Protocol names accepted by validate_session_proto, as IP protocol numbers.
_PROTO_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "sctp": 132}

# Session entry keys checked for each wire filter, in order of preference.
_SESSION_FILTER_KEYS = {
    "srcaddr": ("saddr", "srcaddr"),
    "dstaddr": ("daddr", "dstaddr"),
    "srcport": ("sport", "srcport"),
    "dstport": ("dport", "dstport"),
    "protocol": ("proto", "protocol"),
}


def _proto_number(value: Any) -> Optional[int]:
    """Normalize a protocol name or number to its IP protocol number."""
    text = str(value).strip().lower()
    if text in _PROTO_NUMBERS:
        return _PROTO_NUMBERS[text]
    try:
        return int(text)
    except ValueError:
        return None


def _session_matches(entry: Dict[str, Any], filters: Dict[str, str]) -> bool:
    """Return whether a session entry satisfies every supplied filter.

    Some FortiOS versions ignore the session filter query parameters and
    return unfiltered sessions, so results are always checked client-side.
    An entry missing a filtered field does not match.
    """
    for name, keys in _SESSION_FILTER_KEYS.items():
        if name not in filters:
            continue
        value = next((entry[k] for k in keys if entry.get(k) is not None), None)
        if value is None:
            return False
        if name == "protocol":
            if _proto_number(value) != _proto_number(filters[name]):
                return False
        elif str(value).strip().lower() != filters[name].lower():
            return False
    return True


class MonitorTools(FortiGateTool):
    """Read-only tools for FortiGate monitor-API visibility."""

    def _get_singleton(
        self,
        operation: str,
        resource_type: str,
        device_id: str,
        vdom: Optional[str],
        method_name: str,
    ) -> List[Content]:
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            call: Callable[..., Dict[str, Any]] = getattr(api_client, method_name)
            data = redact_sensitive_fields(call(vdom=vdom))
            return self._format_response(data, resource_type)
        except Exception as e:
            return self._handle_visibility_error(operation, device_id, e)

    def get_system_resources(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get the latest CPU, memory, session and setup-rate values (no history)."""
        return self._get_singleton(
            "get system resources", "system_resources", device_id, vdom,
            "get_system_resource_usage",
        )

    def get_license_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get license and contract entitlement status."""
        return self._get_singleton(
            "get license status", "license_status", device_id, vdom, "get_license_status"
        )

    def get_ha_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get HA peer status; empty peers means a standalone unit (not an error)."""
        return self._get_singleton(
            "get HA status", "ha_status", device_id, vdom, "get_ha_peers"
        )

    def _get_capped_table(
        self,
        operation: str,
        resource_type: str,
        method_name: str,
        device_id: str,
        vdom: Optional[str],
        interface: Optional[str],
        limit: Optional[int],
    ) -> List[Content]:
        try:
            if interface is not None:
                validate_interface_name(interface)
            cap = validate_result_limit(limit, DEFAULT_RESULT_LIMIT, MAX_RESULT_LIMIT)
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            call: Callable[..., Dict[str, Any]] = getattr(api_client, method_name)
            data = redact_sensitive_fields(call(vdom=vdom))
            results = data.get("results") if isinstance(data, dict) else None
            entries = [e for e in results if isinstance(e, dict)] if isinstance(results, list) else []
            if interface is not None:
                entries = [e for e in entries if e.get("interface") == interface]
            total = len(entries)
            payload = {
                "results": entries[:cap],
                "total": total,
                "limit": cap,
                "interface": interface,
            }
            return self._format_response(payload, resource_type)
        except Exception as e:
            return self._handle_visibility_error(operation, device_id, e)

    def get_arp_table(
        self,
        device_id: str,
        vdom: Optional[str] = None,
        interface: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Content]:
        """Get the ARP table, optionally filtered by interface.

        Filtering and capping are client-side. `limit` defaults to
        DEFAULT_RESULT_LIMIT (100) and is rejected above MAX_RESULT_LIMIT (500).
        Output contains MAC addresses and is sensitive.
        """
        return self._get_capped_table(
            "get ARP table", "arp_table", "get_arp_table", device_id, vdom, interface, limit
        )

    def list_dhcp_leases(
        self,
        device_id: str,
        vdom: Optional[str] = None,
        interface: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Content]:
        """List DHCP leases, optionally filtered by interface.

        Filtering and capping are client-side. `limit` defaults to
        DEFAULT_RESULT_LIMIT (100) and is rejected above MAX_RESULT_LIMIT (500).
        Output contains MAC addresses and hostnames and is sensitive.
        """
        return self._get_capped_table(
            "list DHCP leases", "dhcp_leases", "get_dhcp_leases", device_id, vdom, interface,
            limit,
        )

    def list_firewall_sessions(
        self,
        device_id: str,
        vdom: Optional[str] = None,
        count: Optional[int] = None,
        srcaddr: Optional[str] = None,
        dstaddr: Optional[str] = None,
        srcport: Optional[int] = None,
        dstport: Optional[int] = None,
        proto: Optional[str] = None,
    ) -> List[Content]:
        """List active firewall sessions with optional filters.

        `count` defaults to SESSION_DEFAULT_COUNT (20) and is rejected above
        SESSION_MAX_COUNT (200). All inputs are validated before any device
        contact; the cap is also enforced client-side on the returned list.
        """
        try:
            cap = validate_result_limit(count, SESSION_DEFAULT_COUNT, SESSION_MAX_COUNT, "count")
            filters = validate_session_filters(srcaddr, dstaddr, srcport, dstport, proto)
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = redact_sensitive_fields(
                api_client.get_firewall_sessions(cap, filters, vdom=vdom)
            )
            results = data.get("results") if isinstance(data, dict) else None
            device_matched = None
            if isinstance(results, dict):
                # monitor/firewall/sessions (and some FortiOS versions of
                # monitor/firewall/session) wrap sessions as {"summary": ..., "details": [...]}.
                summary = results.get("summary")
                if isinstance(summary, dict):
                    device_matched = summary.get("matched_count")
                results = results.get("details")
            entries = [e for e in results if isinstance(e, dict)] if isinstance(results, list) else []
            # Address/port filters are applied by the device; re-check them to
            # detect a device that ignored them. The protocol filter is never
            # applied device-side by monitor/firewall/sessions, so it is always
            # applied here and does not count as "ignored by the device".
            device_filters = {k: v for k, v in filters.items() if k != "protocol"}
            device_ok = [e for e in entries if _session_matches(e, device_filters)]
            matched = [e for e in device_ok if _session_matches(e, filters)]
            payload = {
                "results": matched[:cap],
                "total": len(matched),
                "limit": cap,
                "truncated": len(entries) >= cap,
                "filters": filters,
            }
            if len(device_ok) < len(entries):
                # The device ignored (some of) the filters: only the first
                # `cap` sessions it returned were inspected.
                payload["filters_ignored_by_device"] = True
                payload["inspected"] = len(entries)
            elif isinstance(device_matched, int) and not isinstance(device_matched, bool):
                payload["device_matched"] = device_matched
                payload["protocol_filtered_locally"] = "protocol" in filters
            return self._format_response(payload, "firewall_sessions")
        except Exception as e:
            return self._handle_visibility_error("list firewall sessions", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for monitor tools."""
        base = [
            {"name": "device_id", "type": "string", "required": True},
            {"name": "vdom", "type": "string", "required": False},
        ]
        filt = base + [
            {"name": "interface", "type": "string", "required": False},
            {"name": "limit", "type": "integer", "required": False},
        ]
        ops = [
            ("get_system_resources", "Get latest CPU/memory/session/setup-rate values", base),
            ("get_license_status", "Get license and contract status", base),
            ("get_ha_status", "Get HA peer status (empty means standalone)", base),
            ("get_arp_table", "Get the ARP table with optional interface filter and cap", filt),
            ("list_dhcp_leases", "List DHCP leases with optional interface filter and cap", filt),
            (
                "list_firewall_sessions",
                "List active firewall sessions with validated filters (default 20, max 200)",
                base + [
                    {"name": "count", "type": "integer", "required": False},
                    {"name": "srcaddr", "type": "string", "required": False},
                    {"name": "dstaddr", "type": "string", "required": False},
                    {"name": "srcport", "type": "integer", "required": False},
                    {"name": "dstport", "type": "integer", "required": False},
                    {"name": "proto", "type": "string", "required": False},
                ],
            ),
        ]
        return {
            "name": "monitor_tools",
            "description": "FortiGate monitor visibility tools (read-only)",
            "operations": [
                {"name": n, "description": d, "parameters": [dict(p) for p in ps]}
                for n, d, ps in ops
            ],
        }
