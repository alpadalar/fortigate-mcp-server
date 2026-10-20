"""Monitor visibility tools (resources, license, HA, ARP, DHCP) for FortiGate MCP."""
from typing import Any, Callable, Dict, List, Optional
from mcp_types import TextContent as Content
from .base import FortiGateTool
from ..validation import redact_sensitive_fields, validate_interface_name, validate_result_limit

# Result cap shared by get_arp_table and list_dhcp_leases.
DEFAULT_RESULT_LIMIT = 100
MAX_RESULT_LIMIT = 500


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
        ]
        return {
            "name": "monitor_tools",
            "description": "FortiGate monitor visibility tools (read-only)",
            "operations": [
                {"name": n, "description": d, "parameters": [dict(p) for p in ps]}
                for n, d, ps in ops
            ],
        }
