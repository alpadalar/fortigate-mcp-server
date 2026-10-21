"""Config-object visibility tools (groups, schedules, IP pools, central SNAT) for FortiGate MCP."""
from typing import Any, Callable, Dict, List, Optional
from mcp_types import TextContent as Content
from .base import FortiGateTool
from .security import _STATUS_TEXT
from ..core.fortigate import FortiGateAPIError
from ..validation import redact_sensitive_fields

_NOT_SUPPORTED_TEXT = "not supported on this FortiOS version"


class ObjectTools(FortiGateTool):
    """Read-only tools for firewall config-object visibility."""

    def _list_single(
        self,
        operation: str,
        resource_type: str,
        device_id: str,
        vdom: Optional[str],
        method_name: str,
    ) -> List[Content]:
        """Shared validate -> api -> redact -> format flow for single-endpoint tools."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            call: Callable[..., Dict[str, Any]] = getattr(api_client, method_name)
            data = call(vdom=vdom)
            data = redact_sensitive_fields(data)
            return self._format_response(data, resource_type)
        except Exception as e:
            return self._handle_visibility_error(operation, device_id, e)

    def list_address_groups(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall address groups with their members."""
        return self._list_single(
            "list address groups", "address_groups", device_id, vdom, "get_address_groups"
        )

    def list_service_groups(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall service groups with their members."""
        return self._list_single(
            "list service groups", "service_groups", device_id, vdom, "get_service_groups"
        )

    def list_ip_pools(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List IP pools (NAT pools)."""
        return self._list_single("list IP pools", "ip_pools", device_id, vdom, "get_ip_pools")

    def list_central_snat_maps(
        self, device_id: str, vdom: Optional[str] = None
    ) -> List[Content]:
        """List central SNAT map entries."""
        return self._list_single(
            "list central SNAT maps",
            "central_snat_maps",
            device_id,
            vdom,
            "get_central_snat_maps",
        )

    def list_zones(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall zones, their member interfaces and the interface-to-zone index."""
        return self._list_single("list zones", "zones", device_id, vdom, "get_zones")

    def list_dhcp_servers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List configured DHCP server scopes (not leases)."""
        return self._list_single(
            "list DHCP servers", "dhcp_servers", device_id, vdom, "get_dhcp_servers"
        )

    def list_schedules(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List recurring, one-time and group schedules.

        Each of the 3 tables is queried and caught independently: a failure on
        one renders as "query failed - ..." for that category only.
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            category_calls = (
                ("recurring", api_client.get_recurring_schedules),
                ("onetime", api_client.get_onetime_schedules),
                ("group", api_client.get_schedule_groups),
            )

            categories: Dict[str, Any] = {}
            for key, call in category_calls:
                try:
                    raw = redact_sensitive_fields(call(vdom=vdom))
                    categories[key] = {"status": "ok", "schedules": raw.get("results", [])}
                except FortiGateAPIError as e:
                    if e.status_code is None:
                        # Network-level failure: don't burn more timeouts.
                        raise
                    if e.status_code == 404:
                        reason = _NOT_SUPPORTED_TEXT
                    else:
                        reason = _STATUS_TEXT.get(e.status_code, f"HTTP {e.status_code}")
                    categories[key] = {"status": "error", "error": reason}

            return self._format_response(categories, "schedules")
        except Exception as e:
            return self._handle_visibility_error("list schedules", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for object tools."""
        params = [
            {"name": "device_id", "type": "string", "required": True},
            {"name": "vdom", "type": "string", "required": False},
        ]
        ops = [
            ("list_address_groups", "List firewall address groups with members"),
            ("list_service_groups", "List firewall service groups with members"),
            ("list_schedules", "List recurring, one-time and group schedules"),
            ("list_ip_pools", "List IP pools (NAT pools)"),
            ("list_central_snat_maps", "List central SNAT map entries"),
            ("list_zones", "List firewall zones with member interfaces and interface-to-zone index"),
            ("list_dhcp_servers", "List configured DHCP server scopes"),
        ]
        return {
            "name": "object_tools",
            "description": "FortiGate config-object visibility tools (read-only)",
            "operations": [
                {"name": n, "description": d, "parameters": [dict(p) for p in params]}
                for n, d in ops
            ],
        }
