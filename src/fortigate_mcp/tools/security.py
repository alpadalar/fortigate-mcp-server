"""Security profile, SSL-VPN, and local-in policy visibility tools for FortiGate MCP."""
from typing import Any, Dict, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.fortigate import FortiGateAPIError
from ..validation import redact_sensitive_fields

# Fixed, status-derived per-category error texts: the raw FortiGateAPIError
# message can embed untrusted device/middlebox-controlled response-body text
# (see the threat model in core/fortigate.py _make_request), so it is never
# rendered verbatim into MCP output -- mirrors the status-code normalization
# _handle_error applies on the non-category error path.
_STATUS_TEXT = {
    401: "authentication failed",
    403: "permission denied",
    404: "endpoint not found",
    500: "device internal error",
}


class SecurityTools(FortiGateTool):
    """Tools for FortiGate security profile, SSL-VPN, and local-in policy visibility (read-only)."""

    def list_security_profiles(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List AV/IPS/web-filter/application-control profile summaries.

        Each of the 4 categories is queried and caught independently: a
        403/licensing failure on one category renders as "query failed - ..."
        for that category only, while the other 3 categories render
        normally -- never collapsed into the same "not configured" text
        (VIS-01).
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            category_calls = (
                ("antivirus", api_client.get_antivirus_profiles),
                ("ips", api_client.get_ips_sensors),
                ("webfilter", api_client.get_webfilter_profiles),
                ("application_control", api_client.get_application_lists),
            )

            categories: Dict[str, Any] = {}
            for key, call in category_calls:
                try:
                    raw = call(vdom=vdom)
                    raw = redact_sensitive_fields(raw)
                    categories[key] = {"status": "ok", "profiles": raw.get("results", [])}
                except FortiGateAPIError as e:
                    if e.status_code is None:
                        # Network-level failure (no HTTP status): the device
                        # is unreachable -- don't burn 3 more sequential
                        # blocking timeouts; re-raise so the outer handler
                        # renders the standard connection-failure response.
                        raise
                    # Render a fixed, status-derived reason -- never the raw
                    # message, which can echo untrusted response-body text.
                    reason = _STATUS_TEXT.get(e.status_code, f"HTTP {e.status_code}")
                    categories[key] = {"status": "error", "error": reason}
                # Any OTHER exception type is intentionally NOT caught here --
                # it propagates to the outer try/except -> self._handle_error,
                # per the locked "no bare-except" decision (VIS-01).

            return self._format_response(categories, "security_profiles")
        except Exception as e:
            return self._handle_error("list security profiles", device_id, e)

    def get_sslvpn_settings(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get SSL-VPN settings plus portal bookmarks (degrades gracefully if
        the portal GET fails -- settings still render)."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            settings_data = api_client.get_sslvpn_settings(vdom=vdom)
            settings_data = redact_sensitive_fields(settings_data)

            try:
                portals_data = api_client.get_sslvpn_portals(vdom=vdom)
                portals_data = redact_sensitive_fields(portals_data)
            except FortiGateAPIError as e:
                self.logger.warning(
                    f"SSL-VPN portal fetch failed for device "
                    f"{self._safe_id(device_id)}: {e} -- rendering settings without bookmarks"
                )
                portals_data = None

            return self._format_response(
                settings_data, "sslvpn_settings", portals_data=portals_data
            )
        except Exception as e:
            return self._handle_error("get SSL-VPN settings", device_id, e)

    def list_local_in_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List IPv4 local-in policies (device-destined traffic rules).

        IPv4 only -- IPv6 local-in-policy6 is not covered (deferred, VIS-F3).
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = api_client.get_local_in_policies(vdom=vdom)
            data = redact_sensitive_fields(data)
            return self._format_response(data, "local_in_policies")
        except Exception as e:
            return self._handle_error("list local-in policies", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for security tools.

        Returns:
            Dictionary with schema information
        """
        return {
            "name": "security_tools",
            "description": "FortiGate security profile, SSL-VPN, and local-in policy visibility tools (read-only)",
            "operations": [
                {
                    "name": "list_security_profiles",
                    "description": "List AV/IPS/web-filter/application-control profile summaries",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_sslvpn_settings",
                    "description": "Get SSL-VPN settings and portal bookmarks",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_local_in_policies",
                    "description": "List IPv4 local-in policies (device-destined traffic rules)",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
