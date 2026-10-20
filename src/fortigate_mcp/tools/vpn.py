"""IPsec VPN status tools for FortiGate MCP."""
from typing import Any, Dict, List, Optional
from mcp_types import TextContent as Content
from .base import FortiGateTool
from ..validation import redact_sensitive_fields


class VPNTools(FortiGateTool):
    """Read-only tools for IPsec VPN visibility."""

    def get_ipsec_tunnel_status(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Get IPsec tunnel status (monitor endpoint only; never returns pre-shared keys).

        The payload is redacted and then rendered through a field whitelist, so
        key material cannot reach the output even if the device returns it.
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = redact_sensitive_fields(api_client.get_ipsec_tunnels(vdom=vdom))
            return self._format_response(data, "ipsec_tunnels")
        except Exception as e:
            return self._handle_visibility_error("get IPsec tunnel status", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for VPN tools."""
        return {
            "name": "vpn_tools",
            "description": "FortiGate IPsec VPN visibility tools (read-only)",
            "operations": [
                {
                    "name": "get_ipsec_tunnel_status",
                    "description": "Get IPsec tunnel status and phase 2 selectors (no key material)",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False},
                    ],
                }
            ],
        }
