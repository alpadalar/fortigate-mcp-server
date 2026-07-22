"""System administrator account visibility tools for FortiGate MCP."""
from typing import Any, Dict, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..validation import redact_sensitive_fields


class AdminTools(FortiGateTool):
    """Tools for FortiGate system administrator account visibility (read-only)."""

    def list_admins(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List system administrator accounts with secret fields redacted.

        Note: cmdb/system/admin is a global-scope (non-VDOM) FortiOS
        object; vdom is accepted for parameter-signature consistency with
        every other tool method but has no effect on this endpoint.
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            admin_data = api_client.get_admin_accounts(vdom=vdom)
            admin_data = redact_sensitive_fields(admin_data)
            return self._format_response(admin_data, "admin_accounts")
        except Exception as e:
            return self._handle_error("list admin accounts", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for admin tools.

        Returns:
            Dictionary with schema information
        """
        return {
            "name": "admin_tools",
            "description": "FortiGate system administrator account visibility tools (read-only)",
            "operations": [
                {
                    "name": "list_admins",
                    "description": "List system administrator accounts",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
