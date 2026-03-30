"""Firewall policy management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class FirewallTools(FortiGateTool):
    """Tools for FortiGate firewall policy management."""

    async def list_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall policies."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            policies_data = await api_client.get_firewall_policies(vdom=vdom)
            return self._format_response(policies_data, "firewall_policies")
        except Exception as e:
            return self._handle_error("list firewall policies", device_id, e)

    async def create_policy(self, device_id: str, policy_data: Dict[str, Any],
                     vdom: Optional[str] = None) -> List[Content]:
        """Create firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)

            api_client = self._get_device_api(device_id)
            await api_client.create_firewall_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create firewall policy", device_id, True, "Policy created successfully")
        except Exception as e:
            return self._handle_error("create firewall policy", device_id, e)

    async def update_policy(self, device_id: str, policy_id: str,
                     policy_data: Dict[str, Any], vdom: Optional[str] = None) -> List[Content]:
        """Update firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)

            api_client = self._get_device_api(device_id)
            await api_client.update_firewall_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update firewall policy", device_id, True, f"Policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update firewall policy", device_id, e)

    async def get_policy_detail(self, device_id: str, policy_id: str,
                         vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)

            api_client = self._get_device_api(device_id)

            # Get policy details
            policy_data = await api_client.get_firewall_policy_detail(policy_id, vdom=vdom)

            # Get address and service objects for resolution
            try:
                address_objects = await api_client.get_address_objects(vdom=vdom)
            except Exception:
                address_objects = None

            try:
                service_objects = await api_client.get_service_objects(vdom=vdom)
            except Exception:
                service_objects = None

            return self._format_response(
                policy_data,
                "firewall_policy_detail",
                device_id=device_id,
                address_objects=address_objects,
                service_objects=service_objects
            )
        except Exception as e:
            return self._handle_error("get firewall policy detail", device_id, e)

    async def delete_policy(self, device_id: str, policy_id: str,
                     vdom: Optional[str] = None) -> List[Content]:
        """Delete firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)

            api_client = self._get_device_api(device_id)
            await api_client.delete_firewall_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete firewall policy", device_id, True, f"Policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete firewall policy", device_id, e)
