"""Firewall policy management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp_types import TextContent as Content
from .base import FortiGateTool
from .security import _STATUS_TEXT
from ..analysis import analyze_policy_hygiene
from ..core.fortigate import FortiGateAPIError
from ..validation import redact_sensitive_fields

class FirewallTools(FortiGateTool):
    """Tools for FortiGate firewall policy management."""
    
    def list_policies(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List firewall policies."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            policies_data = api_client.get_firewall_policies(vdom=vdom)
            return self._format_response(policies_data, "firewall_policies")
        except Exception as e:
            return self._handle_error("list firewall policies", device_id, e)
    
    def create_policy(self, device_id: str, policy_data: Dict[str, Any], 
                     vdom: Optional[str] = None) -> List[Content]:
        """Create firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_data=policy_data)
            
            api_client = self._get_device_api(device_id)
            api_client.create_firewall_policy(policy_data, vdom=vdom)
            return self._format_operation_result("create firewall policy", device_id, True, "Policy created successfully")
        except Exception as e:
            return self._handle_error("create firewall policy", device_id, e)
    
    def update_policy(self, device_id: str, policy_id: str, 
                     policy_data: Dict[str, Any], vdom: Optional[str] = None) -> List[Content]:
        """Update firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id, policy_data=policy_data)
            
            api_client = self._get_device_api(device_id)
            api_client.update_firewall_policy(policy_id, policy_data, vdom=vdom)
            return self._format_operation_result("update firewall policy", device_id, True, f"Policy {policy_id} updated successfully")
        except Exception as e:
            return self._handle_error("update firewall policy", device_id, e)
    
    def get_policy_detail(self, device_id: str, policy_id: str, 
                         vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            
            api_client = self._get_device_api(device_id)
            
            # Get policy details
            policy_data = api_client.get_firewall_policy_detail(policy_id, vdom=vdom)
            
            # Get address and service objects for resolution
            try:
                address_objects = api_client.get_address_objects(vdom=vdom)
            except Exception:
                address_objects = None
                
            try:
                service_objects = api_client.get_service_objects(vdom=vdom)
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
    
    def delete_policy(self, device_id: str, policy_id: str, 
                     vdom: Optional[str] = None) -> List[Content]:
        """Delete firewall policy."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            
            api_client = self._get_device_api(device_id)
            api_client.delete_firewall_policy(policy_id, vdom=vdom)
            return self._format_operation_result("delete firewall policy", device_id, True, f"Policy {policy_id} deleted successfully")
        except Exception as e:
            return self._handle_error("delete firewall policy", device_id, e)
    
    async def get_policy_detail_async(self, device_id: str, policy_id: str, 
                                     vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific firewall policy (async version)."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(policy_id=policy_id)
            
            api_client = self._get_device_api(device_id)
            
            # Get policy details
            policy_data = api_client.get_firewall_policy_detail(policy_id, vdom=vdom)
            
            # Get address and service objects for resolution
            try:
                address_objects = api_client.get_address_objects(vdom=vdom)
            except Exception:
                address_objects = None
                
            try:
                service_objects = api_client.get_service_objects(vdom=vdom)
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
    
    def analyze_policy_hygiene(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """Analyze firewall policies for shadowed, duplicate, any-any and disabled rules.

        Read-only: fetches policy, address and address-group config, then runs the
        pure offline analysis. A failure fetching addresses/groups degrades the
        analysis (fixed status text, no raw error) instead of failing it; a
        failure fetching policies fails the tool.
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            policies = redact_sensitive_fields(api_client.get_firewall_policies(vdom=vdom))
            sources: Dict[str, str] = {"policy": "ok"}
            fetched: Dict[str, List[Any]] = {}
            for key, call in (
                ("address", api_client.get_address_objects),
                ("addrgrp", api_client.get_address_groups),
            ):
                try:
                    raw = redact_sensitive_fields(call(vdom=vdom))
                    results = raw.get("results") if isinstance(raw, dict) else None
                    fetched[key] = results if isinstance(results, list) else []
                    sources[key] = "ok"
                except FortiGateAPIError as e:
                    if e.status_code is None:
                        raise
                    fetched[key] = []
                    sources[key] = _STATUS_TEXT.get(e.status_code, f"HTTP {e.status_code}")

            pol_results = policies.get("results") if isinstance(policies, dict) else None
            result = analyze_policy_hygiene(
                pol_results if isinstance(pol_results, list) else [],
                fetched["address"],
                fetched["addrgrp"],
            )
            result["sources"] = sources
            return self._format_response(result, "policy_hygiene")
        except Exception as e:
            return self._handle_visibility_error("analyze policy hygiene", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for firewall tools.
        
        Returns:
            Dictionary with schema information
        """
        return {
            "name": "firewall_tools",
            "description": "FortiGate firewall policy management tools",
            "operations": [
                {
                    "name": "list_policies",
                    "description": "List firewall policies",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_policy",
                    "description": "Create firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_data", "type": "object", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "update_policy",
                    "description": "Update firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "policy_data", "type": "object", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_policy_detail",
                    "description": "Get detailed information for a specific firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_policy",
                    "description": "Delete firewall policy",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "policy_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "analyze_policy_hygiene",
                    "description": "Offline analysis of shadowed, duplicate, any-any and disabled policies",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
