"""Certificate management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool


class CertificateTools(FortiGateTool):
    """Tools for FortiGate certificate management."""

    def list_local_certificates(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List local (device) certificates."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            certs_data = api_client.get_local_certificates(vdom=vdom)
            return self._format_response(certs_data, "certificates")
        except Exception as e:
            return self._handle_error("list local certificates", device_id, e)

    def list_ca_certificates(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List CA certificates."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            certs_data = api_client.get_ca_certificates(vdom=vdom)
            return self._format_response(certs_data, "certificates")
        except Exception as e:
            return self._handle_error("list CA certificates", device_id, e)

    def list_remote_certificates(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List remote certificates."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            certs_data = api_client.get_remote_certificates(vdom=vdom)
            return self._format_response(certs_data, "certificates")
        except Exception as e:
            return self._handle_error("list remote certificates", device_id, e)

    def get_local_certificate_detail(self, device_id: str, cert_name: str,
                                     vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific local certificate."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name)
            api_client = self._get_device_api(device_id)
            cert_data = api_client.get_local_certificate_detail(cert_name, vdom=vdom)
            return self._format_response(cert_data, "certificate_detail")
        except Exception as e:
            return self._handle_error("get local certificate detail", device_id, e)

    def get_ca_certificate_detail(self, device_id: str, cert_name: str,
                                  vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific CA certificate."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name)
            api_client = self._get_device_api(device_id)
            cert_data = api_client.get_ca_certificate_detail(cert_name, vdom=vdom)
            return self._format_response(cert_data, "certificate_detail")
        except Exception as e:
            return self._handle_error("get CA certificate detail", device_id, e)

    def get_remote_certificate_detail(self, device_id: str, cert_name: str,
                                      vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific remote certificate."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name)
            api_client = self._get_device_api(device_id)
            cert_data = api_client.get_remote_certificate_detail(cert_name, vdom=vdom)
            return self._format_response(cert_data, "certificate_detail")
        except Exception as e:
            return self._handle_error("get remote certificate detail", device_id, e)

    def list_crl(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List certificate revocation lists."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            crl_data = api_client.get_crl(vdom=vdom)
            return self._format_response(crl_data, "crl")
        except Exception as e:
            return self._handle_error("list CRL", device_id, e)

    def get_crl_detail(self, device_id: str, crl_name: str,
                       vdom: Optional[str] = None) -> List[Content]:
        """Get detailed information for a specific CRL."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(crl_name=crl_name)
            api_client = self._get_device_api(device_id)
            crl_data = api_client.get_crl_detail(crl_name, vdom=vdom)
            return self._format_response(crl_data, "crl_detail")
        except Exception as e:
            return self._handle_error("get CRL detail", device_id, e)

    def delete_local_certificate(self, device_id: str, cert_name: str,
                                 vdom: Optional[str] = None) -> List[Content]:
        """Delete a local certificate."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name)
            api_client = self._get_device_api(device_id)
            api_client.delete_local_certificate(cert_name, vdom=vdom)
            return self._format_operation_result(
                "delete local certificate", device_id, True,
                f"Certificate '{cert_name}' deleted successfully"
            )
        except Exception as e:
            return self._handle_error("delete local certificate", device_id, e)

    def delete_ca_certificate(self, device_id: str, cert_name: str,
                              vdom: Optional[str] = None) -> List[Content]:
        """Delete a CA certificate."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name)
            api_client = self._get_device_api(device_id)
            api_client.delete_ca_certificate(cert_name, vdom=vdom)
            return self._format_operation_result(
                "delete CA certificate", device_id, True,
                f"CA Certificate '{cert_name}' deleted successfully"
            )
        except Exception as e:
            return self._handle_error("delete CA certificate", device_id, e)

    def delete_remote_certificate(self, device_id: str, cert_name: str,
                                  vdom: Optional[str] = None) -> List[Content]:
        """Delete a remote certificate."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name)
            api_client = self._get_device_api(device_id)
            api_client.delete_remote_certificate(cert_name, vdom=vdom)
            return self._format_operation_result(
                "delete remote certificate", device_id, True,
                f"Remote Certificate '{cert_name}' deleted successfully"
            )
        except Exception as e:
            return self._handle_error("delete remote certificate", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for certificate tools."""
        return {
            "name": "certificate_tools",
            "description": "FortiGate certificate management tools",
            "operations": [
                {
                    "name": "list_local_certificates",
                    "description": "List local (device) certificates",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_ca_certificates",
                    "description": "List CA certificates",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_remote_certificates",
                    "description": "List remote certificates",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_local_certificate_detail",
                    "description": "Get detailed information for a local certificate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_ca_certificate_detail",
                    "description": "Get detailed information for a CA certificate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_remote_certificate_detail",
                    "description": "Get detailed information for a remote certificate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_crl",
                    "description": "List certificate revocation lists",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_crl_detail",
                    "description": "Get detailed information for a CRL",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "crl_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_local_certificate",
                    "description": "Delete a local certificate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_ca_certificate",
                    "description": "Delete a CA certificate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_remote_certificate",
                    "description": "Delete a remote certificate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
