"""ACME/Let's Encrypt certificate tools for FortiGate MCP."""
import os
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.acme_client import ACMEClient
from ..core.cloudflare_dns import CloudflareDNS, CloudflareDNSChallengeHandler


class ACMETools(FortiGateTool):
    """Tools for ACME/Let's Encrypt certificate management."""

    def __init__(self, manager, config=None):
        """Initialize ACME tools.

        Args:
            manager: FortiGate manager instance
            config: Optional configuration dict with cloudflare_api_token and acme_email
        """
        super().__init__(manager)
        self._config = config or {}
        self._cloudflare_client = None
        self._acme_client = None

    def _get_cloudflare_client(self, api_token: Optional[str] = None) -> CloudflareDNS:
        """Get or create Cloudflare client."""
        token = api_token or self._config.get("cloudflare_api_token") or os.environ.get("CLOUDFLARE_API_TOKEN")
        if not token:
            raise ValueError("Cloudflare API token is required. Provide via parameter, config, or CLOUDFLARE_API_TOKEN env var")
        return CloudflareDNS(token)

    def _get_acme_client(
        self,
        email: Optional[str] = None,
        staging: bool = False
    ) -> ACMEClient:
        """Get or create ACME client."""
        acme_email = email or self._config.get("acme_email") or os.environ.get("ACME_EMAIL")
        if not acme_email:
            raise ValueError("ACME email is required. Provide via parameter, config, or ACME_EMAIL env var")

        account_key_path = self._config.get("acme_account_key_path") or os.environ.get("ACME_ACCOUNT_KEY_PATH")
        if not account_key_path:
            # Default to home directory
            account_key_path = os.path.expanduser("~/.acme/account.key")

        return ACMEClient(
            email=acme_email,
            staging=staging,
            account_key_path=account_key_path
        )

    def request_certificate(
        self,
        domains: List[str],
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        staging: bool = False
    ) -> List[Content]:
        """Request a Let's Encrypt certificate using Cloudflare DNS challenge.

        Args:
            domains: List of domain names for the certificate
            email: Contact email for Let's Encrypt (uses config/env if not provided)
            cloudflare_api_token: Cloudflare API token (uses config/env if not provided)
            key_type: Key type ('rsa' or 'ec')
            key_size: Key size for RSA (2048 or 4096)
            staging: Use Let's Encrypt staging environment for testing

        Returns:
            Certificate details including private key and certificate PEM
        """
        try:
            if not domains:
                raise ValueError("At least one domain is required")

            # Initialize clients
            cloudflare = self._get_cloudflare_client(cloudflare_api_token)
            acme = self._get_acme_client(email, staging)

            # Verify Cloudflare token
            cloudflare.verify_token()

            # Create challenge handler
            challenge_handler = CloudflareDNSChallengeHandler(cloudflare)

            # Request certificate
            private_key_pem, certificate_pem, chain_pem = acme.request_certificate(
                domains=domains,
                dns_challenge_handler=challenge_handler.create_challenge,
                dns_cleanup_handler=challenge_handler.cleanup_challenge,
                key_type=key_type,
                key_size=key_size
            )

            # Get certificate info
            cert_info = acme.get_certificate_info(certificate_pem)

            result = {
                "status": "success",
                "domains": domains,
                "certificate_info": cert_info,
                "staging": staging,
                "private_key": private_key_pem.decode(),
                "certificate": certificate_pem.decode(),
                "chain": chain_pem.decode() if chain_pem else ""
            }

            return [Content(
                type="text",
                text=f"Certificate issued successfully!\n\n"
                     f"Domains: {', '.join(domains)}\n"
                     f"Subject: {cert_info['subject']}\n"
                     f"Issuer: {cert_info['issuer']}\n"
                     f"Valid until: {cert_info['not_valid_after']}\n"
                     f"Days remaining: {cert_info['days_remaining']}\n"
                     f"Staging: {staging}\n\n"
                     f"--- Private Key ---\n{private_key_pem.decode()}\n"
                     f"--- Certificate ---\n{certificate_pem.decode()}\n"
                     f"--- Chain ---\n{chain_pem.decode() if chain_pem else 'N/A'}"
            )]

        except Exception as e:
            return [Content(
                type="text",
                text=f"Failed to request certificate: {str(e)}"
            )]

    def request_and_import_certificate(
        self,
        device_id: str,
        domains: List[str],
        cert_name: str,
        email: Optional[str] = None,
        cloudflare_api_token: Optional[str] = None,
        key_type: str = "rsa",
        key_size: int = 2048,
        staging: bool = False,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Request a Let's Encrypt certificate and import it to FortiGate.

        Args:
            device_id: FortiGate device ID
            domains: List of domain names for the certificate
            cert_name: Name for the certificate in FortiGate
            email: Contact email for Let's Encrypt
            cloudflare_api_token: Cloudflare API token
            key_type: Key type ('rsa' or 'ec')
            key_size: Key size for RSA
            staging: Use Let's Encrypt staging environment
            vdom: Virtual domain for import

        Returns:
            Import result
        """
        try:
            if not domains:
                raise ValueError("At least one domain is required")
            if not cert_name:
                raise ValueError("Certificate name is required")

            self._validate_device_exists(device_id)

            # Initialize clients
            cloudflare = self._get_cloudflare_client(cloudflare_api_token)
            acme = self._get_acme_client(email, staging)

            # Verify Cloudflare token
            cloudflare.verify_token()

            # Create challenge handler
            challenge_handler = CloudflareDNSChallengeHandler(cloudflare)

            # Request certificate
            private_key_pem, certificate_pem, chain_pem = acme.request_certificate(
                domains=domains,
                dns_challenge_handler=challenge_handler.create_challenge,
                dns_cleanup_handler=challenge_handler.cleanup_challenge,
                key_type=key_type,
                key_size=key_size
            )

            # Import to FortiGate
            api_client = self._get_device_api(device_id)

            # Combine certificate and chain for full chain import
            full_cert = certificate_pem.decode()
            if chain_pem:
                full_cert += chain_pem.decode()

            import_result = api_client.import_local_certificate(
                cert_name=cert_name,
                certificate=full_cert,
                private_key=private_key_pem.decode(),
                vdom=vdom
            )

            # Get certificate info
            cert_info = acme.get_certificate_info(certificate_pem)

            return [Content(
                type="text",
                text=f"Certificate issued and imported successfully!\n\n"
                     f"Device: {device_id}\n"
                     f"Certificate Name: {cert_name}\n"
                     f"Domains: {', '.join(domains)}\n"
                     f"Subject: {cert_info['subject']}\n"
                     f"Issuer: {cert_info['issuer']}\n"
                     f"Valid until: {cert_info['not_valid_after']}\n"
                     f"Days remaining: {cert_info['days_remaining']}\n"
                     f"Staging: {staging}"
            )]

        except Exception as e:
            return self._handle_error("request and import certificate", device_id, e)

    def import_certificate(
        self,
        device_id: str,
        cert_name: str,
        certificate: str,
        private_key: str,
        password: Optional[str] = None,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Import an existing certificate to FortiGate.

        Args:
            device_id: FortiGate device ID
            cert_name: Name for the certificate in FortiGate
            certificate: PEM-encoded certificate
            private_key: PEM-encoded private key
            password: Optional password for encrypted private key
            vdom: Virtual domain for import

        Returns:
            Import result
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name, certificate=certificate, private_key=private_key)

            api_client = self._get_device_api(device_id)

            import_result = api_client.import_local_certificate(
                cert_name=cert_name,
                certificate=certificate,
                private_key=private_key,
                password=password,
                vdom=vdom
            )

            return self._format_operation_result(
                "import certificate", device_id, True,
                f"Certificate '{cert_name}' imported successfully"
            )

        except Exception as e:
            return self._handle_error("import certificate", device_id, e)

    def import_ca_certificate(
        self,
        device_id: str,
        cert_name: str,
        certificate: str,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Import a CA certificate to FortiGate.

        Args:
            device_id: FortiGate device ID
            cert_name: Name for the CA certificate in FortiGate
            certificate: PEM-encoded CA certificate
            vdom: Virtual domain for import

        Returns:
            Import result
        """
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(cert_name=cert_name, certificate=certificate)

            api_client = self._get_device_api(device_id)

            import_result = api_client.import_ca_certificate(
                cert_name=cert_name,
                certificate=certificate,
                vdom=vdom
            )

            return self._format_operation_result(
                "import CA certificate", device_id, True,
                f"CA Certificate '{cert_name}' imported successfully"
            )

        except Exception as e:
            return self._handle_error("import CA certificate", device_id, e)

    def list_cloudflare_zones(
        self,
        cloudflare_api_token: Optional[str] = None
    ) -> List[Content]:
        """List Cloudflare zones available for DNS challenges.

        Args:
            cloudflare_api_token: Cloudflare API token

        Returns:
            List of zones
        """
        try:
            cloudflare = self._get_cloudflare_client(cloudflare_api_token)
            zones = cloudflare.list_zones()

            if not zones:
                return [Content(
                    type="text",
                    text="No Cloudflare zones found for this API token."
                )]

            zone_list = "\n".join([
                f"- {z['name']} (ID: {z['id']}, Status: {z['status']})"
                for z in zones
            ])

            return [Content(
                type="text",
                text=f"Cloudflare Zones:\n\n{zone_list}"
            )]

        except Exception as e:
            return [Content(
                type="text",
                text=f"Failed to list Cloudflare zones: {str(e)}"
            )]

    def verify_cloudflare_token(
        self,
        cloudflare_api_token: Optional[str] = None
    ) -> List[Content]:
        """Verify Cloudflare API token is valid.

        Args:
            cloudflare_api_token: Cloudflare API token

        Returns:
            Verification result
        """
        try:
            cloudflare = self._get_cloudflare_client(cloudflare_api_token)
            result = cloudflare.verify_token()

            return [Content(
                type="text",
                text=f"Cloudflare API token is valid.\nStatus: {result['status']}"
            )]

        except Exception as e:
            return [Content(
                type="text",
                text=f"Cloudflare API token verification failed: {str(e)}"
            )]

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for ACME tools."""
        return {
            "name": "acme_tools",
            "description": "ACME/Let's Encrypt certificate management tools",
            "operations": [
                {
                    "name": "request_certificate",
                    "description": "Request a Let's Encrypt certificate using Cloudflare DNS challenge",
                    "parameters": [
                        {"name": "domains", "type": "array", "required": True},
                        {"name": "email", "type": "string", "required": False},
                        {"name": "cloudflare_api_token", "type": "string", "required": False},
                        {"name": "key_type", "type": "string", "required": False},
                        {"name": "key_size", "type": "integer", "required": False},
                        {"name": "staging", "type": "boolean", "required": False}
                    ]
                },
                {
                    "name": "request_and_import_certificate",
                    "description": "Request Let's Encrypt certificate and import to FortiGate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "domains", "type": "array", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "email", "type": "string", "required": False},
                        {"name": "cloudflare_api_token", "type": "string", "required": False},
                        {"name": "key_type", "type": "string", "required": False},
                        {"name": "key_size", "type": "integer", "required": False},
                        {"name": "staging", "type": "boolean", "required": False},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "import_certificate",
                    "description": "Import an existing certificate to FortiGate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "certificate", "type": "string", "required": True},
                        {"name": "private_key", "type": "string", "required": True},
                        {"name": "password", "type": "string", "required": False},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "import_ca_certificate",
                    "description": "Import a CA certificate to FortiGate",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "cert_name", "type": "string", "required": True},
                        {"name": "certificate", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "list_cloudflare_zones",
                    "description": "List Cloudflare zones available for DNS challenges",
                    "parameters": [
                        {"name": "cloudflare_api_token", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "verify_cloudflare_token",
                    "description": "Verify Cloudflare API token is valid",
                    "parameters": [
                        {"name": "cloudflare_api_token", "type": "string", "required": False}
                    ]
                }
            ]
        }
