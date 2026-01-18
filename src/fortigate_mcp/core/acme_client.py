"""ACME client for Let's Encrypt certificate management."""
import os
import time
from typing import Optional, Tuple, Callable
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

import josepy as jose
from acme import challenges, client, messages, crypto_util

from .logging import get_logger


class ACMEClient:
    """ACME client for requesting Let's Encrypt certificates."""

    # Let's Encrypt directories
    LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    LETSENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"

    def __init__(
        self,
        email: str,
        staging: bool = False,
        account_key_path: Optional[str] = None
    ):
        """Initialize ACME client.

        Args:
            email: Contact email for Let's Encrypt account
            staging: Use staging environment (for testing)
            account_key_path: Path to store/load account key
        """
        self.email = email
        self.staging = staging
        self.directory_url = self.LETSENCRYPT_STAGING if staging else self.LETSENCRYPT_PRODUCTION
        self.account_key_path = account_key_path
        self.logger = get_logger("acme_client")

        self._account_key = None
        self._client = None
        self._registration = None

    def _get_or_create_account_key(self) -> jose.JWKRSA:
        """Get existing account key or create new one."""
        if self._account_key:
            return self._account_key

        if self.account_key_path and os.path.exists(self.account_key_path):
            self.logger.info(f"Loading account key from {self.account_key_path}")
            with open(self.account_key_path, "rb") as f:
                key_pem = f.read()
            private_key = serialization.load_pem_private_key(
                key_pem, password=None, backend=default_backend()
            )
            self._account_key = jose.JWKRSA(key=private_key)
        else:
            self.logger.info("Generating new account key")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self._account_key = jose.JWKRSA(key=private_key)

            if self.account_key_path:
                key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                os.makedirs(os.path.dirname(self.account_key_path), exist_ok=True)
                with open(self.account_key_path, "wb") as f:
                    f.write(key_pem)
                self.logger.info(f"Saved account key to {self.account_key_path}")

        return self._account_key

    def _get_client(self) -> client.ClientV2:
        """Get or create ACME client."""
        if self._client:
            return self._client

        account_key = self._get_or_create_account_key()

        # Create network client
        net = client.ClientNetwork(account_key, user_agent="fortigate-mcp-server/1.0")
        directory = messages.Directory.from_json(net.get(self.directory_url).json())
        self._client = client.ClientV2(directory, net=net)

        return self._client

    def register_account(self) -> messages.RegistrationResource:
        """Register or retrieve existing ACME account."""
        if self._registration:
            return self._registration

        acme_client = self._get_client()

        self.logger.info(f"Registering ACME account for {self.email}")

        from acme import errors as acme_errors

        try:
            # Try to create new registration
            registration = acme_client.new_account(
                messages.NewRegistration.from_data(
                    email=self.email,
                    terms_of_service_agreed=True
                )
            )
            self.logger.info("Created new ACME account")
        except acme_errors.ConflictError as e:
            # Account already exists - extract URI from the error
            account_uri = str(e.location) if hasattr(e, 'location') else str(e)
            self.logger.info(f"Account already exists at {account_uri}")

            # Create registration resource with the URI
            # The net.account must be set AFTER we have the URI for subsequent requests
            registration = messages.RegistrationResource(
                uri=account_uri,
                body=messages.Registration(
                    key=self._get_or_create_account_key(),
                    status='valid'
                )
            )
            # Set on network client for future requests
            acme_client.net.account = registration
            self.logger.info(f"Retrieved existing ACME account at {account_uri}")
        except Exception as e:
            self.logger.error(f"Account registration failed: {e}")
            raise

        self._registration = registration
        return registration

    def generate_csr(
        self,
        domains: list[str],
        key_type: str = "rsa",
        key_size: int = 2048
    ) -> Tuple[bytes, bytes]:
        """Generate a Certificate Signing Request.

        Args:
            domains: List of domain names (first is CN, rest are SANs)
            key_type: Key type ('rsa' or 'ec')
            key_size: Key size for RSA (2048, 4096) or curve for EC

        Returns:
            Tuple of (private_key_pem, csr_pem)
        """
        self.logger.info(f"Generating CSR for domains: {domains}")

        # Generate private key
        if key_type.lower() == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif key_type.lower() == "ec":
            private_key = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        # Build CSR
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0])
        ]))

        # Add all domains as SANs
        san_list = [x509.DNSName(domain) for domain in domains]
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

        # Sign CSR
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Export to PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        return private_key_pem, csr_pem

    def request_certificate(
        self,
        domains: list[str],
        dns_challenge_handler: Callable[[str, str, str], None],
        dns_cleanup_handler: Callable[[str, str], None],
        key_type: str = "rsa",
        key_size: int = 2048,
        timeout: int = 300
    ) -> Tuple[bytes, bytes, bytes]:
        """Request a certificate using DNS-01 challenge.

        Args:
            domains: List of domain names
            dns_challenge_handler: Callback to create DNS TXT record
                                   (domain, record_name, record_value) -> None
            dns_cleanup_handler: Callback to remove DNS TXT record
                                (domain, record_name) -> None
            key_type: Key type ('rsa' or 'ec')
            key_size: Key size
            timeout: Timeout for challenge validation in seconds

        Returns:
            Tuple of (private_key_pem, certificate_pem, chain_pem)
        """
        self.logger.info(f"Requesting certificate for: {domains}")

        # Ensure account is registered
        self.register_account()

        acme_client = self._get_client()

        # Generate CSR
        private_key_pem, csr_pem = self.generate_csr(domains, key_type, key_size)

        # Request new order
        order = acme_client.new_order(csr_pem)

        self.logger.info(f"Created order with {len(order.authorizations)} authorizations")

        # Process each authorization
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            self.logger.info(f"Processing authorization for {domain}")

            # Find DNS-01 challenge
            dns_challenge = None
            for challenge in authz.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    dns_challenge = challenge
                    break

            if not dns_challenge:
                raise ValueError(f"No DNS-01 challenge available for {domain}")

            # Get challenge response
            response, validation = dns_challenge.response_and_validation(
                self._get_or_create_account_key()
            )

            # Create DNS record
            record_name = f"_acme-challenge.{domain}"
            self.logger.info(f"Creating DNS TXT record: {record_name} = {validation}")

            try:
                dns_challenge_handler(domain, record_name, validation)

                # Wait for DNS propagation
                self.logger.info("Waiting for DNS propagation (30s)...")
                time.sleep(30)

                # Answer challenge
                self.logger.info("Answering challenge...")
                acme_client.answer_challenge(dns_challenge, response)

                # Wait for validation
                start_time = time.time()
                while time.time() - start_time < timeout:
                    poll_result = acme_client.poll(authz)
                    # Handle both old (single) and new (tuple) return formats
                    if isinstance(poll_result, tuple):
                        authz_resource = poll_result[0]
                    else:
                        authz_resource = poll_result
                    if authz_resource.body.status == messages.STATUS_VALID:
                        self.logger.info(f"Authorization valid for {domain}")
                        break
                    elif authz_resource.body.status == messages.STATUS_INVALID:
                        raise ValueError(f"Authorization failed for {domain}")
                    time.sleep(5)
                else:
                    raise TimeoutError(f"Authorization timeout for {domain}")

            finally:
                # Cleanup DNS record
                self.logger.info(f"Cleaning up DNS record: {record_name}")
                dns_cleanup_handler(domain, record_name)

        # Finalize order
        self.logger.info("Finalizing certificate order...")
        order = acme_client.poll_and_finalize(order)

        # Extract certificate
        cert_pem = order.fullchain_pem.encode()

        # Split certificate and chain
        certs = cert_pem.split(b"-----END CERTIFICATE-----")
        certificate_pem = certs[0] + b"-----END CERTIFICATE-----\n"
        chain_pem = b"-----END CERTIFICATE-----".join(certs[1:]).strip()
        if chain_pem:
            chain_pem = chain_pem + b"\n"

        self.logger.info("Certificate obtained successfully!")

        return private_key_pem, certificate_pem, chain_pem

    def get_certificate_info(self, cert_pem: bytes) -> dict:
        """Parse certificate and return info."""
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

        # Get SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            sans = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            sans = []

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "domains": sans,
            "days_remaining": (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        }
