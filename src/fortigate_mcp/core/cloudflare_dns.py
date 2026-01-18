"""Cloudflare DNS management for ACME DNS-01 challenges."""
import time
from typing import Optional
import httpx

from .logging import get_logger


class CloudflareDNS:
    """Cloudflare DNS API client for managing DNS records."""

    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self, api_token: str):
        """Initialize Cloudflare DNS client.

        Args:
            api_token: Cloudflare API token with DNS edit permissions
        """
        self.api_token = api_token
        self.logger = get_logger("cloudflare_dns")
        self._zone_cache: dict[str, str] = {}

    def _get_headers(self) -> dict:
        """Get authorization headers."""
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None
    ) -> dict:
        """Make API request to Cloudflare."""
        url = f"{self.BASE_URL}{endpoint}"

        with httpx.Client(timeout=30) as client:
            if method == "GET":
                response = client.get(url, headers=self._get_headers())
            elif method == "POST":
                response = client.post(url, headers=self._get_headers(), json=data)
            elif method == "PUT":
                response = client.put(url, headers=self._get_headers(), json=data)
            elif method == "DELETE":
                response = client.delete(url, headers=self._get_headers())
            else:
                raise ValueError(f"Unsupported method: {method}")

            result = response.json()

            if not result.get("success", False):
                errors = result.get("errors", [])
                error_msg = "; ".join([e.get("message", str(e)) for e in errors])
                raise Exception(f"Cloudflare API error: {error_msg}")

            return result

    def get_zone_id(self, domain: str) -> str:
        """Get zone ID for a domain.

        Args:
            domain: Domain name (will find the appropriate zone)

        Returns:
            Zone ID
        """
        # Check cache first
        if domain in self._zone_cache:
            return self._zone_cache[domain]

        # Try to find the zone for this domain
        parts = domain.split(".")

        # Try progressively shorter domain parts to find the zone
        for i in range(len(parts) - 1):
            zone_name = ".".join(parts[i:])

            result = self._make_request("GET", f"/zones?name={zone_name}")
            zones = result.get("result", [])

            if zones:
                zone_id = zones[0]["id"]
                self._zone_cache[domain] = zone_id
                self.logger.info(f"Found zone {zone_name} (ID: {zone_id}) for {domain}")
                return zone_id

        raise ValueError(f"No Cloudflare zone found for domain: {domain}")

    def create_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: str,
        ttl: int = 120
    ) -> str:
        """Create a TXT record.

        Args:
            domain: Domain for zone lookup
            record_name: Full record name (e.g., _acme-challenge.example.com)
            record_value: TXT record value
            ttl: Time to live in seconds

        Returns:
            Record ID
        """
        zone_id = self.get_zone_id(domain)

        self.logger.info(f"Creating TXT record: {record_name} = {record_value}")

        data = {
            "type": "TXT",
            "name": record_name,
            "content": record_value,
            "ttl": ttl
        }

        result = self._make_request("POST", f"/zones/{zone_id}/dns_records", data)
        record_id = result["result"]["id"]

        self.logger.info(f"Created TXT record with ID: {record_id}")
        return record_id

    def delete_txt_record(self, domain: str, record_name: str) -> bool:
        """Delete a TXT record by name.

        Args:
            domain: Domain for zone lookup
            record_name: Full record name

        Returns:
            True if deleted successfully
        """
        zone_id = self.get_zone_id(domain)

        # Find the record
        result = self._make_request(
            "GET",
            f"/zones/{zone_id}/dns_records?type=TXT&name={record_name}"
        )

        records = result.get("result", [])

        if not records:
            self.logger.warning(f"TXT record not found: {record_name}")
            return False

        # Delete all matching records
        for record in records:
            record_id = record["id"]
            self.logger.info(f"Deleting TXT record {record_id}: {record_name}")
            self._make_request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

        return True

    def list_zones(self) -> list[dict]:
        """List all zones in the account.

        Returns:
            List of zone info dicts
        """
        result = self._make_request("GET", "/zones")
        zones = result.get("result", [])

        return [
            {
                "id": z["id"],
                "name": z["name"],
                "status": z["status"],
                "name_servers": z.get("name_servers", [])
            }
            for z in zones
        ]

    def list_dns_records(self, domain: str, record_type: Optional[str] = None) -> list[dict]:
        """List DNS records for a domain.

        Args:
            domain: Domain name
            record_type: Optional filter by record type (A, AAAA, TXT, etc.)

        Returns:
            List of DNS records
        """
        zone_id = self.get_zone_id(domain)

        endpoint = f"/zones/{zone_id}/dns_records"
        if record_type:
            endpoint += f"?type={record_type}"

        result = self._make_request("GET", endpoint)
        records = result.get("result", [])

        return [
            {
                "id": r["id"],
                "type": r["type"],
                "name": r["name"],
                "content": r["content"],
                "ttl": r["ttl"],
                "proxied": r.get("proxied", False)
            }
            for r in records
        ]

    def verify_token(self) -> dict:
        """Verify API token is valid.

        Returns:
            Token verification result
        """
        result = self._make_request("GET", "/user/tokens/verify")
        return {
            "valid": True,
            "status": result.get("result", {}).get("status", "unknown")
        }


class CloudflareDNSChallengeHandler:
    """Handler for ACME DNS-01 challenges using Cloudflare."""

    def __init__(self, cloudflare: CloudflareDNS):
        """Initialize challenge handler.

        Args:
            cloudflare: CloudflareDNS client instance
        """
        self.cloudflare = cloudflare
        self.logger = get_logger("cloudflare_challenge")
        self._created_records: dict[str, str] = {}

    def create_challenge(self, domain: str, record_name: str, record_value: str) -> None:
        """Create DNS challenge record.

        Args:
            domain: Domain name
            record_name: Challenge record name (_acme-challenge.domain)
            record_value: Challenge token value
        """
        self.logger.info(f"Creating ACME challenge for {domain}")
        record_id = self.cloudflare.create_txt_record(
            domain, record_name, record_value, ttl=120
        )
        self._created_records[record_name] = record_id

    def cleanup_challenge(self, domain: str, record_name: str) -> None:
        """Remove DNS challenge record.

        Args:
            domain: Domain name
            record_name: Challenge record name
        """
        self.logger.info(f"Cleaning up ACME challenge for {domain}")
        self.cloudflare.delete_txt_record(domain, record_name)
        self._created_records.pop(record_name, None)

    def cleanup_all(self) -> None:
        """Remove all created challenge records."""
        for record_name in list(self._created_records.keys()):
            try:
                # Extract domain from record name
                parts = record_name.split(".")
                if parts[0] == "_acme-challenge":
                    domain = ".".join(parts[1:])
                else:
                    domain = ".".join(parts)
                self.cleanup_challenge(domain, record_name)
            except Exception as e:
                self.logger.error(f"Failed to cleanup {record_name}: {e}")
