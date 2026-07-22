"""Wire-level (respx) proof tests for SecurityTools and AdminTools (Phase 9,
Plan 09-02).

Proves, against the real httpx.Client request path (not a hand-built
dict), that the tool methods built in Plan 09-01 satisfy VIS-01/VIS-03/
VIS-04/VIS-05's actual observable behaviors:

- VIS-03: AdminTools.list_admins never renders a real secret value.
- VIS-01: SecurityTools.list_security_profiles renders a failed category
  distinctly from an empty one (never collapsed together).
- VIS-04: SecurityTools.get_sslvpn_settings renders the singleton (dict)
  results shape, redacts bookmark credential fields, and degrades to a
  settings-only render when the portal GET fails.
- VIS-05: SecurityTools.list_local_in_policies renders the fixture's IPv4
  policies correctly.
"""
import httpx
import respx

from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.admin import AdminTools
from src.fortigate_mcp.tools.security import SecurityTools
from src.fortigate_mcp.validation import redact_sensitive_fields
from tests.support.fake_fortigate import load_fixture

BASE_URL = "https://198.51.100.10:443/api/v2"


def _build_scaffold():
    """Build the shared FortiGateDeviceConfig/FortiGateAPI/FortiGateManager
    scaffold, matching TestNetworkToolsCreateAddressObjectHTTPMapping's
    exact shape (tests/test_fortigate_api.py)."""
    config = FortiGateDeviceConfig(
        host="198.51.100.10",
        api_token="test-token-not-real",
        vdom="root",
    )
    api = FortiGateAPI("test_device", config)
    auth_config = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
    manager = FortiGateManager({}, auth_config)
    manager.devices["test_device"] = api
    return manager


class TestAdminToolsListAdmins:
    """VIS-03: non-vacuous secret redaction proof for list_admins."""

    def setup_method(self):
        manager = _build_scaffold()
        self.admin_tools = AdminTools(manager)

    def test_list_admins_never_renders_real_secret_values(self, fake_fortigate_router):
        """The admin_accounts template (Phase 8) omits password/ssh-key
        fields entirely rather than rendering a same-position marker (see
        tests/test_formatting.py::test_admin_accounts_with_data -- "No
        assertion on the password field (Phase 9's concern)"). Complete
        omission is a strictly stronger guarantee than a redacted
        placeholder, so the non-vacuous proof here is that the real fixture
        secret values never reach the rendered output at all."""
        result = self.admin_tools.list_admins(device_id="test_device")
        text = result[0].text

        # Real fixture secret values must be ABSENT (non-vacuous proof).
        assert "ENC_FAKE_NOT_REAL_PLACEHOLDER" not in text
        assert "ENC_FAKE_NOT_REAL_PLACEHOLDER_2" not in text
        assert "ssh-rsa AAAAB3NzaC1yc2EAAA" not in text

        # Sanity check against a vacuously empty render.
        assert "admin" in text.lower()

    def test_redact_sensitive_fields_masks_the_call_site_fixture(self):
        """Proves the redact_sensitive_fields primitive invoked at
        list_admins' call site (09-01-SUMMARY.md key-decisions) actually
        masks this exact fixture's password/ssh-key fields with the
        ***REDACTED*** marker -- closing the non-vacuous redaction proof
        loop independently of the admin_accounts template's choice to omit
        those fields from its rendered output entirely."""
        raw = load_fixture("system_admin_list.json")
        redacted = redact_sensitive_fields(raw)

        assert redacted["results"][0]["password"] == "***REDACTED***"
        assert redacted["results"][0]["ssh-public-key1"] == "***REDACTED***"
        assert redacted["results"][1]["password"] == "***REDACTED***"


class TestSecurityToolsListLocalInPolicies:
    """VIS-05: correct IPv4 local-in policy rendering."""

    def setup_method(self):
        manager = _build_scaffold()
        self.security_tools = SecurityTools(manager)

    def test_list_local_in_policies_renders_both_fixture_policies(self, fake_fortigate_router):
        result = self.security_tools.list_local_in_policies(device_id="test_device")
        text = result[0].text

        assert "Policy 1" in text
        assert "Policy 2" in text


class TestSecurityToolsGetSslvpnSettings:
    """VIS-04: singleton-shape rendering plus bookmark credential redaction."""

    def setup_method(self):
        manager = _build_scaffold()
        self.security_tools = SecurityTools(manager)

    def test_get_sslvpn_settings_happy_path_renders_singleton_status(self, fake_fortigate_router):
        result = self.security_tools.get_sslvpn_settings(device_id="test_device")
        text = result[0].text

        assert "Status: enable" in text

    def test_get_sslvpn_settings_redacts_bookmark_passwords(self, fake_fortigate_router):
        result = self.security_tools.get_sslvpn_settings(device_id="test_device")
        text = result[0].text

        # Real fixture secret values must be ABSENT (non-vacuous proof, both
        # logon-password AND the newly-added sso-password field).
        assert "ENC_FAKE_BOOKMARK_PW_NOT_REAL" not in text
        assert "ENC_FAKE_SSO_PW_NOT_REAL" not in text
        assert "***REDACTED***" in text

    def test_portal_fetch_failure_degrades_gracefully(self):
        """VIS-04: a portal GET failure must not raise -- settings still
        render, and the "Portal Bookmarks" section is simply absent."""
        router = respx.mock(
            base_url=BASE_URL,
            assert_all_called=False,
            assert_all_mocked=True,
        )
        router.get("/cmdb/vpn.ssl/settings").mock(
            return_value=httpx.Response(200, json=load_fixture("vpn_ssl_settings.json"))
        )
        router.get("/cmdb/vpn.ssl.web/portal").mock(
            return_value=httpx.Response(
                403, json={"http_method": "GET", "status": "error", "http_status": 403, "error": "Forbidden"}
            )
        )

        with router:
            result = self.security_tools.get_sslvpn_settings(device_id="test_device")

        text = result[0].text

        assert "Status: enable" in text
        assert "Portal Bookmarks" not in text


class TestSecurityToolsListSecurityProfilesPartialFailure:
    """VIS-01: proves the per-category error-vs-empty distinction at the
    wire level -- a 403 on one category must never collapse into the same
    render as a genuinely empty category, and must not prevent the other
    3 categories from rendering their real data."""

    def setup_method(self):
        manager = _build_scaffold()
        self.security_tools = SecurityTools(manager)

    def test_ips_403_other_categories_still_render(self):
        router = respx.mock(
            base_url=BASE_URL,
            assert_all_called=False,
            assert_all_mocked=True,
        )
        router.get("/cmdb/antivirus/profile").mock(
            return_value=httpx.Response(200, json=load_fixture("antivirus_profile_list.json"))
        )
        router.get("/cmdb/ips/sensor").mock(
            return_value=httpx.Response(
                403, json={"http_method": "GET", "status": "error", "http_status": 403, "error": "Forbidden"}
            )
        )
        router.get("/cmdb/webfilter/profile").mock(
            return_value=httpx.Response(200, json=load_fixture("webfilter_profile_list.json"))
        )
        router.get("/cmdb/application/list").mock(
            return_value=httpx.Response(200, json=load_fixture("application_control_profile_list.json"))
        )

        with router:
            result = self.security_tools.list_security_profiles(device_id="test_device")

        text = result[0].text

        # The failed category renders as "query failed", never collapsed
        # into the "none configured" empty-category rendering (VIS-01).
        assert "IPS Sensors: query failed" in text
        assert "IPS Sensors: none configured" not in text

        # The reason is the fixed, status-derived text -- the raw response
        # body ("Forbidden" here) is untrusted device-controlled text and
        # must never be echoed verbatim into MCP output.
        assert "IPS Sensors: query failed - permission denied" in text
        assert "Forbidden" not in text

        # The 3 succeeding categories still render their real data, not
        # "none configured" -- a failure in one category must not swallow
        # the others.
        assert "Antivirus Profiles" in text
        assert "Antivirus Profiles: none configured" not in text

    def test_network_error_escalates_after_single_attempt(self):
        """A network-level FortiGateAPIError (status_code=None: device
        unreachable) must NOT be treated as a per-category failure -- that
        would burn one full connect timeout per category (4 sequential
        blocking waits). It must re-raise out of the per-category loop
        after the FIRST attempt so the outer handler renders the standard
        single error response."""
        router = respx.mock(
            base_url=BASE_URL,
            assert_all_called=False,
            assert_all_mocked=True,
        )
        router.get("/cmdb/antivirus/profile").mock(
            side_effect=httpx.ConnectError("all connection attempts failed")
        )
        # The remaining 3 categories are registered so that reaching them
        # would NOT raise an unmatched-request error -- proving the loop
        # stopped because of the re-raise, not because of missing mocks.
        router.get("/cmdb/ips/sensor").mock(
            side_effect=httpx.ConnectError("all connection attempts failed")
        )
        router.get("/cmdb/webfilter/profile").mock(
            side_effect=httpx.ConnectError("all connection attempts failed")
        )
        router.get("/cmdb/application/list").mock(
            side_effect=httpx.ConnectError("all connection attempts failed")
        )

        with router:
            result = self.security_tools.list_security_profiles(device_id="test_device")
            # Exactly ONE wire attempt: the loop must not proceed to the
            # other 3 categories once the device is known unreachable.
            assert len(router.calls) == 1

        text = result[0].text

        # Rendered as the standard single error response, never as a
        # 4x "query failed" category listing.
        assert "Security Profiles" not in text
        assert "query failed" not in text
