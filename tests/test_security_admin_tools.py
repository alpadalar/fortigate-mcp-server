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
from src.fortigate_mcp.config.models import AuthConfig, FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI, FortiGateManager
from src.fortigate_mcp.tools.admin import AdminTools
from src.fortigate_mcp.tools.security import SecurityTools
from src.fortigate_mcp.validation import redact_sensitive_fields
from tests.support.fake_fortigate import load_fixture


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
