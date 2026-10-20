"""Tests for the centralized injection-safe validator module (CONF-02/CONF-03).

Covers the CONTEXT.md negative corpus (path traversal, CRLF, query/fragment
characters, spaces) plus additional boundary cases: numeric "0",
non-string inputs, trailing \\n and \\r, Unicode decimal digits, overlong
values, scoped IPv6, and embedded :port.
"""

import pytest

from src.fortigate_mcp.validation import (
    redact_sensitive_fields,
    scrub_secrets,
    validate_host,
    validate_interface_name,
    validate_numeric_id,
    validate_object_name,
    validate_port,
    validate_result_limit,
    validate_session_filters,
    validate_session_proto,
    validate_vdom,
)


class TestValidateHost:
    """validate_host: IPv4, unscoped IPv6, and RFC-1123 hostnames only."""

    @pytest.mark.parametrize(
        "host",
        [
            "198.51.100.10",
            "2001:db8::1",
            "::1",
            "fw01.example.com",
            "fw01.lab.example.com",
        ],
    )
    def test_accepts_valid_hosts(self, host):
        assert validate_host(host) == host

    @pytest.mark.parametrize(
        "host",
        [
            "../",
            "%0d%0a",
            "?",
            "#",
            "bad host",
            "bad\r\nhost",
            "host.example.com\n",
            "fe80::1%eth0",
            "198.51.100.10:443",
            "host.example.com:8443",
            "a" * 300,
            "",
            None,
            123,
        ],
    )
    def test_rejects_invalid_hosts(self, host):
        with pytest.raises(ValueError):
            validate_host(host)

    def test_rejected_value_never_echoed(self):
        with pytest.raises(ValueError) as excinfo:
            validate_host("%0d%0a")
        assert "%0d%0a" not in str(excinfo.value)


class TestValidatePort:
    """validate_port: strict integer in [1, 65535], bool explicitly excluded."""

    @pytest.mark.parametrize("port", [1, 443, 65535])
    def test_accepts_valid_ports(self, port):
        assert validate_port(port) == port

    @pytest.mark.parametrize(
        "port",
        [0, 65536, -1, True, False, "443", None, 443.0],
    )
    def test_rejects_invalid_ports(self, port):
        with pytest.raises(ValueError):
            validate_port(port)


class TestValidateVdom:
    """validate_vdom: letters, digits, underscore, hyphen; 1-79 chars; fullmatch."""

    @pytest.mark.parametrize("vdom", ["root", "my-vdom_1"])
    def test_accepts_valid_vdoms(self, vdom):
        assert validate_vdom(vdom) == vdom

    @pytest.mark.parametrize(
        "vdom",
        [
            "../",
            "%0d%0a",
            "?",
            "#",
            " ",
            "\r\n",
            "a" * 80,
            "root\n",
            "root\r",
            1,
            None,
        ],
    )
    def test_rejects_invalid_vdoms(self, vdom):
        with pytest.raises(ValueError):
            validate_vdom(vdom)

    def test_rejected_value_never_echoed(self):
        with pytest.raises(ValueError) as excinfo:
            validate_vdom("%0d%0a")
        assert "%0d%0a" not in str(excinfo.value)


class TestValidateNumericId:
    """validate_numeric_id: ASCII-digit-only string, 1-10 digits, bounded."""

    @pytest.mark.parametrize(
        "value",
        ["0", "1", "4294967294"],
    )
    def test_accepts_valid_numeric_ids(self, value):
        assert validate_numeric_id(value, "policy_id") == value

    @pytest.mark.parametrize(
        "value",
        [
            "4294967295",
            "abc",
            "../",
            "1%0d%0a",
            "1 ",
            "1\n",
            "١٢٣",  # Unicode Arabic-Indic digits "123"
            "",
            1,
            None,
        ],
    )
    def test_rejects_invalid_numeric_ids(self, value):
        with pytest.raises(ValueError):
            validate_numeric_id(value, "policy_id")

    def test_error_message_contains_field_name(self):
        with pytest.raises(ValueError, match="policy_id"):
            validate_numeric_id("abc", "policy_id")
        with pytest.raises(ValueError, match="route_id"):
            validate_numeric_id("abc", "route_id")

    def test_rejected_value_never_echoed(self):
        with pytest.raises(ValueError) as excinfo:
            validate_numeric_id("1%0d%0a", "policy_id")
        assert "1%0d%0a" not in str(excinfo.value)


class TestValidateObjectName:
    """validate_object_name: letters, digits, underscore, hyphen; 1-79 chars."""

    @pytest.mark.parametrize(
        "name",
        ["test_addr", "HTTP-8080"],
    )
    def test_accepts_valid_object_names(self, name):
        assert validate_object_name(name, "address_name") == name

    @pytest.mark.parametrize(
        "name",
        [
            "port1.100",
            "../",
            "%0d%0a",
            "?",
            "#",
            "bad name",
            "bad\r\nname",
            "name\n",
            "a" * 80,
            1,
            None,
        ],
    )
    def test_rejects_invalid_object_names(self, name):
        with pytest.raises(ValueError):
            validate_object_name(name, "address_name")

    def test_error_message_contains_field_name(self):
        with pytest.raises(ValueError, match="address_name"):
            validate_object_name("bad name", "address_name")

    def test_rejected_value_never_echoed(self):
        with pytest.raises(ValueError) as excinfo:
            validate_object_name("%0d%0a", "address_name")
        assert "%0d%0a" not in str(excinfo.value)


class TestValidateInterfaceName:
    """validate_interface_name: separate, dot-permitting grammar (port1.100)."""

    @pytest.mark.parametrize(
        "name",
        ["port1", "port1.100", "x0-lan_2"],
    )
    def test_accepts_valid_interface_names(self, name):
        assert validate_interface_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "../",
            "%0d%0a",
            "?",
            "#",
            " ",
            "\r\n",
            "port1\n",
            "a" * 80,
            "",
            1,
            None,
        ],
    )
    def test_rejects_invalid_interface_names(self, name):
        with pytest.raises(ValueError):
            validate_interface_name(name)

    def test_dots_allowed_for_interface_but_not_object_name(self):
        assert validate_interface_name("port1.100") == "port1.100"
        with pytest.raises(ValueError):
            validate_object_name("port1.100", "address_name")

    def test_rejected_value_never_echoed(self):
        with pytest.raises(ValueError) as excinfo:
            validate_interface_name("%0d%0a")
        assert "%0d%0a" not in str(excinfo.value)


class TestScrubSecrets:
    """scrub_secrets: shared secret-scrubbing primitive for CONF-03."""

    def test_redacts_known_secret(self):
        assert (
            scrub_secrets("token is test-token-not-real here", {"test-token-not-real"})
            == "token is ***REDACTED*** here"
        )

    def test_redacts_bearer_pattern_independent_of_known_secrets(self):
        assert (
            scrub_secrets("Authorization: Bearer any-shaped-token", set())
            == "Authorization: Bearer ***REDACTED***"
        )

    def test_unrelated_text_unchanged(self):
        assert scrub_secrets("no secrets here", {"test-token-not-real"}) == "no secrets here"

    def test_empty_and_none_secrets_dropped(self):
        assert scrub_secrets("some text here", {"", None}) == "some text here"

    def test_overlapping_secrets_fully_redacted_no_residual_fragment(self):
        """CR-01 regression: when one registered secret is a substring of
        another (e.g. a rotated token that extends an older still-registered
        token), redaction must not leave a residual fragment of the longer
        secret behind, regardless of `set` iteration order."""
        result = scrub_secrets(
            "leaked: abcdef and abc are both secrets", {"abc", "abcdef"}
        )
        assert "abcdef" not in result
        assert "abc" not in result
        assert result.count("***REDACTED***") == 2

    def test_overlapping_secrets_stable_across_many_set_orderings(self):
        """Same assertion as above, repeated to reduce the chance a single
        favorable set iteration order masks a regression."""
        for _ in range(25):
            result = scrub_secrets(
                "prefix abcdef-suffix and abc alone", {"abc", "abcdef"}
            )
            assert "abcdef" not in result
            assert "abc" not in result


class TestRedactSensitiveFields:
    """redact_sensitive_fields: key-name-based redaction primitive
    (VIS-06 foundation, built and unit-tested in isolation this phase)."""

    def test_masks_known_sensitive_keys_case_insensitively(self):
        fixture = {
            "PASSWORD": "hash-not-real-abc123",
            "psk": "fake-preshared-key",
            "private-key": "-----BEGIN FAKE KEY-----",
            "logon-password": "fake-secret-1",
            "sso-password": "fake-secret-2",
            "ssh-public-key1": "ssh-rsa AAAAB3fake",
        }

        result = redact_sensitive_fields(fixture)

        assert result["PASSWORD"] == "***REDACTED***"
        assert result["psk"] == "***REDACTED***"
        assert result["private-key"] == "***REDACTED***"
        assert result["logon-password"] == "***REDACTED***"
        assert result["sso-password"] == "***REDACTED***"
        assert result["ssh-public-key1"] == "***REDACTED***"

    def test_non_sensitive_siblings_pass_through_unchanged(self):
        fixture = {
            "name": "admin",
            "accprofile": "super_admin",
            "password": "hash-not-real-abc123",
        }

        result = redact_sensitive_fields(fixture)

        assert result["name"] == "admin"
        assert result["accprofile"] == "super_admin"
        assert result["password"] == "***REDACTED***"

    def test_nested_dict_and_list_recursion(self):
        fixture = {
            "name": "admin",
            "bookmarks": [
                {
                    "name": "rdp1",
                    "logon-password": "fake-secret-1",
                    "sso-password": "fake-secret-2",
                },
            ],
        }

        result = redact_sensitive_fields(fixture)

        assert result["bookmarks"][0]["logon-password"] == "***REDACTED***"
        assert result["bookmarks"][0]["sso-password"] == "***REDACTED***"
        assert result["bookmarks"][0]["name"] == "rdp1"

    def test_input_not_mutated(self):
        fixture = {"password": "hash-not-real-abc123", "name": "admin"}

        redact_sensitive_fields(fixture)

        assert fixture["password"] == "hash-not-real-abc123"
        assert fixture["name"] == "admin"

    def test_none_and_empty_inputs_safe(self):
        assert redact_sensitive_fields(None) is None
        assert redact_sensitive_fields({}) == {}
        assert redact_sensitive_fields([]) == []

    def test_scalar_passthrough(self):
        assert redact_sensitive_fields("plain string") == "plain string"
        assert redact_sensitive_fields(42) == 42

    def test_single_use_generator_override_redacts_nested_secret(self):
        """WR-01 regression: `sensitive_keys` accepts any Iterable[str], and a
        single-use generator is a valid Iterable. The override must be
        normalized exactly once at entry and threaded through the recursion --
        otherwise the top-level call exhausts the generator and every nested
        node re-runs the comprehension over an empty iterator, silently
        leaking sensitive fields below the top level."""
        gen = (k for k in ["custom-secret"])
        fixture = {
            "custom-secret": "TOP",
            "child": {"custom-secret": "NESTED"},
        }

        result = redact_sensitive_fields(fixture, gen)

        assert result["custom-secret"] == "***REDACTED***"
        assert result["child"]["custom-secret"] == "***REDACTED***"

    def test_psksecret_field_redacted(self):
        """IN-02 hardening: FortiOS IPsec phase1/phase2 preshared-key fields
        are named `psksecret` / `psksecret-remote` (the bare `psk` enumerated
        earlier does not match the real wire field). Both carry raw secret
        MATERIAL and must be redacted by the default deny-list."""
        fixture = {
            "psksecret": "fake-preshared-key",
            "psksecret-remote": "fake-remote-preshared-key",
        }

        result = redact_sensitive_fields(fixture)

        assert result["psksecret"] == "***REDACTED***"
        assert result["psksecret-remote"] == "***REDACTED***"


class TestValidateResultLimit:
    """validate_result_limit: explicit rejection, never silent clamping."""

    def test_none_returns_default(self):
        assert validate_result_limit(None, 20, 200) == 20

    @pytest.mark.parametrize("value", [1, 20, 200])
    def test_in_range_returned(self, value):
        assert validate_result_limit(value, 20, 200) == value

    @pytest.mark.parametrize("value", [True, False, 1.5, "10", 0, -1, 201, 10**9])
    def test_invalid_rejected_naming_field(self, value):
        with pytest.raises(ValueError, match="max_items"):
            validate_result_limit(value, 20, 200, "max_items")

    @pytest.mark.parametrize("default,maximum", [(0, 10), (11, 10), (-1, 10)])
    def test_bad_default_is_error(self, default, maximum):
        with pytest.raises(ValueError):
            validate_result_limit(None, default, maximum)


class TestSessionFilters:
    """validate_session_filters / validate_session_proto: injection-safe wire params."""

    def test_none_yields_empty(self):
        assert validate_session_filters() == {}

    def test_valid_filters_become_wire_params(self):
        out = validate_session_filters("192.0.2.1", "2001:db8::1", 1024, 443, "TCP")
        assert out == {
            "srcaddr": "192.0.2.1",
            "dstaddr": "2001:db8::1",
            "srcport": "1024",
            "dstport": "443",
            "protocol": "tcp",
            "ip_version": "ipboth",
        }

    def test_ipv6_only_sets_ip_version(self):
        assert validate_session_filters(None, "2001:db8::1")["ip_version"] == "ipv6"
        assert "ip_version" not in validate_session_filters("192.0.2.1")

    @pytest.mark.parametrize("proto", ["tcp", "udp", "icmp", "sctp", 1, 255, "47", 6])
    def test_proto_accepted(self, proto):
        assert validate_session_proto(proto)

    @pytest.mark.parametrize(
        "proto", ["", "tcp&x=1", "tcp\n", "0", 0, 256, "256", True, 1.5, "ip", "tcp udp", "'tcp'"]
    )
    def test_proto_rejected(self, proto):
        with pytest.raises(ValueError):
            validate_session_proto(proto)

    @pytest.mark.parametrize("field", ["srcaddr", "dstaddr"])
    @pytest.mark.parametrize(
        "bad",
        ["", "192.0.2.1 ", "192.0.2.1\n", "192.0.2.1&x=1", "a b", "'1.1.1.1'", "example.com",
         "fe80::1%eth0", "192.0.2.0/24", 3232235777, "1.2.3.4;ls"],
    )
    def test_bad_addresses_rejected_without_echo(self, field, bad):
        with pytest.raises(ValueError, match=field) as exc:
            validate_session_filters(**{field: bad})
        assert str(bad) not in str(exc.value) or str(bad) == ""

    @pytest.mark.parametrize("field", ["srcport", "dstport"])
    @pytest.mark.parametrize("bad", [0, 65536, -1, "80", True, 1.5])
    def test_bad_ports_rejected(self, field, bad):
        with pytest.raises(ValueError, match=field):
            validate_session_filters(**{field: bad})
