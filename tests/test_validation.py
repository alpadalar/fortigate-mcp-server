"""Tests for the centralized injection-safe validator module (CONF-02/CONF-03).

Covers the CONTEXT.md negative corpus (path traversal, CRLF, query/fragment
characters, spaces) plus the Codex-mandated boundary cases: numeric "0",
non-string inputs, trailing \\n and \\r, Unicode decimal digits, overlong
values, scoped IPv6, and embedded :port.
"""

import pytest

from src.fortigate_mcp.validation import (
    scrub_secrets,
    validate_host,
    validate_interface_name,
    validate_numeric_id,
    validate_object_name,
    validate_port,
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
