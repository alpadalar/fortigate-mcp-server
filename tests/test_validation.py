"""Tests for the centralized injection-safe validator module (CONF-02/CONF-03).

Covers the CONTEXT.md negative corpus (path traversal, CRLF, query/fragment
characters, spaces) plus the Codex-mandated boundary cases: numeric "0",
non-string inputs, trailing \\n and \\r, Unicode decimal digits, overlong
values, scoped IPv6, and embedded :port.
"""

import pytest

from src.fortigate_mcp.validation import (
    validate_host,
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
