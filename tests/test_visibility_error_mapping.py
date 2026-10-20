"""Tests for Phase 15 _format_response dispatch and 404 error mapping."""

import pytest

from src.fortigate_mcp.config.models import AuthConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPIError, FortiGateManager
from src.fortigate_mcp.formatting import FortiGateFormatters
from src.fortigate_mcp.tools.base import FortiGateTool

RESOURCE_TYPES = [
    "address_groups", "service_groups", "schedules", "ip_pools", "central_snat_maps",
    "system_resources", "license_status", "ha_status", "arp_table", "dhcp_leases",
]


@pytest.fixture
def tool():
    auth = AuthConfig(require_auth=False, api_tokens=[], allowed_origins=["*"])
    return FortiGateTool(FortiGateManager({}, auth))


@pytest.mark.parametrize("rtype", RESOURCE_TYPES)
def test_dispatch_matches_formatter(tool, rtype):
    expected = getattr(FortiGateFormatters, f"format_{rtype}")({})
    got = tool._format_response({}, rtype, ignored="x")
    assert got[0].text == expected[0].text
    assert "{" not in got[0].text.split("\n")[0]  # not the JSON fallback


def test_404_maps_to_fixed_message(tool):
    err = FortiGateAPIError("raw secret-ish detail xyz", status_code=404)
    out = tool._handle_visibility_error("list_ip_pools", "dev1", err)
    assert "not supported on this FortiOS version" in out[0].text
    assert "xyz" not in out[0].text


@pytest.mark.parametrize("err", [
    FortiGateAPIError("x", status_code=401),
    FortiGateAPIError("x", status_code=500),
    ValueError("Device 'd' not found"),
    RuntimeError("boom timeout"),
])
def test_other_errors_delegate(tool, err):
    assert (tool._handle_visibility_error("op", "d", err)[0].text
            == tool._handle_error("op", "d", err)[0].text)


def test_handle_error_404_unchanged(tool):
    out = tool._handle_error("op", "d", FortiGateAPIError("x", status_code=404))
    assert "Resource not found. The specified item may not exist." in out[0].text
    assert "FortiOS version" not in out[0].text
