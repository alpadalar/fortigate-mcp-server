"""Offline behavioral tests for VirtualIPTools (mocked API client)."""
from unittest.mock import MagicMock

import pytest

from src.fortigate_mcp.tools.virtual_ip import VirtualIPTools


def _make():
    api = MagicMock()
    manager = MagicMock()
    manager.devices = {"dev1": api}
    manager.get_device.return_value = api
    return VirtualIPTools(manager), api


def _text(result):
    return "\n".join(c.text for c in result)


class TestList:
    def test_success(self):
        tools, api = _make()
        api.get_virtual_ips.return_value = {"results": []}
        out = tools.list_virtual_ips("dev1", vdom="lab")
        api.get_virtual_ips.assert_called_once_with(vdom="lab")
        assert out and out[0].type == "text"

    def test_unknown_device_is_handled(self):
        tools, _ = _make()
        out = tools.list_virtual_ips("nope")
        assert "not found" in _text(out)

    def test_api_error_is_handled(self):
        tools, api = _make()
        api.get_virtual_ips.side_effect = RuntimeError("boom")
        assert "boom" in _text(tools.list_virtual_ips("dev1"))


class TestCreate:
    def test_minimal_payload(self):
        tools, api = _make()
        out = tools.create_virtual_ip("dev1", "v1", "1.2.3.4", "10.0.0.1", "port1", protocol="")
        payload = api.create_virtual_ip.call_args.args[0]
        assert payload == {
            "name": "v1", "extip": "1.2.3.4", "mappedip": "10.0.0.1",
            "extintf": "port1", "portforward": "disable",
        }
        assert "v1" in _text(out)

    def test_full_payload(self):
        tools, api = _make()
        tools.create_virtual_ip(
            "dev1", "v1", "1.2.3.4", "10.0.0.1", "port1", portforward="enable",
            protocol="udp", extport="53", mappedport="5353", vdom="lab",
        )
        payload = api.create_virtual_ip.call_args.args[0]
        assert payload["protocol"] == "udp"
        assert payload["extport"] == "53" and payload["mappedport"] == "5353"
        assert api.create_virtual_ip.call_args.kwargs == {"vdom": "lab"}

    def test_missing_required_param(self):
        tools, api = _make()
        out = tools.create_virtual_ip("dev1", " ", "1.2.3.4", "10.0.0.1", "port1")
        assert "required" in _text(out)
        api.create_virtual_ip.assert_not_called()

    def test_api_error(self):
        tools, api = _make()
        api.create_virtual_ip.side_effect = RuntimeError("denied")
        assert "denied" in _text(tools.create_virtual_ip("dev1", "v", "1.1.1.1", "2.2.2.2", "p"))


class TestUpdateDetailDelete:
    def test_update(self):
        tools, api = _make()
        out = tools.update_virtual_ip("dev1", "v1", {"comment": "x"}, vdom="lab")
        api.update_virtual_ip.assert_called_once_with("v1", {"comment": "x"}, vdom="lab")
        assert "updated" in _text(out)

    def test_detail(self):
        tools, api = _make()
        api.get_virtual_ip_detail.return_value = {"results": [{"name": "v1"}]}
        out = tools.get_virtual_ip_detail("dev1", "v1")
        api.get_virtual_ip_detail.assert_called_once_with("v1", vdom=None)
        assert "v1" in _text(out)

    def test_delete(self):
        tools, api = _make()
        out = tools.delete_virtual_ip("dev1", "v1")
        api.delete_virtual_ip.assert_called_once_with("v1", vdom=None)
        assert "deleted" in _text(out)

    @pytest.mark.parametrize("method,args", [
        ("update_virtual_ip", ("dev1", "", {})),
        ("get_virtual_ip_detail", ("dev1", "")),
        ("delete_virtual_ip", ("dev1", "")),
    ])
    def test_empty_name_rejected(self, method, args):
        tools, _ = _make()
        assert "required" in _text(getattr(tools, method)(*args))

    @pytest.mark.parametrize("method,api_method,args", [
        ("update_virtual_ip", "update_virtual_ip", ("dev1", "v", {})),
        ("get_virtual_ip_detail", "get_virtual_ip_detail", ("dev1", "v")),
        ("delete_virtual_ip", "delete_virtual_ip", ("dev1", "v")),
    ])
    def test_api_errors_handled(self, method, api_method, args):
        tools, api = _make()
        getattr(api, api_method).side_effect = RuntimeError("kaput")
        assert "kaput" in _text(getattr(tools, method)(*args))


def test_schema_info_lists_five_operations():
    tools, _ = _make()
    names = [o["name"] for o in tools.get_schema_info()["operations"]]
    assert names == [
        "list_virtual_ips", "create_virtual_ip", "update_virtual_ip",
        "get_virtual_ip_detail", "delete_virtual_ip",
    ]
