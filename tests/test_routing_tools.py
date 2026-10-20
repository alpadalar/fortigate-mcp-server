"""Offline behavioral tests for RoutingTools (mocked API client)."""
from unittest.mock import MagicMock

import pytest

from src.fortigate_mcp.tools.routing import RoutingTools


def _make():
    api = MagicMock()
    manager = MagicMock()
    manager.devices = {"dev1": api}
    manager.get_device.return_value = api
    return RoutingTools(manager), api


def _text(result):
    return "\n".join(c.text for c in result)


class TestReads:
    def test_list_static_routes(self):
        tools, api = _make()
        api.get_static_routes.return_value = {"results": []}
        assert tools.list_static_routes("dev1", vdom="lab")
        api.get_static_routes.assert_called_once_with(vdom="lab")

    def test_list_interfaces(self):
        tools, api = _make()
        api.get_interfaces.return_value = {"results": []}
        assert tools.list_interfaces("dev1")
        api.get_interfaces.assert_called_once_with(vdom=None)

    def test_interface_status_wraps_in_object(self):
        tools, api = _make()
        api.get_interface_status.return_value = {"link": True}
        out = tools.get_interface_status("dev1", "port1")
        api.get_interface_status.assert_called_once_with("port1", vdom=None)
        assert "port1" in _text(out)

    def test_static_route_detail(self):
        tools, api = _make()
        api.get_static_route_detail.return_value = {"results": [{"seq-num": 1}]}
        assert tools.get_static_route_detail("dev1", "1")
        api.get_static_route_detail.assert_called_once_with("1", vdom=None)

    def test_routing_table_renders_ip_mask(self):
        tools, api = _make()
        api.get_routing_table.return_value = {
            "results": [{"ip_mask": "10.1.0.0/16", "gateway": "10.0.0.1", "interface": "port1"}]
        }
        text = _text(tools.get_routing_table("dev1"))
        assert "10.1.0.0/16" in text

    def test_routing_table_legacy_dst_is_na(self):
        tools, api = _make()
        api.get_routing_table.return_value = {
            "results": [{"dst": "10.2.0.0/16", "gateway": "10.0.0.1", "interface": "port1"}]
        }
        text = _text(tools.get_routing_table("dev1"))
        assert "Route: N/A" in text

    @pytest.mark.parametrize("method,api_method,args", [
        ("list_static_routes", "get_static_routes", ("dev1",)),
        ("get_routing_table", "get_routing_table", ("dev1",)),
        ("list_interfaces", "get_interfaces", ("dev1",)),
        ("get_interface_status", "get_interface_status", ("dev1", "p1")),
        ("get_static_route_detail", "get_static_route_detail", ("dev1", "1")),
        ("update_static_route", "update_static_route", ("dev1", "1", {})),
        ("delete_static_route", "delete_static_route", ("dev1", "1")),
        ("create_static_route", "create_static_route", ("dev1", "1.0.0.0/8", "2.2.2.2")),
        ("create_static_route_from_payload", "create_static_route",
         ("dev1", {"dst": "1.0.0.0/8", "gateway": "2.2.2.2"})),
    ])
    def test_api_errors_handled(self, method, api_method, args):
        tools, api = _make()
        getattr(api, api_method).side_effect = RuntimeError("kaput")
        assert "kaput" in _text(getattr(tools, method)(*args))

    def test_unknown_device(self):
        tools, _ = _make()
        assert "not found" in _text(tools.list_static_routes("zzz"))


class TestWrites:
    def test_create_with_device(self):
        tools, api = _make()
        out = tools.create_static_route("dev1", "10.0.0.0/8", "1.1.1.1", device="port2", vdom="lab")
        assert api.create_static_route.call_args.args[0] == {
            "dst": "10.0.0.0/8", "gateway": "1.1.1.1", "device": "port2"}
        assert api.create_static_route.call_args.kwargs == {"vdom": "lab"}
        assert "10.0.0.0/8" in _text(out)

    def test_create_without_device(self):
        tools, api = _make()
        tools.create_static_route("dev1", "10.0.0.0/8", "1.1.1.1")
        assert "device" not in api.create_static_route.call_args.args[0]

    def test_create_missing_gateway(self):
        tools, api = _make()
        assert "required" in _text(tools.create_static_route("dev1", "10.0.0.0/8", ""))
        api.create_static_route.assert_not_called()

    def test_payload_forwarded_unchanged(self):
        tools, api = _make()
        payload = {"dst": "10.0.0.0/8", "gateway": "1.1.1.1", "distance": 5, "comment": "c"}
        tools.create_static_route_from_payload("dev1", payload)
        assert api.create_static_route.call_args.args[0] is payload

    def test_payload_missing_dst(self):
        tools, api = _make()
        out = tools.create_static_route_from_payload("dev1", {"gateway": "1.1.1.1"})
        assert "required" in _text(out)
        api.create_static_route.assert_not_called()

    def test_update(self):
        tools, api = _make()
        out = tools.update_static_route("dev1", "3", {"distance": 9})
        api.update_static_route.assert_called_once_with("3", {"distance": 9}, vdom=None)
        assert "updated" in _text(out)

    def test_delete(self):
        tools, api = _make()
        out = tools.delete_static_route("dev1", "3")
        api.delete_static_route.assert_called_once_with("3", vdom=None)
        assert "deleted" in _text(out)

    @pytest.mark.parametrize("method,args", [
        ("update_static_route", ("dev1", "", {})),
        ("delete_static_route", ("dev1", "")),
        ("get_static_route_detail", ("dev1", "")),
        ("get_interface_status", ("dev1", "")),
    ])
    def test_empty_id_rejected(self, method, args):
        tools, _ = _make()
        assert "required" in _text(getattr(tools, method)(*args))


def test_schema_info_operations():
    tools, _ = _make()
    names = [o["name"] for o in tools.get_schema_info()["operations"]]
    assert "get_routing_table" in names and "create_static_route" in names
