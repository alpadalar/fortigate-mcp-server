"""respx-based FortiGate HTTP mock harness.

Provides a reusable `respx` router pre-registered with fixture-backed
responses for the FortiGate REST v2 endpoints exercised by
`FortiGateAPI` (see src/fortigate_mcp/core/fortigate.py). Used by
tests/test_fortigate_api.py to test the real httpx.Client request path
with zero code changes to core/fortigate.py.

Verified live behavior this session (differs from a naive reading of
respx's docs):

- `respx.Router(base_url=...)` does NOT support the context-manager
  protocol directly (`with respx.Router(...):` raises `TypeError`).
  Use `respx.mock(base_url=..., ...)` as a FACTORY call instead -- it
  returns a `MockRouter` that DOES support `with router: ...`.
- `router.calls` (and `router.calls.last`) must be accessed WHILE still
  inside the `with router:` block -- call history is cleared on exit;
  accessing it after raises `IndexError`.
- `router.get("/cmdb/firewall/policy")` matches that path REGARDLESS of
  query string (a request with `?vdom=root` still matches) -- fixture
  routes do not need to encode `vdom=` explicitly.
"""
import json
from pathlib import Path

import httpx
import respx

FIXTURES = Path(__file__).parent.parent / "fixtures" / "fortigate"


def load_fixture(name: str) -> dict:
    """Load and parse a fixture JSON file by filename."""
    return json.loads((FIXTURES / name).read_text())


def fortigate_router(
    base_url: str = "https://198.51.100.10:443/api/v2",
    assert_all_called: bool = False,
) -> respx.MockRouter:
    """Build a respx MockRouter pre-registered with FortiGate fixture routes.

    `base_url` must match FortiGateAPI.base_url's exact
    f"https://{host}:{port}/api/v2" construction (core/fortigate.py line
    60) or requests silently miss the mock.

    The strict "fail loud on unmatched request" mode is enabled EXPLICITLY
    below -- never inherited from a library default -- so any unmatched
    request raises immediately instead of escaping toward the network.

    Usage:
        # Explicit per-test scoping (reads better for single-assertion tests):
        with fortigate_router() as router:
            ...
            sent_body = json.loads(router.calls.last.request.content)

        # Or via the ACTIVE conftest.py `fake_fortigate_router` fixture,
        # which enters the router context for the duration of the test.
    """
    router = respx.mock(
        base_url=base_url,
        assert_all_called=assert_all_called,
        assert_all_mocked=True,
    )
    router.get("/cmdb/firewall/policy").mock(
        return_value=httpx.Response(200, json=load_fixture("firewall_policy_list.json"))
    )
    router.post("/cmdb/firewall/address").mock(
        return_value=httpx.Response(200, json=load_fixture("address_object_create.json"))
    )
    router.post("/cmdb/firewall.service/custom").mock(
        return_value=httpx.Response(200, json=load_fixture("service_object_create.json"))
    )
    router.get("/monitor/system/status").mock(
        return_value=httpx.Response(401, json=load_fixture("error_401.json"))
    )
    return router
