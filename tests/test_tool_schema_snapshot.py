"""Golden JSON-schema snapshot tests freezing the MCP tool surface (STAB-04).

These tests capture, per transport, the tool NAME + normalized parameter
schema (``inputSchema``) of every registered tool and compare it against a
committed golden file under ``tests/fixtures/``.

Surface composition: 61 transport registrations total (30 stdio + 31 HTTP),
33 unique tool names (28 names registered on both transports + 2 stdio-only:
``health_check``, ``get_server_info`` + 3 HTTP-only: ``test_connection``,
``health``, ``get_schema_info``). "61 tools" without qualification is
misleading -- always use the qualified phrasing above.

Contract decision: the frozen bytes cover exactly tool NAME + normalized
``inputSchema``. Tool descriptions and engine metadata (schema-root
``title``, per-property ``title``/``description``) are EXCLUDED from the
goldens, because (a) the requirement text is "isim + parametre semasi"
(name + parameter schema), (b) descriptions already differ between the two
transports for the same tool names, and (c) Phase 3's registry
consolidation (CONS-01) may legitimately unify description text --
freezing descriptions would force golden regeneration for a non-contract
change. What IS frozen: property names, types, defaults, required lists,
and enum values -- the full parameter contract.

Golden files are NEVER hand-edited. To regenerate after an intentional,
reviewed schema change:

    UPDATE_SNAPSHOTS=1 uv run pytest tests/test_tool_schema_snapshot.py --no-cov

Goldens provenance: originally generated against the pinned dependency set
from plan 01-02 (mcp 1.28.1, fastmcp 2.11.3), re-verified byte-identical
after plan 06-01's CVE-2026-32871 remediation bumped the fastmcp ceiling --
mcp 1.28.1, fastmcp 3.4.0 (resolved within the ``mcp>=1.23.0,<2.0`` /
``fastmcp>=3.2.0`` PyPI bands).

Adapted from the working reference implementation at
``/media/workspace/NetOpsMCP/tests/test_tool_schema_snapshot.py``. The two
servers are NOT consolidated this phase (Phase 3's job), and the three
create-tools genuinely differ in parameter schema between transports, so
this file intentionally does not port NetOpsMCP's merged-count or
cross-server-parity tests.
"""

import asyncio
import atexit
import json
import os
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

FIXTURES = Path(__file__).parent / "fixtures"
STDIO_GOLDEN = FIXTURES / "tool_schemas_stdio.json"
HTTP_GOLDEN = FIXTURES / "tool_schemas_http.json"

# 61 transport registrations total: 30 stdio + 31 HTTP.
# 33 unique tool names: 28 shared + 2 stdio-only (health_check,
# get_server_info) + 3 HTTP-only (test_connection, health, get_schema_info).
EXPECTED_STDIO_TOOL_COUNT = 30
EXPECTED_HTTP_TOOL_COUNT = 31
EXPECTED_UNIQUE_TOOL_NAMES = 33

# Schema-container keys whose VALUES are individually-normalized schema
# objects but whose own KEYS are user-facing names (parameter names for
# "properties", model/type names for "$defs"/"definitions"). These
# containers must never have title/description popped from themselves, and
# their keys must never be treated as generic schema keys -- otherwise a
# parameter literally named "description" or "title" would be silently
# deleted instead of preserved as a property name.
_SCHEMA_CONTAINER_KEYS = {"properties", "$defs", "definitions", "patternProperties"}


def _build_servers() -> Tuple[Any, Any]:
    """Instantiate both servers with zero socket access.

    The stdio server's constructor (``FortiGateMCPServer``) performs no
    network I/O -- verified live in research, no patch needed. The HTTP
    server's constructor (``FortiGateMCPHTTPServer``) unconditionally calls
    ``self._test_initial_connection()`` at line 82, which attempts a real
    connection per configured device -- patched to a no-op here so snapshot
    construction never touches a socket, even the RFC 5737 TEST-NET-2
    address used in the fixture config below.
    """
    config = {
        "server": {"host": "0.0.0.0", "port": 8814, "name": "test", "version": "1.0.0"},
        "fortigate": {
            "devices": {
                "default": {
                    "host": "198.51.100.10",
                    "api_token": "test-token-not-real",
                    "vdom": "root",
                    "verify_ssl": False,
                    "timeout": 1,
                }
            }
        },
        "auth": {"require_auth": False, "api_tokens": [], "allowed_origins": ["*"]},
        "logging": {"level": "INFO", "console": True},
    }
    fd, config_path = tempfile.mkstemp(suffix=".json", prefix="tool_schema_snapshot_config_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    atexit.register(lambda: os.path.exists(config_path) and os.unlink(config_path))

    from src.fortigate_mcp.server import FortiGateMCPServer
    from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer

    with patch.object(FortiGateMCPHTTPServer, "_test_initial_connection", lambda self: None):
        stdio_server = FortiGateMCPServer(config_path)
        http_server = FortiGateMCPHTTPServer(config_path=config_path)

    return stdio_server, http_server


def _canonicalize_anyof(node: Dict[str, Any]) -> None:
    """Flatten nested ``anyOf``, hoist sibling keys, dedupe members, in place.

    Older pydantic/fastmcp combinations can emit, for
    ``Annotated[Optional[X], Field(...)] = None``:
        {"anyOf": [{"anyOf": [X, {"type": "null"}], "description": d}, {"type": "null"}], ...}
    while newer combinations emit the flat equivalent:
        {"anyOf": [X, {"type": "null"}], "description": d, ...}
    Flattening one level + hoisting + dedupe converts the former into the
    latter and is a no-op on the latter (idempotent), so goldens stay frozen
    across dependency/interpreter versions.
    """
    members = node.get("anyOf")
    if not isinstance(members, list):
        return
    flat: List[Dict[str, Any]] = []
    for member in members:
        if isinstance(member, dict) and "anyOf" in member:
            for key, value in member.items():
                if key != "anyOf" and key not in node:
                    node[key] = value  # hoist e.g. description onto the parent
            flat.extend(member["anyOf"])
        else:
            flat.append(member)
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for member in flat:
        marker = json.dumps(member, sort_keys=True)
        if marker not in seen:
            seen.add(marker)
            deduped.append(member)
    node["anyOf"] = deduped


def _walk_and_normalize(node: Any) -> None:
    """Recursively strip engine decoration from EVERY nested schema object.

    Walks every nested dict in the structure, not just top-level
    properties. At each schema-object dict: canonicalize anyOf, then strip
    title/description and a spuriously-``False`` ``additionalProperties``.
    "properties"/"$defs"/"definitions" containers are special-cased -- their
    own keys are names (parameter/model names), so we recurse into their
    VALUES only, never popping title/description from the container dict
    itself and never deleting a container key (e.g. a parameter literally
    named "description" survives as a key).

    ``additionalProperties: false`` (only that exact value, never ``true``)
    is stripped alongside title/description because fastmcp>=3.2.0's
    parameter-schema builder started emitting it at each tool's top-level
    schema root (absent under fastmcp 2.11.3) -- a schema-generator-version
    artifact affecting every tool uniformly, not a change to any property's
    name/type/default/required-ness/enum. ``additionalProperties: true`` is
    intentionally left untouched: it is emitted identically by both fastmcp
    versions for genuine ``Dict[str, Any]`` payload parameters
    (``address_data``/``policy_data``/``service_data``/``route_data``/
    ``vip_data``) and IS part of the frozen golden bytes today -- stripping
    it too would silently paper over an actual schema regression instead of
    only absorbing the version-specific decoration difference (CLAUDE.md:
    snapshot tests must be environment/dependency-version independent from
    the start).
    """
    if isinstance(node, dict):
        _canonicalize_anyof(node)
        node.pop("title", None)
        node.pop("description", None)
        if node.get("additionalProperties") is False:
            node.pop("additionalProperties", None)
        for key, value in node.items():
            if key in _SCHEMA_CONTAINER_KEYS and isinstance(value, dict):
                for member_schema in value.values():
                    _walk_and_normalize(member_schema)
            else:
                _walk_and_normalize(value)
    elif isinstance(node, list):
        for item in node:
            _walk_and_normalize(item)


def _normalize_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Contract-only projection: property names/types/defaults/required/enum
    survive; title, description, and a fastmcp>=3.2.0-only spurious
    ``additionalProperties: false`` (schema-root and per-property) do not."""
    normalized: Dict[str, Any] = json.loads(json.dumps(schema))  # deep copy
    _walk_and_normalize(normalized)
    return normalized


def _stdio_snapshot(server: Any) -> Dict[str, Dict[str, Any]]:
    """Extract {name: {inputSchema}} from the fastmcp 3.x (stdio) server.

    Post-CONS-01 consolidation, stdio runs on ``fastmcp.FastMCP`` (same
    engine as HTTP) -- structurally identical to ``_http_snapshot`` below
    except for which server it receives. fastmcp>=3.2.0 removed the
    dict-returning ``get_tools()``/``_tool_manager`` private path in favor
    of the public ``list_tools()`` -> ``list[FunctionTool]``.
    """

    async def _get() -> Dict[str, Any]:
        tools = await server.mcp.list_tools()  # list[FunctionTool]
        return {tool.name: tool.to_mcp_tool() for tool in tools}

    mcp_tools = asyncio.run(_get())
    return {name: {"inputSchema": _normalize_schema(t.inputSchema)} for name, t in mcp_tools.items()}


def _http_snapshot(server: Any) -> Dict[str, Dict[str, Any]]:
    """Extract {name: {inputSchema}} from the fastmcp 3.x (HTTP) server."""

    async def _get() -> Dict[str, Any]:
        tools = await server.mcp.list_tools()  # list[FunctionTool]
        return {tool.name: tool.to_mcp_tool() for tool in tools}

    mcp_tools = asyncio.run(_get())
    return {name: {"inputSchema": _normalize_schema(t.inputSchema)} for name, t in mcp_tools.items()}


@lru_cache(maxsize=1)
def _snapshots() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Build both servers once per test session and cache their snapshots."""
    stdio_server, http_server = _build_servers()
    return _stdio_snapshot(stdio_server), _http_snapshot(http_server)


def _canonical(snapshot: Dict[str, Dict[str, Any]]) -> str:
    """Canonical serialization: sorted keys, 2-space indent, trailing newline."""
    return json.dumps(snapshot, indent=2, sort_keys=True) + "\n"


def _assert_or_update(snapshot: Dict[str, Dict[str, Any]], golden_path: Path) -> None:
    """Compare snapshot against the golden file; rewrite it under UPDATE_SNAPSHOTS=1."""
    text = _canonical(snapshot)
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        golden_path.write_text(text)
    assert golden_path.exists(), (
        f"Golden file {golden_path.name} missing. Generate it with "
        "UPDATE_SNAPSHOTS=1 uv run pytest tests/test_tool_schema_snapshot.py --no-cov"
    )
    assert golden_path.read_text() == text, (
        f"Tool schema drift vs {golden_path.name}. The MCP tool surface is frozen; "
        "if this change is intentional and reviewed, regen with "
        "UPDATE_SNAPSHOTS=1 uv run pytest tests/test_tool_schema_snapshot.py --no-cov"
    )


# --- Snapshot / count tests -------------------------------------------------


def test_stdio_schema_matches_golden() -> None:
    stdio_snap, _ = _snapshots()
    _assert_or_update(stdio_snap, STDIO_GOLDEN)


def test_http_schema_matches_golden() -> None:
    _, http_snap = _snapshots()
    _assert_or_update(http_snap, HTTP_GOLDEN)


def test_stdio_registers_30_tools() -> None:
    stdio_snap, _ = _snapshots()
    assert len(stdio_snap) == EXPECTED_STDIO_TOOL_COUNT, sorted(stdio_snap)


def test_http_registers_31_tools() -> None:
    _, http_snap = _snapshots()
    assert len(http_snap) == EXPECTED_HTTP_TOOL_COUNT, sorted(http_snap)


def test_union_of_tool_names_is_33() -> None:
    stdio_snap, http_snap = _snapshots()
    assert len(set(stdio_snap) | set(http_snap)) == EXPECTED_UNIQUE_TOOL_NAMES


# --- Normalizer unit tests (contrived nested-anyOf inputs) ------------------


def test_anyof_flattens_nested_members() -> None:
    prop = {
        "anyOf": [
            {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "d"},
            {"type": "null"},
        ]
    }

    _canonicalize_anyof(prop)

    assert prop["anyOf"] == [{"type": "string"}, {"type": "null"}]


def test_anyof_hoists_sibling_keys() -> None:
    prop = {
        "anyOf": [
            {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "d"},
            {"type": "null"},
        ]
    }

    _canonicalize_anyof(prop)

    assert prop["description"] == "d"


def test_anyof_dedupes_identical_members() -> None:
    prop = {"anyOf": [{"type": "null"}, {"type": "null"}, {"type": "integer"}]}

    _canonicalize_anyof(prop)

    null_members = [m for m in prop["anyOf"] if m == {"type": "null"}]
    assert len(null_members) == 1
    assert prop["anyOf"] == [{"type": "null"}, {"type": "integer"}]


def test_anyof_is_idempotent() -> None:
    nested = {
        "anyOf": [
            {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "d"},
            {"type": "null"},
        ]
    }
    once = json.loads(json.dumps(nested))
    _canonicalize_anyof(once)
    twice = json.loads(json.dumps(once))
    _canonicalize_anyof(twice)
    assert once == twice

    already_flat = {"anyOf": [{"type": "string"}, {"type": "null"}], "description": "d"}
    before = json.loads(json.dumps(already_flat))
    _canonicalize_anyof(already_flat)
    assert already_flat == before
