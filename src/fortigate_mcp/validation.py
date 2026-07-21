"""Centralized injection-safe validation for FortiGate MCP server (CONF-02/CONF-03).

Purpose:
    - CONF-02: single, testable choke point for every value interpolated
      into a FortiGate REST path (host, vdom, policy/route identifiers,
      object names, interface names) before an f-string/URL is built.
    - CONF-03: `scrub_secrets` is the single reusable secret-scrubbing
      primitive shared by `core/fortigate.py`'s error sanitization and
      `core/logging.py`'s token-redaction filter.

Neutrality constraint (load-bearing):
    This module lives at the TOP LEVEL of the `fortigate_mcp` package
    (sibling of `config/` and `core/`, not inside either) and imports
    ONLY the Python standard library. It MUST NEVER import from
    `fortigate_mcp.config` or `fortigate_mcp.core`. Doing so would
    recreate a circular import:
    `core/__init__.py` eagerly imports `core.logging`, which imports
    `config.models` -- so `config.models -> core.validation -> core
    (__init__) -> core.logging -> config.models` deadlocks at import
    time. Placing validation here lets both `config/models.py` and
    `core/fortigate.py` import it without ever touching that cycle.

Error contract:
    Every validator raises a plain `ValueError` on rejection (matching
    this codebase's existing convention -- see `core/fortigate.py`'s
    `ValueError` usage and `tools/base.py`'s `_handle_error`, which
    already special-cases `ValueError`). No validator ever echoes the
    raw rejected value in its message: a rejected CRLF-bearing or
    oversized value could otherwise perform log-line injection once the
    message flows through `tools/base.py`'s `_handle_error` into logs
    or MCP error content -- field-name-and-expected-format only.
"""

import ipaddress
import re
from typing import Iterable, Optional

# RFC-1123-style hostname: dot-separated labels, each 1-63 chars of
# [A-Za-z0-9-], no leading/trailing hyphen per label, 253-char overall cap.
# Used with fullmatch() only (regex methods that check only a leading
# prefix are never used here) -- fullmatch requires consuming the ENTIRE
# input, so even the trailing `$` inside this pattern cannot let a
# trailing "\n" slip through the way a prefix-anchored check would.
_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
)

# vdom / generic identifier charset: letters, digits, underscore, hyphen.
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9_-]{1,79}")

# Numeric identifier (policy_id, route_id): explicit ASCII digit class only.
# Python's Unicode-aware digit shorthand accepts non-ASCII decimal digits
# (e.g. Arabic-Indic "١٢٣" == "123"), and int() happily
# parses them too -- so an ASCII-only character class is load-bearing here,
# not a style preference.
_NUMERIC_ID_RE = re.compile(r"[0-9]{1,10}")
_MAX_POLICY_ID = 4294967294  # community-sourced sanity bound (RESEARCH.md A2)

# Interface name grammar: identical to the identifier charset PLUS dots,
# because FortiGate VLAN subinterfaces are named like "port1.100". This is
# deliberately a SEPARATE grammar from _IDENTIFIER_RE / validate_object_name
# -- object names never need dots, interfaces sometimes do.
_INTERFACE_RE = re.compile(r"[A-Za-z0-9_.-]{1,79}")

_BEARER_RE = re.compile(r"Bearer\s+\S+", re.IGNORECASE)


def validate_host(host: str) -> str:
    """Validate a FortiGate device host: IPv4, unscoped IPv6, or RFC-1123 hostname.

    Rejects (by construction, not special-casing):
        - scoped IPv6 zone IDs (``fe80::1%eth0``) and any percent character
          -- zone IDs cannot be safely placed in a URL.
        - any embedded ``:port`` (e.g. ``"198.51.100.10:443"``) -- host and
          port are separate config fields; a bare IPv6 literal still parses
          via the ``ipaddress`` branch since it is not ``host:port`` form.
        - path traversal / query / fragment / CRLF / whitespace characters,
          non-string input, empty string, and oversized values.

    Raises:
        ValueError: if `host` is not a valid IPv4 address, unscoped IPv6
            address, or RFC-1123 hostname. The message never contains the
            rejected value.
    """
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a non-empty string")

    if "%" in host:
        raise ValueError(
            "host must not contain a percent character "
            "(scoped IPv6 zone IDs and percent-encoding are not supported)"
        )

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if _HOSTNAME_RE.fullmatch(host):
        return host

    raise ValueError(
        "host is not a valid IPv4 address, IPv6 address, or RFC-1123 hostname"
    )


def validate_port(port: int) -> int:
    """Validate a TCP port number: strict int in [1, 65535], bool excluded.

    ``bool`` is a subclass of ``int`` in Python (``isinstance(True, int)``
    is ``True``), so it is explicitly rejected rather than silently
    accepted as 0 or 1.

    Raises:
        ValueError: if `port` is not a plain int in range 1-65535.
    """
    if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
        raise ValueError("port must be an integer between 1 and 65535")
    return port


def validate_vdom(vdom: str) -> str:
    """Validate a FortiOS VDOM name: letters, digits, underscore, hyphen; 1-79 chars.

    Raises:
        ValueError: if `vdom` is not a string, or does not fullmatch the
            allowed identifier charset (rejects trailing newline/CR,
            traversal, query/fragment characters, spaces, and oversized
            values by construction).
    """
    if not isinstance(vdom, str):
        raise ValueError("vdom must be a string")
    if not _IDENTIFIER_RE.fullmatch(vdom):
        raise ValueError(
            "vdom is not a valid VDOM name "
            "(allowed: letters, digits, underscore, hyphen; 1-79 chars)"
        )
    return vdom


def validate_numeric_id(value: str, field_name: str) -> str:
    """Validate a FortiGate numeric identifier (policy_id, route_id, etc.).

    The value stays a string on return -- callers interpolate it directly
    into a REST path segment; this function only proves it is safe to do
    so (1-10 ASCII digits, bounded to a sane maximum).

    Args:
        value: the raw identifier string to validate.
        field_name: the caller-facing field name, included in the error
            message for traceability (e.g. "policy_id", "route_id") --
            never the rejected value itself.

    Raises:
        ValueError: if `value` is not a string of 1-10 ASCII digits, or
            exceeds the sanity bound.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string of ASCII digits")
    if not _NUMERIC_ID_RE.fullmatch(value) or int(value) > _MAX_POLICY_ID:
        raise ValueError(
            f"{field_name} is not a valid numeric ID "
            "(expected 1-10 ASCII digits, max 4294967294)"
        )
    return value


def validate_object_name(name: str, field_name: str) -> str:
    """Validate a FortiGate object name (address, service, VIP names, etc.).

    Args:
        name: the raw object name to validate.
        field_name: the caller-facing field name, included in the error
            message for traceability -- never the rejected value itself.

    Raises:
        ValueError: if `name` is not a string, or does not fullmatch the
            allowed identifier charset. Dots are NOT allowed here -- see
            `validate_interface_name` for the dot-permitting grammar used
            by FortiGate VLAN subinterface names.
    """
    if not isinstance(name, str):
        raise ValueError(f"{field_name} must be a string")
    if not _IDENTIFIER_RE.fullmatch(name):
        raise ValueError(
            f"{field_name} is not a valid object name "
            "(allowed: letters, digits, underscore, hyphen; 1-79 chars)"
        )
    return name


def validate_interface_name(name: str) -> str:
    """Validate a FortiGate interface name (e.g. "port1", "port1.100").

    This is deliberately a SEPARATE, more permissive grammar than
    `validate_object_name`: FortiGate VLAN subinterfaces are named like
    "port1.100", so dots must be allowed here. `get_interface_status`
    sends this value via httpx `params=` (not a raw path segment), so the
    permissive-but-still-anchored pattern remains safe.

    Raises:
        ValueError: if `name` is not a string, or does not fullmatch the
            interface-name charset.
    """
    if not isinstance(name, str):
        raise ValueError("interface_name must be a string")
    if not _INTERFACE_RE.fullmatch(name):
        raise ValueError(
            "interface_name is not a valid interface name "
            "(allowed: letters, digits, underscore, hyphen, dot; 1-79 chars)"
        )
    return name


def scrub_secrets(text: str, secrets: Iterable[Optional[str]]) -> str:
    """Redact known secret values and Bearer-pattern tokens from `text`.

    The single shared scrubbing primitive: `core/fortigate.py` applies
    this to untrusted HTTP-response/exception text before building a
    `FortiGateAPIError` (CONF-03), and `core/logging.py`'s
    `TokenRedactionFilter` delegates to it for every log record.

    Args:
        text: the text to scrub. Non-string input is returned unchanged
            (defensive; callers are expected to pass a str).
        secrets: any iterable of known secret strings. Empty-string and
            `None` entries are dropped before use -- an empty secret must
            never become a redact-everything match.

    Returns:
        `text` with every occurrence of each non-empty secret replaced by
        ``***REDACTED***``, plus any ``Bearer <token>`` pattern masked
        independently of the known-secrets set.
    """
    if not isinstance(text, str):
        return text  # type: ignore[unreachable]  # defensive: callers may bypass the str hint

    # Longest-first: two registered secrets can be in a substring
    # relationship (e.g. a rotated token that extends an older still-
    # registered token -- register_secrets() never removes entries).
    # Replacing the shorter one first would fragment the longer one and
    # leave a residual, undredacted tail. Sorting descending by length
    # guarantees the longer secret is always matched whole before a
    # shorter substring of it can consume part of it. This also makes the
    # result independent of `set` iteration order (which is per-process
    # hash-seed dependent) -- ties in length keep a stable relative order
    # via Python's stable sort over the (also order-independent) input.
    known = sorted({s for s in secrets if s}, key=len, reverse=True)
    for secret in known:
        text = text.replace(secret, "***REDACTED***")

    return _BEARER_RE.sub("Bearer ***REDACTED***", text)
