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
    recreate a circular import identified during cross-AI review:
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
