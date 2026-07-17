"""Pure-ASGI Bearer-token auth middleware enforcing SEC-05.

Mirrors ``middleware/trace.py::TraceMiddleware``'s pure-ASGI shape (no
Starlette ``BaseHTTPMiddleware`` response-buffering, which is unsafe on
the streamable-HTTP MCP mount this middleware sits in front of): the
constructor takes ``app``; ``__call__(self, scope, receive, send)``. Unlike
TraceMiddleware, non-"http" scopes are NOT passed through wholesale: only
"lifespan" is forwarded; "websocket" is closed with policy-violation code
1008 and any other scope type is dropped -- an auth gate fails closed on
every connection class it cannot vet, so a future websocket route (or a
fastmcp upgrade that adds one) can never be served unauthenticated.

Threat model this closes (04-REVIEWS.md, T-04-09/T-04-10/T-04-11/T-04-16):

- Reject-before-compare: a missing Authorization header, a non-Bearer
  scheme, or an empty/whitespace-only candidate is denied BEFORE any
  ``hmac.compare_digest`` call runs -- there is no ""-vs-"" comparison
  path in this code, structurally.
- Filtered, fail-closed token set: only entries that are truthy after
  ``.strip()`` survive construction (defense in depth below AuthConfig's
  own validators in config/models.py). If the filtered set ends up empty,
  every request is denied -- including header-less ones -- rather than
  silently accepting anything.
- No short-circuit comparison: every filtered token is compared via
  ``hmac.compare_digest`` for a non-empty candidate, accumulated with
  ``|=`` rather than an ``any(...)`` generator that stops at the first
  match, so per-token comparison count does not vary with which token (if
  any) matches.
- Bytes-only comparison: ``hmac.compare_digest`` on ``str`` operands
  raises ``TypeError`` for any non-ASCII character, and Starlette decodes
  header bytes as latin-1 -- so a single ``0x80``-``0xff`` byte in the
  Authorization header (valid obs-text per RFC 7230) would crash the gate
  with an unhandled exception instead of a 401. Tokens are encoded once at
  construction (utf-8); the candidate is re-encoded via latin-1, the exact
  lossless inverse of Starlette's header decode, which can never raise.
- Method-scoped /health exemption: GET/HEAD /health bypasses the token
  check (liveness probes must work even when require_auth is True); any
  other verb to /health is NOT exempt and still requires a valid token.
  The exemption lives inside __call__ because there is no way to register
  /health "outside" the wrapped ASGI stack -- build_http_app() wraps the
  entire served app in this middleware.
- No token echo: the 401 body is a fixed, generic JSON object -- never a
  configured token, header value, or other request material.
"""
import hmac
from typing import Iterable, Tuple

from starlette.datastructures import Headers
from starlette.responses import JSONResponse

_BEARER_PREFIX = "bearer "


class AuthMiddleware:
    """Pure-ASGI Bearer-token gate for build_http_app()'s middleware stack.

    Constructed with the raw, unfiltered ``AuthConfig.api_tokens`` list;
    filtering happens once here at construction time.
    """

    def __init__(self, app, api_tokens: Iterable[str]):
        self.app = app
        # Defense in depth: only non-empty-after-strip entries participate
        # in comparison, even though AuthConfig already rejects those at
        # the config layer. A filtered-empty set fails closed below.
        # Encoded to bytes once here: hmac.compare_digest on str raises
        # TypeError for non-ASCII input, and the candidate side is
        # attacker-controlled header material.
        self._tokens: Tuple[bytes, ...] = tuple(
            token.encode("utf-8") for token in api_tokens if token and token.strip()
        )

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            # Auth gate fails closed on any connection type it cannot vet.
            # Today no websocket route exists behind this middleware, but a
            # wholesale non-http passthrough would silently exempt any
            # future one from the token check.
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        if scope["path"] == "/health" and scope["method"] in ("GET", "HEAD"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        auth_header = headers.get("authorization")

        candidate = ""
        if auth_header is not None and auth_header.lower().startswith(_BEARER_PREFIX):
            candidate = auth_header[len(_BEARER_PREFIX):]

        # Reject before compare: no candidate, no configured tokens to
        # compare against -- hmac.compare_digest must never run against an
        # empty candidate or an empty expected-token set.
        if not candidate.strip() or not self._tokens:
            await self._deny(scope, receive, send)
            return

        # Compare bytes, never str: Starlette decoded the header value as
        # latin-1, so encoding back via latin-1 losslessly recovers the raw
        # wire bytes and can never raise -- unlike compare_digest on a str
        # containing obs-text (0x80-0xff), which raises TypeError.
        candidate_bytes = candidate.encode("latin-1")
        matched = False
        for token in self._tokens:
            matched |= hmac.compare_digest(candidate_bytes, token)

        if not matched:
            await self._deny(scope, receive, send)
            return

        await self.app(scope, receive, send)

    @staticmethod
    async def _deny(scope, receive, send) -> None:
        response = JSONResponse({"error": "unauthorized"}, status_code=401)
        await response(scope, receive, send)
