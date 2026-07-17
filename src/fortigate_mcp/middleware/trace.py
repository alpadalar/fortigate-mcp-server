"""Pure-ASGI trace middleware proving the build_http_app() middleware seam.

Starlette's base-class HTTP middleware helper buffers and re-wraps the
entire HTTP response before it is allowed through, which is unsafe on the
streamable-HTTP MCP mount this middleware runs in front of (SSE/chunked
responses can be corrupted or deadlocked by that buffering). ``TraceMiddleware``
is implemented as pure ASGI instead: it appends exactly one header on the
``http.response.start`` message and otherwise passes every ASGI message
through untouched, so it is fully transparent to streaming responses.
"""
from starlette.datastructures import MutableHeaders


class TraceMiddleware:
    """Pure-ASGI middleware that stamps ``X-FortiGate-MCP-Trace`` on every
    HTTP response produced by the app it wraps.

    Two things this class exists to prove, both load-bearing:

    1. It proves the middleware seam in ``build_http_app()`` actually
       executes on the served app -- Plan 03-05's live E2E test asserts on
       this header against a real, network-served instance (not a
       hand-built test-only app object). Phase 4 (SEC-05) adds real
       auth/CORS/rate-limit middleware to this exact same
       ``Middleware([...])`` list.
    2. The trace header itself is INTENTIONAL, PERMANENT production
       behavior -- a live canary that the production middleware stack is
       actually attached to the served app -- not a temporary test
       artifact. Do not delete it as "leftover debug code"; its absence on
       a live response is itself a meaningful signal that the middleware
       stack failed to attach.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_trace(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.append("X-FortiGate-MCP-Trace", "build_http_app")
            await send(message)

        await self.app(scope, receive, send_with_trace)
