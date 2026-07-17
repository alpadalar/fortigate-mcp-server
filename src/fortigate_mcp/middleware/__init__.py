"""FortiGate MCP ASGI middleware package.

Empty package marker -- middleware classes are imported from their own
submodules directly (e.g. ``from .middleware.trace import TraceMiddleware``),
not re-exported here. Phase 4 (SEC-05) adds real auth/CORS/rate-limit
middleware modules alongside ``trace.py`` in this same package.
"""
