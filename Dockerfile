# FortiGate MCP Server Dockerfile
# Base image is version- AND digest-pinned: a floating `python:3.11-slim`
# tag is the same mutable-reference supply-chain class the workflows
# eliminate with SHA-pinned `uses:`. Human tag: python:3.11-slim ==
# 3.11.15-slim-trixie. Digest is the multi-arch OCI index digest, verified
# live against the registry:
#   docker buildx imagetools inspect python:3.11-slim
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

# Metadata
LABEL maintainer="FortiGate MCP Team"
LABEL description="FortiGate MCP Server - FastMCP based FortiGate management server"
LABEL version="1.0.0"

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=8814

# Create app user
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

# Set working directory
WORKDIR /app

# Install system dependencies and uv
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        netcat-traditional \
        git \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install uv. Version- AND digest-pinned: this binary performs the entire
# dependency install, so a floating tag here is the same mutable-reference
# supply-chain class the workflows eliminate with SHA-pinned `uses:`.
# Digest verified live against the registry (OCI index for tag 0.11.30):
#   GET https://ghcr.io/v2/astral-sh/uv/manifests/0.11.30
COPY --from=ghcr.io/astral-sh/uv:0.11.30@sha256:93b61e21202b1dab861092748e46bbd6e0e41dd84f59b9174efd2353186e1b47 /uv /uvx /usr/local/bin/

# Copy project files needed for installation
COPY pyproject.toml README.md uv.lock ./
COPY src/ src/

# Install Python dependencies with uv. --no-cache avoids baking uv's ~85MB
# build/download cache (which can retain build-time-only copies of packages
# like setuptools/wheel at whatever version was current when the cache was
# populated) into the image layer -- the app only ever needs the resulting
# .venv, never uv's cache.
RUN uv sync --locked --no-dev --no-editable --no-cache

# The python:3.11-slim base image bootstraps its own system-level pip,
# setuptools, and wheel via ensurepip. The application never uses them --
# uv manages /app/.venv directly via the standalone uv binary above, and the
# container's CMD runs `uv run`, not the system python's pip -- but they
# still ship in the image and setuptools vendors its own copies of `wheel`
# and `jaraco.context` internally (setuptools/_vendor/), which can lag
# behind the patched versions pinned in uv.lock and trip container
# vulnerability scanning (e.g. CVE-2026-24049 in vendored wheel 0.45.1,
# CVE-2026-23949 in vendored jaraco.context 5.3.0). Removing this unused
# toolchain eliminates that surface entirely rather than chasing vendored
# copies we don't control via uv.lock.
RUN python3 -m pip uninstall --yes pip setuptools wheel

# Copy remaining application code
COPY config/ config/
COPY tests/ tests/

# Create logs directory
RUN mkdir -p /app/logs && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check - Sadece port kontrolü yap
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost ${MCP_SERVER_PORT} || exit 1

# Expose port
EXPOSE ${MCP_SERVER_PORT}

# Default command. --no-sync is load-bearing: a bare `uv run` performs an
# implicit `uv sync` at every container start, which re-installs the project
# editable (the build used --no-editable) and -- because the image was built
# with --no-cache -- must reach PyPI to re-fetch the build backend, mutating
# the audited uv.lock venv and failing outright in egress-restricted
# deployments. --no-sync executes against /app/.venv exactly as built.
CMD ["uv", "run", "--no-sync", "python", "-m", "src.fortigate_mcp.server_http", "--host", "0.0.0.0", "--port", "8814", "--path", "/fortigate-mcp", "--config", "/app/config/config.json"]
