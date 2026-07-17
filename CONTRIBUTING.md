# Contributing to fortigate-mcp-server

Thanks for your interest in contributing. This document covers development setup, the test/
lint/coverage commands this project actually enforces, and a few hard rules specific to this
release line that are not obvious from the code alone.

## Development Setup

This project uses [`uv`](https://docs.astral.sh/uv/) as its package manager, with a committed
`uv.lock` for reproducible installs.

```bash
git clone https://github.com/alpadalar/fortigate-mcp-server.git
cd fortigate-mcp-server

# Install the locked dependency set, including all dev/test/lint/security extras
uv sync --locked --all-extras
```

`uv sync --locked` must succeed without modifying `uv.lock` — if it doesn't, the lockfile is
out of sync with `pyproject.toml` and needs to be regenerated (`uv lock`) as part of your
change, not worked around.

## Test, Lint, and Coverage Commands

These commands are copied verbatim from this project's actual configured tool settings in
`pyproject.toml` — run them locally before opening a pull request:

```bash
# Fast test run (no coverage gate)
uv run pytest -q

# Full test run — enforces the coverage gate (--cov-fail-under=67, currently ~75%)
uv run pytest

# Formatting (line-length 88, target py311)
uv run black src tests

# Import sorting (profile = black)
uv run isort src tests

# Static typing (disallow_untyped_defs, warn_return_any, warn_unreachable, etc.)
uv run mypy src

# Security static analysis (excludes tests/, skips B101/B601)
uv run bandit -c pyproject.toml -r src
```

A pull request that drops test coverage below the `--cov-fail-under=67` gate, or that
introduces new `mypy`/`bandit` findings in `src/`, will not be merged as-is.

## The MCP Tool Surface Is Frozen — This Is a Prohibition, Not a Routine Path

The MCP tool surface (every tool's **name** and **parameter schema**) is byte-frozen for the
entire `1.0.x` release line, guarded by golden fixtures under
`tests/fixtures/tool_schemas_stdio.json` and `tests/fixtures/tool_schemas_http.json`
(`tests/test_tool_schema_snapshot.py`).

**Intentional changes to a tool's name or parameter schema are NOT a normal contributor path
in this release line and will not be merged.** This includes adding, removing, or renaming a
parameter; changing a parameter's type, default, or required-ness; and renaming a tool. Any
such change requires a major version bump and a separately-approved process outside the
scope of a routine pull request.

The regeneration command exists for **maintainer reference only**, for use after an
approved major-version schema change — it is not a fix for a failing snapshot test:

```bash
UPDATE_SNAPSHOTS=1 uv run pytest tests/test_tool_schema_snapshot.py --no-cov
```

If `tests/test_tool_schema_snapshot.py` fails on your branch, the correct response is almost
always to **revert the change that altered the schema**, not to regenerate the golden file.
A failing snapshot test means the change should not be made in this release line.

## Commit Message Convention (Recommended, Not Enforced)

This repository's history generally follows a `type(scope): imperative summary` style, for
example:

```
fix(01-01): resolve stdio server NameError and extract server_main
feat(02-01): add neutral host/port/vdom validators
```

Following this convention is appreciated but not a hard requirement for external
contributions — clear, imperative commit summaries are what actually matters.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Make your change, following the frozen-tool-surface rule above.
3. Run the test/lint/coverage commands listed above and confirm they pass locally.
4. Open a pull request describing what changed and why.

**Commit attribution:** every commit must be attributed to its human author only. Do not
include AI co-authorship footers (for example, a `Co-Authored-By:` line naming an AI
assistant/tool) in any commit message, regardless of what tooling was used to help write the
change. This is a hard project rule for this repository, independent of whatever your own
tooling defaults to.

## Reporting Bugs and Requesting Features

Use the GitHub issue templates. If you believe you've found a security vulnerability, do
**not** open a public issue — see [SECURITY.md](SECURITY.md) for the private reporting
channel.
