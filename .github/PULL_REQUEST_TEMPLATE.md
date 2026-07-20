<!-- .github/PULL_REQUEST_TEMPLATE.md -->
## Summary

<!-- What does this change do, and why? -->

## Checklist
- [ ] I have NOT changed any MCP tool name or parameter schema
      (the tool surface is byte-frozen for this release line — see
      tests/fixtures/tool_schemas_*.json — schema changes require a major version bump)
- [ ] Tests pass locally with the coverage gate: `uv run pytest`
      (pyproject.toml addopts enforce `--cov-fail-under=67`; `uv run pytest -q --no-cov`
      is only a quick iteration aid and does not satisfy this item)
