# Directory listing references

The repository was renamed from `ss1738/agent-guardrail` to `ss1738/qedra`.

- Repository: https://github.com/ss1738/qedra
- Glama: https://glama.ai/mcp/servers/ss1738/qedra
- awesome-mcp-servers submission: https://github.com/punkpeye/awesome-mcp-servers/pull/10907
- Package metadata and version: `pyproject.toml`
- Install instructions and client configuration: `README.md`

The README contains the Glama backlink requested on PR #10907. The PR description
also confirms that backlink. Listing approval is controlled by the directory's
maintainers; a backlink does not guarantee approval or a review date.

Suggested short description:

> A local policy gate for coding-agent tool calls, with heuristic shell/file
> checks, a z3 model of a structured Git sub-policy, and signed decision receipts.

Use the README as the source for current installation commands and limitations.
Verify package availability and each registry's current schema before submitting
or publishing. Do not reuse historical benchmark counts as current test results.

## Glama build configuration

Glama generates its own Dockerfile from the listing settings; it does not use the
repository Dockerfile directly. Sync the repository before building, then use:

- Python: `3.12` (covered by CI).
- Build steps: `["uv sync --frozen --no-dev --extra mcp --python 3.12"]`.
- CMD arguments: `["mcp-proxy", "--", "/app/.venv/bin/qedra-mcp"]`.
- Placeholder environment: `{"GUARDRAIL_WORKSPACE":"/workspace"}`. Do not supply
  personal credentials or a production repository for introspection.

Create a release only from a successful build test of the intended source commit.
Publishing a Glama release queues the tool definitions for TDQS evaluation; a
successful build alone does not establish a quality grade or listing approval.
