# mcp-vet

Trust-scan gate for MCP servers: evidence-backed verdicts before you install.

```bash
uvx mcp-vet some-mcp-server        # or: pipx install mcp-vet
mcp-vet @modelcontextprotocol/server-filesystem
mcp-vet gh:owner/repo --json
mcp-vet ./my-local-server-dir --gate
```

Verdict: **SAFE_TO_INSTALL** · **REVIEW_BEFORE_INSTALL** · **DO_NOT_INSTALL**,
every finding with file:line + plain-English explanation.

## Targets

- `npm:pkg` (or bare name) — npm registry + tarball
- `pypi:pkg` — PyPI JSON + sdist
- `gh:owner/repo` — GitHub metadata + source tarball
- `./path` — local source directory (offline)

## Checks

`ssrf` (36.7% of public servers) · `exec` (43%) · `secrets` ·
`auth` (41% have none) · `provenance` · `deps`

## As an MCP server

```json
{ "mcpServers": { "mcp-vet": { "command": "uvx", "args": ["mcp-vet-server"] } } }
```

Tools: `vet_server`, `vet_directory`, `get_verdict`, `list_scanners`.
Gate mode (`--gate`) exits 1 on DO_NOT_INSTALL for CI.

## Honest limits

Static analysis has false positives/negatives. A verdict is a gate for
humans, not a replacement for them — every finding is reviewable.
Local-first by design: no telemetry, no cloud round-trips.
