# Marketplace submission kit

Everything to paste into each MCP marketplace. All five take the repo URL;
the blurbs below are the copy.

## One-liner (title / subtitle fields)

Trust-scan gate for MCP servers: evidence-backed verdicts before you install.

## Short description (the "description" field — ~60 words)

Vet any MCP server before installing it. Static scanners (SSRF, command
execution, secrets, auth posture, provenance, dependencies) return an
evidence-backed verdict — SAFE_TO_INSTALL, REVIEW_BEFORE_INSTALL or
DO_NOT_INSTALL — with file:line findings. Includes paste-ready config
adapters for Claude Code, Cursor, VS Code and Hermes. Local-first: no
telemetry, no cloud round-trips. `uvx --from mcp-vetting mcp-vet <target>`.

## Tags

mcp, mcp-server, security, vetting, trust, llm, agent, audit

## Category

Security / Developer Tools

## Per-marketplace cheat sheet

| Marketplace | URL | Paste |
|---|---|---|
| mcp.so | https://mcp.so/submit | repo URL + short description + tags |
| Glama | https://glama.ai/mcp/servers/ElDiegolar/mcp-vet | LIVE — verified Aug 2026 |
| Smithery | https://smithery.ai | repo URL + short description |
| PulseMCP | https://pulsemcp.com | repo URL + short description + tags |
| mcpregistry.com | https://mcpregistry.com | repo URL + short description |

## Key facts (some forms ask)

- Name: mcp-vetting
- Repository: https://github.com/ElDiegolar/mcp-vet
- PyPI: https://pypi.org/project/mcp-vetting/
- License: MIT
- Language: Python 3.10+
- Install: `uvx --from mcp-vetting mcp-vet <target>`
- Server entry point: `mcp-vet-server` (stdio MCP server)
- Server name (official registry): io.github.eldiegolar/mcp-vetting
