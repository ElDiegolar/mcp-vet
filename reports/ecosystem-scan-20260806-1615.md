# mcp-vet — Ecosystem safety snapshot

Generated: 2026-08-06T16:14
Tool: mcp-vet v0.1 · static scanners: ssrf, exec, secrets, auth, provenance, deps

Verdicts: **SAFE_TO_INSTALL** · **REVIEW_BEFORE_INSTALL** · **DO_NOT_INSTALL**

| target | version | verdict | findings | top findings |
|---|---|---|---|---|
| @modelcontextprotocol/server-filesystem | 2026.7.10 | **SAFE_TO_INSTALL** | 2 | low:auth; low:deps |
| @modelcontextprotocol/server-fetch | ? | **REVIEW_BEFORE_INSTALL** | 1 | medium:provenance |
| @modelcontextprotocol/server-memory | 2026.7.4 | **SAFE_TO_INSTALL** | 6 | low:secrets; low:secrets; low:secrets |
| @modelcontextprotocol/server-git | ? | **REVIEW_BEFORE_INSTALL** | 1 | medium:provenance |
| @modelcontextprotocol/server-everything | 2026.7.4 | **REVIEW_BEFORE_INSTALL** | 10 | low:secrets; low:secrets; low:secrets |
| @modelcontextprotocol/server-sequential-thinking | 2026.7.4 | **SAFE_TO_INSTALL** | 3 | low:secrets; low:auth; low:deps |
| puppeteer-mcp-server | 0.7.2 | **SAFE_TO_INSTALL** | 4 | low:secrets; low:secrets; low:auth |
| @playwright/mcp | 0.0.79 | **SAFE_TO_INSTALL** | 1 | low:auth |
| mcp-server-sqlite | 0.0.2 | **SAFE_TO_INSTALL** | 6 | low:exec; low:secrets; low:secrets |
| @supabase/mcp-server | ? | **REVIEW_BEFORE_INSTALL** | 1 | medium:provenance |
| @modelcontextprotocol/server-brave-search | 0.6.2 | **REVIEW_BEFORE_INSTALL** | 10 | medium:ssrf; medium:ssrf; medium:ssrf |
| @modelcontextprotocol/server-slack | 2025.4.25 | **SAFE_TO_INSTALL** | 17 | low:ssrf; low:ssrf; low:ssrf |
| @modelcontextprotocol/server-github | 2025.4.8 | **REVIEW_BEFORE_INSTALL** | 35 | low:ssrf; low:ssrf; low:ssrf |
| @modelcontextprotocol/server-postgres | 0.6.2 | **SAFE_TO_INSTALL** | 1 | low:auth |
| mcp-server-time | ? | **REVIEW_BEFORE_INSTALL** | 1 | medium:provenance |
| pypi:mcp | 2.0.0 | **DO_NOT_INSTALL** | 37 | low:ssrf; low:ssrf; low:ssrf |
| pypi:fastmcp | 3.4.6 | **REVIEW_BEFORE_INSTALL** | 123 | low:ssrf; low:ssrf; low:ssrf |
| gh:modelcontextprotocol/servers | ? | **REVIEW_BEFORE_INSTALL** | 39 | low:secrets; low:secrets; low:secrets |
| gh:madnh/mcp-server-sqlite | ? | **SAFE_TO_INSTALL** | 5 | low:exec; low:secrets; low:secrets |
| gh:modelcontextprotocol/python-sdk | ? | **DO_NOT_INSTALL** | 37 | low:ssrf; low:ssrf; low:ssrf |

## Summary
- **9 SAFE_TO_INSTALL** · **9 REVIEW_BEFORE_INSTALL** · **2 DO_NOT_INSTALL**

## Honest caveats
- Static analysis: false positives/negatives are expected; every finding is a human-reviewable gate, not a verdict on intent (e.g. a fetch server is SSRF-shaped *by design* — the REVIEW flags it, a human decides).
- This snapshot reflects the listed package versions at scan time; re-run to refresh.