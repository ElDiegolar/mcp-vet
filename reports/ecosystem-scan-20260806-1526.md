# mcp-vet — Ecosystem safety snapshot

Generated: 2026-08-06T15:26
Tool: mcp-vet v0.1 · static scanners: ssrf, exec, secrets, auth, provenance, deps

Verdicts: **SAFE_TO_INSTALL** · **REVIEW_BEFORE_INSTALL** · **DO_NOT_INSTALL**

| target | version | verdict | findings | top findings |
|---|---|---|---|---|
| @modelcontextprotocol/server-filesystem | 2026.7.10 | **SAFE_TO_INSTALL** | 3 | low:auth; low:deps; low:provenance |
| @modelcontextprotocol/server-fetch | unknown | **REVIEW_BEFORE_INSTALL** | 2 | low:auth; medium:provenance |
| @modelcontextprotocol/server-memory | 2026.7.4 | **SAFE_TO_INSTALL** | 7 | low:secrets; low:secrets; low:secrets |
| @modelcontextprotocol/server-git | unknown | **REVIEW_BEFORE_INSTALL** | 2 | low:auth; medium:provenance |
| @modelcontextprotocol/server-everything | 2026.7.4 | **REVIEW_BEFORE_INSTALL** | 11 | low:secrets; low:secrets; low:secrets |
| @modelcontextprotocol/server-sequential-thinking | 2026.7.4 | **SAFE_TO_INSTALL** | 4 | low:secrets; low:auth; low:deps |
| puppeteer-mcp-server | 0.7.2 | **SAFE_TO_INSTALL** | 4 | low:secrets; low:secrets; low:auth |
| @playwright/mcp | 0.0.79 | **SAFE_TO_INSTALL** | 1 | low:auth |
| mcp-server-sqlite | 0.0.2 | **DO_NOT_INSTALL** | 11 | low:secrets; low:secrets; low:secrets |
| @supabase/mcp-server | unknown | **REVIEW_BEFORE_INSTALL** | 2 | low:auth; medium:provenance |

## Summary
- **5 SAFE_TO_INSTALL** · **4 REVIEW_BEFORE_INSTALL** · **1 DO_NOT_INSTALL**

## Honest caveats
- Static analysis: false positives/negatives are expected; every finding is a human-reviewable gate, not a verdict on intent (e.g. a fetch server is SSRF-shaped *by design* — the REVIEW flags it, a human decides).
- This snapshot reflects the listed package versions at scan time; re-run to refresh.