# mcp-vet — Trust-scan gate for MCP servers

**One-liner:** `uvx mcp-vet some-mcp-server` → an evidence-backed verdict
(SAFE / REVIEW / DO_NOT_INSTALL) with findings, before you add it to your
agent-IDE harness (Cursor, Claude Code, VS Code, Gemini CLI).

**Problem it solves (from 2026 market research):**
- 36.7% of public MCP servers have SSRF vulnerabilities; 43% unsafe
  command-execution paths; 41% of official-registry servers have zero auth.
- Noob reality: "the permission model is basically 'do you trust this server
  yes or no'" — no sandbox, no audit trail, hours lost on GitHub issues.
- Security scanning is the #1 differentiator users ask for from directories;
  none provide evidence-backed verdicts + an enforceable gate.

**Positioning:** NOT a 22nd directory. A verification layer on top of every
directory. Trust, productized as a gate.

---

## Target surface (v1)

| Target | How specified | Scanner inputs |
|---|---|---|
| npm package | `mcp-vet @org/pkg` | registry metadata + tarball |
| PyPI package | `mcp-vet pkg-name` | PyPI JSON + sdist/wheel |
| GitHub repo | `mcp-vet owner/repo` | repo metadata + shallow clone |
| Local dir | `mcp-vet ./path` | on-disk source |

## Scanner set (v1) — static, local, evidence-based

1. **ssrf.py — network exfil / SSRF**
   - outbound HTTP calls whose host is built from user/tool input
     (`requests.get(var_url)`, `fetch(\`${host}\`)`, `urllib` with vars)
   - `http://` + variable host, DNS-rebinding patterns, redirect-to-internal
   - weighted severity; false-positive notes attached to every finding
2. **exec.py — command execution**
   - `child_process.exec/spawn` with non-literal args, `os.system`,
     `subprocess(..., shell=True)`, `eval`/`exec`/`Function()` of strings
3. **secrets.py — credential handling**
   - hardcoded keys/tokens, reading `~/.aws`/`~/.ssh`, `.env` upload,
     `os.environ` exfil to remote, key-logging patterns
4. **auth.py — auth posture**
   - detects OAuth/PKCE vs API-key-in-config vs NO auth (the 41%)
   - reports posture even when "no auth" is a design choice (local-only tools)
5. **provenance.py — supply-chain identity**
   - official vs fork (repo, publisher on npm/PyPI), last release recency,
     stars/downloads, license, binary-vs-source distribution (warn on
     prebuilt binaries with no source match)
6. **deps.py — dependency posture (v1 minimal)**
   - dep count, recency, pinned vs floating versions; full CVE DB in v2

## Verdict model

- **SAFE_TO_INSTALL** — no high/medium findings; provenance clean
- **REVIEW_BEFORE_INSTALL** — findings exist; every one shown with file:line,
  severity, and a plain-English explanation (noob-readable)
- **DO_NOT_INSTALL** — high-severity pattern (remote exec, credential exfil,
  known-malicious fixture, prebuilt binary with no source)
- Always evidence-backed, never a black box; `explain_finding(id)` tool
  expands any finding to a human explanation.

## Tool surface (MCP server, FastMCP/Python)

- `vet_server(target)` → verdict + findings[]
- `vet_directory(path)` → scan local source
- `get_verdict(target)` → cached verdict
- `explain_finding(id)` → plain-English detail
- `gate(target)` → exits non-zero on DO_NOT_INSTALL (CI/automation hook)

## Harness integration

- After a PASS: prints ready-to-paste config for Cursor (`mcp.json`),
  Claude Code (`claude mcp add`), VS Code (`.mcp.json`), Gemini CLI.
- Verdicts cached locally (SQLite) with TTL; invalidated on version bump.
- Gate mode for pre-commit / CI: `mcp-vet pkg --gate`.

## Architecture

```
mcp-vet/
  pyproject.toml            # FastMCP dep, console script, uvx entry
  src/mcp_vet/
    server.py               # MCP tool surface (FastMCP)
    cli.py                  # mcp-vet <target> [--json] [--gate]
    scan/
      ssrf.py exec.py secrets.py auth.py provenance.py deps.py
      engine.py             # orchestrates scanners, aggregates verdict
    verdict.py              # verdict model, severities
    cache.py                # SQLite cache + TTL + version-bump invalidation
  tests/
    corpus/known_good/      # official filesystem/fetch/memory — MUST pass
    corpus/malicious/       # crafted fixtures — MUST be caught
    test_scanners.py        # per-scanner unit tests on both corpora
  README.md                 # noob onboarding: uvx mcp-vet ...
```

## First version — cut line

**IN:** npm/PyPI/GitHub/local targets; 6 static scanners; verdict + findings;
CLI + MCP server; local cache; `--gate`; golden corpus tests.
**OUT (v2+):** sandboxed dynamic execution, egress monitoring (the
audit-trail product), live CVE lookups, hosted API, monetization.

## Acceptance test (the honest bar)

The scanner must demonstrably catch the top vulnerability class: the golden
corpus (known-good official servers) passes with SAFE verdicts, and the
malicious corpus (SSRF-variable-URL fixtures, shell=True exec, `.env`
exfiltration, no-auth posture) must be caught with correct severities and
file:line evidence. Quality = corpus coverage, not marketing.

## Known limits (state them up front)

- Static analysis has false positives and false negatives; verdicts are a
  gate for humans, not a replacement for them. Every finding is
  human-reviewable with evidence.
- Local-first by design: a trust tool that phones home would be absurd.
  Optional cloud enrichment stays opt-in (v2).
