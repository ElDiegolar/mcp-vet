# mcp-vet

**A trust-scan framework for MCP servers: evidence-backed verdicts before you
install — usable from any harness.**

<!-- mcp-name: io.github.eldiegolar/mcp-vetting -->

```bash
uvx --from mcp-vetting mcp-vet @modelcontextprotocol/server-fetch   # one command
uvx --from mcp-vetting mcp-vet ./my-server --harness hermes          # verdict + config for YOUR harness
uvx --from mcp-vetting mcp-vet pypi:fastmcp --json --gate            # machine-readable, CI-friendly
```

Verdicts: **SAFE_TO_INSTALL** · **REVIEW_BEFORE_INSTALL** · **DO_NOT_INSTALL** —
every finding carries file:line and plain-English evidence. A verdict is a
gate for humans, never a black box.

---

## The flow

1. **Vet** any target: npm / PyPI / GitHub / local directory.
2. **Read** the verdict + findings (evidence, not vibes).
3. **Configure**: pick your harness, paste the emitted config block.
4. **Gate** it in CI with `--gate` (exit 1 on DO_NOT_INSTALL).

## Three surfaces, one engine

| Surface | Use |
|---|---|
| **Library** | `from mcp_vet import vet, Policy` → `VetResult` (verdict, findings, provenance) |
| **CLI** | `mcp-vet <target> [--json] [--gate] [--strict] [--harness ...]` |
| **MCP server** | `mcp-vet-server` — tools: `vet_server`, `vet_directory`, `get_verdict`, `list_scanners`, `list_harnesses`, `get_config` |

## Targets

```
npm:pkg            npm registry + tarball        (bare names default to npm)
pypi:pkg           PyPI JSON + sdist/wheel
gh:owner/repo      GitHub metadata + source
./path             local source directory (offline)

Bare names that fail to resolve on npm (e.g. PyPI-only servers like
`mcp-server-time`) automatically fall back to PyPI before reporting failure.
```

## Harness adapters (any harness, paste-ready)

`--harness` emits the exact config block for your tool:

| harness | output |
|---|---|
| `generic` | universal `mcpServers` block |
| `claude-code` | `claude mcp add <name> -- <cmd> <args>` |
| `cursor` | `.cursor/mcp.json` |
| `vscode` | `.vscode/mcp.json` (VS Code `servers` schema) |
| `hermes` | `~/.hermes/config.yaml` `mcp_servers` block |

`--harness all` prints every adapter. Programmatic: `config_for(harness, ServerSpec(...))`.

## Policy (calibrated defaults, `--strict` to disable)

Static analysis must not cry wolf. Defaults, learned by vetting the real
ecosystem:

- **Examples/tests/docs are informational** — `examples/`, `tests/`, `docs/`
  code can't block a package on its own (strict restores raw findings).
- **Fake secrets don't count** — `sk-test-…`, `example`, `xxxx` literals are
  placeholders, not exfiltration.
- **Trusted-host auth is normal** — credentials sent to a host *named in the
  file* (constant or literal) is client auth; HIGH only when the destination
  host appears nowhere in the code.
- **Host interpolation → REVIEW** — `https://${host}/…` is a strong signal,
  but static analysis can't prove the host is user-controlled; a human
  decides. Strict mode blocks on it.

## JSON schema (stable)

```json
{
  "target": "npm:some-server", "kind": "npm", "version": "1.2.3",
  "verdict": {
    "level": "REVIEW_BEFORE_INSTALL",
    "summary": "3 finding(s); 0 high, 1 medium.",
    "findings": [
      {"scanner": "ssrf", "severity": "medium", "message": "...",
       "file": "dist/index.js", "line": 41, "evidence": "fetch(url)"}
    ]
  },
  "provenance": {"version": "1.2.3", "license": "MIT",
                 "source_url": "git+https://...", "source": "npm"},
  "files_scanned": 214, "duration_s": 1.7
}
```

## Scanners

`ssrf` · `exec` · `secrets` · `auth` · `provenance` · `deps` — static,
local-first (no telemetry, no cloud round-trips; the cache is a local SQLite
file under `~/.cache/mcp-vet`).

## Verification

```bash
python3 -m unittest discover -s tests    # 48 checks: golden corpus is the quality bar
```

The golden corpus is the contract: known-good fixtures must never carry HIGH
findings; malicious fixtures must always block. The ecosystem scan
(`scripts/ecosystem_scan.py`) keeps the tool honest against real packages.

## Honest limits

Static analysis has false positives and negatives. A verdict is a gate for
humans, not a replacement for them — read the evidence. Sandboxed execution,
egress audit-trail, and live CVE lookups are planned for v2.
