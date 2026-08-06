#!/usr/bin/env python3
"""Ecosystem safety snapshot: vet a curated set of popular MCP servers with
mcp-vet and produce a report. Run: .venv/bin/python scripts/ecosystem_scan.py"""
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_vet.engine import vet  # noqa: E402

TARGETS = [
    "@modelcontextprotocol/server-filesystem",   # official: local files
    "@modelcontextprotocol/server-fetch",        # official: fetches URLs (SSRF-shaped by design)
    "@modelcontextprotocol/server-memory",       # official: knowledge graph
    "@modelcontextprotocol/server-git",          # official: git ops
    "@modelcontextprotocol/server-everything",   # official: test kitchen sink
    "@modelcontextprotocol/server-sequential-thinking",  # official: reasoning
    "puppeteer-mcp-server",                      # community: browser automation
    "@playwright/mcp",                           # MS: browser automation
    "mcp-server-sqlite",                         # community: sqlite
    "@supabase/mcp-server",                      # community: supabase
]

REPORT = Path(__file__).resolve().parent.parent / "reports"
REPORT.mkdir(exist_ok=True)

lines = [
    "# mcp-vet — Ecosystem safety snapshot",
    "",
    f"Generated: {datetime.now().isoformat(timespec='minutes')}",
    f"Tool: mcp-vet v0.1 · static scanners: ssrf, exec, secrets, auth, provenance, deps",
    "",
    "Verdicts: **SAFE_TO_INSTALL** · **REVIEW_BEFORE_INSTALL** · **DO_NOT_INSTALL**",
    "",
    "| target | version | verdict | findings | top findings |",
    "|---|---|---|---|---|",
]

print(f"veting {len(TARGETS)} servers...\n")
results = []
for t in TARGETS:
    start = time.time()
    try:
        r = vet(t, use_cache=False)
    except Exception as e:  # noqa: BLE001
        results.append((t, "ERROR", 0, str(e)[:120]))
        print(f"  ERROR {t}: {e}")
        continue
    v = r["verdict"]
    top = "; ".join(f"{f['severity']}:{f['scanner']}" for f in v["findings"][:3])
    results.append((t, v["level"], len(v["findings"]), top))
    print(f"  {v['level']:<24} {t}  ({len(v['findings'])} findings, {time.time()-start:.0f}s)")
    lines.append(f"| {t} | {r.get('version','?')} | **{v['level']}** | {len(v['findings'])} | {top} |")

blocked = [r for r in results if r[1] == "DO_NOT_INSTALL"]
review = [r for r in results if r[1] == "REVIEW_BEFORE_INSTALL"]
safe = [r for r in results if r[1] == "SAFE_TO_INSTALL"]

lines += [
    "",
    f"## Summary",
    f"- **{len(safe)} SAFE_TO_INSTALL** · **{len(review)} REVIEW_BEFORE_INSTALL** · "
    f"**{len(blocked)} DO_NOT_INSTALL**",
    "",
    "## Honest caveats",
    "- Static analysis: false positives/negatives are expected; every finding is a "
    "human-reviewable gate, not a verdict on intent (e.g. a fetch server is SSRF-shaped "
    "*by design* — the REVIEW flags it, a human decides).",
    "- This snapshot reflects the listed package versions at scan time; re-run to refresh.",
]

path = REPORT / f"ecosystem-scan-{datetime.now():%Y%m%d-%H%M}.md"
path.write_text("\n".join(lines), encoding="utf-8")
print(f"\nwrote {path}")
print(f"summary: {len(safe)} safe, {len(review)} review, {len(blocked)} blocked")
