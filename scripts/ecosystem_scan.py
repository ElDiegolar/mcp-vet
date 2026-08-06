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
    # official npm (already vetted in the first pass — keep for a stable core)
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
    "puppeteer-mcp-server",
    "@playwright/mcp",
    "mcp-server-sqlite",
    "@supabase/mcp-server",
    # extension: more official npm servers
    "@modelcontextprotocol/server-brave-search",   # API-key server
    "@modelcontextprotocol/server-slack",          # OAuth server
    "@modelcontextprotocol/server-github",         # API-key server
    "@modelcontextprotocol/server-postgres",       # DB server
    "mcp-server-time",                             # official time server
    # extension: PyPI targets (exercises the pypi: path)
    "pypi:mcp",                                    # official MCP Python SDK
    "pypi:fastmcp",                                # FastMCP framework
    # extension: GitHub targets (exercises the gh: path)
    "gh:modelcontextprotocol/servers",             # official servers repo
    "gh:madnh/mcp-server-sqlite",                  # the sqlite server source
    "gh:modelcontextprotocol/python-sdk",          # python SDK repo
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
    v = r.verdict
    top = "; ".join(f"{f.severity.value}:{f.scanner}" for f in v.findings[:3])
    results.append((t, v.level.value, len(v.findings), top))
    print(f"  {v.level.value:<24} {t}  ({len(v.findings)} findings, {time.time()-start:.0f}s)")
    lines.append(f"| {t} | {r.version or '?'} | **{v.level.value}** | {len(v.findings)} | {top} |")

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
