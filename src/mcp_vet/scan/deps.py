"""Dependency-posture scanner (v1 minimal): counts + pinning + recency."""
from __future__ import annotations

import re

from mcp_vet.verdict import Finding, Severity

REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|<|>)?\s*([0-9][A-Za-z0-9.\-]*)?")
PINNED = re.compile(r"^[A-Za-z0-9_.\-]+\s*==\s*[0-9]")
UNPINNED_JS = re.compile(r"[\"'][^\"']+[\"']\s*:\s*[\"'](\^|~|>=|latest|\*)")


def scan_dir(source_files: list[str]) -> list[Finding]:
    """source_files: list of (path, text). Minimal posture: pinning + count."""
    findings: list[Finding] = []
    unpinned = 0
    total = 0
    for path, text in source_files:
        base = path.rsplit("/", 1)[-1]
        if base == "requirements.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                total += 1
                if not PINNED.match(line):
                    unpinned += 1
        elif base == "package.json":
            m = re.search(r"\"dependencies\"\s*:\s*\{.*?\}", text, flags=re.S)
            if m:
                deps = re.findall(r"\"[^\"']+\"\s*:\s*\"[^\"]+\"", m.group(0))
                total += len(deps)
                unpinned += len(UNPINNED_JS.findall(m.group(0)))
        elif base == "pyproject.toml":
            m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, flags=re.S)
            if m:
                deps = re.findall(r"[\"'][^\"']+[\"']", m.group(1))
                total += len(deps)
                unpinned += sum(1 for d in deps if "==" not in d and "~=" not in d)
    if total and unpinned / total > 0.5:
        findings.append(Finding(
            scanner="deps", severity=Severity.LOW,
            message=f"{unpinned}/{total} dependencies unpinned — floating versions "
            f"drift and can pull in changed (or malicious) code.",
            evidence=f"unpinned={unpinned} total={total}",
        ))
    return findings
