"""Provenance scanner: registry metadata for npm / PyPI / GitHub targets.

Returns metadata + findings (recency, fork, license, binary-only dist).
"""
from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass, field

from mcp_vet.verdict import Finding, Severity

UA = {"User-Agent": "mcp-vet/0.1 (trust-scan gate)"}


@dataclass
class Provenance:
    kind: str = ""
    name: str = ""
    version: str = ""
    license: str = ""
    updated: str = ""
    source_url: str = ""
    findings: list[Finding] = field(default_factory=list)


def _get_json(url: str, timeout: int = 20) -> dict | None:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - provenance is best-effort
        return None


def _recency_finding(updated_iso: str, name: str) -> Finding | None:
    try:
        updated_ts = time.mktime(time.strptime(updated_iso[:10], "%Y-%m-%d"))
    except (ValueError, TypeError):
        return None
    if time.time() - updated_ts > 365 * 86400:
        return Finding(
            scanner="provenance", severity=Severity.LOW,
            message=f"'{name}' last updated over a year ago — possibly "
            f"unmaintained.", evidence=updated_iso[:10],
        )
    return None


def from_npm(pkg: str) -> Provenance:
    p = Provenance(kind="npm", name=pkg)
    data = _get_json(f"https://registry.npmjs.org/{pkg.replace('@', '%40')}")
    if not data:
        p.findings.append(Finding(scanner="provenance", severity=Severity.MEDIUM,
                                  message="npm metadata unavailable — cannot verify provenance."))
        return p
    latest = data.get("dist-tags", {}).get("latest", "")
    lp = data.get("versions", {}).get(latest, {})
    p.version = latest
    p.license = str(lp.get("license", "unknown"))
    p.source_url = lp.get("repository", {}).get("url", "") or data.get("homepage", "")
    t = lp.get("_npmUser", {}).get("name", "") or (data.get("maintainers") or [{}])[0].get("name", "")
    dist = lp.get("dist", {})
    if dist.get("tarball"):
        p.updated = (lp.get("time") or {}).get(latest, "") or data.get("time", {}).get("latest", "")
    # binary-only detection
    files = lp.get("files") or []
    if any(f.endswith((".node", ".exe", ".so", ".dll")) for f in files):
        p.findings.append(Finding(scanner="provenance", severity=Severity.MEDIUM,
                                  message="Package ships prebuilt binaries (.node/.exe/.so) — "
                                  "verify the source matches (supply-chain risk)."))
    f = _recency_finding(p.updated, pkg)
    if f:
        p.findings.append(f)
    if p.license in ("UNLICENSED", "SEE LICENSE IN LICENSE") or not p.license or p.license == "unknown":
        p.findings.append(Finding(scanner="provenance", severity=Severity.LOW,
                                  message=f"License '{p.license}' — unclear reuse terms."))
    return p


def from_pypi(pkg: str) -> Provenance:
    p = Provenance(kind="pypi", name=pkg)
    data = _get_json(f"https://pypi.org/pypi/{pkg}/json")
    if not data:
        p.findings.append(Finding(scanner="provenance", severity=Severity.MEDIUM,
                                  message="PyPI metadata unavailable — cannot verify provenance."))
        return p
    info = data.get("info", {})
    p.version = info.get("version", "")
    p.license = info.get("license") or "unknown"
    p.source_url = info.get("project_urls", {}).get("Source", "") or info.get("home_page", "")
    rel = data.get("releases", {}).get(p.version, [])
    if rel:
        p.updated = rel[0].get("upload_time_iso_8601", "") or rel[0].get("upload_time", "")
    # wheel vs sdist: flag if only wheels
    if rel and all(u.get("packagetype") == "bdist_wheel" for u in rel):
        p.findings.append(Finding(scanner="provenance", severity=Severity.LOW,
                                  message="Only wheel distributions published — source sdist "
                                  "missing (harder to audit)."))
    f = _recency_finding(p.updated, pkg)
    if f:
        p.findings.append(f)
    return p


def from_github(repo: str) -> Provenance:
    p = Provenance(kind="github", name=repo)
    data = _get_json(f"https://api.github.com/repos/{repo}")
    if not data:
        p.findings.append(Finding(scanner="provenance", severity=Severity.MEDIUM,
                                  message="GitHub metadata unavailable — cannot verify provenance."))
        return p
    p.updated = data.get("pushed_at", "")
    p.license = (data.get("license") or {}).get("spdx_id", "unknown")
    p.source_url = data.get("html_url", "")
    if data.get("fork"):
        p.findings.append(Finding(scanner="provenance", severity=Severity.LOW,
                                  message="This is a FORK — verify it tracks upstream and "
                                  "check what changed."))
    if data.get("archived"):
        p.findings.append(Finding(scanner="provenance", severity=Severity.MEDIUM,
                                  message="Repository is ARCHIVED — no longer maintained."))
    f = _recency_finding(p.updated, repo)
    if f:
        p.findings.append(f)
    return p
