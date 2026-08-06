"""Scan engine: target resolution, source acquisition, orchestration."""
from __future__ import annotations

import io
import os
import re
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from mcp_vet.cache import VerdictCache
from mcp_vet.scan import auth, deps, exec as exec_scan, provenance, secrets, ssrf
from mcp_vet.verdict import Finding, Verdict

TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".toml", ".txt", ".cfg", ".ini", ".sh", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", ".pytest_cache", ".mypy_cache", "site-packages"}
UA = {"User-Agent": "mcp-vet/0.1 (trust-scan gate)"}
NETWORK_CALL = re.compile(r"\b(requests\.|urlopen|fetch\(|axios\.|child_process\.exec|got\()")
LOCALHOST_ONLY = re.compile(r"localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _scan_text(text: str, path: str) -> list[Finding]:
    out: list[Finding] = []
    out += ssrf.scan(text, path)
    out += exec_scan.scan(text, path)
    out += secrets.scan(text, path)
    return out


def scan_local_dir(directory: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    source_files: list[tuple[str, str]] = []
    makes_network = False
    count = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            p = Path(root) / fn
            if p.suffix.lower() not in TEXT_EXT or fn.endswith(".map"):
                continue
            rel = str(p.relative_to(directory))
            text = _read(p)
            count += 1
            source_files.append((rel, text))
            # network calls to LOCALHOST only (DevTools, local daemons) are
            # local-by-nature and must not trigger the auth medium
            for line in text.splitlines():
                if NETWORK_CALL.search(line) and not LOCALHOST_ONLY.search(line):
                    makes_network = True
                    break
            findings += _scan_text(text, rel)
    findings += auth.scan("\n".join(t for _, t in source_files), makes_network_calls=makes_network)
    findings += deps.scan_dir(source_files)
    return findings, count


def extract_tarball(url: str, dest: Path) -> bool:
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
        if url.endswith(".zip") or url.endswith(".whl"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(dest)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
                t.extractall(dest, filter="data")
        return True
    except Exception:  # noqa: BLE001
        return False


def download_source(kind: str, name: str, dest: Path) -> str | None:
    """Download+extract source; return version string if known."""
    if kind == "npm":
        p = provenance.from_npm(name)
        latest = p.version or "latest"
        dist = _npm_tarball_url(name, latest)
        if dist and extract_tarball(dist, dest):
            return latest
    elif kind == "pypi":
        p = provenance.from_pypi(name)
        url = _pypi_sdist_url(name, p.version)
        if url and extract_tarball(url, dest):
            return p.version
    elif kind == "github":
        for branch in ("main", "master"):
            if extract_tarball(f"https://codeload.github.com/{name}/tar.gz/refs/heads/{branch}", dest):
                return branch
    return None


def _npm_tarball_url(pkg: str, version: str) -> str | None:
    import json
    try:
        req = urllib.request.Request(
            f"https://registry.npmjs.org/{pkg.replace('@', '%40')}/{version}", headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return (data.get("dist") or {}).get("tarball")
    except Exception:  # noqa: BLE001
        return None


def _pypi_sdist_url(pkg: str, version: str) -> str | None:
    import json
    try:
        req = urllib.request.Request(f"https://pypi.org/pypi/{pkg}/{version}/json", headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        for u in data.get("urls", []):
            if u.get("packagetype") == "sdist":
                return u["url"]
        return (data.get("urls") or [{}])[0].get("url")
    except Exception:  # noqa: BLE001
        return None


def resolve_target(target: str) -> tuple[str, str]:
    """Return (kind, name). Explicit prefixes win; bare names -> npm."""
    if target.startswith(("npm:", "pypi:", "gh:")):
        kind, _, name = target.partition(":")
        return {"gh": "github"}.get(kind, kind), name
    if target.startswith(("./", "/", "~")) or Path(target).is_dir():
        return "local", target
    if "/" in target and not target.startswith("@"):
        return "github", target
    return "npm", target


def vet(target: str, use_cache: bool = True, ttl_s: int = 24 * 3600) -> dict:
    kind, name = resolve_target(target)
    cache = VerdictCache(ttl_s=ttl_s) if use_cache else None

    if kind == "local":
        findings, nfiles = scan_local_dir(Path(name))
        prov = provenance.Provenance(kind="local", name=str(Path(name).resolve()))
        version = "local"
    else:
        # provenance first (also gives us version + download URL)
        if kind == "npm":
            prov = provenance.from_npm(name)
        elif kind == "pypi":
            prov = provenance.from_pypi(name)
        else:
            prov = provenance.from_github(name)
        version = prov.version or "unknown"
        if cache:
            hit = cache.get(target, version)
            if hit:
                hit["_cached"] = True
                return hit
        with tempfile.TemporaryDirectory(prefix="mcpvet-") as td:
            dl_version = download_source(kind, name, Path(td))
            if dl_version:
                version = dl_version
            findings, nfiles = scan_local_dir(Path(td))

    findings += prov.findings
    verdict = Verdict.from_findings(findings)
    result = {
        "target": target,
        "kind": kind,
        "name": name,
        "version": version,
        "source_url": prov.source_url,
        "license": prov.license,
        "files_scanned": nfiles,
        "verdict": verdict.to_dict(),
    }
    if cache:
        cache.put(target, version, result)
    return result
