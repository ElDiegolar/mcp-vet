"""Scan engine: target resolution, source acquisition, orchestration, policy.

The framework core: `vet()` returns a VetResult; the CLI and the MCP server
are thin serializations of the same call.
"""
from __future__ import annotations

import io
import os
import re
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from mcp_vet.cache import VerdictCache
from mcp_vet.policy import DEFAULT, Policy
from mcp_vet.scan import auth, deps, exec as exec_scan, provenance, secrets, ssrf
from mcp_vet.verdict import Finding, Severity, Verdict

TEXT_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".toml", ".txt", ".cfg", ".ini", ".sh", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", ".pytest_cache", ".mypy_cache", "site-packages"}
UA = {"User-Agent": "mcp-vet/0.2 (trust-scan framework)"}
NETWORK_CALL = re.compile(r"\b(requests\.|urlopen|fetch\(|axios\.|child_process\.exec|got\()")
LOCALHOST_ONLY = re.compile(r"localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0")

# --- policy helpers ---------------------------------------------------------
FAKE_SECRET = re.compile(r"(?i)(test|example|fake|sample|demo|xxxx|placeholder|changeme|sk-test|your[-_ ]?key)")
LITERAL_HOST = re.compile(r"https?://[^{}$\s/\"'`]+")
EXAMPLE_OR_TEST = re.compile(r"(?:^|/)(examples?|tests?|fixtures?|samples?|docs?_?src?)(?:/|$)")


def _apply_policy(findings: list[Finding], policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        sev = f.severity
        if policy.examples_are_informational and EXAMPLE_OR_TEST.search(f.file or ""):
            sev = Severity.LOW
        elif policy.fake_secrets_ignored and f.scanner == "secrets" \
                and sev == Severity.HIGH and FAKE_SECRET.search(f.evidence or ""):
            sev = Severity.LOW
        elif policy.trusted_host_auth_ok and f.scanner == "secrets" \
                and sev == Severity.HIGH and "exfiltration" in f.message \
                and LITERAL_HOST.search(f.evidence or ""):
            sev = Severity.LOW
        elif policy.host_interp_is_review and f.scanner == "ssrf" \
                and sev == Severity.HIGH and "interpolates into the HOST" in f.message:
            sev = Severity.MEDIUM
        if sev is f.severity:
            out.append(f)
        else:
            out.append(Finding(scanner=f.scanner, severity=sev, message=f.message,
                               file=f.file, line=f.line, evidence=f.evidence))
    return out


# --- source acquisition -----------------------------------------------------
def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _extract_tar(url: str, dest: Path) -> None:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
        data = r.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(dest, filter="data")


def _extract_zip(url: str, dest: Path) -> None:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)


def _download(kind: str, name: str, dest: Path) -> None:
    if kind == "npm":
        meta = provenance.npm_meta(name)
        _extract_tar(meta["tarball"], dest)
    elif kind == "pypi":
        info = provenance.pypi_meta(name)
        url = info.get("sdist_url") or info.get("wheel_url")
        if url and url.endswith(".whl"):
            _extract_zip(url, dest)
        elif url:
            _extract_tar(url, dest)
    elif kind == "github":
        _extract_tar(f"https://codeload.github.com/{name}/tar.gz/refs/heads/main", dest)


def scan_text(text: str, path: str = "") -> list[Finding]:
    return ssrf.scan(text, path) + exec_scan.scan(text, path) + secrets.scan(text, path)


def scan_local_dir(directory: Path | str, policy: Policy = DEFAULT) -> tuple[list[Finding], int]:
    directory = Path(directory)
    findings: list[Finding] = []
    source_files: list[tuple[str, str]] = []
    count = 0
    makes_network = False
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
            for line in text.splitlines():
                if NETWORK_CALL.search(line) and not LOCALHOST_ONLY.search(line):
                    makes_network = True
                    break
            findings += scan_text(text, rel)
    findings += auth.scan("\n".join(t for _, t in source_files), makes_network_calls=makes_network)
    findings += deps.scan_dir(source_files)
    return _apply_policy(findings, policy), count


@dataclass
class VetResult:
    target: str
    kind: str
    version: str | None
    verdict: Verdict
    provenance: dict
    files_scanned: int
    duration_s: float

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "kind": self.kind,
            "version": self.version,
            "verdict": self.verdict.to_dict(),
            "provenance": self.provenance,
            "files_scanned": self.files_scanned,
            "duration_s": round(self.duration_s, 2),
        }


def vet(target: str, use_cache: bool = True, policy: Policy = DEFAULT,
        cache: VerdictCache | None = None) -> VetResult:
    """The framework's single entry point: vet any target, get a VetResult."""
    t0 = time.time()
    kind, name = resolve_target(target)
    cache = cache or VerdictCache()
    if kind == "local":
        # local targets always re-scan (the code is right there; cache is moot)
        findings, count = scan_local_dir(name, policy=policy)
        return VetResult(target=target, kind=kind, version=None,
                         verdict=Verdict.from_findings(findings),
                         provenance={"source": "local directory"},
                         files_scanned=count, duration_s=time.time() - t0)
    meta = provenance.meta(kind, name)
    version = meta.get("version", "")
    if use_cache:
        cached = cache.get(f"{kind}:{name}", version)
        if cached and "verdict" in cached:
            return VetResult(target=target, kind=kind, version=version,
                             verdict=Verdict.from_dict(cached["verdict"]),
                             provenance=cached.get("provenance", meta),
                             files_scanned=cached.get("files_scanned", 0),
                             duration_s=time.time() - t0)
    with tempfile.TemporaryDirectory() as td:
        try:
            _download(kind, name, Path(td))
        except Exception as e:  # noqa: BLE001
            return VetResult(target=target, kind=kind, version=version,
                             verdict=Verdict.from_findings([Finding(
                                 scanner="provenance", severity=Severity.MEDIUM,
                                 message=f"failed to download source: {e}",
                                 file="", line=0, evidence="")]),
                             provenance=meta, files_scanned=0,
                             duration_s=time.time() - t0)
        findings, count = scan_local_dir(Path(td), policy=policy)
    v = Verdict.from_findings(findings)
    if use_cache:
        cache.put(f"{kind}:{name}", version,
                  {"verdict": v.to_dict(), "provenance": meta,
                   "files_scanned": count})
    return VetResult(target=target, kind=kind, version=version, verdict=v,
                     provenance=meta, files_scanned=count,
                     duration_s=time.time() - t0)


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
