"""SSRF / network-exfiltration scanner: outbound HTTP with non-literal hosts."""
from __future__ import annotations

import re

from mcp_vet.verdict import Finding, Severity

# call sites that take a URL as first arg
HTTP_CALLS = re.compile(
    r"\b(?:requests\.(?:get|post|put|delete|patch)|urllib\.request\.urlopen|"
    r"urlopen|fetch|axios\.(?:get|post|put|delete)|got|node-fetch)\(([^)]*)\)",
    re.S,
)
VAR_HTTP = re.compile(r"https?://\s*[\"\']?\s*(\{|f\"|\$\{)", re.S)
TEMPLATE_URL = re.compile(r"https?://[^\"'\s]*\{", re.S)
# variable-looking first arg (not a literal URL string)
IS_LITERAL_URL = re.compile(r"^[\"']https?://")
WHITESPACE = re.compile(r"\s+")
LOCALHOST = re.compile(r"://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)")
URL_SPLIT = re.compile(r"^(https?://)([^/\"'\s]*)(/.*)?$", re.S)


def _is_localhost_url(url: str) -> bool:
    """SSRF is about REMOTE hosts; localhost templates (DevTools, local daemons)
    are a normal pattern and must not be flagged."""
    return bool(LOCALHOST.search(url))


def _host_is_variable(url: str) -> bool:
    """True when the interpolation sits in the HOST/authority (the SSRF class),
    not the path. Path interpolation on a literal host is normal for API
    clients (e.g. https://api.github.com/repos/{owner}/{repo})."""
    m = URL_SPLIT.match(url)
    if not m:
        return False
    authority = m.group(2)
    return "{" in authority or "$" in authority


def _path_is_variable(url: str) -> bool:
    m = URL_SPLIT.match(url)
    if not m or not m.group(3):
        return False
    return "{" in m.group(3) or "$" in m.group(3)


def _first_arg(inner: str) -> str:
    inner = WHITESPACE.sub("", inner)
    if not inner:
        return ""
    depth = 0
    for i, ch in enumerate(inner):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return inner[:i]
    return inner


def _literal_url_names(text: str) -> set[str]:
    """Names assigned a literal https?:// string in the same file (dataflow-lite:
    resolves the common `url = "https://..."` false-positive class)."""
    return set(re.findall(r"^\s*(\w+)\s*=\s*[\"']https?://", text, flags=re.M))


def scan(text: str, path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    literals = _literal_url_names(text)
    for m in HTTP_CALLS.finditer(text):
        arg = _first_arg(m.group(1))
        if not arg or IS_LITERAL_URL.match(arg) or arg in literals:
            continue
        if _is_localhost_url(arg):
            continue
        line = text[: m.start()].count("\n") + 1
        if re.search(r"https?://[^{}$\s/\"'`]+", arg):
            # literal host present: path-level dynamics only — normal for API
            # clients talking to a FIXED trusted host; informational
            findings.append(
                Finding(
                    scanner="ssrf",
                    severity=Severity.LOW,
                    message="URL has a fixed host with dynamic path/query — "
                    "normal for API clients; confirm the host is trusted.",
                    file=path,
                    line=line,
                    evidence=arg[:120],
                )
            )
        else:
            findings.append(
                Finding(
                    scanner="ssrf",
                    severity=Severity.MEDIUM,
                    message="Outbound HTTP call whose URL is not a literal — "
                    "user/tool-controlled hosts can exfiltrate or probe internal "
                    "networks (SSRF).",
                    file=path,
                    line=line,
                    evidence=arg[:120],
                )
            )
    for m in TEMPLATE_URL.finditer(text):
        if _is_localhost_url(m.group(0)):
            continue
        line = text[: m.start()].count("\n") + 1
        url = m.group(0)
        if _host_is_variable(url):
            findings.append(
                Finding(
                    scanner="ssrf",
                    severity=Severity.HIGH,
                    message="URL template interpolates into the HOST — classic "
                    "SSRF pattern; verify the interpolated host is NOT "
                    "user-controlled.",
                    file=path,
                    line=line,
                    evidence=url[:120],
                )
            )
        elif _path_is_variable(url):
            findings.append(
                Finding(
                    scanner="ssrf",
                    severity=Severity.LOW,
                    message="URL template interpolates into the PATH of a fixed "
                    "host — normal API-client pattern; confirm the host is trusted.",
                    file=path,
                    line=line,
                    evidence=url[:120],
                )
            )
    # de-dup adjacent literal findings on same line
    seen = {(f.line, f.evidence) for f in findings}
    return [f for f in findings if (f.line, f.evidence) in seen]
