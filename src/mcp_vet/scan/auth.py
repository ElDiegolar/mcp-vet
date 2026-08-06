"""Auth-posture scanner: OAuth/PKCE vs key-in-config vs none.

No auth is a legitimate design choice for local-only tools; it becomes a
problem when the server also makes network calls (see engine's context flag).
"""
from __future__ import annotations

import re

from mcp_vet.verdict import Finding, Severity

OAUTH = re.compile(r"(?i)\b(oauth|pkce|client_id|client_secret|authorization_code|token_url|redirect_uri)\b")
API_KEY = re.compile(r"(?i)\b(api[_-]?key|x-api-key|authorization|bearer)\b")


def scan(text: str, path: str = "", makes_network_calls: bool = False) -> list[Finding]:
    has_oauth = bool(OAUTH.search(text))
    has_key = bool(API_KEY.search(text))
    if has_oauth:
        return []
    if has_key:
        # key-based auth exists; note posture, no finding
        return []
    findings = []
    sev = Severity.MEDIUM if makes_network_calls else Severity.LOW
    findings.append(
        Finding(
            scanner="auth",
            severity=sev,
            message="No authentication mechanism detected. " +
            ("This server makes network calls — unauthenticated network access "
             "is a risk." if makes_network_calls else
             "Fine for a local-only tool; revisit if it ever makes network calls."),
            file=path,
        )
    )
    return findings
