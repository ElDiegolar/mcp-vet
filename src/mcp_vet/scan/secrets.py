"""Secret-handling scanner: hardcoded credentials + credential-file reads."""
from __future__ import annotations

import re

from mcp_vet.verdict import Finding, Severity

HARDCODED = [
    (re.compile(r"(?i)\b(api[_-]?key|apikey|secret|token|password|passwd)\s*[=:]\s*[\"'][A-Za-z0-9_\-]{8,}"), "hardcoded credential-looking literal", Severity.HIGH),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key literal", Severity.HIGH),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "embedded private key", Severity.HIGH),
]
CRED_FILE_READS = [
    (re.compile(r"(?i)\.aws\b"), "reads ~/.aws", Severity.MEDIUM),
    (re.compile(r"(?i)\.ssh|id_rsa|id_ed25519"), "reads SSH keys", Severity.MEDIUM),
    (re.compile(r"(?i)\.env\b"), "reads .env", Severity.MEDIUM),
    (re.compile(r"(?i)credentials(?:\.json|\.ini|\.txt)"), "reads credentials file", Severity.MEDIUM),
]
SEND_WITH_CREDS = re.compile(
    r"(?is)(?:requests\.(?:get|post|put|delete)|urlopen|fetch)\([^)]*(?:api_key|token|secret|password|access_token)",
)


def scan(text: str, path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for pat, label, sev in HARDCODED:
        for m in pat.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(scanner="secrets", severity=sev,
                        message=f"{label} in source — credentials belong in a "
                        f"secret store, not the repo.",
                        file=path, line=line, evidence=m.group(0)[:80])
            )
    for pat, label, sev in CRED_FILE_READS:
        for m in pat.finditer(text):
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(scanner="secrets", severity=sev,
                        message=f"{label} — exposed to whoever runs this server.",
                        file=path, line=line, evidence=m.group(0)[:80])
            )
    for m in SEND_WITH_CREDS.finditer(text):
        line = text[: m.start()].count("\n") + 1
        findings.append(
            Finding(scanner="secrets", severity=Severity.HIGH,
                    message="Network call appears to transmit credentials — "
                    "credential exfiltration pattern.",
                    file=path, line=line, evidence=m.group(0)[:100])
        )
    return findings
