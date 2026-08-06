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
    (re.compile(r"(?i)\.aws\b"), "reads ~/.aws", Severity.LOW),
    (re.compile(r"(?i)\.ssh|id_rsa|id_ed25519"), "reads SSH keys", Severity.LOW),
    (re.compile(r"(?i)\.env\b"), "reads .env", Severity.LOW),
    (re.compile(r"(?i)credentials(?:\.json|\.ini|\.txt)"), "reads credentials file", Severity.LOW),
]
SEND_WITH_CREDS = re.compile(
    r"(?is)(?:requests\.(?:get|post|put|delete)|urlopen|fetch)\([^)]*(?:api_key|token|secret|password|access_token|\.env|credentials|creds)",
)


def _literal_url_names(text: str) -> set[str]:
    """Names assigned a literal https?:// string in this file (dataflow-lite:
    resolves `API_URL = "https://..."` -> send-to-fixed-host)."""
    return set(re.findall(r"^\s*(\w+)\s*=\s*[\"']https?://", text, flags=re.M))


def scan(text: str, path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    literals = _literal_url_names(text)
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
                        message=f"{label} — legitimate for local config, but "
                        f"HIGH risk if it is ever transmitted (caught separately).",
                        file=path, line=line, evidence=m.group(0)[:80])
            )
    for m in SEND_WITH_CREDS.finditer(text):
        line = text[: m.start()].count("\n") + 1
        call = m.group(0)
        # destination resolution (dataflow-lite): if the first arg names a
        # file-level literal-URL constant, OR the file defines any literal
        # host URL, the destination is NAMED in the file — normal client auth
        # (informational), not exfiltration (HIGH). HIGH is reserved for creds
        # sent to a host the file never names.
        argm = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", call[call.find("(") + 1:])
        named_destination = (argm and argm.group(1) in literals) or bool(
            re.search(r"https?://[^{}$\s/\"'`]+", text))
        if named_destination:
            findings.append(
                Finding(scanner="secrets", severity=Severity.LOW,
                        message="Credentials sent to a host defined in this "
                        "file — normal client auth; verify the host is trusted.",
                        file=path, line=line, evidence=call[:100])
            )
            continue
        findings.append(
            Finding(scanner="secrets", severity=Severity.HIGH,
                    message="Network call appears to transmit credentials to "
                    "a host not defined anywhere in this file — credential "
                    "exfiltration pattern.",
                    file=path, line=line, evidence=call[:100])
        )
    # de-dup: same line + same evidence (e.g. a line mentioning .env twice)
    seen = {(f.line, f.evidence) for f in findings}
    return [f for f in findings if (f.line, f.evidence) in seen]
