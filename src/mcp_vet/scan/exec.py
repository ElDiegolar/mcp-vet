"""Command-execution scanner: shell=True, os.system, eval of variables."""
from __future__ import annotations

import re

from mcp_vet.verdict import Finding, Severity

PATTERNS = [
    (re.compile(r"\bos\.system\(\s*([^)]+)\)"), "os.system(...) with argument", Severity.MEDIUM),
    (re.compile(r"\bsubprocess\.[a-z]+\([^)]*shell\s*=\s*True"), "subprocess with shell=True", Severity.MEDIUM),
    (re.compile(r"\bchild_process\.(?:exec|execSync|spawn|spawnSync)\(\s*([^,)]+)"), "child_process exec/spawn with argument", Severity.MEDIUM),
    (re.compile(r"\bexecSync?\(\s*([^)]+)"), "exec() of a string argument", Severity.HIGH),
    (re.compile(r"\beval\(\s*([^)]+)"), "eval() of a string argument", Severity.HIGH),
    (re.compile(r"\bnew Function\(\s*([^)]*)"), "new Function(...) dynamic code", Severity.HIGH),
    (re.compile(r"\bexec\(\s*([^)]+)"), "exec() of a string argument", Severity.HIGH),
]

IS_LITERAL = re.compile(r"^[\"']")


def scan(text: str, path: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for pat, label, sev in PATTERNS:
        for m in pat.finditer(text):
            arg = m.group(1) if m.groups() else ""
            arg = re.sub(r"\s+", "", arg)[:80]
            literal = bool(arg) and bool(IS_LITERAL.match(arg))
            line = text[: m.start()].count("\n") + 1
            findings.append(
                Finding(
                    scanner="exec",
                    severity=Severity.LOW if literal else sev,
                    message=f"{label} — dynamic code execution risk.",
                    file=path,
                    line=line,
                    evidence=arg or label,
                )
            )
    return findings
