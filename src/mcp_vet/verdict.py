"""Verdict model: evidence-backed, never a black box."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Level(str, Enum):
    SAFE = "SAFE_TO_INSTALL"
    REVIEW = "REVIEW_BEFORE_INSTALL"
    BLOCK = "DO_NOT_INSTALL"


@dataclass
class Finding:
    scanner: str
    severity: Severity
    message: str
    file: str = ""
    line: int = 0
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
        }


@dataclass
class Verdict:
    level: Level
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "Verdict":
        highs = [f for f in findings if f.severity == Severity.HIGH]
        mediums = [f for f in findings if f.severity == Severity.MEDIUM]
        if highs:
            level = Level.BLOCK
        elif mediums:
            level = Level.REVIEW
        else:
            # LOW-only (informational) findings do not block a SAFE verdict
            level = Level.SAFE
        summary = f"{len(findings)} finding(s); {len(highs)} high, {len(mediums)} medium."
        return cls(level=level, findings=findings, summary=summary)

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
