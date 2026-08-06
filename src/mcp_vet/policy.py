"""Scan policy: the calibration knobs that keep verdicts honest.

Defaults are the calibrated settings (learned from vetting the real
ecosystem). --strict turns every downgrade off so findings are raw.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Policy:
    # examples/ and tests/ are illustrative, not the shipped runtime surface:
    # their findings are downgraded to informational (LOW) unless strict.
    examples_are_informational: bool = True
    # fake/placeholder credential literals (test-, example, xxxx, sk-test...)
    # are not exfiltration evidence.
    fake_secrets_ignored: bool = True
    # credentials sent to a FIXED trusted host (Authorization: Bearer key) is
    # normal client behavior; exfil is only when the host is uncontrolled.
    trusted_host_auth_ok: bool = True
    # URL templates interpolating into the HOST are a strong signal but static
    # analysis cannot prove the host is user-controlled: REVIEW by default,
    # HIGH (block) only in strict mode.
    host_interp_is_review: bool = True
    # strict: no downgrades at all — raw scanner output.
    strict: bool = False

    def __post_init__(self) -> None:
        if self.strict:
            object.__setattr__(self, "examples_are_informational", False)
            object.__setattr__(self, "fake_secrets_ignored", False)
            object.__setattr__(self, "trusted_host_auth_ok", False)
            object.__setattr__(self, "host_interp_is_review", False)


DEFAULT = Policy()
