"""Detection rules.

Every detector is a small function with the same shape::

    def detect_something(ctx: Context) -> list[Finding]

It looks at one aspect of the email and returns zero or more findings. The
detectors do *not* decide the score; they only report what they saw. Scoring
(weights and thresholds) is done separately in :mod:`phish_triage.scoring`,
which keeps "what is suspicious" apart from "how suspicious is it".

To add a rule: write a function here, add it to ``ALL_DETECTORS``, and give
its ``rule_id`` a weight in the config.
"""

from __future__ import annotations

from collections.abc import Callable

from ..models import Finding
from .attachments import detect_attachments
from .content import detect_language
from .context import Context
from .headers import detect_auth_failures, detect_display_name_spoof, detect_header_mismatch
from .links import detect_link_issues, detect_lookalike_domains

Detector = Callable[[Context], list[Finding]]

ALL_DETECTORS: list[Detector] = [
    detect_auth_failures,
    detect_header_mismatch,
    detect_display_name_spoof,
    detect_lookalike_domains,
    detect_link_issues,
    detect_attachments,
    detect_language,
]

__all__ = ["ALL_DETECTORS", "Context", "Detector", "run_all"]


def run_all(ctx: Context) -> list[Finding]:
    """Run every detector and return all findings in a stable order."""
    findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(ctx))
    return findings
