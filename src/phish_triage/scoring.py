"""Transparent weighted scoring.

score = sum of the weights of every rule that fired (each rule counts once),
capped at ``max_score``. The verdict comes from two thresholds:

    score >= thresholds.likely_phish  -> "likely-phish"
    score >= thresholds.suspicious    -> "suspicious"
    otherwise                         -> "likely-benign"

Why "each rule counts once"? An email with 30 bad links is not 30 times more
phishy than one with 1 bad link. Counting once stops a single noisy rule from
dominating, and keeps the score explainable.

Why rules and not machine learning? An analyst must be able to justify a
verdict ("blocked because DMARC failed and the link pointed to a lookalike
domain"). Every point in the score maps to a listed reason.
"""

from __future__ import annotations

from typing import Any

from .models import Finding

LIKELY_PHISH = "likely-phish"
SUSPICIOUS = "suspicious"
LIKELY_BENIGN = "likely-benign"


def apply_weights(findings: list[Finding], config: dict[str, Any]) -> list[Finding]:
    """Set each finding's weight from the config (unknown rules get 0 = informational)."""
    weights = config.get("weights", {})
    for f in findings:
        f.weight = int(weights.get(f.rule_id, 0))
    return findings


def score(findings: list[Finding], config: dict[str, Any]) -> int:
    """Sum the weights of distinct rule IDs, capped at max_score."""
    per_rule: dict[str, int] = {}
    for f in findings:
        per_rule[f.rule_id] = max(per_rule.get(f.rule_id, 0), f.weight)
    return min(sum(per_rule.values()), int(config.get("max_score", 100)))


def verdict(total: int, config: dict[str, Any]) -> str:
    thresholds = config.get("thresholds", {})
    if total >= int(thresholds.get("likely_phish", 60)):
        return LIKELY_PHISH
    if total >= int(thresholds.get("suspicious", 30)):
        return SUSPICIOUS
    return LIKELY_BENIGN
