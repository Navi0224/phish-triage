"""Language heuristics: urgency, credential harvesting, payment-change (BEC) wording.

Phishing relies on social engineering: pressure ("within 24 hours"), a
reason to log in ("verify your account"), or for invoice fraud a reason to
pay a different account. Keyword lists live in the config so they can be
extended, e.g. with Bahasa Malaysia phrases.

These are weak signals on their own (real banks also say "urgent"), so they
carry low weights and mostly add to stronger technical findings.
"""

from __future__ import annotations

import re

from ..models import Finding
from .context import Context

_RULES = (
    ("urgency_phrases", "urgency_language", "Urgent / threatening language"),
    ("credential_phrases", "credential_language", "Credential-harvesting language"),
    ("payment_change_phrases", "payment_change_language", "Payment / bank-detail change language (BEC)"),
)


def find_phrases(text: str, phrases: list[str]) -> list[str]:
    """Return the phrases that appear in ``text`` as whole words (case-insensitive).

    Whole-word matching stops short keywords like "tac" matching "contact".
    """
    lowered = text.lower()
    return [p for p in phrases if re.search(r"\b" + re.escape(p.lower()) + r"\b", lowered)]


def detect_language(ctx: Context) -> list[Finding]:
    text = ctx.all_text
    findings = []
    for config_key, rule_id, title in _RULES:
        hits = find_phrases(text, ctx.config.get(config_key, []))
        if hits:
            findings.append(Finding(rule_id, title, f"{len(hits)} phrase(s) matched.", [f'"{h}"' for h in hits]))
    return findings
