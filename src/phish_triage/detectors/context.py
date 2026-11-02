"""The bundle of inputs every detector receives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..iocs import IOCs, HtmlInfo
from ..models import ParsedEmail


@dataclass
class Context:
    """Parsed email plus derived data, so detectors don't re-parse anything."""

    email: ParsedEmail
    html: HtmlInfo
    iocs: IOCs
    config: dict[str, Any]
    link_mismatches: list[dict[str, str]] = field(default_factory=list)

    @property
    def brands(self) -> list[dict[str, Any]]:
        return self.config.get("protected_brands", [])

    @property
    def all_text(self) -> str:
        """Subject + plain text + visible HTML text, for keyword checks."""
        return "\n".join([self.email.subject, self.email.text_body, self.html.text])
