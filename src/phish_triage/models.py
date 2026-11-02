"""Plain data classes shared by every module.

Keeping the data shapes in one file makes the pipeline easy to follow:
``parser`` produces a :class:`ParsedEmail`, detectors produce
:class:`Finding` objects, and ``analyzer`` bundles everything into a
:class:`TriageResult` that the report writers consume.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Address:
    """An email address split into its parts."""

    display_name: str = ""
    address: str = ""

    @property
    def domain(self) -> str:
        """Lower-case domain part of the address ('' if there is none)."""
        if "@" not in self.address:
            return ""
        return self.address.rsplit("@", 1)[1].strip().strip(">").lower()


@dataclass
class ReceivedHop:
    """One ``Received:`` header, i.e. one mail server the message passed through."""

    from_host: str = ""
    by_host: str = ""
    ip: str = ""
    date: str = ""
    raw: str = ""


@dataclass
class AuthResults:
    """SPF / DKIM / DMARC results as recorded by the receiving mail server."""

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    source: str = "missing"  # which header we read: "Authentication-Results", "Received-SPF" or "missing"
    authserv_id: str = ""


@dataclass
class Attachment:
    """An attachment held in memory as bytes. It is never written to disk or executed."""

    filename: str
    content_type: str
    data: bytes = field(repr=False)


@dataclass
class Link:
    """A hyperlink found in the HTML body."""

    href: str
    text: str


@dataclass
class ParsedEmail:
    """Everything the detectors need, extracted from the raw .eml file."""

    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_addr: Address = field(default_factory=Address)
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""
    to: list[Address] = field(default_factory=list)
    received: list[ReceivedHop] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)


@dataclass
class Finding:
    """One triggered detection rule.

    ``rule_id`` is the key used to look up the weight in the config.
    ``evidence`` holds the concrete values that triggered it (already defanged
    where they are IOCs) so the analyst can verify the reasoning.
    """

    rule_id: str
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    weight: int = 0  # filled in by the scoring step


@dataclass
class TriageResult:
    """Final output of an analysis run."""

    file: str
    file_sha256: str
    analyzed_at: str
    headers: dict[str, Any]
    auth: dict[str, str]
    received_hops: list[dict[str, str]]
    iocs: dict[str, list[dict[str, str]]]
    link_mismatches: list[dict[str, str]]
    attachments: list[dict[str, Any]]
    findings: list[Finding]
    score: int
    verdict: str
    recommended_actions: list[str]
    enrichment: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to plain dicts/lists so it can be dumped as JSON."""
        return asdict(self)
