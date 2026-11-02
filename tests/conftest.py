"""Shared test helpers: build small synthetic emails in memory."""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from pathlib import Path

import pytest

from phish_triage.config import load_config
from phish_triage.detectors import Context
from phish_triage.iocs import extract_iocs, find_link_mismatches, parse_html
from phish_triage.parser import parse_bytes

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def make_eml(
    from_: str = "Alice <alice@example.com>",
    to: str = "bob@example.org",
    subject: str = "Hello",
    text: str = "Hi Bob, see you tomorrow.",
    html: str | None = None,
    headers: dict[str, str] | list[tuple[str, str]] | None = None,
    attachments: list[tuple[str, bytes]] | None = None,
) -> bytes:
    """Return raw .eml bytes for a simple message."""
    msg = EmailMessage()
    items = headers.items() if isinstance(headers, dict) else (headers or [])
    for name, value in items:
        msg[name] = value
    msg["From"] = from_
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    if html is not None:
        msg.add_alternative(html, subtype="html")
    for filename, data in attachments or []:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=filename)
    return msg.as_bytes(policy=policy.SMTP)


def make_context(raw: bytes, config: dict | None = None) -> Context:
    """Parse raw bytes and build the detector Context the same way the analyzer does."""
    config = config or load_config()
    email = parse_bytes(raw)
    html = parse_html(email.html_body)
    return Context(email=email, html=html, iocs=extract_iocs(email, html), config=config,
                   link_mismatches=find_link_mismatches(html.links))


@pytest.fixture
def config() -> dict:
    return load_config()


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}
