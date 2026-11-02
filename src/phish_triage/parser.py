"""Parse a raw .eml file into a :class:`ParsedEmail`.

Uses only the Python standard library ``email`` package. Everything in an
email is attacker-controlled, so this module is written defensively: malformed
headers or broken charsets must never crash the triage, they just produce
empty/partial values.
"""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from .models import Address, Attachment, AuthResults, ParsedEmail, ReceivedHop

# Matches "spf=pass", "dkim=fail", "dmarc=none" etc. inside Authentication-Results.
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", re.IGNORECASE)
# Received: from <host> ... by <host> ... ; <date>
_RECV_FROM_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_RECV_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
# IPv4 inside square brackets or parentheses, e.g. "[192.0.2.10]".
_RECV_IP_RE = re.compile(r"[\[(]((?:\d{1,3}\.){3}\d{1,3})[\])]")


def parse_file(path: Path | str, trusted_authserv_ids: list[str] | None = None) -> ParsedEmail:
    """Read an .eml file from disk and parse it."""
    return parse_bytes(Path(path).read_bytes(), trusted_authserv_ids)


def parse_bytes(raw: bytes, trusted_authserv_ids: list[str] | None = None) -> ParsedEmail:
    """Parse raw RFC 5322 message bytes.

    ``trusted_authserv_ids`` optionally restricts which Authentication-Results
    header is believed (see :func:`parse_auth_results`).
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    parsed = ParsedEmail(
        subject=_header(msg, "Subject"),
        date=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        from_addr=_first_address(_header(msg, "From")),
        reply_to=_addresses(_header(msg, "Reply-To")),
        return_path=parseaddr(_header(msg, "Return-Path"))[1].lower(),
        to=_addresses(_header(msg, "To")),
        received=parse_received(_all_headers(msg, "Received")),
        auth=parse_auth_results(
            _all_headers(msg, "Authentication-Results"),
            _all_headers(msg, "Received-SPF"),
            trusted_authserv_ids,
        ),
    )
    _walk_parts(msg, parsed)
    return parsed


# --------------------------------------------------------------------------- headers


def _header(msg: Message, name: str) -> str:
    """Return a header as a string, or '' if missing or undecodable."""
    try:
        value = msg.get(name)
    except Exception:  # malformed header: treat as missing rather than crash
        return ""
    return str(value).strip() if value is not None else ""


def _all_headers(msg: Message, name: str) -> list[str]:
    """Return every occurrence of a header, in the order they appear (top first)."""
    try:
        return [str(v) for v in msg.get_all(name, [])]
    except Exception:
        return []


def _addresses(value: str) -> list[Address]:
    """Split a header like ``"A" <a@x>, b@y`` into Address objects."""
    if not value:
        return []
    return [Address(name.strip(), addr.strip().lower()) for name, addr in getaddresses([value]) if addr]


def _first_address(value: str) -> Address:
    found = _addresses(value)
    return found[0] if found else Address()


def parse_received(headers: list[str]) -> list[ReceivedHop]:
    """Parse Received headers into hops, ordered oldest (sender side) first.

    Each server *prepends* its Received header, so the top header is the most
    recent hop (your own mail server) and the bottom one is closest to the
    sender. Only the hops added by servers you control are trustworthy; an
    attacker can forge any Received headers below those.
    """
    hops = []
    for raw in reversed(headers):
        flat = " ".join(raw.split())  # unfold multi-line headers
        main, _, date = flat.rpartition(";")
        if not main:  # no ';' present
            main, date = flat, ""
        from_m = _RECV_FROM_RE.search(main)
        by_m = _RECV_BY_RE.search(main)
        ip_m = _RECV_IP_RE.search(main)
        hops.append(
            ReceivedHop(
                from_host=from_m.group(1) if from_m else "",
                by_host=by_m.group(1) if by_m else "",
                ip=ip_m.group(1) if ip_m else "",
                date=date.strip(),
                raw=flat,
            )
        )
    return hops


def parse_auth_results(
    auth_headers: list[str],
    received_spf: list[str],
    trusted_authserv_ids: list[str] | None = None,
) -> AuthResults:
    """Extract SPF/DKIM/DMARC verdicts.

    Security note: an attacker can put a fake ``Authentication-Results: ...
    spf=pass`` header in the message they send. Your own receiving server adds
    its header at the *top*, so by default we only trust the first one. If
    ``trusted_authserv_ids`` is configured (e.g. ``["mx.yourcompany.com"]``) we
    only accept a header whose authserv-id matches.
    """
    for header in auth_headers:
        authserv_id = header.split(";", 1)[0].strip().lower()
        if trusted_authserv_ids and authserv_id not in [t.lower() for t in trusted_authserv_ids]:
            continue
        results = AuthResults(source="Authentication-Results", authserv_id=authserv_id)
        seen: set[str] = set()
        for method, verdict in _AUTH_RE.findall(header):
            method = method.lower()
            if method not in seen:  # keep the first result for each method
                setattr(results, method, verdict.lower())
                seen.add(method)
        return results

    # Fallback: older servers only add "Received-SPF: pass (...)".
    if received_spf:
        first_word = received_spf[0].strip().split(" ", 1)[0].lower()
        return AuthResults(spf=first_word or "none", source="Received-SPF")
    return AuthResults()


# --------------------------------------------------------------------------- body


def _walk_parts(msg: EmailMessage, parsed: ParsedEmail) -> None:
    """Collect text/HTML bodies and attachments from every MIME part."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        if filename or disposition == "attachment":
            # Keep attachment bytes in memory only. We hash and inspect them,
            # we never save them to disk with their real name or run them.
            data = part.get_payload(decode=True) or b""
            parsed.attachments.append(Attachment(filename or "(unnamed)", ctype, data))
        elif ctype == "text/plain":
            text_parts.append(_decode_text(part))
        elif ctype == "text/html":
            html_parts.append(_decode_text(part))
    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)


def _decode_text(part: Message) -> str:
    """Decode a text part, tolerating wrong or unknown charsets."""
    try:
        return part.get_content()  # type: ignore[attr-defined]
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
