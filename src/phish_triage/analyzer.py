"""The triage pipeline: parse -> extract -> detect -> (enrich) -> score -> recommend.

This is the one place that knows the order of the steps, so it reads like the
SOAR playbook it imitates.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import scoring
from .config import load_config
from .defang import defang_domain, defang_email, defang_ip, defang_url
from .detectors import Context, run_all
from .detectors.attachments import inspect_attachment
from .enrichment import enrich
from .iocs import IOCs, extract_iocs, find_link_mismatches, parse_html
from .models import ParsedEmail, TriageResult
from .parser import parse_bytes
from .playbook import recommend_actions


def analyze_file(path: Path | str, config: dict[str, Any] | None = None, do_enrich: bool = False) -> TriageResult:
    """Analyse one .eml file from disk."""
    path = Path(path)
    return analyze_bytes(path.read_bytes(), name=str(path), config=config, do_enrich=do_enrich)


def analyze_bytes(raw: bytes, name: str = "<bytes>", config: dict[str, Any] | None = None,
                  do_enrich: bool = False) -> TriageResult:
    """Run the full triage on raw message bytes."""
    config = config if config is not None else load_config()

    # 1. Parse
    email = parse_bytes(raw, config.get("trusted_authserv_ids") or None)
    # 2. Extract IOCs and link information
    html = parse_html(email.html_body)
    iocs = extract_iocs(email, html)
    ctx = Context(email=email, html=html, iocs=iocs, config=config,
                  link_mismatches=find_link_mismatches(html.links))
    # 3. Detect
    findings = run_all(ctx)
    attachments = [inspect_attachment(a, config) for a in email.attachments]
    # 4. Optional enrichment (network) - never runs unless explicitly requested
    enrichment: dict[str, Any] = {}
    if do_enrich:
        enrichment, extra = enrich(iocs.urls, [a["sha256"] for a in attachments])
        findings.extend(extra)
    # 5. Score and decide
    scoring.apply_weights(findings, config)
    findings.sort(key=lambda f: f.weight, reverse=True)
    total = scoring.score(findings, config)
    verdict = scoring.verdict(total, config)

    return TriageResult(
        file=name,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        analyzed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        headers=_header_summary(email),
        auth={k: v for k, v in asdict(email.auth).items()},
        received_hops=[{k: v for k, v in asdict(h).items() if k != "raw"} for h in email.received],
        iocs=_ioc_table(iocs),
        link_mismatches=[{**m, "href": defang_url(m["href"])} for m in ctx.link_mismatches],
        attachments=attachments,
        findings=findings,
        score=total,
        verdict=verdict,
        recommended_actions=recommend_actions(verdict, findings),
        enrichment=enrichment,
    )


def _header_summary(email: ParsedEmail) -> dict[str, Any]:
    return {
        "subject": email.subject,
        "date": email.date,
        "message_id": email.message_id,
        "from_display_name": email.from_addr.display_name,
        "from_address": email.from_addr.address,
        "reply_to": [r.address for r in email.reply_to],
        "return_path": email.return_path,
        "to": [t.address for t in email.to],
    }


def _ioc_table(iocs: IOCs) -> dict[str, list[dict[str, str]]]:
    """Each IOC with its raw value (for machine use, e.g. a SIEM) and defanged value (for humans)."""
    return {
        "urls": [{"value": u, "defanged": defang_url(u)} for u in iocs.urls],
        "domains": [{"value": d, "defanged": defang_domain(d)} for d in iocs.domains],
        "ips": [{"value": i, "defanged": defang_ip(i)} for i in iocs.ips],
        "emails": [{"value": e, "defanged": defang_email(e)} for e in iocs.emails],
    }
