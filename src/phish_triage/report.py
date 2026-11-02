"""Output writers: console text, JSON, Markdown and HTML.

SECURITY: every string that came from the email (subject, names, file names,
URLs) is attacker-controlled. If we pasted it into HTML unescaped, an email
with a subject like ``<script>...</script>`` would run JavaScript in the
analyst's browser when they open the report (stored XSS). So:

* HTML: every value goes through ``html.escape``, nothing is turned into a
  clickable link, and a Content-Security-Policy blocks scripts and remote
  loads as a second layer of defence.
* Markdown: attacker values are wrapped in inline code spans, where Markdown
  and HTML are not interpreted.
* IOCs are always shown defanged in human-readable reports.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any

from .defang import defang_email, defang_ip
from .models import TriageResult

TOOL_NAME = "phish-triage"
IOC_LABELS = {"urls": "URLs", "domains": "Domains", "ips": "IP addresses", "emails": "Email addresses"}


# --------------------------------------------------------------------------- helpers


def _one_line(value: Any, limit: int = 300) -> str:
    """Collapse whitespace/newlines (a header can't fake extra report lines) and truncate."""
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _email_or_blank(addr: str) -> str:
    return defang_email(addr) if addr else "(none)"


# --------------------------------------------------------------------------- JSON


def to_json(result: TriageResult) -> str:
    """Machine-readable output for a SIEM/SOAR. ``ensure_ascii`` keeps homoglyphs visible as \\u escapes."""
    data = result.to_dict()
    data = {"tool": TOOL_NAME, **data}
    return json.dumps(data, indent=2, ensure_ascii=True)


# --------------------------------------------------------------------------- console


def to_console(result: TriageResult) -> str:
    """Short human summary for the terminal."""
    h = result.headers
    lines = [
        "=" * 70,
        f"File     : {result.file}",
        f"Subject  : {_one_line(h['subject'], 100)}",
        f"From     : {_one_line(h['from_display_name'], 60)} <{_email_or_blank(h['from_address'])}>",
        f"Reply-To : {', '.join(defang_email(r) for r in h['reply_to']) or '(none)'}",
        f"Auth     : SPF={result.auth['spf']}  DKIM={result.auth['dkim']}  DMARC={result.auth['dmarc']}",
        f"VERDICT  : {result.verdict.upper()}  (score {result.score}/100)",
        "-" * 70,
        "Reasons:",
    ]
    if not result.findings:
        lines.append("  (no rules triggered)")
    for f in result.findings:
        lines.append(f"  [+{f.weight:>2}] {f.title}")
        for ev in f.evidence[:5]:
            lines.append(f"         - {_one_line(ev, 110)}")
        if len(f.evidence) > 5:
            lines.append(f"         ... and {len(f.evidence) - 5} more (see JSON/report)")
    iocs = result.iocs
    lines.append("-" * 70)
    lines.append(f"IOCs: {len(iocs['urls'])} URLs, {len(iocs['domains'])} domains, "
                 f"{len(iocs['ips'])} IPs, {len(iocs['emails'])} emails, {len(result.attachments)} attachments")
    for u in iocs["urls"][:5]:
        lines.append(f"  url  {_one_line(u['defanged'], 100)}")
    for a in result.attachments:
        lines.append(f"  file {_one_line(a['filename'], 60)}  sha256={a['sha256']}")
    lines.append("-" * 70)
    lines.append("Recommended actions:")
    for i, action in enumerate(result.recommended_actions, 1):
        lines.append(f"  {i}. {action}")
    for note in result.enrichment.get("notes", []):
        lines.append(f"  note: {note}")
    lines.append("=" * 70)
    return "\n".join(lines)


# --------------------------------------------------------------------------- Markdown


def _code(value: Any) -> str:
    """Wrap a value in a Markdown code span that it cannot break out of."""
    text = _one_line(value)
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def to_markdown(result: TriageResult) -> str:
    """Analyst report in Markdown (renders nicely in GitHub, Jira, Confluence...)."""
    h = result.headers
    md = [
        f"# Phishing triage report: {result.verdict.upper()} ({result.score}/100)",
        "",
        f"- **File:** {_code(result.file)} (sha256 {_code(result.file_sha256)})",
        f"- **Analysed at (UTC):** {_code(result.analyzed_at)}",
        f"- **Subject:** {_code(h['subject'])}",
        f"- **From:** {_code(h['from_display_name'])} {_code(_email_or_blank(h['from_address']))}",
        f"- **Reply-To:** {', '.join(_code(defang_email(r)) for r in h['reply_to']) or '(none)'}",
        f"- **Return-Path:** {_code(_email_or_blank(h['return_path']))}",
        f"- **Authentication:** SPF {_code(result.auth['spf'])}, DKIM {_code(result.auth['dkim'])}, "
        f"DMARC {_code(result.auth['dmarc'])} (source: {_code(result.auth['source'])})",
        "",
        "## Why this verdict",
        "",
    ]
    if not result.findings:
        md.append("No detection rules triggered.")
    for f in result.findings:
        md.append(f"- **+{f.weight} {f.title}** ({_code(f.rule_id)}) {f.detail}")
        md.extend(f"  - {_code(ev)}" for ev in f.evidence)
    md += ["", "## Recommended actions", ""]
    md += [f"{i}. {a}" for i, a in enumerate(result.recommended_actions, 1)]
    md += ["", "## Indicators of compromise (defanged)", ""]
    for kind, label in IOC_LABELS.items():
        values = result.iocs[kind]
        md.append(f"**{label}:** " + ("none" if not values else ""))
        md.extend(f"- {_code(v['defanged'])}" for v in values)
        md.append("")
    md += ["## Attachments", ""]
    if not result.attachments:
        md.append("None.")
    for a in result.attachments:
        md.append(f"- {_code(a['filename'])} ({_code(a['content_type'])}, {a['size']} bytes) "
                  f"flags: {', '.join(a['flags']) or 'none'}")
        md.append(f"  - MD5 {_code(a['md5'])}")
        md.append(f"  - SHA1 {_code(a['sha1'])}")
        md.append(f"  - SHA256 {_code(a['sha256'])}")
    md += ["", "## Received chain (oldest hop first)", ""]
    if not result.received_hops:
        md.append("No Received headers.")
    for i, hop in enumerate(result.received_hops, 1):
        md.append(f"{i}. from {_code(hop['from_host'] or '?')} by {_code(hop['by_host'] or '?')} "
                  f"ip {_code(defang_ip(hop['ip']) or '?')} at {_code(hop['date'] or '?')}")
    if result.enrichment:
        md += ["", "## Enrichment", "", "```json", json.dumps(result.enrichment, indent=2, ensure_ascii=True)
               .replace("```", "'''"), "```"]
    md += ["", f"_Generated by {TOOL_NAME}. URLs and attachments were not opened or executed._", ""]
    return "\n".join(md)


# --------------------------------------------------------------------------- HTML

_CSS = """
body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1b1b1b}
h1{font-size:1.4rem} .likely-phish{color:#b00020} .suspicious{color:#a15c00} .likely-benign{color:#1b7a2b}
code{background:#f3f3f3;padding:0 .25rem;word-break:break-all} td,th{border:1px solid #ccc;padding:.3rem;text-align:left;vertical-align:top}
table{border-collapse:collapse;width:100%} li{margin:.2rem 0}
"""


def _e(value: Any) -> str:
    """HTML-escape (including quotes) - used on EVERY dynamic value."""
    return html.escape(_one_line(value, 2000), quote=True)


def to_html(result: TriageResult) -> str:
    """Self-contained HTML report. No scripts, no external resources, no clickable IOC links."""
    h = result.headers
    rows = [
        ("File", f"<code>{_e(result.file)}</code>"),
        ("File SHA-256", f"<code>{_e(result.file_sha256)}</code>"),
        ("Analysed at (UTC)", _e(result.analyzed_at)),
        ("Subject", _e(h["subject"])),
        ("From", f"{_e(h['from_display_name'])} <code>{_e(_email_or_blank(h['from_address']))}</code>"),
        ("Reply-To", ", ".join(f"<code>{_e(defang_email(r))}</code>" for r in h["reply_to"]) or "(none)"),
        ("Return-Path", f"<code>{_e(_email_or_blank(h['return_path']))}</code>"),
        ("SPF / DKIM / DMARC", f"{_e(result.auth['spf'])} / {_e(result.auth['dkim'])} / {_e(result.auth['dmarc'])}"),
    ]
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        # Defence in depth: even if something slipped through escaping, the browser
        # is told not to run scripts or fetch anything external.
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>{TOOL_NAME} report</title><style>{_CSS}</style></head><body>",
        f'<h1>Verdict: <span class="{_e(result.verdict)}">{_e(result.verdict.upper())}</span> '
        f"(score {result.score}/100)</h1>",
        "<table>",
        *[f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows],
        "</table>",
        "<h2>Why this verdict</h2><ul>",
    ]
    if not result.findings:
        parts.append("<li>No detection rules triggered.</li>")
    for f in result.findings:
        evidence = "".join(f"<li><code>{_e(ev)}</code></li>" for ev in f.evidence)
        parts.append(f"<li><b>+{f.weight} {_e(f.title)}</b> (<code>{_e(f.rule_id)}</code>) {_e(f.detail)}"
                     f"<ul>{evidence}</ul></li>")
    parts.append("</ul><h2>Recommended actions</h2><ol>")
    parts += [f"<li>{_e(a)}</li>" for a in result.recommended_actions]
    parts.append("</ol><h2>Indicators of compromise (defanged)</h2>")
    for kind, label in IOC_LABELS.items():
        values = result.iocs[kind]
        items = "".join(f"<li><code>{_e(v['defanged'])}</code></li>" for v in values) or "<li>none</li>"
        parts.append(f"<h3>{label}</h3><ul>{items}</ul>")
    parts.append("<h2>Attachments</h2>")
    if result.attachments:
        parts.append("<table><tr><th>Name</th><th>Type</th><th>Size</th><th>Hashes</th><th>Flags</th></tr>")
        for a in result.attachments:
            hashes = "<br>".join(f"{alg.upper()} <code>{_e(a[alg])}</code>" for alg in ("md5", "sha1", "sha256"))
            parts.append(f"<tr><td><code>{_e(a['filename'])}</code></td><td>{_e(a['content_type'])}</td>"
                         f"<td>{a['size']}</td><td>{hashes}</td><td>{_e(', '.join(a['flags']) or 'none')}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p>None.</p>")
    parts.append("<h2>Received chain (oldest hop first)</h2><ol>")
    parts += [f"<li>from <code>{_e(hop['from_host'] or '?')}</code> by <code>{_e(hop['by_host'] or '?')}</code> "
              f"ip <code>{_e(defang_ip(hop['ip']) or '?')}</code> at {_e(hop['date'] or '?')}</li>" for hop in result.received_hops]
    parts.append("</ol>")
    if result.enrichment:
        parts.append(f"<h2>Enrichment</h2><pre>{html.escape(json.dumps(result.enrichment, indent=2))}</pre>")
    parts.append(f"<p><i>Generated by {TOOL_NAME}. URLs and attachments were not opened or executed.</i></p>")
    parts.append("</body></html>")
    return "\n".join(parts)
