"""URL and domain detectors: lookalike domains, link text mismatch, IP hosts, shorteners, forms."""

from __future__ import annotations

from ..defang import defang_domain, defang_url
from ..domains import check_lookalike, to_unicode
from ..iocs import is_ip, url_host
from ..models import Finding
from .context import Context


def detect_lookalike_domains(ctx: Context) -> list[Finding]:
    """Check sender, reply-to, return-path and every URL domain against protected brands."""
    email = ctx.email
    candidates = [email.from_addr.domain] + [r.domain for r in email.reply_to]
    if "@" in email.return_path:
        candidates.append(email.return_path.rsplit("@", 1)[1])
    candidates += ctx.iocs.domains

    evidence = []
    for domain in dict.fromkeys(d for d in candidates if d):
        match = check_lookalike(
            domain,
            ctx.brands,
            max_distance=int(ctx.config.get("lookalike_max_distance", 2)),
            min_brand_length=int(ctx.config.get("lookalike_min_brand_length", 5)),
        )
        if match:
            shown = defang_domain(domain)
            uni = to_unicode(domain)
            if uni != domain:  # show the decoded IDN so the analyst sees the trick
                shown += f" (decodes to {ascii(defang_domain(uni))})"
            evidence.append(f"{shown} imitates {match.brand} ({defang_domain(match.brand_domain)}): {match.technique}")

    if not evidence:
        return []
    return [Finding("lookalike_domain", "Lookalike of a protected brand domain",
                    "A domain in the email imitates a brand on the protected list.", evidence)]


def detect_link_issues(ctx: Context) -> list[Finding]:
    """Flag deceptive or evasive links in the body."""
    findings = []
    if ctx.link_mismatches:
        findings.append(Finding(
            "href_text_mismatch", "Link text shows a different domain than the real link",
            "The user sees one address but clicking goes somewhere else.",
            [f"shows {defang_domain(m['shown_domain'])} -> goes to {defang_url(m['href'])}" for m in ctx.link_mismatches],
        ))

    ip_urls = [u for u in ctx.iocs.urls if is_ip(url_host(u))]
    if ip_urls:
        findings.append(Finding("url_ip_host", "URL uses a raw IP address instead of a domain",
                                "Legitimate organisations almost always link to named domains.",
                                [defang_url(u) for u in ip_urls]))

    shorteners = set(ctx.config.get("url_shorteners", []))
    short = [u for u in ctx.iocs.urls if url_host(u).removeprefix("www.") in shorteners]
    if short:
        findings.append(Finding("url_shortener", "URL shortener hides the real destination",
                                "Shorteners are used to hide phishing domains from the user and from filters.",
                                [defang_url(u) for u in short]))

    # A <form> or password box inside an email is a strong credential-phishing sign:
    # legitimate services never ask you to type a password into the email itself.
    if ctx.html.has_password_input or ctx.html.form_actions:
        evidence = [defang_url(a) if "://" in a else (a or "(no action)") for a in ctx.html.form_actions]
        if ctx.html.has_password_input:
            evidence.append("password input field present")
        findings.append(Finding("html_credential_form", "HTML form embedded in email",
                                "The email contains a form that can submit data directly.", evidence))
    return findings
