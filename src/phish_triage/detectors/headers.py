"""Header-based detectors: authentication results, address mismatches, display-name spoofing."""

from __future__ import annotations

import re

from ..defang import defang_domain, defang_email
from ..domains import is_brand_domain, registrable_domain
from ..iocs import EMAIL_RE
from ..models import Finding
from .context import Context

# Results that mean "the sender is NOT authorised / the signature is broken".
# SPF "softfail" (~all) is treated as a failure: the domain owner said this
# server is probably not allowed to send for them.
_FAIL = {"fail", "softfail", "permerror"}


def detect_auth_failures(ctx: Context) -> list[Finding]:
    """Flag SPF / DKIM / DMARC failures recorded by the receiving server.

    * SPF  - was the sending server's IP allowed to send for the envelope domain?
    * DKIM - is the cryptographic signature on the message valid?
    * DMARC - does SPF or DKIM pass *for the domain shown in From:*? (alignment)
    """
    auth = ctx.email.auth
    if auth.source == "missing":
        return [Finding("auth_results_missing", "No authentication results header",
                        "No Authentication-Results or Received-SPF header was found, so SPF/DKIM/DMARC "
                        "cannot be checked. Common for exported or forwarded samples.")]
    findings = []
    where = auth.source + (f" by {auth.authserv_id}" if auth.authserv_id else "")
    for method, rule in (("spf", "spf_fail"), ("dkim", "dkim_fail"), ("dmarc", "dmarc_fail")):
        result = getattr(auth, method)
        if result in _FAIL:
            findings.append(Finding(rule, f"{method.upper()} {result}",
                                    f"The receiving server recorded {method}={result} ({where}).",
                                    [f"{method}={result}"]))
    return findings


def detect_header_mismatch(ctx: Context) -> list[Finding]:
    """Compare the From domain with Reply-To and Return-Path.

    Reply-To mismatch is classic Business Email Compromise (BEC): the email
    *looks* like it's from your supplier, but when you press Reply your answer
    goes to the attacker. Return-Path mismatch is weaker evidence because
    legitimate mailing services (newsletters, ticketing tools) use their own
    bounce domain, so it gets a low weight.
    """
    findings = []
    from_dom = ctx.email.from_addr.domain
    if not from_dom:
        return findings

    bad_reply = [r.address for r in ctx.email.reply_to
                 if r.domain and registrable_domain(r.domain) != registrable_domain(from_dom)]
    if bad_reply:
        findings.append(Finding("reply_to_mismatch", "Reply-To domain differs from From domain",
                                f"Replies would go to a different domain than {defang_domain(from_dom)}.",
                                [defang_email(a) for a in bad_reply]))

    rp = ctx.email.return_path
    if "@" in rp and registrable_domain(rp.rsplit("@", 1)[1]) != registrable_domain(from_dom):
        findings.append(Finding("return_path_mismatch", "Return-Path domain differs from From domain",
                                "Envelope sender differs from the visible sender. Often legitimate "
                                "(mailing services), but also seen in spoofing.",
                                [defang_email(rp)]))
    return findings


def detect_display_name_spoof(ctx: Context) -> list[Finding]:
    """Detect a display name that impersonates a brand or another address.

    Most mail apps (especially on phones) show only the display name, e.g.
    "Maybank2u Security", and hide the real address. Attackers exploit this.
    Two patterns are checked:

    1. The display name contains a protected brand name but the real domain
       is not one of that brand's domains.
    2. The display name itself contains an email address with a different
       domain, e.g. ``"support@paypal.com" <x@attacker.example>``.
    """
    sender = ctx.email.from_addr
    name = sender.display_name.lower()
    if not name or not sender.domain:
        return []

    evidence = []
    for brand in ctx.brands:
        for keyword in brand.get("display_names", []):
            if re.search(r"\b" + re.escape(keyword.lower()) + r"\b", name) and not is_brand_domain(sender.domain, brand):
                evidence.append(f'"{sender.display_name}" claims {brand.get("name")} but sent from '
                                f'{defang_domain(sender.domain)}')
                break

    for embedded in EMAIL_RE.findall(sender.display_name):
        dom = embedded.rsplit("@", 1)[1].lower()
        if registrable_domain(dom) != registrable_domain(sender.domain):
            evidence.append(f"display name shows {defang_email(embedded)} but real sender is "
                            f"{defang_email(sender.address)}")

    if not evidence:
        return []
    return [Finding("display_name_spoof", "Display name impersonates another sender",
                    "The friendly name shown to the user does not match the real sending domain.", evidence)]
