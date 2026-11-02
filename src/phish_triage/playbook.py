"""Recommended response actions, like the steps of a SOAR playbook.

A SOAR platform (Splunk SOAR, Cortex XSOAR, Microsoft Sentinel playbooks...)
would *execute* these steps automatically or after analyst approval. This tool
only recommends them; executing actions such as purging mailboxes needs
access to the mail platform and a human decision.
"""

from __future__ import annotations

from .models import Finding
from .scoring import LIKELY_BENIGN, LIKELY_PHISH, SUSPICIOUS


def recommend_actions(verdict: str, findings: list[Finding]) -> list[str]:
    """Build an ordered action list from the verdict and which rules fired."""
    rules = {f.rule_id for f in findings}

    if verdict == LIKELY_BENIGN:
        return [
            "No strong phishing indicators. Close as likely benign / false positive after a quick manual check.",
            "Thank the reporter and remind them that reporting suspicious mail is always the right call.",
        ]

    actions: list[str] = []
    if verdict == SUSPICIOUS:
        actions.append("Escalate for manual analyst review before taking blocking actions; quarantine the "
                       "message for the recipient while reviewing.")
        actions.append("If deeper analysis is needed, have an analyst detonate URLs/attachments in an isolated "
                       "sandbox (this tool never opens them).")
    else:  # likely-phish: contain it now
        if "reply_to_mismatch" in rules:
            # In BEC the From domain is often a real supplier being spoofed (or a
            # compromised supplier mailbox). Blocking it would cut off a real
            # business partner, so block the attacker's reply address instead.
            actions.append("Block the Reply-To address at the email gateway. Do NOT block the From domain without "
                           "checking: in BEC it is often a real supplier that was spoofed or compromised.")
        else:
            actions.append("Block the sender address and sending domain at the email gateway.")
        actions.append("Search all mailboxes for the same sender/subject/URLs and purge matching messages "
                       "(e.g. Microsoft 365 Content Search + Purge, Google Workspace security investigation tool).")

    if rules & {"href_text_mismatch", "lookalike_domain", "url_ip_host", "url_shortener", "html_credential_form"}:
        actions.append("Block the listed URL domains/IPs at the web proxy, DNS filter and firewall.")
    if rules & {"credential_language", "html_credential_form", "lookalike_domain", "href_text_mismatch"}:
        actions.append("Check proxy/DNS logs for users who visited the URLs. For anyone who clicked or entered "
                       "credentials: reset password, revoke active sessions/tokens, verify MFA methods and look "
                       "for new inbox forwarding rules.")
    if rules & {"double_extension", "risky_attachment_type", "office_macro", "executable_content"}:
        actions.append("Add the attachment SHA-256 hashes to the EDR/antivirus blocklist and hunt for them on "
                       "endpoints. Isolate any host where the attachment was opened.")
    if rules & {"reply_to_mismatch", "payment_change_language"}:
        actions.append("Possible BEC / invoice fraud: alert Finance to hold any payment or bank-detail change, and "
                       "verify the request with the supplier using a phone number from your records, not the email.")
    if "display_name_spoof" in rules or "lookalike_domain" in rules:
        actions.append("Report the impersonation to the impersonated brand's abuse/security team and, if your "
                       "policy requires it, to MyCERT (Cyber999) in Malaysia.")
    actions.append("Record the defanged IOCs in the case/ticket and share them with your threat-intel platform.")
    return actions
