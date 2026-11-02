"""One test group per detector, using tiny in-memory emails."""

from phish_triage.detectors.content import detect_language, find_phrases
from phish_triage.detectors.headers import (detect_auth_failures, detect_display_name_spoof,
                                            detect_header_mismatch)
from phish_triage.detectors.links import detect_link_issues, detect_lookalike_domains

from conftest import make_context, make_eml, rule_ids

AUTH_FAIL = "mx.example.org; spf=softfail smtp.mailfrom=x.example; dkim=fail; dmarc=fail"
AUTH_PASS = "mx.example.org; spf=pass; dkim=pass; dmarc=pass"


# --- authentication -------------------------------------------------------------

def test_auth_failures_flagged():
    ctx = make_context(make_eml(headers={"Authentication-Results": AUTH_FAIL}))
    assert rule_ids(detect_auth_failures(ctx)) == {"spf_fail", "dkim_fail", "dmarc_fail"}


def test_auth_pass_is_clean():
    ctx = make_context(make_eml(headers={"Authentication-Results": AUTH_PASS}))
    assert detect_auth_failures(ctx) == []


def test_missing_auth_results_is_reported():
    ctx = make_context(make_eml())
    assert rule_ids(detect_auth_failures(ctx)) == {"auth_results_missing"}


# --- From / Reply-To / Return-Path ---------------------------------------------------

def test_reply_to_mismatch():
    ctx = make_context(make_eml(from_="ceo@example.com", headers={"Reply-To": "ceo.office@example.net"}))
    findings = detect_header_mismatch(ctx)
    assert rule_ids(findings) == {"reply_to_mismatch"}
    assert findings[0].evidence == ["ceo.office[@]example[.]net"]


def test_reply_to_same_organisation_is_fine():
    ctx = make_context(make_eml(from_="a@example.com", headers={"Reply-To": "support@help.example.com"}))
    assert detect_header_mismatch(ctx) == []


def test_return_path_mismatch():
    ctx = make_context(make_eml(from_="a@example.com", headers={"Return-Path": "<b@bounce.example.net>"}))
    assert rule_ids(detect_header_mismatch(ctx)) == {"return_path_mismatch"}


# --- display name ---------------------------------------------------------------------

def test_display_name_brand_spoof():
    ctx = make_context(make_eml(from_='"PayPal Service" <service@pay-notice.example>'))
    findings = detect_display_name_spoof(ctx)
    assert rule_ids(findings) == {"display_name_spoof"}
    assert "PayPal" in findings[0].evidence[0]


def test_display_name_with_embedded_address():
    ctx = make_context(make_eml(from_='"support@example.com" <x@attacker.example>'))
    assert rule_ids(detect_display_name_spoof(ctx)) == {"display_name_spoof"}


def test_real_brand_sender_not_spoof():
    ctx = make_context(make_eml(from_='"PayPal" <service@mail.paypal.com>'))
    assert detect_display_name_spoof(ctx) == []


def test_brand_keyword_must_be_whole_word():
    # "cimbalom" contains "cimb" but is not the brand.
    ctx = make_context(make_eml(from_='"Cimbalom Music Club" <club@music.example>'))
    assert detect_display_name_spoof(ctx) == []


# --- lookalike domains --------------------------------------------------------------

def test_lookalike_in_sender_and_url():
    ctx = make_context(make_eml(from_="alert@paypa1.example", text="Login: https://cimbclicks-verify.example/x"))
    findings = detect_lookalike_domains(ctx)
    assert rule_ids(findings) == {"lookalike_domain"}
    assert len(findings[0].evidence) == 2


def test_no_lookalike_for_clean_mail():
    ctx = make_context(make_eml(text="see https://www.example.com/"))
    assert detect_lookalike_domains(ctx) == []


# --- links -------------------------------------------------------------------------

def test_link_issues():
    html = ('<a href="http://evil.example/a">www.paypal.com</a>'
            '<a href="http://192.0.2.50/login">here</a>'
            '<a href="https://bit.ly/abc123">short</a>'
            '<form action="https://collect.example/post"><input type="password"></form>')
    ctx = make_context(make_eml(html=html))
    assert rule_ids(detect_link_issues(ctx)) == {
        "href_text_mismatch", "url_ip_host", "url_shortener", "html_credential_form"}


def test_clean_links():
    ctx = make_context(make_eml(html='<a href="https://www.example.com/">www.example.com</a>'))
    assert detect_link_issues(ctx) == []


# --- language ------------------------------------------------------------------------

def test_language_rules(config):
    text = ("URGENT: your account will be suspended. Please verify your account. "
            "Also note our change of bank details, pay by wire transfer.")
    ctx = make_context(make_eml(text=text))
    assert rule_ids(detect_language(ctx)) == {"urgency_language", "credential_language", "payment_change_language"}


def test_language_uses_whole_words():
    # "tac" is in the credential list, but must not match inside "contact".
    assert find_phrases("please contact us", ["tac"]) == []
    assert find_phrases("enter the TAC sent to you", ["tac"]) == ["tac"]


def test_language_clean():
    ctx = make_context(make_eml(subject="Lunch", text="Shall we have lunch at noon?"))
    assert detect_language(ctx) == []
