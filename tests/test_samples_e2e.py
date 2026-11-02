"""End-to-end: run the full pipeline on every shipped sample."""

import pytest

from phish_triage.analyzer import analyze_file

from conftest import SAMPLES_DIR

EXPECTED = {
    "01_credential_harvest_bank_lookalike.eml": (
        "likely-phish", {"lookalike_domain", "display_name_spoof", "href_text_mismatch", "url_ip_host",
                         "credential_language"}),
    "02_malicious_attachment_double_extension.eml": (
        "likely-phish", {"double_extension", "executable_content", "office_macro", "dmarc_fail"}),
    "03_bec_reply_to_mismatch_invoice.eml": (
        "likely-phish", {"reply_to_mismatch", "payment_change_language", "dmarc_fail"}),
    "04_benign_newsletter.eml": ("likely-benign", set()),
    "05_benign_it_maintenance_notice.eml": ("likely-benign", set()),
}


def test_every_sample_has_an_expectation():
    assert {p.name for p in SAMPLES_DIR.glob("*.eml")} == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample_verdict(name):
    verdict, must_fire = EXPECTED[name]
    result = analyze_file(SAMPLES_DIR / name)
    fired = {f.rule_id for f in result.findings}
    assert result.verdict == verdict, (result.score, fired)
    assert must_fire <= fired
    if verdict == "likely-benign":
        assert result.score < 30


def test_bec_playbook_does_not_block_spoofed_supplier_domain():
    result = analyze_file(SAMPLES_DIR / "03_bec_reply_to_mismatch_invoice.eml")
    assert any("Reply-To address" in a for a in result.recommended_actions)
    assert any("Finance" in a for a in result.recommended_actions)


def test_attachment_hashes_reported():
    result = analyze_file(SAMPLES_DIR / "02_malicious_attachment_double_extension.eml")
    names = {a["filename"]: a for a in result.attachments}
    assert "INV-2026-0193.pdf.exe" in names
    assert len(names["Payment_Details.docm"]["sha256"]) == 64
