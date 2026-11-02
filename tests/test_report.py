import json

from phish_triage.analyzer import analyze_bytes
from phish_triage.report import to_console, to_html, to_json, to_markdown

from conftest import make_eml

XSS = '<script>alert("x")</script><img src=x onerror=alert(1)>'


def _hostile_result():
    raw = make_eml(
        from_=f'"{XSS}" <evil@paypa1.example>',
        subject=f"Invoice {XSS} `code` | pipe",
        text="Pay at https://paypa1.example/a?<b>",
        attachments=[(f'{XSS}.pdf.exe', b"MZ")],
    )
    return analyze_bytes(raw, name="hostile.eml")


def test_html_report_escapes_attacker_content():
    out = to_html(_hostile_result())
    assert "<script>" not in out
    assert "<img" not in out
    assert "&lt;script&gt;" in out
    assert "default-src 'none'" in out  # CSP present
    assert "href=" not in out  # nothing is clickable


def test_markdown_wraps_attacker_content_in_code_spans():
    out = to_markdown(_hostile_result())
    subject_line = next(line for line in out.splitlines() if line.startswith("- **Subject:**"))
    # The backtick inside the subject forces a longer fence, so it cannot close the span early.
    assert subject_line.startswith("- **Subject:** ``")
    assert "paypa1[.]example" in out
    assert "https://paypa1.example" not in out  # IOCs defanged


def test_json_is_valid_and_has_raw_and_defanged_iocs():
    data = json.loads(to_json(_hostile_result()))
    assert data["tool"] == "phish-triage"
    url = data["iocs"]["urls"][0]
    assert url["value"].startswith("https://paypa1.example")
    assert url["defanged"].startswith("hxxps://paypa1[.]example")
    assert {"rule_id", "title", "weight", "evidence", "detail"} <= set(data["findings"][0])


def test_console_summary_contains_verdict_and_reasons():
    out = to_console(_hostile_result())
    assert "VERDICT  : LIKELY-PHISH" in out
    assert "[+35]" in out
    assert "https://" not in out
