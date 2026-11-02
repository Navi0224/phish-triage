from phish_triage.parser import parse_auth_results, parse_bytes, parse_received

from conftest import make_eml


def test_basic_headers_are_parsed():
    raw = make_eml(
        from_='"Example Support" <Support@Example.com>',
        headers={"Reply-To": "help@example.net", "Return-Path": "<bounce@example.com>",
                 "Message-ID": "<abc@example.com>", "Date": "Mon, 12 Oct 2026 09:00:00 +0800"},
        subject="Test subject",
    )
    email = parse_bytes(raw)
    assert email.subject == "Test subject"
    assert email.from_addr.display_name == "Example Support"
    assert email.from_addr.address == "support@example.com"
    assert email.from_addr.domain == "example.com"
    assert [r.address for r in email.reply_to] == ["help@example.net"]
    assert email.return_path == "bounce@example.com"
    assert email.message_id == "<abc@example.com>"


def test_rfc2047_encoded_display_name_is_decoded():
    raw = b"From: =?utf-8?b?TWF5YmFuazJ1IFNlY3VyaXR5?= <a@b.example>\nSubject: x\n\nbody\n"
    assert parse_bytes(raw).from_addr.display_name == "Maybank2u Security"


def test_received_chain_is_oldest_first():
    headers = [
        "from mx2.example.com (mx2.example.com [192.0.2.2]) by mx.example.org; Mon, 12 Oct 2026 10:00:02 +0000",
        "from client.example (unknown [203.0.113.9]) by mx2.example.com; Mon, 12 Oct 2026 10:00:01 +0000",
    ]
    hops = parse_received(headers)
    assert [h.ip for h in hops] == ["203.0.113.9", "192.0.2.2"]
    assert hops[0].from_host == "client.example"
    assert hops[1].by_host == "mx.example.org"
    assert hops[1].date == "Mon, 12 Oct 2026 10:00:02 +0000"


def test_auth_results_parsed():
    auth = parse_auth_results(["mx.example.org; spf=pass smtp.mailfrom=a.example; dkim=fail; dmarc=fail"], [])
    assert (auth.spf, auth.dkim, auth.dmarc) == ("pass", "fail", "fail")
    assert auth.source == "Authentication-Results"
    assert auth.authserv_id == "mx.example.org"


def test_only_topmost_auth_results_header_is_trusted():
    # The bottom header could have been forged by the sender.
    headers = ["mx.example.org; spf=fail; dmarc=fail", "fake.example; spf=pass; dkim=pass; dmarc=pass"]
    auth = parse_auth_results(headers, [])
    assert auth.spf == "fail" and auth.dmarc == "fail"


def test_trusted_authserv_id_skips_untrusted_headers():
    headers = ["attacker.example; spf=pass; dmarc=pass", "mx.example.org; spf=fail; dmarc=fail"]
    auth = parse_auth_results(headers, [], trusted_authserv_ids=["mx.example.org"])
    assert auth.authserv_id == "mx.example.org" and auth.spf == "fail"


def test_received_spf_fallback_and_missing():
    assert parse_auth_results([], ["softfail (example) client-ip=192.0.2.1"]).spf == "softfail"
    missing = parse_auth_results([], [])
    assert missing.source == "missing" and missing.spf == "none"


def test_bodies_and_attachments_extracted():
    raw = make_eml(text="plain body", html="<p>html body</p>", attachments=[("a.txt", b"hello")])
    email = parse_bytes(raw)
    assert "plain body" in email.text_body
    assert "html body" in email.html_body
    assert email.attachments[0].filename == "a.txt"
    assert email.attachments[0].data == b"hello"


def test_garbage_input_does_not_crash():
    email = parse_bytes(b"\x00\xff not an email at all \n\n\xfe")
    assert email.from_addr.address == ""
