from phish_triage.iocs import extract_iocs, find_link_mismatches, parse_html, url_host
from phish_triage.models import Link
from phish_triage.parser import parse_bytes

from conftest import make_eml


def test_extracts_urls_ips_emails_domains():
    raw = make_eml(
        text="Go to https://bad.example/login. Or http://198.51.100.7/x, mail help@bad.example.",
        html='<a href="https://other.example/a">Click here</a> <a href="mailto:drop@collect.example">mail</a>',
    )
    email = parse_bytes(raw)
    html = parse_html(email.html_body)
    iocs = extract_iocs(email, html)
    assert "https://bad.example/login" in iocs.urls  # trailing "." stripped
    assert "http://198.51.100.7/x" in iocs.urls
    assert "https://other.example/a" in iocs.urls
    assert "198.51.100.7" in iocs.ips
    assert {"help@bad.example", "drop@collect.example", "alice@example.com"} <= set(iocs.emails)
    assert {"bad.example", "other.example", "collect.example"} <= set(iocs.domains)


def test_invalid_ip_not_reported():
    email = parse_bytes(make_eml(text="version 999.1.1.1 is out"))
    assert extract_iocs(email, parse_html("")).ips == []


def test_visible_decoy_url_in_html_is_not_an_ioc():
    html = parse_html('<a href="http://evil.example/x">https://www.paypal.com/signin</a>')
    email = parse_bytes(make_eml(text="hi"))
    iocs = extract_iocs(email, html)
    assert iocs.urls == ["http://evil.example/x"]
    assert "www.paypal.com" not in iocs.domains


def test_href_text_mismatch_detected():
    links = [Link("http://evil.example/login", "https://www.maybank2u.com.my/login")]
    result = find_link_mismatches(links)
    assert result[0]["shown_domain"] == "www.maybank2u.com.my"
    assert result[0]["href_domain"] == "evil.example"


def test_matching_or_generic_link_text_is_not_a_mismatch():
    links = [
        Link("https://www.example.com/", "example.com"),  # www vs bare: same site
        Link("https://news.example.com/a", "www.example.com"),  # subdomain of shown domain
        Link("https://evil.example/", "Click here"),  # no domain claimed in text
    ]
    assert find_link_mismatches(links) == []


def test_html_parser_finds_forms_and_ignores_script_text():
    info = parse_html('<script>var u="http://x.example";</script><form action="https://collect.example/p">'
                      '<input type="password" name="pw"></form><p>Hello</p>')
    assert info.form_actions == ["https://collect.example/p"]
    assert info.has_password_input
    assert "x.example" not in info.text and "Hello" in info.text


def test_url_host():
    assert url_host("https://User@Evil.Example:8443/a") == "evil.example"
    assert url_host("www.example.com/path") == "www.example.com"
