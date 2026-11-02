from phish_triage.defang import defang_domain, defang_email, defang_ip, defang_url, refang


def test_defang_url_scheme_and_host_only():
    assert defang_url("https://evil.example/login.php?a=b.c") == "hxxps://evil[.]example/login.php?a=b.c"
    assert defang_url("http://203.0.113.5:8080/x") == "hxxp://203[.]0[.]113[.]5:8080/x"


def test_defang_domain_ip_email():
    assert defang_domain("a.b.example") == "a[.]b[.]example"
    assert defang_ip("192.0.2.1") == "192[.]0[.]2[.]1"
    assert defang_email("bad@evil.example") == "bad[@]evil[.]example"


def test_refang_round_trip():
    for value in ["https://evil.example/login", "bad@evil.example", "192.0.2.1"]:
        defanged = defang_url(value) if "://" in value else defang_email(value)
        assert refang(defanged) == value


def test_defang_non_url_text_is_still_safe():
    assert defang_url("www.evil.example/path") == "www[.]evil[.]example/path"
