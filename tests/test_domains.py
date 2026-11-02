import pytest

from phish_triage.domains import (check_lookalike, levenshtein, registrable_domain, skeleton, to_unicode)


@pytest.fixture
def brands(config):
    return config["protected_brands"]


def test_registrable_domain_handles_multi_part_suffix():
    assert registrable_domain("login.secure.maybank2u.com.my") == "maybank2u.com.my"
    assert registrable_domain("mail.example.com") == "example.com"
    assert registrable_domain("example.co.uk") == "example.co.uk"


def test_levenshtein():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypa") == 1
    assert levenshtein("kitten", "sitting") == 3


def test_skeleton_maps_confusables():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("mаybank2u") == "maybank2u"  # Cyrillic a


def test_punycode_is_decoded():
    assert to_unicode("xn--mybank2u-16g.example") == "mаybank2u.example"


@pytest.mark.parametrize("domain, technique", [
    ("xn--mybank2u-16g.example", "IDN homoglyph"),
    ("paypa1.example", "character substitution"),
    ("rnicrosoft.example", "character substitution"),
    ("maybenk2u.com.my", "typo-squat"),
    ("cimbclicks-secure.example", "embedded"),
    ("maybank2u.com.my.verify-login.example", "subdomain"),
    ("paypal.example", "different top-level domain"),
])
def test_lookalikes_detected(brands, domain, technique):
    match = check_lookalike(domain, brands)
    assert match is not None, domain
    assert technique in match.technique


@pytest.mark.parametrize("domain", [
    "maybank2u.com.my", "www.maybank2u.com.my", "secure.paypal.com", "login.microsoftonline.com",
    "example.com", "officedepot.example", "unrelated.example",
])
def test_legitimate_or_unrelated_domains_not_flagged(brands, domain):
    assert check_lookalike(domain, brands) is None


def test_short_brand_names_are_skipped():
    brands = [{"name": "HP", "domains": ["hp.com"]}]
    assert check_lookalike("hq.com", brands) is None
