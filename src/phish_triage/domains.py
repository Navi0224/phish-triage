"""Domain helpers: registrable domain, homoglyph normalisation, lookalike checks.

A "lookalike" (or "cousin") domain is registered by an attacker to resemble a
brand the victim trusts, for example:

* typo-squat:     maybenk2u.com.my      (one letter changed)
* homoglyph:      paypa1.com            ("1" looks like "l")
* IDN/punycode:   xn--...               (Cyrillic "а" that looks like Latin "a")
* brand embedded: maybank2u-secure.com  (real brand name plus extra words)
* brand as sub:   maybank2u.com.my.verify-login.example

We compare the attacker's domain against a configurable list of protected
brands.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Two-label public suffixes we care about. A full Public Suffix List would be
# more accurate (see README "Limitations"), but this keeps the tool
# dependency-free and covers the Malaysian and common cases.
MULTI_PART_SUFFIXES = {
    "com.my", "net.my", "org.my", "gov.my", "edu.my", "name.my", "mil.my",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "com.sg", "edu.sg", "gov.sg", "co.id", "co.jp", "co.in", "com.cn", "com.hk", "co.nz",
}

# Characters that look like ASCII letters. Attackers use them in IDN domains
# (Cyrillic/Greek) or as simple digit swaps in plain ASCII domains.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ʟ": "l", "ո": "n", "ս": "u",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "κ": "k", "ι": "i",
    "0": "o", "1": "l", "3": "e", "5": "s", "!": "i", "|": "l",
}
# Multi-character tricks: "rn" looks like "m", "vv" like "w".
SEQUENCE_CONFUSABLES = {"rn": "m", "vv": "w", "cl": "d"}


@dataclass
class LookalikeMatch:
    domain: str
    brand: str
    brand_domain: str
    technique: str


def to_unicode(domain: str) -> str:
    """Decode punycode labels (``xn--...``) to Unicode so homoglyphs become visible."""
    labels = []
    for label in domain.lower().strip(".").split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass  # invalid punycode: keep the raw label
        labels.append(label)
    return ".".join(labels)


def registrable_domain(domain: str) -> str:
    """Approximate the registrable domain ("eTLD+1").

    ``login.secure.maybank2u.com.my`` -> ``maybank2u.com.my``
    ``mail.example.com``             -> ``example.com``
    """
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def core_label(domain: str) -> str:
    """The brand-bearing label: ``maybank2u`` from ``www.maybank2u.com.my``."""
    return registrable_domain(domain).split(".")[0]


def skeleton(text: str) -> str:
    """Map look-alike characters to the ASCII letters they imitate.

    Two strings with the same skeleton *look* the same to a human.
    """
    out = "".join(CONFUSABLES.get(ch, ch) for ch in text.lower())
    for seq, repl in SEQUENCE_CONFUSABLES.items():
        out = out.replace(seq, repl)
    return out


def levenshtein(a: str, b: str) -> int:
    """Edit distance: the minimum single-character inserts/deletes/substitutions to turn a into b."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def same_registrable(a: str, b: str) -> bool:
    return registrable_domain(a) == registrable_domain(b)


def is_brand_domain(domain: str, brand: dict[str, Any]) -> bool:
    """True if ``domain`` is (a subdomain of) one of the brand's legitimate domains."""
    reg = registrable_domain(to_unicode(domain))
    return any(reg == registrable_domain(d) for d in brand.get("domains", []))


def check_lookalike(domain: str, brands: list[dict[str, Any]], max_distance: int = 2,
                    min_brand_length: int = 5) -> LookalikeMatch | None:
    """Return a match if ``domain`` imitates one of the protected brands.

    Order of checks goes from most to least specific, and the first hit wins.
    """
    if not domain:
        return None
    uni = to_unicode(domain)
    core = core_label(uni)
    is_idn = uni != domain.lower().strip(".") or any(ord(c) > 127 for c in uni)

    if any(is_brand_domain(domain, b) for b in brands):
        return None  # the real thing, e.g. secure.maybank2u.com.my

    for brand in brands:
        # "lookalike_targets" lets a brand list legit domains (e.g. live.com)
        # without using their generic names for lookalike matching.
        for legit in brand.get("lookalike_targets", brand.get("domains", [])):
            brand_core = core_label(legit)
            if len(brand_core) < min_brand_length:
                continue  # very short names ("hp") would match everything
            match = _compare(core, uni, brand_core, is_idn, max_distance)
            if match:
                return LookalikeMatch(domain, brand.get("name", legit), legit, match)
    return None


def _compare(core: str, full: str, brand_core: str, is_idn: bool, max_distance: int) -> str | None:
    """Compare one candidate against one brand label; return the technique name or None."""
    if core == brand_core:
        return "same name, different top-level domain"
    if skeleton(core) == skeleton(brand_core):
        return "IDN homoglyph (punycode)" if is_idn else "character substitution (homoglyph)"
    distance = levenshtein(core, brand_core)
    if 0 < distance <= max_distance:
        return f"typo-squat (edit distance {distance})"
    brand_skel = skeleton(brand_core)
    if brand_skel in skeleton(core):
        return "brand name embedded in domain"
    other_labels = full.split(".")[: -len(registrable_domain(full).split("."))]
    if any(brand_skel in skeleton(label) for label in other_labels):
        return "brand name used as subdomain"
    return None
