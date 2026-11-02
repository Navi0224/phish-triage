"""Defang and refang indicators of compromise (IOCs).

"Defanging" rewrites a malicious URL/domain/IP so it can't be clicked or
auto-linked by a ticketing system, chat tool or email client, e.g.::

    https://evil.example/login  ->  hxxps://evil[.]example/login
    192.0.2.7                   ->  192[.]0[.]2[.]7
    bad@evil.example            ->  bad[@]evil[.]example

Analysts share defanged IOCs so nobody accidentally visits a phishing page
while reading a report. "Refanging" reverses it when a tool needs the real value.
"""

from __future__ import annotations

import re

# scheme :// host (up to the first / ? or #) and the rest of the URL.
_URL_PARTS_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)(.*)$", re.DOTALL)


def defang_domain(domain: str) -> str:
    """Replace every dot with ``[.]``."""
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    return defang_domain(ip)


def defang_email(address: str) -> str:
    """``first.last@evil.example`` -> ``first.last[@]evil[.]example`` (only the domain's dots change)."""
    local, at, domain = address.rpartition("@")
    if not at:
        return defang_domain(address)
    return f"{local}[@]{defang_domain(domain)}"


def defang_url(url: str) -> str:
    """Defang the scheme and the host part of a URL.

    Only the host's dots are bracketed; the path is left readable so the
    analyst can still see e.g. ``/login.php``.
    """
    match = _URL_PARTS_RE.match(url)
    if not match:  # not a normal scheme://host URL, defang conservatively
        return defang_domain(url)
    scheme, host, rest = match.groups()
    scheme = scheme.lower().replace("http", "hxxp").replace("ftp", "fxp")
    return f"{scheme}://{defang_domain(host)}{rest}"


def refang(value: str) -> str:
    """Undo defanging (for feeding values to another tool)."""
    return (
        value.replace("[.]", ".")
        .replace("[@]", "@")
        .replace("hxxp", "http")
        .replace("fxp", "ftp")
    )
