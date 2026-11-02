"""Extract indicators of compromise (IOCs) from the email body.

IOCs collected: URLs, domains, IPv4 addresses and email addresses. We also
compare each HTML link's real destination (``href``) with the text the user
sees, because "the link says bank.com but goes somewhere else" is one of the
strongest phishing signals.

Nothing here ever fetches a URL. We only read text.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .models import Link, ParsedEmail

# http(s)/ftp URLs or bare "www." links in plain text. Stops at whitespace,
# quotes and angle brackets, which commonly surround URLs.
URL_RE = re.compile(r"""(?:https?|ftp)://[^\s<>"'`]+|\bwww\.[^\s<>"'`]+""", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Something in the visible link text that looks like a domain, e.g. "www.maybank2u.com.my".
DOMAIN_LIKE_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}'\""


class _LinkParser(HTMLParser):
    """Collect <a href> links with their visible text, form actions and plain text.

    ``HTMLParser`` only tokenises the markup; it never runs scripts or loads
    images, so it is safe on hostile HTML.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.form_actions: list[str] = []
        self.has_password_input = False
        self.text_chunks: list[str] = []
        self._href: str | None = None
        self._link_text: list[str] = []
        self._skip_depth = 0  # inside <script>/<style>

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a" and attr.get("href"):
            self._href = attr["href"].strip()
            self._link_text = []
        elif tag == "form":
            self.form_actions.append(attr.get("action", ""))
        elif tag == "input" and attr.get("type", "").lower() == "password":
            self.has_password_input = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._link_text).split())))
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text_chunks.append(data)
        if self._href is not None:
            self._link_text.append(data)


@dataclass
class HtmlInfo:
    links: list[Link] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    has_password_input: bool = False
    text: str = ""


@dataclass
class IOCs:
    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)


def parse_html(html: str) -> HtmlInfo:
    """Extract links, forms and visible text from an HTML body."""
    if not html:
        return HtmlInfo()
    parser = _LinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # broken HTML: keep whatever we collected so far
        pass
    return HtmlInfo(
        links=parser.links,
        form_actions=parser.form_actions,
        has_password_input=parser.has_password_input,
        text=" ".join(" ".join(parser.text_chunks).split()),
    )


def clean_url(url: str) -> str:
    """Strip trailing punctuation picked up from surrounding prose."""
    return url.rstrip(_TRAILING_PUNCT)


def url_host(url: str) -> str:
    """Return the lower-case hostname of a URL ('' if it has none)."""
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _unique(items: list[str]) -> list[str]:
    """De-duplicate while keeping first-seen order (stable output for tests/reports)."""
    return list(dict.fromkeys(i for i in items if i))


def extract_iocs(email: ParsedEmail, html: HtmlInfo) -> IOCs:
    """Collect URLs, domains, IPs and email addresses from the bodies."""
    corpus = "\n".join([email.text_body, html.text])
    # URLs come from the plain-text body and from real HTML link targets. We
    # deliberately do NOT regex the HTML *visible* text: in a phish the visible
    # text is often the genuine bank URL used as a decoy, and listing it as an
    # IOC could lead someone to block the real bank.
    urls = [clean_url(u) for u in URL_RE.findall(email.text_body)]
    urls += [l.href for l in html.links if l.href.lower().startswith(("http://", "https://", "ftp://", "www."))]
    urls += [a for a in html.form_actions if a.lower().startswith(("http://", "https://"))]
    urls = _unique(urls)

    ips = [ip for ip in IPV4_RE.findall(corpus) if is_ip(ip)]
    hosts = [url_host(u) for u in urls]
    ips += [h for h in hosts if is_ip(h)]

    # Sender-side addresses from the headers are IOCs too (the gateway blocks on them).
    header_emails = [email.from_addr.address, email.return_path] + [r.address for r in email.reply_to]
    # mailto: links count as email IOCs as well
    mailtos = [l.href[7:].split("?")[0] for l in html.links if l.href.lower().startswith("mailto:")]
    emails = _unique([e.lower() for e in header_emails + EMAIL_RE.findall(corpus) + mailtos if "@" in e])

    domains = [h for h in hosts if h and not is_ip(h)]
    domains += [e.rsplit("@", 1)[1] for e in emails]
    return IOCs(urls=urls, domains=_unique(domains), ips=_unique(ips), emails=emails)


def find_link_mismatches(links: list[Link]) -> list[dict[str, str]]:
    """Find links whose visible text shows one domain but whose href goes to another.

    Example: ``<a href="http://evil.example">www.maybank2u.com.my</a>``.
    Links with ordinary text ("Click here") are not compared, there is no
    claimed destination to contradict.
    """
    mismatches = []
    for link in links:
        shown = DOMAIN_LIKE_RE.search(link.text)
        real_host = url_host(link.href)
        if not shown or not real_host:
            continue
        shown_host = url_host(shown.group(0)) or shown.group(0).lower()
        if not _same_site(shown_host, real_host):
            mismatches.append({"text": link.text, "shown_domain": shown_host, "href": link.href, "href_domain": real_host})
    return mismatches


def _same_site(a: str, b: str) -> bool:
    """True if one host equals or is a subdomain of the other (www.x.com vs x.com)."""
    a, b = a.lower().removeprefix("www."), b.lower().removeprefix("www.")
    return a == b or a.endswith("." + b) or b.endswith("." + a)
