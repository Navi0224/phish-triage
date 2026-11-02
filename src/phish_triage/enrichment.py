"""Optional threat-intel enrichment (OFF by default).

Enabled with ``--enrich``. Only runs a lookup if the matching API key is set
in an environment variable; keys are never stored in code or config files:

* ``VT_API_KEY``       - VirusTotal API v3 (free community key works, ~4 requests/min)
* ``URLHAUS_AUTH_KEY`` - abuse.ch URLhaus API (free Auth-Key from abuse.ch)

Privacy/OPSEC: we only *look up* existing reports (by hash or URL ID). We
never upload attachments or submit URLs for scanning, because submissions to
VirusTotal are visible to other subscribers and can leak internal data or tip
off the attacker.

Any error (no key, no network, rate-limit, bad response) is recorded in the
result and the triage continues without enrichment.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Protocol

from .defang import defang_url
from .models import Finding

VT_BASE = "https://www.virustotal.com/api/v3"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT_SECONDS = 10
MAX_LOOKUPS_PER_SERVICE = 4  # keeps us inside the VirusTotal free-tier rate limit


class HttpSession(Protocol):
    """The tiny part of ``requests.Session`` we use (lets tests pass a fake)."""

    def get(self, url: str, **kwargs: Any) -> Any: ...
    def post(self, url: str, **kwargs: Any) -> Any: ...


def _default_session() -> HttpSession | None:
    try:
        import requests  # optional dependency, imported only when enrichment is used
    except ImportError:
        return None
    return requests.Session()


def vt_url_id(url: str) -> str:
    """VirusTotal identifies a URL by its unpadded URL-safe base64 encoding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def virustotal_lookup(kind: str, value: str, api_key: str, session: HttpSession) -> dict[str, Any]:
    """Look up a file hash (kind='files') or URL (kind='urls') report."""
    ident = vt_url_id(value) if kind == "urls" else value
    try:
        resp = session.get(f"{VT_BASE}/{kind}/{ident}", headers={"x-apikey": api_key}, timeout=TIMEOUT_SECONDS)
    except Exception as exc:  # network error, DNS failure, timeout...
        return {"status": "error", "error": type(exc).__name__}
    if resp.status_code == 404:
        return {"status": "not_found"}
    if resp.status_code != 200:
        return {"status": "error", "error": f"HTTP {resp.status_code}"}
    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except (ValueError, KeyError, TypeError):
        return {"status": "error", "error": "unexpected response format"}
    return {"status": "ok", "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0))}


def urlhaus_lookup(url: str, auth_key: str, session: HttpSession) -> dict[str, Any]:
    """Ask URLhaus whether a URL is a known malware-distribution URL."""
    try:
        resp = session.post(URLHAUS_URL, data={"url": url}, headers={"Auth-Key": auth_key}, timeout=TIMEOUT_SECONDS)
    except Exception as exc:
        return {"status": "error", "error": type(exc).__name__}
    if resp.status_code != 200:
        return {"status": "error", "error": f"HTTP {resp.status_code}"}
    try:
        body = resp.json()
    except ValueError:
        return {"status": "error", "error": "unexpected response format"}
    if body.get("query_status") == "ok":
        return {"status": "listed", "threat": body.get("threat", ""), "url_status": body.get("url_status", "")}
    return {"status": body.get("query_status", "unknown")}


def enrich(urls: list[str], sha256s: list[str], session: HttpSession | None = None,
           env: dict[str, str] | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Run all available lookups. Returns (raw results for the report, findings for scoring)."""
    env = dict(os.environ) if env is None else env
    vt_key, uh_key = env.get("VT_API_KEY", ""), env.get("URLHAUS_AUTH_KEY", "")
    result: dict[str, Any] = {"virustotal": {}, "urlhaus": {}, "notes": []}

    if not vt_key:
        result["notes"].append("VirusTotal skipped: VT_API_KEY not set.")
    if not uh_key:
        result["notes"].append("URLhaus skipped: URLHAUS_AUTH_KEY not set.")
    if not (vt_key or uh_key):
        return result, []

    session = session or _default_session()
    if session is None:
        result["notes"].append("Enrichment skipped: the 'requests' package is not installed.")
        return result, []

    vt_hits, uh_hits = [], []
    if vt_key:
        targets = [("files", h) for h in sha256s] + [("urls", u) for u in urls]
        for kind, value in targets[:MAX_LOOKUPS_PER_SERVICE]:
            res = virustotal_lookup(kind, value, vt_key, session)
            label = value if kind == "files" else defang_url(value)
            result["virustotal"][label] = res
            if res.get("malicious", 0) > 0:
                vt_hits.append(f"{label}: {res['malicious']} engines flag as malicious")
    if uh_key:
        for url in urls[:MAX_LOOKUPS_PER_SERVICE]:
            res = urlhaus_lookup(url, uh_key, session)
            result["urlhaus"][defang_url(url)] = res
            if res.get("status") == "listed":
                uh_hits.append(f"{defang_url(url)}: {res.get('threat') or 'listed'}")

    findings = []
    if vt_hits:
        findings.append(Finding("enrichment_virustotal_malicious", "VirusTotal reports malicious detections", "", vt_hits))
    if uh_hits:
        findings.append(Finding("enrichment_urlhaus_listed", "URL listed on URLhaus", "", uh_hits))
    return result, findings
