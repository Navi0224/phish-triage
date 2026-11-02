"""Enrichment tests use a fake HTTP session: no real network access, no real keys."""

from phish_triage.enrichment import enrich, vt_url_id


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, get_response=None, post_response=None, raise_exc=None):
        self.get_response, self.post_response, self.raise_exc = get_response, post_response, raise_exc
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if self.raise_exc:
            raise self.raise_exc
        return self.get_response

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if self.raise_exc:
            raise self.raise_exc
        return self.post_response


def test_no_keys_means_no_lookups():
    session = FakeSession()
    result, findings = enrich(["http://a.example/"], ["0" * 64], session=session, env={})
    assert session.calls == []
    assert findings == []
    assert any("VT_API_KEY not set" in n for n in result["notes"])


def test_virustotal_malicious_creates_finding():
    vt = FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1}}}})
    session = FakeSession(get_response=vt)
    result, findings = enrich([], ["a" * 64], session=session, env={"VT_API_KEY": "test-key"})
    assert findings[0].rule_id == "enrichment_virustotal_malicious"
    assert result["virustotal"]["a" * 64]["malicious"] == 7
    assert session.calls[0][2]["headers"] == {"x-apikey": "test-key"}


def test_virustotal_not_found_and_http_error():
    result, findings = enrich([], ["b" * 64], session=FakeSession(get_response=FakeResponse(404)),
                              env={"VT_API_KEY": "k"})
    assert result["virustotal"]["b" * 64]["status"] == "not_found" and findings == []
    result, _ = enrich([], ["c" * 64], session=FakeSession(get_response=FakeResponse(429)), env={"VT_API_KEY": "k"})
    assert result["virustotal"]["c" * 64] == {"status": "error", "error": "HTTP 429"}


def test_urlhaus_listed_creates_finding():
    session = FakeSession(post_response=FakeResponse(200, {"query_status": "ok", "threat": "malware_download"}))
    result, findings = enrich(["http://bad.example/x"], [], session=session, env={"URLHAUS_AUTH_KEY": "k"})
    assert findings[0].rule_id == "enrichment_urlhaus_listed"
    assert result["urlhaus"]["hxxp://bad[.]example/x"]["status"] == "listed"


def test_network_error_is_handled():
    session = FakeSession(raise_exc=ConnectionError("offline"))
    result, findings = enrich(["http://a.example/"], ["d" * 64], session=session,
                              env={"VT_API_KEY": "k", "URLHAUS_AUTH_KEY": "k"})
    assert findings == []
    assert result["virustotal"]["d" * 64] == {"status": "error", "error": "ConnectionError"}
    assert result["urlhaus"]["hxxp://a[.]example/"]["status"] == "error"


def test_vt_url_id_is_unpadded_base64url():
    assert vt_url_id("http://a.example/") == "aHR0cDovL2EuZXhhbXBsZS8"
