"""Socket-free pytest suite for the Security Misconfiguration module (API8:2023)."""
import asyncio

import pytest

from apistrike.modules.misconfig import (
    MisconfigModule, OWASP_ID, ALL_CHECKS, _resp_headers, _body_str,
)


class Resp:
    def __init__(self, status=200, body="", headers=None):
        self.status_code = status
        self.body = body
        self.headers = {} if headers is None else headers
        self.elapsed_ms = 5.0


def _path(url):
    rest = url.split("://", 1)[-1]
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


class Server:
    def __init__(self, *, sec_headers=False, banner=True, cors="none",
                 verbose=False, trace=False, expose_headers=True):
        self.sec_headers = sec_headers
        self.banner = banner
        self.cors = cors
        self.verbose = verbose
        self.trace = trace
        self.expose_headers = expose_headers
        self.calls = []

    async def request(self, method, url, headers=None, params=None):
        headers = headers or {}
        self.calls.append((method, url, params))
        origin = headers.get("Origin") or headers.get("origin")
        path = _path(url)
        h = {"content-type": "application/json"}
        h["server"] = "Werkzeug/2.0.1 Python/3.11" if self.banner else "nginx"
        if self.sec_headers:
            h["content-security-policy"] = "default-src 'self'"
            h["x-content-type-options"] = "nosniff"
            h["x-frame-options"] = "DENY"
            h["referrer-policy"] = "no-referrer"
            h["strict-transport-security"] = "max-age=63072000"
        if origin:
            if self.cors == "reflect_creds":
                h["access-control-allow-origin"] = origin
                h["access-control-allow-credentials"] = "true"
            elif self.cors == "reflect":
                h["access-control-allow-origin"] = origin
            elif self.cors == "wildcard":
                h["access-control-allow-origin"] = "*"
        if not self.expose_headers:
            h = {}
        if method == "TRACE":
            if self.trace:
                return Resp(200, "TRACE " + path + " HTTP/1.1", h)
            return Resp(405, "method not allowed", h)
        is_err = (params and "apistrike_err" in params) or ("%c0%ae" in path)
        if is_err and self.verbose:
            return Resp(500, 'Traceback (most recent call last):\n  File "/app/app.py", line 42\nWerkzeug', h)
        return Resp(200, '{"message": "ok"}', h)


def run(coro):
    return asyncio.run(coro)


def test_taxonomy():
    assert OWASP_ID == "API8:2023"
    assert set(ALL_CHECKS) == {"headers", "cors", "errors", "methods", "banner"}


def test_helpers():
    assert _resp_headers(Resp(headers={"A": "B"})) == {"a": "B"}
    assert _body_str(Resp(body=b"hi")) == "hi"


def test_invalid_checks_raise():
    with pytest.raises(ValueError):
        MisconfigModule(Server(), "http://t", checks=("nope",))


def test_missing_security_headers():
    res = run(MisconfigModule(Server(sec_headers=False), "http://t", checks=("headers",)).run())
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "low" and f.cwe == "CWE-693"
    assert "Content-Security-Policy" in f.evidence[0]
    assert "Strict-Transport-Security" not in f.evidence[0]  # http -> HSTS skipped


def test_hsts_flagged_over_https():
    res = run(MisconfigModule(Server(sec_headers=False), "https://t", checks=("headers",)).run())
    assert "Strict-Transport-Security" in res.findings[0].evidence[0]


def test_banner_disclosure():
    res = run(MisconfigModule(Server(banner=True, sec_headers=True), "http://t", checks=("banner",)).run())
    assert len(res.findings) == 1 and res.findings[0].cwe == "CWE-200"
    res2 = run(MisconfigModule(Server(banner=False, sec_headers=True), "http://t", checks=("banner",)).run())
    assert res2.findings == []


def test_cors_reflect_with_credentials_high():
    res = run(MisconfigModule(Server(cors="reflect_creds", sec_headers=True, banner=False), "https://t", checks=("cors",)).run())
    f = res.findings[0]
    assert f.severity == "high" and f.confidence == "confirmed" and f.cwe == "CWE-942"


def test_cors_reflect_medium():
    res = run(MisconfigModule(Server(cors="reflect", sec_headers=True, banner=False), "https://t", checks=("cors",)).run())
    assert res.findings[0].severity == "medium"


def test_cors_wildcard_low():
    res = run(MisconfigModule(Server(cors="wildcard", sec_headers=True, banner=False), "https://t", checks=("cors",)).run())
    assert res.findings[0].severity == "low"


def test_cors_none_no_finding():
    res = run(MisconfigModule(Server(cors="none", sec_headers=True, banner=False), "https://t", checks=("cors",)).run())
    assert res.findings == []


def test_verbose_error_medium():
    res = run(MisconfigModule(Server(verbose=True, sec_headers=True, banner=False), "http://t", checks=("errors",)).run())
    assert len(res.findings) == 1 and res.findings[0].cwe == "CWE-209"
    res2 = run(MisconfigModule(Server(verbose=False, sec_headers=True, banner=False), "http://t", checks=("errors",)).run())
    assert res2.findings == []


def test_trace_enabled_medium():
    res = run(MisconfigModule(Server(trace=True, sec_headers=True, banner=False), "http://t", checks=("methods",)).run())
    assert len(res.findings) == 1 and res.findings[0].cwe == "CWE-16"


def test_headers_not_exposed_skips_with_note():
    srv = Server(expose_headers=False)
    res = run(MisconfigModule(srv, "http://t").run())
    assert res.findings == []
    assert any("not exposed" in n for n in res.notes)
