"""Tests for the SSRF module and the built-in OAST listener.

Socket-free by default (fake listener + fake clients). One test exercises the
real stdlib listener over loopback and is skipped if the sandbox blocks sockets.
"""

import asyncio
import urllib.request

import pytest

from apistrike.modules.ssrf import (
    Interaction,
    InteractionStore,
    OASTListener,
    SSRFModule,
    SSRFTarget,
    OWASP_ID,
    OWASP_API_TOP_10,
)


class Resp:
    def __init__(self, status, body="", elapsed_ms=5.0):
        self.status_code = status
        self.body = body
        self.elapsed_ms = elapsed_ms


def _path_of(url):
    p = url.split("://", 1)[-1]
    return p[p.find("/"):] if "/" in p else "/"


def _value(kwargs, param):
    params = kwargs.get("params") or {}
    body = kwargs.get("json") or {}
    if param in params:
        return str(params[param])
    if param in body:
        return str(body[param])
    for src in (params, body):
        for v in src.values():
            return str(v)
    return ""


class FakeListener:
    BASE = "http://oast.local:1"

    def __init__(self):
        self.armed = set()
        self._n = 0

    def new_token(self):
        self._n += 1
        return "tok" + str(self._n)

    def payload_url(self, token, path_suffix=""):
        return self.BASE + "/" + token + path_suffix

    def poll(self, token, wait_ms=0):
        if token in self.armed:
            return [Interaction("GET", "/" + token, "oast.local", "10.9.9.9")]
        return []


class OastClient:
    def __init__(self, listener, param="url"):
        self.listener = listener
        self.param = param

    async def request(self, method, url, **kwargs):
        val = _value(kwargs, self.param)
        if val.startswith(self.listener.BASE):
            self.listener.armed.add(val.rsplit("/", 1)[-1])
            return Resp(200, "queued")
        return Resp(200, "ok")


class MetadataClient:
    async def request(self, method, url, **kwargs):
        val = _value(kwargs, "target")
        if "169.254.169.254" in val or "metadata.google" in val:
            return Resp(200, "ami-id: ami-0abc\ninstance-id: i-999")
        return Resp(200, "hello")


class LocalhostClient:
    async def request(self, method, url, **kwargs):
        val = _value(kwargs, "target")
        internal = any(s in val for s in ("127.0.0.1", "localhost", "[::1]", "2130706433", "0x7f000001"))
        if internal:
            return Resp(200, "INTERNAL DASHBOARD " + "x" * 200)
        return Resp(403, "forbidden")


class TimingClient:
    async def request(self, method, url, **kwargs):
        val = _value(kwargs, "target")
        if any(s in val for s in ("10.255.255.1", "192.168.255.254", "169.254.169.254:9")):
            return Resp(200, "...", elapsed_ms=3600.0)
        return Resp(200, "fast", elapsed_ms=6.0)


class CleanClient:
    async def request(self, method, url, **kwargs):
        return Resp(200, "static ok", elapsed_ms=5.0)


class MultiClient:
    def __init__(self, listener):
        self.listener = listener

    async def request(self, method, url, **kwargs):
        path = _path_of(url)
        if path.startswith("/oast"):
            val = _value(kwargs, "url")
            if val.startswith(self.listener.BASE):
                self.listener.armed.add(val.rsplit("/", 1)[-1])
            return Resp(200, "queued")
        if path.startswith("/meta"):
            val = _value(kwargs, "target")
            if "169.254.169.254" in val:
                return Resp(200, "ami-id: ami-1")
            return Resp(200, "ok")
        return Resp(200, "static ok")


def run(m):
    return asyncio.run(m.run())


def test_taxonomy_has_ssrf():
    assert OWASP_ID == "API7:2023"
    assert "API7:2023" in OWASP_API_TOP_10


def test_target_normalizes():
    t = SSRFTarget("post", "fetch", "url", "body")
    assert t.method == "POST" and t.path == "/fetch" and t.location == "json"


def test_path_target_requires_marker():
    with pytest.raises(ValueError):
        SSRFTarget("GET", "/fetch/here", "u", "path")
    ok = SSRFTarget("GET", "fetch/INJECT", "u", "path")
    assert ok.location == "path" and ok.path == "/fetch/INJECT"


def test_requires_at_least_one_target():
    with pytest.raises(ValueError):
        SSRFModule(CleanClient(), "http://t", [])


def test_oast_url_and_token_helpers():
    o = OASTListener(host="127.0.0.1", port=0)
    o.port = 8099
    assert o.base_url == "http://127.0.0.1:8099"
    assert o.payload_url("abc") == "http://127.0.0.1:8099/abc"
    assert o.new_token().startswith("oast")


def test_oast_public_host_override():
    o = OASTListener(host="0.0.0.0", port=0, public_host="10.0.0.5")
    o.port = 7000
    assert o.base_url == "http://10.0.0.5:7000"


def test_interaction_store_matching():
    s = InteractionStore()
    s.record(Interaction("GET", "/tokABC/x", "h", "1.1.1.1"))
    s.record(Interaction("GET", "/other", "h", "1.1.1.1"))
    assert len(s.matching("tokABC")) == 1
    assert len(s.matching("nope")) == 0


def test_oast_listener_real_loopback():
    try:
        with OASTListener() as oast:
            tok = oast.new_token()
            urllib.request.urlopen(oast.payload_url(tok), timeout=3).read()
            hits = oast.poll(tok, wait_ms=300)
            assert len(hits) >= 1
            assert tok in hits[0].path
    except OSError as e:
        pytest.skip("loopback sockets unavailable: " + str(e))


def test_oast_confirmed_via_fake_listener():
    fl = FakeListener()
    res = run(SSRFModule(OastClient(fl), "http://t", [SSRFTarget("GET", "/fetch", "url")], listener=fl, techniques=["oast"], oast_wait_ms=0))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "critical" and f.cwe == "CWE-918" and f.confidence == "confirmed"
    assert "out-of-band" in f.title.lower()


def test_oast_skipped_without_listener():
    res = run(SSRFModule(OastClient(FakeListener()), "http://t", [SSRFTarget("GET", "/fetch", "url")], listener=None, techniques=["oast"]))
    assert res.findings == []
    assert any("no callback listener" in n.lower() for n in res.notes)


def test_metadata_confirmed():
    res = run(SSRFModule(MetadataClient(), "http://t", [SSRFTarget("GET", "/img", "target")], techniques=["metadata"]))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "critical" and f.confidence == "confirmed"
    assert "metadata" in f.title.lower()


def test_localhost_reachable_firm():
    res = run(SSRFModule(LocalhostClient(), "http://t", [SSRFTarget("GET", "/img", "target", benign_value="http://example.com/")], techniques=["metadata"]))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "high" and f.confidence == "firm" and f.cwe == "CWE-918"


def test_timing_blind_firm():
    res = run(SSRFModule(TimingClient(), "http://t", [SSRFTarget("GET", "/img", "target")], techniques=["timing"], time_threshold_ms=2500))
    assert len(res.findings) == 1
    assert res.findings[0].severity == "medium" and res.findings[0].confidence == "firm"


def test_clean_no_false_positives():
    res = run(SSRFModule(CleanClient(), "http://t", [SSRFTarget("GET", "/img", "target")], listener=FakeListener(), techniques=["oast", "metadata", "timing"], oast_wait_ms=0))
    assert res.findings == []
    assert any("no ssrf confirmed" in n.lower() for n in res.notes)


def test_oast_precedence_over_metadata():
    fl = FakeListener()

    class BothClient:
        async def request(self, method, url, **kwargs):
            val = _value(kwargs, "target")
            if val.startswith(fl.BASE):
                fl.armed.add(val.rsplit("/", 1)[-1])
                return Resp(200, "ami-id: leaked")
            if "169.254.169.254" in val:
                return Resp(200, "ami-id: leaked")
            return Resp(200, "ok")

    res = run(SSRFModule(BothClient(), "http://t", [SSRFTarget("GET", "/img", "target")], listener=fl, techniques=["oast", "metadata"], oast_wait_ms=0))
    assert len(res.findings) == 1
    assert "out-of-band" in res.findings[0].title.lower()


def test_multi_target_aggregates():
    fl = FakeListener()
    targets = [
        SSRFTarget("GET", "/oast", "url"),
        SSRFTarget("GET", "/meta", "target"),
        SSRFTarget("GET", "/clean", "x"),
    ]
    res = run(SSRFModule(MultiClient(fl), "http://t", targets, listener=fl, techniques=["oast", "metadata", "timing"], oast_wait_ms=0))
    assert len(res.findings) == 2
    assert all(f.cwe == "CWE-918" for f in res.findings)
    assert res.requests_made > 0
