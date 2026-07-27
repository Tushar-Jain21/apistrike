"""Pytest suite for the APIStrike recon crawler."""
import asyncio
import os
import re

import pytest

from apistrike.recon.crawler import (
    Crawler, load_wordlist, candidate_paths, DEFAULT_PATH_WORDS, SAFE_METHODS,
)


class _Resp:
    def __init__(self, status_code, body="", response_headers=None):
        self.status_code = status_code
        self.body = body
        self.response_headers = response_headers or {}


class _Client:
    def __init__(self, server):
        self.server = server
        self.calls = []

    async def request(self, method, url, headers=None):
        path, _, query = url.partition("?")
        path = re.sub(r"^https?://[^/]+", "", path)
        self.calls.append((method.upper(), path, query))
        return self.server(method.upper(), path, query)

    async def get(self, url, headers=None):
        return await self.request("GET", url, headers=headers)


SPEC = ["/users/v1", "/users/v1/login", "/books/v1"]
SOFT404 = "not found xxxxxxxx"
ALLOW = {
    "/users/v1": "OPTIONS, GET",
    "/users/v1/login": "OPTIONS, POST",
    "/books/v1": "OPTIONS, GET",
    "/admin": "OPTIONS, GET",
}


def _vampi_like(method, path, query):
    if method == "OPTIONS":
        if path in ALLOW:
            return _Resp(204, "", {"Allow": ALLOW[path]})
        return _Resp(404, SOFT404)
    if path == "/users/v1":
        body = '{"users":["a","b"]}'
        if "debug=" in query:
            body = '{"users":["a","b"],"debug":true,"secret":"xxxxxxxxxxxxxxxxxxxxxxxx"}'
        return _Resp(200, body)
    if path == "/users/v1/login":
        return _Resp(200, '{"token":"t"}') if method == "POST" else _Resp(405, "nope")
    if path == "/books/v1":
        return _Resp(200, '{"books":[]}')
    if path == "/admin":
        return _Resp(200, '{"admin":true,"panel":"secret"}')
    if path == "/internal":
        return _Resp(401, "unauthorized")
    return _Resp(404, SOFT404)


def _soft404_everywhere(method, path, query):
    if method == "OPTIONS":
        return _Resp(200, "", {"Allow": "OPTIONS, GET"})
    if path in SPEC:
        return _Resp(200, '{"real":true}')
    return _Resp(200, "<html>generic landing page</html>")


def _run_vampi(**kw):
    client = _Client(_vampi_like)
    cr = Crawler(client, "http://t", seed_endpoints=SPEC,
                 path_words=DEFAULT_PATH_WORDS, **kw)
    res = asyncio.run(cr.run())
    return client, res


def test_load_wordlist_parses_dedups_and_trims(tmp_path):
    wl = tmp_path / "paths.txt"
    wl.write_text("# comment\nadmin\n\ninternal\nadmin\n  spaced  \n")
    assert load_wordlist(str(wl)) == ["admin", "internal", "spaced"]


def test_load_wordlist_falls_back_when_missing():
    assert load_wordlist("/no/such/file", fallback=["a", "b"]) == ["a", "b"]


def test_candidate_paths_join_and_dedup():
    assert candidate_paths(["admin", "admin", "v1/users"]) == ["/admin", "/v1/users"]


def test_shadow_endpoints_discovered():
    _client, res = _run_vampi(safe=True)
    assert set(res.shadow_endpoints) == {"/admin", "/internal"}


def test_shadow_findings_are_api9_low():
    _client, res = _run_vampi(safe=True)
    assert len(res.findings) == 2
    assert all(f.owasp_id == "API9:2023" for f in res.findings)
    assert all(f.severity == "low" for f in res.findings)


def test_protected_shadow_flagged_as_auth_required():
    _client, res = _run_vampi(safe=True)
    internal = [f for f in res.findings if f.endpoint == "/internal"][0]
    assert "authentication" in internal.description


def test_safe_mode_never_sends_state_changing_methods():
    client, _res = _run_vampi(safe=True)
    used = {m for m, _, _ in client.calls}
    assert used <= set(SAFE_METHODS)
    assert not any(m in ("POST", "PUT", "PATCH", "DELETE") for m, _, _ in client.calls)


def test_safe_mode_detects_post_via_options_without_firing_it():
    client, res = _run_vampi(safe=True)
    login = [e for e in res.endpoints if e.path == "/users/v1/login"][0]
    assert "POST" in login.methods_allowed
    assert not any(m == "POST" and p == "/users/v1/login" for m, p, _ in client.calls)


def test_active_mode_fires_state_changing_methods():
    client = _Client(_vampi_like)
    cr = Crawler(client, "http://t", seed_endpoints=["/admin"], path_words=[], safe=False)
    asyncio.run(cr.run())
    assert any(m in ("POST", "PUT", "PATCH", "DELETE") for m, _, _ in client.calls)


def test_param_fuzz_discovers_hidden_param():
    _client, res = _run_vampi(safe=True)
    assert "debug" in res.discovered_params.get("/users/v1", [])


def test_soft404_site_yields_no_false_shadows():
    client = _Client(_soft404_everywhere)
    cr = Crawler(client, "http://t", seed_endpoints=SPEC,
                 path_words=DEFAULT_PATH_WORDS, safe=True)
    res = asyncio.run(cr.run())
    assert res.shadow_endpoints == []
