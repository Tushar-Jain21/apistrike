"""Regression tests for inventory content-verification + configurable login field.

These cover the two crAPI-validation fixes:
  1. content-sensitive surfaces (.env, .git/config, ...) must not fire on a
     catch-all / SPA HTML response (the crAPI /.env false positive);
  2. AuthEngine can send the identity under a configurable body field
     (e.g. 'email' for crAPI) via LoginConfig.username_field.
"""
import asyncio

from apistrike.auth.auth_engine import AuthEngine, LoginConfig
from apistrike.modules.inventory import (
    InventoryModule,
    _content_verified,
    _evidence_snippet,
    _looks_like_html,
)


class _Resp:
    def __init__(self, status_code: int, body: str = ""):
        self.status_code = status_code
        self.body = body


class _FakeClient:
    """Returns canned responses per path; 404 for anything else."""

    def __init__(self, routes):
        self.routes = routes

    async def request(self, method, url, **kwargs):
        # url == base_url + path; strip a leading scheme+host if present.
        path = url
        for sep in ("://",):
            if sep in path:
                path = "/" + path.split(sep, 1)[1].split("/", 1)[1]
        for known, resp in self.routes.items():
            if path == known:
                return resp
        return _Resp(404, "not found")


SPA_HTML = "<!doctype html><html><head><title>crAPI</title></head><body>app</body></html>"
REAL_ENV = "SECRET_KEY=supersecret\nDB_PASSWORD=hunter2\nDEBUG=true\n"


def _run_surfaces(routes):
    mod = InventoryModule(_FakeClient(routes), "http://t", checks=("surfaces",))
    return asyncio.run(mod.run())


def test_looks_like_html():
    assert _looks_like_html(SPA_HTML) is True
    assert _looks_like_html(REAL_ENV) is False
    assert _looks_like_html("") is False


def test_content_verified_env():
    assert _content_verified("/.env", REAL_ENV) is True
    assert _content_verified("/.env", SPA_HTML) is False
    # A path without a signature is always accepted (unchanged behavior).
    assert _content_verified("/openapi.json", SPA_HTML) is True


def test_env_html_is_not_flagged():
    """The crAPI false positive: SPA HTML at /.env must NOT produce a finding."""
    res = _run_surfaces({"/.env": _Resp(200, SPA_HTML)})
    titles = [f.title for f in res.findings]
    assert not any("/.env" in t for t in titles), titles
    assert any(".env" in n for n in res.notes)


def test_env_real_content_is_flagged():
    """A genuine dotenv body must still be flagged HIGH."""
    res = _run_surfaces({"/.env": _Resp(200, REAL_ENV)})
    env = [f for f in res.findings if "/.env" in f.title]
    assert len(env) == 1, [f.title for f in res.findings]
    assert env[0].severity == "high"


def test_git_config_html_is_not_flagged():
    res = _run_surfaces({"/.git/config": _Resp(200, SPA_HTML)})
    assert not any(".git" in f.title for f in res.findings)


def test_git_config_real_is_flagged():
    body = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
    res = _run_surfaces({"/.git/config": _Resp(200, body)})
    assert any(".git" in f.title for f in res.findings)


def test_evidence_has_body_snippet():
    res = _run_surfaces({"/.env": _Resp(200, REAL_ENV)})
    env = [f for f in res.findings if "/.env" in f.title][0]
    assert any(e.startswith("body[:180]:") for e in env.evidence)
    joined = " ".join(env.evidence)
    # secret values are masked, not dumped verbatim; keys stay visible
    assert "supersecret" not in joined and "hunter2" not in joined
    assert "SECRET_KEY" in joined


def test_evidence_snippet_masks_values():
    s = _evidence_snippet("API_KEY=abcdef\nMODE=prod")
    assert "abcdef" not in s
    assert "API_KEY=ab" in s


def test_login_field_email_payload():
    cfg = LoginConfig(username_field="email")
    eng = AuthEngine(client=None, base_url="http://t", login_config=cfg)
    ident = eng.add_identity("primary", username="a@b.com", password="pw")
    assert eng._login_payload(ident) == {"email": "a@b.com", "password": "pw"}


def test_login_field_default_username():
    eng = AuthEngine(client=None, base_url="http://t", login_config=LoginConfig())
    ident = eng.add_identity("primary", username="bob", password="pw")
    assert eng._login_payload(ident) == {"username": "bob", "password": "pw"}
