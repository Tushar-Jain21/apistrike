"""PR-8b: live in-loop session refresh via RefreshingClient.

These tests use a fake transport so they run offline and deterministically.
They exercise the REAL AuthEngine session-lifecycle (ensure_fresh + the bounded
401 re-auth in authed_request), proving that a token which expires mid-scan is
refreshed underneath the authorization modules WITHOUT any module change -- and
that the sentinel header never leaks to the target and unauthenticated probes
stay untouched.
"""
import asyncio

from apistrike.auth.auth_engine import AuthEngine, Credentials, Identity
from apistrike.auth.refresh_client import RefreshingClient, IDENTITY_HEADER


class _Resp:
    """Minimal stand-in for the ScopedHTTPClient Evidence object."""

    def __init__(self, status_code=200, body=""):
        self.status_code = status_code
        self.body = body


class FakeClient:
    """Records every request and returns a programmed sequence of responses."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []  # list of (method, url, headers)

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, dict(kwargs.get("headers") or {})))
        if self.responses:
            return self.responses.pop(0)
        return _Resp(200, "ok")

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)


class FakeProvider:
    """An AuthProvider whose (re)authentication is observable."""

    name = "fake"

    def __init__(self):
        self.auth_calls = 0
        self.refresh_calls = 0

    async def authenticate(self, ident, engine):
        self.auth_calls += 1
        ident.token = "fresh-token"
        ident.expires_at = None
        return ident.token

    async def refresh(self, ident, engine):
        self.refresh_calls += 1
        ident.token = "refreshed-token"
        ident.expires_at = None
        return ident.token


def _engine_with(ident, client):
    eng = AuthEngine(client, base_url="http://t")
    eng.register_identity(ident)
    return eng


def _last_headers(client):
    return client.calls[-1][2]


def test_expired_token_is_refreshed_before_the_request():
    prov = FakeProvider()
    ident = Identity(name="userA", credentials=Credentials("userA"),
                     token="stale", expires_at=1.0, provider=prov)  # far past -> expired
    client = FakeClient([_Resp(200, "ok")])
    eng = _engine_with(ident, client)
    rc = RefreshingClient(client, eng)

    resp = asyncio.run(rc.get("http://t/orders/1", headers={IDENTITY_HEADER: "userA"}))

    assert resp.status_code == 200
    assert prov.refresh_calls == 1  # proven expiry -> refresh, not a fresh auth
    hdrs = _last_headers(client)
    assert hdrs.get("Authorization") == "Bearer refreshed-token"
    assert IDENTITY_HEADER not in hdrs and IDENTITY_HEADER.lower() not in {k.lower() for k in hdrs}


def test_401_triggers_one_bounded_reauth_then_retries():
    prov = FakeProvider()
    ident = Identity(name="userA", credentials=Credentials("userA"),
                     token="live-token", expires_at=None, provider=prov)
    client = FakeClient([_Resp(401, "nope"), _Resp(200, "ok")])
    eng = _engine_with(ident, client)
    rc = RefreshingClient(client, eng)

    resp = asyncio.run(rc.request("GET", "http://t/orders/1", headers={IDENTITY_HEADER: "userA"}))

    assert resp.status_code == 200
    assert prov.refresh_calls == 1
    assert len(client.calls) == 2  # original + one retry, never an unbounded loop
    assert _last_headers(client).get("Authorization") == "Bearer refreshed-token"


def test_no_sentinel_passes_through_untouched():
    client = FakeClient([_Resp(200, "ok")])
    eng = _engine_with(Identity(name="x", credentials=Credentials("x")), client)
    rc = RefreshingClient(client, eng)

    asyncio.run(rc.get("http://t/public", headers={}))

    hdrs = _last_headers(client)
    assert "Authorization" not in hdrs
    assert IDENTITY_HEADER not in hdrs


def test_unknown_label_is_stripped_and_passes_through():
    client = FakeClient([_Resp(200, "ok")])
    eng = _engine_with(Identity(name="known", credentials=Credentials("known")), client)
    rc = RefreshingClient(client, eng)

    asyncio.run(rc.get("http://t/x", headers={IDENTITY_HEADER: "ghost"}))

    hdrs = _last_headers(client)
    assert IDENTITY_HEADER not in hdrs
    assert "Authorization" not in hdrs  # unknown identity -> no auth injected


def test_static_token_identity_without_provider_is_not_reauthed_on_401():
    ident = Identity(name="userB", credentials=Credentials("userB"),
                     token="static", expires_at=None, provider=None)
    client = FakeClient([_Resp(401, "denied")])
    eng = _engine_with(ident, client)
    rc = RefreshingClient(client, eng)

    resp = asyncio.run(rc.get("http://t/orders/1", headers={IDENTITY_HEADER: "userB"}))

    assert resp.status_code == 401  # honest 401, no masking
    assert len(client.calls) == 1  # provider-less identity: no re-auth attempt
    hdrs = _last_headers(client)
    assert hdrs.get("Authorization") == "Bearer static"
    assert IDENTITY_HEADER not in hdrs
