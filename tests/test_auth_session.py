"""Session lifecycle: expiry awareness + bounded single re-auth (ADR-0014)."""
import asyncio
import time

from apistrike.auth.auth_engine import AuthEngine, Credentials, Identity


class Ev:
    def __init__(self, status_code, body=""):
        self.status_code = status_code
        self.body = body


class SeqClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


class StubProvider:
    def __init__(self):
        self.auth_calls = 0
        self.refresh_calls = 0

    async def authenticate(self, ident, engine):
        self.auth_calls += 1
        ident.token = "FRESH"
        return ident.token

    async def refresh(self, ident, engine):
        self.refresh_calls += 1
        ident.token = "REFRESHED"
        return ident.token


def test_is_expired_semantics():
    ident = Identity(name="a", credentials=Credentials("a"), token="t")
    assert ident.is_expired() is False  # unknown expiry is never treated as expired
    ident.expires_at = time.time() - 10
    assert ident.is_expired() is True
    ident.expires_at = time.time() + 3600
    assert ident.is_expired() is False


def test_ensure_fresh_authenticates_when_no_token():
    eng = AuthEngine(client=None)
    prov = StubProvider()
    ident = Identity(name="a", credentials=Credentials("a"), provider=prov)
    assert asyncio.run(eng.ensure_fresh(ident)) == "FRESH"
    assert prov.auth_calls == 1


def test_ensure_fresh_noop_when_valid():
    eng = AuthEngine(client=None)
    prov = StubProvider()
    ident = Identity(name="a", credentials=Credentials("a"), token="good", provider=prov)
    assert asyncio.run(eng.ensure_fresh(ident)) == "good"
    assert prov.auth_calls == 0 and prov.refresh_calls == 0


def test_ensure_fresh_refreshes_when_expired():
    eng = AuthEngine(client=None)
    prov = StubProvider()
    ident = Identity(name="a", credentials=Credentials("a"), token="old", provider=prov)
    ident.expires_at = time.time() - 5
    assert asyncio.run(eng.ensure_fresh(ident)) == "REFRESHED"
    assert prov.refresh_calls == 1


def test_authed_request_reauths_once_on_401():
    client = SeqClient([Ev(401), Ev(200, "ok")])
    eng = AuthEngine(client=client)
    prov = StubProvider()
    ident = Identity(name="a", credentials=Credentials("a"), token="old", provider=prov)
    ev = asyncio.run(eng.authed_request(ident, "GET", "http://localhost:5000/me"))
    assert ev.status_code == 200
    assert prov.refresh_calls == 1
    assert len(client.calls) == 2
    assert client.calls[1][2]["headers"]["Authorization"] == "Bearer REFRESHED"


def test_authed_request_does_not_loop_on_persistent_401():
    client = SeqClient([Ev(401), Ev(401)])
    eng = AuthEngine(client=client)
    prov = StubProvider()
    ident = Identity(name="a", credentials=Credentials("a"), token="old", provider=prov)
    ev = asyncio.run(eng.authed_request(ident, "GET", "http://localhost:5000/me"))
    assert ev.status_code == 401  # surfaced honestly, not masked
    assert len(client.calls) == 2  # exactly one re-auth + retry, no infinite loop
