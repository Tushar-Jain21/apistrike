"""Pluggable auth providers: password, static token, OAuth2 (ADR-0011/0012)."""
import asyncio
import json
import time

import pytest

from apistrike.auth.auth_engine import AuthEngine, AuthError, Credentials, Identity
from apistrike.auth.providers import (
    OAuth2Provider,
    PasswordLoginProvider,
    TokenProvider,
)


class Ev:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_password_provider_logs_in():
    client = FakeClient([Ev(200, json.dumps({"auth_token": "TOK"}))])
    eng = AuthEngine(client=client, base_url="http://localhost:5000")
    ident = eng.add_identity("u", username="u", password="p")
    tok = asyncio.run(PasswordLoginProvider().authenticate(ident, eng))
    assert tok == "TOK"
    assert ident.token == "TOK"


def test_password_provider_reports_rejection_clearly():
    # VAmPI-style 200 + fail body must raise a credentials-rejected error.
    client = FakeClient([Ev(200, json.dumps({"status": "fail", "message": "bad"}))])
    eng = AuthEngine(client=client, base_url="http://localhost:5000")
    ident = eng.add_identity("u", username="u", password="p")
    with pytest.raises(AuthError) as ei:
        asyncio.run(PasswordLoginProvider().authenticate(ident, eng))
    assert "rejected" in str(ei.value).lower()


def test_token_provider_uses_static_and_cannot_refresh():
    eng = AuthEngine(client=None)
    ident = Identity(name="a", credentials=Credentials("a", token="STATIC"))
    prov = TokenProvider()
    assert asyncio.run(prov.authenticate(ident, eng)) == "STATIC"
    assert ident.token == "STATIC"
    with pytest.raises(AuthError):
        asyncio.run(prov.refresh(ident, eng))


def test_oauth2_client_credentials():
    body = json.dumps({
        "access_token": "AT", "refresh_token": "RT",
        "expires_in": 3600, "token_type": "bearer",
    })
    client = FakeClient([Ev(200, body)])
    eng = AuthEngine(client=client)
    ident = Identity(name="svc", credentials=Credentials("svc"))
    prov = OAuth2Provider(
        token_url="http://localhost:5000/oauth/token",
        grant="client_credentials", client_id="cid", client_secret="sec",
    )
    ident.provider = prov
    tok = asyncio.run(prov.authenticate(ident, eng))
    assert tok == "AT"
    assert ident.refresh_token == "RT"
    assert ident.token_type == "Bearer"
    assert ident.expires_at is not None and ident.expires_at > time.time()
    assert client.calls[0][2]["data"]["grant_type"] == "client_credentials"


def test_oauth2_rejects_interactive_grant():
    with pytest.raises(AuthError):
        OAuth2Provider(token_url="http://x/y", grant="authorization_code")


def test_oauth2_refresh_uses_refresh_token_grant():
    first = json.dumps({"access_token": "AT1", "refresh_token": "RT1", "expires_in": 1})
    second = json.dumps({"access_token": "AT2", "refresh_token": "RT2", "expires_in": 3600})
    client = FakeClient([Ev(200, first), Ev(200, second)])
    eng = AuthEngine(client=client)
    ident = Identity(name="svc", credentials=Credentials("svc"))
    prov = OAuth2Provider(
        token_url="http://localhost:5000/oauth/token",
        grant="password", username="u", password="p",
    )
    ident.provider = prov
    asyncio.run(prov.authenticate(ident, eng))
    assert ident.token == "AT1"
    asyncio.run(prov.refresh(ident, eng))
    assert ident.token == "AT2"
    assert client.calls[1][2]["data"]["grant_type"] == "refresh_token"
    assert client.calls[1][2]["data"]["refresh_token"] == "RT1"
