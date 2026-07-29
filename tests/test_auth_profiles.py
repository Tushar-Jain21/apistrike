"""Declarative auth profiles + env-referenced secrets (ADR-0010/0013)."""
import pytest

from apistrike.auth.auth_engine import AuthEngine, AuthError
from apistrike.auth.profiles import (
    build_identities,
    register_scope_identities,
    resolve_value,
)
from apistrike.auth.providers import (
    OAuth2Provider,
    PasswordLoginProvider,
    TokenProvider,
)


class ScopeStub:
    def __init__(self, auth):
        self.auth = auth


def test_resolve_env_reference(monkeypatch):
    monkeypatch.setenv("APISTRIKE_TEST_SECRET", "s3cr3t")
    assert resolve_value("${APISTRIKE_TEST_SECRET}", field_name="password") == "s3cr3t"


def test_resolve_rejects_inline_secret():
    with pytest.raises(AuthError):
        resolve_value("literalpw", field_name="password")


def test_resolve_missing_env_raises(monkeypatch):
    monkeypatch.delenv("APISTRIKE_MISSING", raising=False)
    with pytest.raises(AuthError):
        resolve_value("${APISTRIKE_MISSING}", field_name="token")


def test_resolve_allows_literal_nonsecret():
    assert resolve_value("name1", field_name="username") == "name1"


def test_build_password_and_token_identities(monkeypatch):
    monkeypatch.setenv("PW", "pass1")
    monkeypatch.setenv("TOK", "tok-123")
    scope = ScopeStub([
        {"name": "user1", "type": "password", "username": "name1", "password": "${PW}", "role": "user"},
        {"name": "admin", "type": "token", "token": "${TOK}", "role": "admin"},
    ])
    by = {i.name: i for i in build_identities(scope)}
    assert isinstance(by["user1"].provider, PasswordLoginProvider)
    assert by["user1"].credentials.password == "pass1"
    assert isinstance(by["admin"].provider, TokenProvider)
    assert by["admin"].token == "tok-123"
    assert by["admin"].role == "admin"


def test_build_oauth2_identity(monkeypatch):
    monkeypatch.setenv("CS", "shh")
    scope = ScopeStub([
        {"name": "svc", "type": "oauth2", "grant": "client_credentials",
         "token_url": "http://localhost:5000/oauth/token",
         "client_id": "cid", "client_secret": "${CS}", "scope": "read"},
    ])
    prov = build_identities(scope)[0].provider
    assert isinstance(prov, OAuth2Provider)
    assert prov.client_secret == "shh"


def test_register_scope_identities_adds_to_engine(monkeypatch):
    monkeypatch.setenv("PW", "pass1")
    eng = AuthEngine(client=None, base_url="http://localhost:5000")
    scope = ScopeStub([{"name": "user1", "type": "password", "username": "name1", "password": "${PW}"}])
    got = register_scope_identities(eng, scope)
    assert len(got) == 1
    assert "user1" in eng.identities


def test_unknown_type_raises():
    with pytest.raises(AuthError):
        build_identities(ScopeStub([{"name": "x", "type": "magic"}]))


def test_empty_scope_yields_no_identities():
    assert build_identities(ScopeStub([])) == []
    assert build_identities(None) == []
