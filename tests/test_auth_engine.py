import base64
import json

import pytest

from apistrike.auth.auth_engine import (
    DEFAULT_TOKEN_FIELDS,
    AuthEngine,
    Credentials,
    Identity,
    LoginConfig,
    _find_token,
    decode_jwt,
)


def _make_jwt(header: dict, payload: dict, sig: str = "sig") -> str:
    def enc(obj: dict) -> str:
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    return f"{enc(header)}.{enc(payload)}.{sig}"


def test_decode_jwt_reads_header_and_payload():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "name1", "role": "user"})
    decoded = decode_jwt(token)
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "name1"
    assert decoded["signature"] == "sig"


def test_decode_jwt_rejects_malformed():
    with pytest.raises(ValueError):
        decode_jwt("not-a-jwt")


def test_identity_auth_headers_and_claims():
    token = _make_jwt({"alg": "HS256"}, {"sub": "admin", "role": "admin"})
    ident = Identity(name="admin", credentials=Credentials("admin", "pass"), token=token)
    assert ident.authenticated
    assert ident.auth_headers()["Authorization"] == f"Bearer {token}"
    assert ident.claims()["role"] == "admin"


def test_unauthenticated_identity_has_no_auth_header():
    ident = Identity(name="anon", credentials=Credentials("anon"))
    assert not ident.authenticated
    assert "Authorization" not in ident.auth_headers()
    assert ident.claims() == {}


def test_find_token_top_level_and_nested():
    assert _find_token({"auth_token": "abc"}, DEFAULT_TOKEN_FIELDS) == "abc"
    assert _find_token({"data": {"access_token": "xyz"}}, DEFAULT_TOKEN_FIELDS) == "xyz"
    assert _find_token({"nope": "1"}, DEFAULT_TOKEN_FIELDS) == ""


def test_apply_token_response_extracts_and_sets():
    eng = AuthEngine(client=None, base_url="http://localhost:5000")
    ident = eng.add_identity("name1", username="name1", password="pass1")
    token = eng._apply_token_response(ident, json.dumps({"message": "ok", "auth_token": "TOK123"}))
    assert token == "TOK123"
    assert ident.token == "TOK123"
    assert ident.auth_headers()["Authorization"] == "Bearer TOK123"


def test_apply_token_response_raises_when_missing():
    eng = AuthEngine(client=None)
    ident = eng.add_identity("x", username="x", password="y")
    with pytest.raises(ValueError):
        eng._apply_token_response(ident, json.dumps({"message": "no token here"}))


def test_login_payload_and_url_use_config():
    eng = AuthEngine(client=None, base_url="http://localhost:5000/")
    ident = eng.add_identity("name1", username="name1", password="pass1")
    assert eng._login_payload(ident) == {"username": "name1", "password": "pass1"}
    assert eng._login_url() == "http://localhost:5000/users/v1/login"
