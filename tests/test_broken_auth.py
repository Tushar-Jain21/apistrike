import asyncio
import hmac
import json
import time

import pytest

from apistrike.modules.broken_auth import (
    BrokenAuthModule,
    crack_hs256_secret,
    forge_alg_none,
    hs256_signature,
    resign_hs256,
    _encode_segment,
)
from apistrike.auth.auth_engine import decode_jwt, _b64url_decode
from apistrike.core.findings import FindingsStore

NOW = int(time.time())


def _mint(secret, payload, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    h = _encode_segment(header)
    p = _encode_segment(payload)
    return f"{h}.{p}.{hs256_signature(f'{h}.{p}'.encode(), secret)}"


class _Ev:
    def __init__(self, status_code, body="", url=""):
        self.status_code = status_code
        self.body = body
        self.url = url


class _Server:
    """A tiny fake API that validates bearer JWTs like a real server."""

    def __init__(self, secret, accept_alg_none=False, enforce_expiry=True):
        self.secret = secret
        self.accept_alg_none = accept_alg_none
        self.enforce_expiry = enforce_expiry

    def handle(self, url, headers):
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _Ev(401, "unauth", url)
        parts = auth[len("Bearer "):].split(".")
        if len(parts) != 3:
            return _Ev(401, "bad", url)
        alg = str(json.loads(_b64url_decode(parts[0])).get("alg", "")).lower()
        if alg == "none":
            return _Ev(200 if self.accept_alg_none else 401, "", url)
        expected = hs256_signature(f"{parts[0]}.{parts[1]}".encode(), self.secret)
        if not hmac.compare_digest(expected, parts[2]):
            return _Ev(401, "badsig", url)
        exp = json.loads(_b64url_decode(parts[1])).get("exp")
        if self.enforce_expiry and exp is not None and exp < int(time.time()):
            return _Ev(401, "expired", url)
        return _Ev(200, "ok", url)


class _Client:
    def __init__(self, server):
        self.server = server

    async def get(self, url, headers=None, **kwargs):
        return self.server.handle(url, headers or {})


def test_crack_finds_weak_secret():
    assert crack_hs256_secret(_mint("secret123", {"sub": "name1"})) == "secret123"


def test_crack_returns_none_for_strong_secret():
    assert crack_hs256_secret(_mint("Zx9!longrandom-not-in-list-8f3a2b7c9d", {"sub": "x"})) is None


def test_forge_alg_none_variants():
    forged = forge_alg_none(_mint("secret123", {"sub": "name1"}))
    assert len(forged) == 4
    for f in forged:
        assert f.endswith(".")
        assert decode_jwt(f)["header"]["alg"].lower() == "none"
        assert decode_jwt(f)["payload"]["sub"] == "name1"


def test_resign_updates_claims_and_signature():
    rs = resign_hs256(_mint("secret123", {"sub": "name1"}), "secret123", {"sub": "admin"})
    assert decode_jwt(rs)["payload"]["sub"] == "admin"
    assert crack_hs256_secret(rs) == "secret123"


def test_vulnerable_server_yields_three_findings():
    tok = _mint("secret123", {"sub": "name1", "iat": NOW, "exp": NOW + 60})
    client = _Client(_Server("secret123", accept_alg_none=True, enforce_expiry=False))
    store = FindingsStore(":memory:")
    module = BrokenAuthModule(client, "http://localhost:5000", valid_token=tok, probe_path="/me")
    result = asyncio.run(module.run(store=store))
    assert result.alg_none_accepted
    assert result.cracked_secret == "secret123"
    assert result.forged_identity_accepted
    assert result.expired_accepted
    assert len(result.findings) == 3
    assert all(f.owasp_id == "API2:2023" for f in result.findings)
    assert store.summary()["total"] == 3
    store.close()


def test_secure_server_yields_no_findings():
    secret = "Zx9!longrandom-not-in-list-8f3a2b7c9d0e1f2a3b4c"
    tok = _mint(secret, {"sub": "name1", "iat": NOW, "exp": NOW + 60})
    client = _Client(_Server(secret, accept_alg_none=False, enforce_expiry=True))
    store = FindingsStore(":memory:")
    module = BrokenAuthModule(client, "http://localhost:5000", valid_token=tok, probe_path="/me")
    result = asyncio.run(module.run(store=store))
    assert result.findings == []
    assert result.cracked_secret is None
    assert not result.alg_none_accepted
    assert not result.expired_accepted
    store.close()


def test_requires_valid_token():
    with pytest.raises(ValueError):
        BrokenAuthModule(_Client(_Server("x")), "http://localhost:5000", valid_token="")
