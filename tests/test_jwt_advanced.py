"""Offline tests for the advanced JWT attack helpers.

Pure-function tests need no network and no live server. The RSA-backed tests
skip automatically when 'cryptography' is not installed.
"""
import base64
import json

import pytest

from apistrike.modules.jwt_advanced import (
    forge_algorithm_confusion,
    forge_kid_injection,
    forge_jwk_header_injection,
    jwk_to_pem,
    hs256_signature,
    token_alg,
    _HAS_CRYPTO,
)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "==="))


def _token(alg: str = "RS256", claims: dict | None = None) -> str:
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims or {"sub": "alice"}).encode())
    return f"{header}.{payload}.AAAA"


def test_token_alg():
    assert token_alg(_token("RS256")) == "RS256"
    assert token_alg("not-a-jwt") == ""


def test_algorithm_confusion_signs_with_public_key():
    pem = "-----BEGIN PUBLIC KEY-----\nMIIBFAKE\n-----END PUBLIC KEY-----\n"
    forged = forge_algorithm_confusion(_token(), pem, {"sub": "admin"})
    assert forged, "should emit at least one variant"
    variants = {pem, pem.strip(), pem.strip() + "\n", pem.rstrip("\n")}
    for t in forged:
        h_raw, p_raw, sig = t.split(".")
        assert _decode(h_raw)["alg"] == "HS256"
        assert _decode(p_raw)["sub"] == "admin"
        expected = {hs256_signature(f"{h_raw}.{p_raw}".encode(), s) for s in variants}
        assert sig in expected


def test_kid_injection_uses_empty_key():
    forged = forge_kid_injection(_token(alg="HS256"))
    assert len(forged) >= 2
    for t in forged:
        h_raw, p_raw, sig = t.split(".")
        header = _decode(h_raw)
        assert "kid" in header and header["alg"] == "HS256"
        assert sig == hs256_signature(f"{h_raw}.{p_raw}".encode(), "")


@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
def test_jwk_injection_roundtrips_through_jwk_to_pem():
    t = forge_jwk_header_injection(_token(), {"sub": "admin"})
    assert t is not None
    header = _decode(t.split(".")[0])
    assert header["alg"] == "RS256"
    assert header["jwk"]["kty"] == "RSA"
    pem = jwk_to_pem(header["jwk"])
    assert pem and pem.startswith("-----BEGIN PUBLIC KEY-----")


@pytest.mark.skipif(_HAS_CRYPTO, reason="only meaningful without cryptography")
def test_jwk_injection_degrades_gracefully_without_crypto():
    assert forge_jwk_header_injection(_token()) is None


class _FakeEvidence:
    def __init__(self, status_code):
        self.status_code = status_code
        self.body = "{}"


class _FakeResult:
    def __init__(self):
        self.findings = []
        self.notes = []


class _FakeModule:
    """Minimal stand-in for BrokenAuthModule to exercise the live orchestration."""
    OWASP_ID = "API2:2023"
    probe_path = "/me"

    def __init__(self, valid_token, accept_forged=True):
        self.valid_token = valid_token
        self._accept = accept_forged
        self.status_valid = 200

    async def _probe(self, token):
        return _FakeEvidence(200 if self._accept else 401)

    def _authorized(self, status):
        return status == self.status_valid and status < 400

    def _evidence(self, check, token, status, extra=None):
        return {"check": check, "status": status, **(extra or {})}


@pytest.mark.asyncio
async def test_kid_injection_records_finding_when_accepted():
    from apistrike.modules.jwt_advanced import run_advanced_jwt_checks
    module = _FakeModule(_token(alg="HS256"), accept_forged=True)
    result = _FakeResult()
    await run_advanced_jwt_checks(module, result, live=True)
    titles = [f.title for f in result.findings]
    assert any("kid" in t for t in titles)


@pytest.mark.asyncio
async def test_no_findings_when_rejected():
    from apistrike.modules.jwt_advanced import run_advanced_jwt_checks
    module = _FakeModule(_token(alg="HS256"), accept_forged=False)
    result = _FakeResult()
    await run_advanced_jwt_checks(module, result, live=True)
    assert result.findings == []
