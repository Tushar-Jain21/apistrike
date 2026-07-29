"""Authentication engine for APIStrike.

Manages one or more authenticated identities against a target API so the
authorization modules (BOLA = object level, BFLA = function level) can compare
what different users are allowed to see and do. It also decodes JWTs read-only,
so the broken-auth module can later tamper with algorithm, secret, and expiry.

Design notes:
- No module calls httpx directly. `login()` drives the shared ScopedHTTPClient
  that is injected in, so scope gating + rate limiting always apply.
- All token / profile / JWT logic is pure and dependency-light (standard library
  only), so it is trivial to unit test without a live server.

v1.6 evolution (Auth subsystem, PR-8):
- Login attempts are now *classified* (see AuthOutcome). This fixes #91/#101:
  VAmPI returns HTTP 200 with a ``{"status": "fail"}`` body for bad
  credentials, which used to slip past the ``status >= 400`` gate and get
  misreported as "no token field found". A rejected credential is now reported
  as such, distinct from a genuinely unrecognised token field.
- Identities gained a session lifecycle (``refresh_token`` / ``expires_at`` /
  ``provider``) plus bounded, single-shot re-authentication on 401/expiry, so a
  token expiring mid-scan no longer silently degrades into false negatives.
- Pluggable providers (password / static token / OAuth2) live in
  ``apistrike.auth.providers`` and drive this engine; the historical form-login
  path is preserved unchanged as the default.
"""
from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

# Response fields we will look for when hunting for a token, in priority order.
DEFAULT_TOKEN_FIELDS = ("auth_token", "token", "access_token", "jwt", "id_token")

# Body markers that mean the server *rejected* the request even though it may
# have answered with a 2xx status (VAmPI does exactly this -- see #91/#101).
_REJECTION_STATUS_VALUES = {"fail", "failure", "error", "unauthorized", "denied"}
_REJECTION_KEYS = ("error", "errors", "error_description")


class AuthOutcome(str, Enum):
    """Classified result of a single login attempt.

    Fixes #91/#101 by distinguishing *why* a login produced no usable token
    instead of collapsing every failure into one misleading message.
    """

    SUCCESS = "success"                       # a token was issued
    CREDENTIALS_REJECTED = "credentials_rejected"  # server said no (200+fail, 401, 403)
    TOKEN_NOT_FOUND = "token_not_found"       # 2xx, no rejection marker, no known token field
    TRANSPORT_ERROR = "transport_error"       # 4xx (other) / 5xx / network-level failure


class AuthError(ValueError):
    """Raised when authentication cannot complete.

    Subclasses ``ValueError`` for backwards compatibility: earlier code and
    tests expect ``login()`` / ``_apply_token_response`` failures to be
    ``ValueError``. The ``outcome`` attribute carries the classified reason.
    """

    def __init__(self, message: str, outcome: Optional["AuthOutcome"] = None):
        super().__init__(message)
        self.outcome = outcome


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> dict:
    """Decode a JWT WITHOUT verifying its signature (read-only inspection).

    Returns {"header": {...}, "payload": {...}, "signature": "..."}.
    For analysis / tamper tests only -- never use this to trust a token.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a well-formed JWT (expected 3 dot-separated parts).")
    header_raw, payload_raw, signature = parts
    try:
        header = json.loads(_b64url_decode(header_raw))
        payload = json.loads(_b64url_decode(payload_raw))
    except (binascii.Error, json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not decode JWT segments: {exc}") from exc
    return {"header": header, "payload": payload, "signature": signature}


@dataclass
class Credentials:
    """Login material for one identity (password OR a pre-issued token)."""

    username: str
    password: str = ""
    token: str = ""


@dataclass
class Identity:
    """An authenticated (or to-be-authenticated) user profile."""

    name: str  # profile label, e.g. "userA", "admin"
    credentials: Credentials
    token: str = ""
    token_type: str = "Bearer"
    role: str = "user"
    extra_headers: dict = field(default_factory=dict)
    # --- session lifecycle (v1.6) ------------------------------------------
    refresh_token: str = ""
    # Epoch seconds when the token expires. ``None`` means unknown -> we never
    # invent an expiry we cannot prove (see is_expired).
    expires_at: Optional[float] = None
    # The AuthProvider that can (re)authenticate this identity. Kept as Any to
    # avoid a hard import cycle with apistrike.auth.providers.
    provider: Any = None

    @property
    def authenticated(self) -> bool:
        return bool(self.token)

    def auth_headers(self) -> dict:
        """Headers to attach to a request made AS this identity."""
        headers = dict(self.extra_headers)
        if self.token:
            headers["Authorization"] = f"{self.token_type} {self.token}".strip()
        return headers

    def claims(self) -> dict:
        """Decoded JWT payload (empty dict if the token is not a JWT)."""
        if not self.token:
            return {}
        try:
            return decode_jwt(self.token)["payload"]
        except ValueError:
            return {}

    def is_expired(self, *, now: Optional[float] = None, skew: float = 30.0) -> bool:
        """True if we can *prove* the token has expired (within ``skew`` seconds).

        Unknown expiry (``expires_at is None``) is treated as NOT expired: we
        never force a re-auth we cannot justify. ``skew`` refreshes slightly
        early to avoid racing the server clock.
        """
        if self.expires_at is None:
            return False
        now = time.time() if now is None else now
        return now >= (self.expires_at - skew)


@dataclass
class LoginConfig:
    """How to obtain a token for a particular target API."""

    login_path: str = "/users/v1/login"
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    token_fields: tuple = DEFAULT_TOKEN_FIELDS
    token_type: str = "Bearer"
    send_as_json: bool = True


def _find_token(data: Any, fields: Iterable[str]) -> str:
    """Search a decoded JSON response for the first matching token field.

    Checks the top level first, then one level deep (e.g. {"data": {...}}).
    """
    if not isinstance(data, dict):
        return ""
    for f in fields:
        val = data.get(f)
        if isinstance(val, str) and val:
            return val
    for v in data.values():
        if isinstance(v, dict):
            found = _find_token(v, fields)
            if found:
                return found
    return ""


def _coerce_json(body: Any) -> Any:
    """Best-effort parse of a response body into JSON, else return as-is."""
    if isinstance(body, (dict, list)):
        return body
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return body


def _looks_rejected(data: Any) -> bool:
    """Heuristic: does this 2xx body actually signal a rejected request?

    Recognises the VAmPI shape ``{"status": "fail", ...}`` (#91) plus the common
    ``{"success": false}`` and ``{"error": "..."}`` conventions.
    """
    if not isinstance(data, dict):
        return False
    status = data.get("status")
    if isinstance(status, str) and status.strip().lower() in _REJECTION_STATUS_VALUES:
        return True
    if data.get("success") is False:
        return True
    for k in _REJECTION_KEYS:
        if data.get(k):
            return True
    return False


def _extract_expires_at(data: Any, *, now: Optional[float] = None) -> Optional[float]:
    """Return an absolute expiry (epoch seconds) from an ``expires_in`` field."""
    if not isinstance(data, dict):
        return None
    exp = data.get("expires_in")
    if isinstance(exp, (int, float)) and exp > 0:
        base = time.time() if now is None else now
        return base + float(exp)
    return None


class AuthEngine:
    """Logs identities in against a target API and hands out auth headers.

    The engine is deliberately transport-agnostic: it is given any object with
    an async ``request(method, url, **kwargs)`` coroutine (our ScopedHTTPClient),
    so scope + rate limiting are enforced for every login too.
    """

    def __init__(self, client, base_url: str = "", login_config: Optional[LoginConfig] = None):
        self.client = client  # ScopedHTTPClient (injected)
        self.base_url = base_url.rstrip("/")
        self.config = login_config or LoginConfig()
        self.identities: dict = {}

    def add_identity(self, name: str, username: str = "", password: str = "",
                     token: str = "", role: str = "user") -> Identity:
        ident = Identity(
            name=name,
            credentials=Credentials(username=username or name, password=password, token=token),
            token=token,
            token_type=self.config.token_type,
            role=role,
        )
        self.identities[name] = ident
        return ident

    def register_identity(self, ident: Identity) -> Identity:
        """Attach an already-built Identity (used by declarative auth profiles)."""
        self.identities[ident.name] = ident
        return ident

    def get(self, name: str) -> Identity:
        return self.identities[name]

    def profiles(self) -> list:
        return list(self.identities.values())

    def _login_url(self) -> str:
        return f"{self.base_url}{self.config.login_path}"

    def _login_payload(self, ident: Identity) -> dict:
        return {
            self.config.username_field: ident.credentials.username,
            self.config.password_field: ident.credentials.password,
        }

    # -- classification (the #91/#101 fix) ---------------------------------
    def classify_login(self, status_code: int, body: Any) -> AuthOutcome:
        """Classify a login response by status AND body.

        This is the heart of the #91 fix: a 2xx response with a failure body is
        a credential rejection, not a mysterious missing token field.
        """
        if status_code >= 500:
            return AuthOutcome.TRANSPORT_ERROR
        if status_code in (401, 403):
            return AuthOutcome.CREDENTIALS_REJECTED
        if status_code >= 400:
            return AuthOutcome.TRANSPORT_ERROR
        data = _coerce_json(body)
        if _find_token(data, self.config.token_fields):
            return AuthOutcome.SUCCESS
        if _looks_rejected(data):
            return AuthOutcome.CREDENTIALS_REJECTED
        return AuthOutcome.TOKEN_NOT_FOUND

    def _apply_token_response(self, ident: Identity, body: str) -> str:
        """Pure: parse a login response body, extract + store the token.

        Raises AuthError (a ValueError) when no token is present, distinguishing
        an explicit credential rejection from an unrecognised token field.
        """
        data = _coerce_json(body)
        token = _find_token(data, self.config.token_fields)
        if not token:
            if _looks_rejected(data):
                raise AuthError(
                    "Authentication rejected: the server accepted the request but "
                    "issued no token (credentials likely invalid). "
                    f"Response: {str(body)[:200]}",
                    AuthOutcome.CREDENTIALS_REJECTED,
                )
            raise AuthError(
                "Login succeeded but no token field was found in the response "
                f"(looked for: {', '.join(self.config.token_fields)}).",
                AuthOutcome.TOKEN_NOT_FOUND,
            )
        ident.token = token
        ident.credentials.token = token
        exp = _extract_expires_at(data)
        if exp is not None:
            ident.expires_at = exp
        return token

    async def _do_password_login(self, ident: Identity) -> str:
        """Perform a form/JSON password login unconditionally (no token short-circuit)."""
        url = self._login_url()
        payload = self._login_payload(ident)
        if self.config.send_as_json:
            ev = await self.client.request(self.config.method, url, json=payload)
        else:
            ev = await self.client.request(self.config.method, url, data=payload)
        outcome = self.classify_login(ev.status_code, ev.body)
        if outcome is AuthOutcome.SUCCESS:
            return self._apply_token_response(ident, ev.body)
        if outcome is AuthOutcome.CREDENTIALS_REJECTED:
            raise AuthError(
                f"Authentication rejected for '{ident.name}' (HTTP {ev.status_code}): "
                f"the server issued no token, credentials are likely invalid. "
                f"Response: {str(ev.body)[:200]}",
                AuthOutcome.CREDENTIALS_REJECTED,
            )
        if outcome is AuthOutcome.TRANSPORT_ERROR:
            raise AuthError(
                f"Login transport error for '{ident.name}' (HTTP {ev.status_code}): "
                f"{str(ev.body)[:200]}",
                AuthOutcome.TRANSPORT_ERROR,
            )
        # TOKEN_NOT_FOUND
        raise AuthError(
            f"Login for '{ident.name}' returned HTTP {ev.status_code} but no token "
            f"field was found (looked for: {', '.join(self.config.token_fields)}).",
            AuthOutcome.TOKEN_NOT_FOUND,
        )

    async def login(self, ident: Identity) -> str:
        """Log one identity in via the scoped client and store its token."""
        if ident.token:
            return ident.token
        return await self._do_password_login(ident)

    async def login_all(self) -> None:
        """Log in every identity that still needs a token.

        Provider-backed identities (declarative profiles / OAuth2 / static
        token) are authenticated through their provider; classic password
        identities keep the historical behavior.
        """
        for ident in self.identities.values():
            if ident.token:
                continue
            if ident.provider is not None:
                await self.ensure_fresh(ident)
            elif ident.credentials.password:
                await self.login(ident)

    # -- session lifecycle (v1.6) ------------------------------------------
    async def ensure_fresh(self, ident: Identity) -> str:
        """Return a usable token for ``ident``, (re)authenticating if needed."""
        if ident.token and not ident.is_expired():
            return ident.token
        if ident.provider is not None:
            if ident.token and ident.is_expired():
                return await ident.provider.refresh(ident, self)
            return await ident.provider.authenticate(ident, self)
        # No provider: fall back to the classic password login path.
        if ident.is_expired():
            ident.token = ""  # force re-login
        return await self.login(ident)

    async def _force_reauth(self, ident: Identity) -> str:
        """Force a single re-authentication (used when the server returns 401).

        A 401 means the server rejected THIS token regardless of what we
        believe locally about its expiry, so we must not short-circuit.
        """
        if ident.provider is not None:
            if ident.token:
                return await ident.provider.refresh(ident, self)
            return await ident.provider.authenticate(ident, self)
        ident.token = ""
        return await self.login(ident)

    async def authed_request(self, ident: Identity, method: str, url: str, **kwargs):
        """Make a request AS ``ident`` with a single bounded re-auth on 401/expiry.

        This is intentionally distinct from the v1.5 HTTP retry policy: it never
        blindly replays a request, it only re-authenticates once (to recover a
        token that expired mid-scan) and then retries exactly one time. An
        expired/invalid token therefore surfaces honestly instead of masquerading
        as a clean 401 "not vulnerable" result.
        """
        return await self._authed_request(ident, method, url, kwargs, reauthed=False)

    async def _authed_request(self, ident: Identity, method: str, url: str,
                              kwargs: dict, reauthed: bool):
        if not reauthed and ident.is_expired():
            await self.ensure_fresh(ident)
        base_headers = dict(kwargs.get("headers") or {})
        call_kwargs = dict(kwargs)
        call_kwargs["headers"] = {**base_headers, **ident.auth_headers()}
        ev = await self.client.request(method, url, **call_kwargs)
        if getattr(ev, "status_code", None) == 401 and not reauthed and ident.provider is not None:
            # Server rejected this token; force one re-auth then retry once.
            await self._force_reauth(ident)
            return await self._authed_request(ident, method, url, kwargs, reauthed=True)
        return ev
