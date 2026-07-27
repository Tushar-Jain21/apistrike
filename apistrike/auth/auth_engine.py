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
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# Response fields we will look for when hunting for a token, in priority order.
DEFAULT_TOKEN_FIELDS = ("auth_token", "token", "access_token", "jwt", "id_token")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt(token: str) -> dict:
    """Decode a JWT WITHOUT verifying its signature (read-only inspection).

    Returns {"header": {...}, "payload": {...}, "signature": "<raw>"}.
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
    name: str                      # profile label, e.g. "userA", "admin"
    credentials: Credentials
    token: str = ""
    token_type: str = "Bearer"
    role: str = "user"
    extra_headers: dict = field(default_factory=dict)

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


class AuthEngine:
    """Logs identities in against a target API and hands out auth headers.

    The engine is deliberately transport-agnostic: it is given any object with
    an async ``request(method, url, **kwargs)`` coroutine (our ScopedHTTPClient),
    so scope + rate limiting are enforced for every login too.
    """

    def __init__(self, client, base_url: str = "", login_config: Optional[LoginConfig] = None):
        self.client = client                      # ScopedHTTPClient (injected)
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

    def _apply_token_response(self, ident: Identity, body: str) -> str:
        """Pure: parse a login response body, extract + store the token."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            data = body
        token = _find_token(data, self.config.token_fields)
        if not token:
            raise ValueError(
                "Login succeeded but no token field was found in the response "
                f"(looked for: {', '.join(self.config.token_fields)})."
            )
        ident.token = token
        ident.credentials.token = token
        return token

    async def login(self, ident: Identity) -> str:
        """Log one identity in via the scoped client and store its token."""
        if ident.token:
            return ident.token
        url = self._login_url()
        payload = self._login_payload(ident)
        if self.config.send_as_json:
            ev = await self.client.request(self.config.method, url, json=payload)
        else:
            ev = await self.client.request(self.config.method, url, data=payload)
        if ev.status_code >= 400:
            raise ValueError(
                f"Login failed for '{ident.name}' (HTTP {ev.status_code}): {ev.body[:200]}"
            )
        return self._apply_token_response(ident, ev.body)

    async def login_all(self) -> None:
        """Log in every identity that has a password but no token yet."""
        for ident in self.identities.values():
            if not ident.token and ident.credentials.password:
                await self.login(ident)
