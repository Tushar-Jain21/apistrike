"""Pluggable authentication providers for APIStrike (v1.6, PR-8).

A *provider* knows how to turn an Identity's credentials into a bearer token
and, where the mechanism supports it, how to refresh that token. The historical
form/JSON password login is preserved verbatim as ``PasswordLoginProvider`` and
remains the default, so every existing call site keeps working unchanged
(ADR-0011).

Automation boundary (ADR-0012): only non-interactive OAuth2 grants
(``client_credentials``, ``password``, ``refresh_token``) are automated. Browser
/ MFA flows (``authorization_code`` + PKCE) are deliberately NOT automated --
capture a token out of band and feed it in as a static ``token`` provider.

Every provider drives the injected ScopedHTTPClient, so scope gating, rate
limiting and the v1.5 retry policy apply to authentication traffic too. No
provider imports httpx directly.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

from apistrike.auth.auth_engine import (
    AuthError,
    AuthOutcome,
    Identity,
    LoginConfig,
    _coerce_json,
    _extract_expires_at,
    _find_token,
    _looks_rejected,
)


@runtime_checkable
class AuthProvider(Protocol):
    """Structural contract every provider satisfies.

    ``authenticate`` obtains a fresh token from scratch; ``refresh`` renews an
    existing session (falling back to a full re-authentication when the
    mechanism has no cheaper refresh path).
    """

    async def authenticate(self, ident: Identity, engine: Any) -> str: ...
    async def refresh(self, ident: Identity, engine: Any) -> str: ...


@dataclass
class PasswordLoginProvider:
    """Wraps the classic form/JSON password login (default provider).

    When ``login_config`` is None the engine's own LoginConfig is used, so this
    is behaviour-identical to the pre-v1.6 path. Providing a config lets a
    declarative profile point at a non-default login endpoint.
    """

    login_config: Optional[LoginConfig] = None

    async def authenticate(self, ident: Identity, engine: Any) -> str:
        prev = engine.config
        try:
            if self.login_config is not None:
                engine.config = self.login_config
            ident.token = ""  # force the login request (skip the token short-circuit)
            return await engine._do_password_login(ident)
        finally:
            engine.config = prev

    async def refresh(self, ident: Identity, engine: Any) -> str:
        # Password logins have no refresh token; re-authenticate from scratch.
        return await self.authenticate(ident, engine)


@dataclass
class TokenProvider:
    """Uses a pre-issued static token (e.g. captured from a browser/MFA flow)."""

    async def authenticate(self, ident: Identity, engine: Any) -> str:
        token = ident.token or ident.credentials.token
        if not token:
            raise AuthError(
                f"TokenProvider for '{ident.name}' has no pre-issued token to use.",
                AuthOutcome.CREDENTIALS_REJECTED,
            )
        ident.token = token
        ident.credentials.token = token
        return token

    async def refresh(self, ident: Identity, engine: Any) -> str:
        raise AuthError(
            f"Static token for '{ident.name}' expired and cannot be refreshed "
            "automatically. Capture a fresh token (e.g. re-run the browser/MFA "
            "flow) and supply it again.",
            AuthOutcome.CREDENTIALS_REJECTED,
        )


_AUTOMATABLE_GRANTS = {"client_credentials", "password", "refresh_token"}
_INTERACTIVE_GRANTS = {"authorization_code", "implicit", "device_code"}


@dataclass
class OAuth2Provider:
    """OAuth2 token endpoint client for non-interactive grants (ADR-0012).

    Supported grants: client_credentials, password, refresh_token. Interactive
    grants (authorization_code / implicit / device_code) raise a clear error
    telling the operator to capture a token out of band and use TokenProvider.
    """

    token_url: str
    grant: str = "client_credentials"
    client_id: str = ""
    client_secret: str = ""
    username: str = ""
    password: str = ""
    scope: str = ""
    token_fields: tuple = ("access_token", "token", "id_token")
    extra_params: dict = field(default_factory=dict)

    def __post_init__(self):
        grant = (self.grant or "").strip().lower()
        if grant in _INTERACTIVE_GRANTS:
            raise AuthError(
                f"OAuth2 grant '{grant}' is interactive (browser/MFA) and is not "
                "automated by APIStrike (ADR-0012). Capture a token out of band "
                "and configure it as a static 'token' identity instead.",
                AuthOutcome.CREDENTIALS_REJECTED,
            )
        if grant not in _AUTOMATABLE_GRANTS:
            raise AuthError(
                f"Unsupported OAuth2 grant '{grant}'. Supported: "
                f"{', '.join(sorted(_AUTOMATABLE_GRANTS))}.",
                AuthOutcome.TRANSPORT_ERROR,
            )
        self.grant = grant

    def _token_request_params(self, ident: Identity, *, for_refresh: bool) -> dict:
        params = {"grant_type": self.grant}
        if self.grant == "client_credentials":
            pass
        elif self.grant == "password":
            params["username"] = self.username or ident.credentials.username
            params["password"] = self.password or ident.credentials.password
        if for_refresh or self.grant == "refresh_token":
            if not ident.refresh_token:
                raise AuthError(
                    f"Cannot refresh '{ident.name}': no refresh_token was issued.",
                    AuthOutcome.CREDENTIALS_REJECTED,
                )
            params = {"grant_type": "refresh_token", "refresh_token": ident.refresh_token}
        if self.client_id:
            params["client_id"] = self.client_id
        if self.client_secret:
            params["client_secret"] = self.client_secret
        if self.scope:
            params["scope"] = self.scope
        params.update(self.extra_params)
        return params

    async def _post_token(self, ident: Identity, engine: Any, *, for_refresh: bool) -> str:
        params = self._token_request_params(ident, for_refresh=for_refresh)
        # OAuth2 token endpoints take application/x-www-form-urlencoded bodies.
        ev = await engine.client.request("POST", self.token_url, data=params)
        status = getattr(ev, "status_code", 0)
        body = getattr(ev, "body", "")
        data = _coerce_json(body)
        if status >= 400 or _looks_rejected(data):
            raise AuthError(
                f"OAuth2 token request for '{ident.name}' failed (HTTP {status}): "
                f"{str(body)[:200]}",
                AuthOutcome.CREDENTIALS_REJECTED
                if status in (400, 401, 403)
                else AuthOutcome.TRANSPORT_ERROR,
            )
        token = _find_token(data, self.token_fields)
        if not token:
            raise AuthError(
                f"OAuth2 token endpoint for '{ident.name}' returned no access_token. "
                f"Response: {str(body)[:200]}",
                AuthOutcome.TOKEN_NOT_FOUND,
            )
        ident.token = token
        ident.credentials.token = token
        if isinstance(data, dict):
            new_refresh = data.get("refresh_token")
            if isinstance(new_refresh, str) and new_refresh:
                ident.refresh_token = new_refresh
            token_type = data.get("token_type")
            if isinstance(token_type, str) and token_type:
                # Normalise "bearer" -> "Bearer" for the Authorization header.
                ident.token_type = token_type[:1].upper() + token_type[1:]
        exp = _extract_expires_at(data)
        if exp is not None:
            ident.expires_at = exp
        return token

    async def authenticate(self, ident: Identity, engine: Any) -> str:
        return await self._post_token(ident, engine, for_refresh=False)

    async def refresh(self, ident: Identity, engine: Any) -> str:
        if ident.refresh_token:
            return await self._post_token(ident, engine, for_refresh=True)
        # No refresh token (e.g. client_credentials): just re-authenticate.
        return await self._post_token(ident, engine, for_refresh=False)
