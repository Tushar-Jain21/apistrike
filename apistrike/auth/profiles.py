"""Declarative multi-identity auth profiles for APIStrike (v1.6, PR-8).

An optional ``auth:`` block in ``scope.yaml`` lets an engagement declare several
identities up front (a user and an admin, a service account, etc.) so the
authorization modules can compare them. The identity travels *with* the
authorization scope (ADR-0010), which is exactly where the credentials that a
tester is authorized to use belong.

Secret hygiene (ADR-0013): secret material (passwords, static tokens, OAuth2
client secrets) MUST be referenced via ``${ENV_VAR}`` and is resolved from the
process environment at load time. Inline literal secrets are rejected so a
scope file can be committed to version control without leaking credentials.

Example ``scope.yaml`` block::

    auth:
      - name: user1
        type: password
        username: name1
        password: ${VAMPI_USER1_PASS}
        role: user
      - name: admin
        type: token
        token: ${VAMPI_ADMIN_TOKEN}
        role: admin
      - name: svc
        type: oauth2
        grant: client_credentials
        token_url: https://auth.example.com/oauth/token
        client_id: apistrike
        client_secret: ${SVC_CLIENT_SECRET}
        scope: "api.read api.write"

This module imports only the auth layer + stdlib (it duck-types the ``scope``
object), so it introduces no new cross-layer dependency.
"""
from __future__ import annotations

import os
import re
from typing import Any, List

from apistrike.auth.auth_engine import (
    AuthError,
    AuthOutcome,
    Credentials,
    Identity,
    LoginConfig,
)
from apistrike.auth.providers import (
    OAuth2Provider,
    PasswordLoginProvider,
    TokenProvider,
)

_ENV_REF_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")

# Fields whose values are secret and therefore must be env-referenced.
_SECRET_FIELDS = {"password", "token", "client_secret"}


def resolve_value(raw: Any, *, field_name: str) -> str:
    """Resolve a scalar profile value, enforcing the secret-hygiene rule.

    - ``${ENV}`` is resolved from the environment (missing env -> AuthError).
    - A literal is allowed for non-secret fields, but a literal in a secret
      field is rejected (ADR-0013).
    """
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raw = str(raw)
    m = _ENV_REF_RE.match(raw.strip())
    if m:
        env_name = m.group(1)
        val = os.environ.get(env_name)
        if val is None or val == "":
            raise AuthError(
                f"Auth profile references environment variable '${{{env_name}}}' "
                f"for field '{field_name}', but it is unset or empty.",
                AuthOutcome.CREDENTIALS_REJECTED,
            )
        return val
    if field_name in _SECRET_FIELDS:
        raise AuthError(
            f"Secret field '{field_name}' must be provided via an environment "
            f"reference like ${{ENV_VAR}}, not an inline literal (ADR-0013).",
            AuthOutcome.CREDENTIALS_REJECTED,
        )
    return raw


def _login_config_from_entry(entry: dict, default: LoginConfig) -> LoginConfig:
    """Build a per-profile LoginConfig, inheriting engine defaults."""
    return LoginConfig(
        login_path=entry.get("login_path", default.login_path),
        method=entry.get("method", default.method),
        username_field=entry.get("username_field", default.username_field),
        password_field=entry.get("password_field", default.password_field),
        token_fields=tuple(entry.get("token_fields", default.token_fields)),
        token_type=entry.get("token_type", default.token_type),
        send_as_json=bool(entry.get("send_as_json", default.send_as_json)),
    )


def build_identity(entry: dict, *, default_login: LoginConfig) -> Identity:
    """Turn one ``auth:`` entry into an Identity with its provider attached."""
    if not isinstance(entry, dict):
        raise AuthError(
            f"Each auth profile must be a mapping, got: {type(entry).__name__}.",
            AuthOutcome.TRANSPORT_ERROR,
        )
    name = entry.get("name")
    if not name:
        raise AuthError("Each auth profile needs a 'name'.", AuthOutcome.TRANSPORT_ERROR)
    ptype = (entry.get("type") or "password").strip().lower()
    role = entry.get("role", "user")

    if ptype == "password":
        username = resolve_value(entry.get("username", name), field_name="username")
        password = resolve_value(entry.get("password"), field_name="password")
        login_config = _login_config_from_entry(entry, default_login)
        ident = Identity(
            name=name,
            credentials=Credentials(username=username, password=password),
            token_type=login_config.token_type,
            role=role,
            provider=PasswordLoginProvider(login_config=login_config),
        )
        return ident

    if ptype == "token":
        token = resolve_value(entry.get("token"), field_name="token")
        if not token:
            raise AuthError(
                f"Auth profile '{name}' is type 'token' but no token was provided.",
                AuthOutcome.CREDENTIALS_REJECTED,
            )
        ident = Identity(
            name=name,
            credentials=Credentials(username=entry.get("username", name), token=token),
            token=token,
            token_type=entry.get("token_type", "Bearer"),
            role=role,
            provider=TokenProvider(),
        )
        return ident

    if ptype == "oauth2":
        token_url = entry.get("token_url")
        if not token_url:
            raise AuthError(
                f"Auth profile '{name}' (oauth2) requires a 'token_url'.",
                AuthOutcome.TRANSPORT_ERROR,
            )
        provider = OAuth2Provider(
            token_url=token_url,
            grant=entry.get("grant", "client_credentials"),
            client_id=resolve_value(entry.get("client_id", ""), field_name="client_id"),
            client_secret=resolve_value(entry.get("client_secret"), field_name="client_secret"),
            username=resolve_value(entry.get("username", ""), field_name="username"),
            password=resolve_value(entry.get("password"), field_name="password"),
            scope=entry.get("scope", ""),
        )
        ident = Identity(
            name=name,
            credentials=Credentials(username=entry.get("username", name)),
            token_type=entry.get("token_type", "Bearer"),
            role=role,
            provider=provider,
        )
        return ident

    raise AuthError(
        f"Auth profile '{name}' has unknown type '{ptype}' "
        "(expected: password, token, oauth2).",
        AuthOutcome.TRANSPORT_ERROR,
    )


def _scope_auth_entries(scope: Any) -> List[dict]:
    """Extract the ``auth:`` list from a Scope object or a raw mapping."""
    if scope is None:
        return []
    entries = getattr(scope, "auth", None)
    if entries is None and isinstance(scope, dict):
        entries = scope.get("auth")
    if not entries:
        return []
    if not isinstance(entries, list):
        raise AuthError(
            "The 'auth:' block in scope must be a list of profiles.",
            AuthOutcome.TRANSPORT_ERROR,
        )
    return entries


def build_identities(scope: Any, *, default_login: LoginConfig | None = None) -> List[Identity]:
    """Build all identities declared in a scope's ``auth:`` block."""
    default_login = default_login or LoginConfig()
    return [build_identity(e, default_login=default_login) for e in _scope_auth_entries(scope)]


def register_scope_identities(engine: Any, scope: Any) -> List[Identity]:
    """Build declared identities and register them on ``engine``.

    Returns the identities registered (empty list if the scope declares none),
    so a CLI can decide whether to fall back to ``-u/-p`` identities.
    """
    idents = build_identities(scope, default_login=getattr(engine, "config", None) or LoginConfig())
    for ident in idents:
        engine.register_identity(ident)
    return idents
