"""Identity-aware HTTP client wrapper -- live in-loop session refresh (PR-8b).

The authorization modules (BOLA/BFLA) issue every request through an injected
client and distinguish identities only by the ``headers`` dict they attach. On
a long scan a token can expire mid-loop; with a *frozen* ``Authorization``
header every subsequent request silently 401s, which is indistinguishable from
"endpoint not vulnerable" -- a false negative, the one result APIStrike must
never produce.

``RefreshingClient`` closes that gap WITHOUT touching any module. Instead of a
frozen Bearer header, the ``auto`` orchestrator tags each identity request with
a sentinel header (``X-APIStrike-Identity: <label>``). This wrapper:

  * resolves the sentinel to the live ``AuthEngine`` Identity,
  * routes the call through ``AuthEngine.authed_request`` -- which refreshes a
    provably-expired token up front and performs a single bounded re-auth on a
    401 for provider-backed identities (ADR-0014), then
  * strips the sentinel so it never reaches the target.

Requests with no sentinel (the deliberate unauthenticated probes, or any other
caller) pass straight through to the wrapped ``ScopedHTTPClient`` unchanged, so
scope, pacing, concurrency and transient-retry (ADR-0008/0009/0010) still apply
to every request and the unauth semantics stay byte-for-byte identical.

See ADR-0015: authorization modules obtain bearer headers through a refreshing
client seam, never a frozen header.
"""
from __future__ import annotations

from typing import Optional, Tuple

# Sentinel request header that carries the identity label from the orchestrator
# to the RefreshingClient. It is resolved + stripped here and NEVER sent to the
# target.
IDENTITY_HEADER = "X-APIStrike-Identity"


class RefreshingClient:
    """Wrap a ScopedHTTPClient so identity-tagged requests self-refresh.

    Parameters
    ----------
    inner:
        The ScopedHTTPClient every request ultimately flows through (already
        entered as an async context manager by the caller).
    engine:
        The AuthEngine holding the live Identity objects, keyed by name in
        ``engine.identities``.
    identity_header:
        The sentinel header name carrying the identity label.
    """

    def __init__(self, inner, engine, identity_header: str = IDENTITY_HEADER):
        self._inner = inner
        self._engine = engine
        self._identity_header = identity_header

    # -- identity resolution ------------------------------------------------
    def _resolve(self, headers: Optional[dict]) -> Tuple[object, dict]:
        """Split a header dict into ``(identity_or_None, headers_without_sentinel)``.

        The sentinel lookup is case-insensitive so a copied/normalised header
        dict (BFLA copies via ``dict(headers or {})``) still matches.
        """
        clean = dict(headers or {})
        if not clean:
            return None, clean
        label = None
        for key in list(clean.keys()):
            if key.lower() == self._identity_header.lower():
                label = clean.pop(key)
                break
        if label is None:
            return None, clean
        ident = None
        identities = getattr(self._engine, "identities", None)
        if isinstance(identities, dict):
            ident = identities.get(label)
        return ident, clean

    # -- surface used by the modules ---------------------------------------
    async def request(self, method: str, url: str, **kwargs):
        headers = kwargs.pop("headers", None)
        ident, clean = self._resolve(headers)
        if ident is not None:
            # authed_request merges ident.auth_headers() (the LIVE token) over
            # these headers, refreshes on proven expiry, and does one bounded
            # re-auth on a 401 for provider-backed identities.
            return await self._engine.authed_request(
                ident, method, url, headers=clean, **kwargs
            )
        return await self._inner.request(method, url, headers=clean, **kwargs)

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)

    # -- transparent passthrough for anything else -------------------------
    def __getattr__(self, name):
        # Delegate any other attribute/method (close, scope, _count, ...) to the
        # wrapped client so RefreshingClient is a drop-in stand-in.
        return getattr(self._inner, name)
