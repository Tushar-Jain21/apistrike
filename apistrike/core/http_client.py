"""Async HTTP client wrapper with scope enforcement, rate limiting, bounded
concurrency, and transient-failure retries.

No module in APIStrike should ever call httpx directly. Everything goes through
ScopedHTTPClient so that (1) scope is enforced, (2) we stay polite (per-host
rate limiting + a hard concurrency ceiling), (3) transient network failures are
retried safely, and (4) every request/response is captured as evidence.

The reliability + politeness policy lives in two small, offline-tested modules:
``apistrike.core.retry`` (RetryPolicy + run_with_retry) and
``apistrike.core.ratelimit`` (HostLimiter). This module is the thin httpx glue
that composes them. See ADR-0008 (asyncio + per-host semaphores, no threads),
ADR-0009 (retry only safe methods; honour Retry-After) and ADR-0010 (politeness
config lives in Scope).
"""
from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from apistrike.core.ratelimit import HostLimiter
from apistrike.core.retry import RetryPolicy, run_with_retry
from apistrike.core.scope import Scope

# Safe-mode hard ceiling: never exceed this many concurrent requests per host,
# no matter what the scope file asks for. Aggressive concurrency against a
# target is indistinguishable from a DoS, so safe mode clamps it. (ADR-0008.)
SAFE_MODE_MAX_CONCURRENCY = 4


@dataclass
class Evidence:
    """A logged request/response pair -- the proof behind every finding."""
    method: str
    url: str
    status_code: int
    elapsed_ms: float
    request_headers: dict
    response_headers: dict
    body: str


def _is_transient(exc: Exception) -> bool:
    """A network-layer failure worth retrying (connect/read/timeout/protocol)."""
    return isinstance(exc, httpx.TransportError)


class ScopedHTTPClient:
    """Wraps httpx.AsyncClient. Every request is scope-checked, paced,
    concurrency-limited, and retried on transient failure."""

    def __init__(self, scope: Scope, timeout: float = 15.0):
        self.scope = scope

        concurrency = int(getattr(scope, "concurrency", SAFE_MODE_MAX_CONCURRENCY) or 1)
        if getattr(scope, "safe_mode", True):
            concurrency = min(concurrency, SAFE_MODE_MAX_CONCURRENCY)
        concurrency = max(1, concurrency)
        self._concurrency = concurrency

        self._limiter = HostLimiter(scope.rate_limit, concurrency)
        self._policy = RetryPolicy(
            max_retries=max(0, int(getattr(scope, "retries", 2))),
            backoff_base=float(getattr(scope, "retry_backoff", 0.5)),
        )

        limits = httpx.Limits(
            max_connections=max(concurrency, 10),
            max_keepalive_connections=max(concurrency, 10),
        )
        self._client = httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, limits=limits,
        )
        self._count = 0

    async def __aenter__(self) -> "ScopedHTTPClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    def _reserve_request(self) -> None:
        """Count one network attempt against the hard request cap.

        Every *attempt* (including retries) counts -- that is the honest measure
        of the load we place on the target, and it keeps the safety cap tight.
        """
        if self._count >= self.scope.max_requests:
            raise RuntimeError(
                f"Request cap reached ({self.scope.max_requests}). Stopping."
            )
        self._count += 1

    async def request(self, method: str, url: str, **kwargs) -> Evidence:
        self.scope.assert_in_scope(url)
        method = method.upper()
        host = (urlparse(url).hostname or "").lower()

        async def _send():
            return await self._client.request(method, url, **kwargs)

        async with self._limiter.slot(host):
            response = await run_with_retry(
                _send,
                method,
                self._policy,
                is_transient=_is_transient,
                sleep=asyncio.sleep,
                on_attempt=self._reserve_request,
                rng=random.random,
            )
        return self._evidence(method, response)

    def _evidence(self, method: str, r: "httpx.Response") -> Evidence:
        return Evidence(
            method=method,
            url=str(r.request.url),
            status_code=r.status_code,
            elapsed_ms=r.elapsed.total_seconds() * 1000,
            request_headers=dict(r.request.headers),
            response_headers=dict(r.headers),
            body=r.text,
        )

    async def get(self, url: str, **kwargs) -> Evidence:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Evidence:
        return await self.request("POST", url, **kwargs)
