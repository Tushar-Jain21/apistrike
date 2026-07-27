"""Async HTTP client wrapper with built-in scope enforcement + rate limiting.

No module in APIStrike should ever call httpx directly. Everything goes
through ScopedHTTPClient so that (1) scope is enforced, (2) we stay polite
with rate limiting, and (3) every request/response is captured as evidence.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from apistrike.core.scope import Scope


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


class ScopedHTTPClient:
    """Wraps httpx.AsyncClient. Every request is scope-checked and rate-limited."""

    def __init__(self, scope: Scope, timeout: float = 15.0):
        self.scope = scope
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
        self._min_interval = 1.0 / scope.rate_limit if scope.rate_limit > 0 else 0.0
        self._last_request = 0.0
        self._count = 0

    async def __aenter__(self) -> "ScopedHTTPClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        wait = self._min_interval - (time.monotonic() - self._last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.monotonic()

    async def request(self, method: str, url: str, **kwargs) -> Evidence:
        self.scope.assert_in_scope(url)
        if self._count >= self.scope.max_requests:
            raise RuntimeError(
                f"Request cap reached ({self.scope.max_requests}). Stopping."
            )
        await self._throttle()

        self._count += 1
        r = await self._client.request(method, url, **kwargs)
        return Evidence(
            method=method.upper(),
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
