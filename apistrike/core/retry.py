"""Retry policy + transport-agnostic retry driver for APIStrike's HTTP engine.

Reliability is a *correctness* property for a scanner, not a performance nicety.
An un-retried transient blip -- a dropped connection, a 503 while a service
autoscales, a 429 rate-limit -- silently turns a real test into a *missed* test,
i.e. a false negative. This module converts that noise into signal with a small,
deterministic, well-tested retry policy.

Safety first: only *safe* HTTP methods (GET/HEAD/OPTIONS) are retried by
default. Replaying a POST/PATCH/PUT/DELETE could duplicate a side effect on a
target we are only authorised to probe, so non-idempotent flakiness is surfaced
as an honest error instead of being silently repeated. See ADR-0009.

Pure standard library -- no httpx import -- so the whole policy and the retry
driver ``run_with_retry`` are unit-testable offline with fakes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Awaitable, Callable, Optional

# RFC 9110 "safe" methods: no side effects, so replaying them is harmless.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Transient server/proxy statuses worth one more try.
RETRYABLE_STATUSES: frozenset[int] = frozenset({408, 429, 502, 503, 504})

# Default ceiling on how long we are willing to wait for a server-supplied
# Retry-After. If a server asks for longer we do NOT under-wait (that would be
# impolite and risk hammering it) -- we stop retrying and surface the response.
DEFAULT_MAX_RETRY_AFTER = 60.0


def parse_retry_after(value: Optional[str],
                      *, now: Optional[datetime] = None) -> Optional[float]:
    """Parse an HTTP ``Retry-After`` header into non-negative seconds.

    Accepts either delta-seconds (``"120"``) or an HTTP-date
    (``"Wed, 21 Oct 2026 07:28:00 GMT"``). Returns ``None`` when absent or
    unparseable; past dates clamp to ``0``. The raw value is returned as-is --
    the *decision* about whether a wait is too long lives in the retry loop, so
    we never silently under-wait a server's request.
    """
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    if raw.isdigit():
        seconds = float(raw)
    else:
        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        base = now or datetime.now(timezone.utc)
        seconds = (when - base).total_seconds()
    if seconds < 0:
        seconds = 0.0
    return seconds


@dataclass(frozen=True)
class RetryPolicy:
    """Decides *whether* and *how long* to wait before a retry.

    ``max_retries`` is the number of *additional* attempts after the first, so
    ``max_retries=2`` allows up to three total requests. Backoff is exponential
    (``backoff_base * 2**attempt``) capped at ``backoff_max``; an injected
    ``rng`` in ``[0, 1)`` turns it into AWS-style *full jitter* so concurrent
    failures do not retry in lockstep.
    """
    max_retries: int = 2
    backoff_base: float = 0.5
    backoff_max: float = 8.0
    safe_methods: frozenset[str] = SAFE_METHODS
    retryable_statuses: frozenset[int] = RETRYABLE_STATUSES
    max_retry_after: float = DEFAULT_MAX_RETRY_AFTER

    def is_retryable_method(self, method: str) -> bool:
        return method.upper() in self.safe_methods

    def should_retry_status(self, method: str, status: int, attempt: int) -> bool:
        return (
            attempt < self.max_retries
            and self.is_retryable_method(method)
            and status in self.retryable_statuses
        )

    def should_retry_exception(self, method: str, attempt: int) -> bool:
        return attempt < self.max_retries and self.is_retryable_method(method)

    def compute_delay(self, attempt: int, *,
                      retry_after: Optional[float] = None,
                      rng: Optional[Callable[[], float]] = None) -> float:
        """Seconds to sleep before the retry numbered ``attempt`` (0-based).

        A server-supplied ``retry_after`` always wins (politeness). Otherwise
        use capped exponential backoff, optionally multiplied by ``rng()`` for
        full jitter.
        """
        if retry_after is not None:
            return max(0.0, retry_after)
        capped = min(self.backoff_max, self.backoff_base * (2 ** attempt))
        if rng is None:
            return capped
        return capped * rng()


def _header_get(response: object, name: str) -> Optional[str]:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    return getter(name)


async def run_with_retry(
    send: Callable[[], Awaitable[object]],
    method: str,
    policy: RetryPolicy,
    *,
    is_transient: Callable[[Exception], bool],
    sleep: Callable[[float], Awaitable[None]],
    on_attempt: Optional[Callable[[], None]] = None,
    rng: Optional[Callable[[], float]] = None,
):
    """Transport-agnostic retry loop shared by the real client and the tests.

    ``send`` performs one attempt and returns a response exposing
    ``.status_code`` and a ``.headers`` mapping, or raises. ``is_transient``
    classifies an exception as retryable (the real client passes
    ``isinstance(exc, httpx.TransportError)``). ``on_attempt`` runs before every
    network attempt -- the client uses it to enforce the global request cap --
    and may raise to abort. Retries honour the policy and ``Retry-After``.
    """
    attempt = 0
    while True:
        if on_attempt is not None:
            on_attempt()
        try:
            response = await send()
        except Exception as exc:
            if is_transient(exc) and policy.should_retry_exception(method, attempt):
                await sleep(policy.compute_delay(attempt, rng=rng))
                attempt += 1
                continue
            raise
        status = getattr(response, "status_code", None)
        if status is not None and policy.should_retry_status(method, status, attempt):
            retry_after = parse_retry_after(_header_get(response, "Retry-After"))
            if retry_after is not None and retry_after > policy.max_retry_after:
                # The server wants a longer pause than we will wait. Honour it
                # by NOT retrying (never under-wait) and surface the response.
                return response
            await sleep(policy.compute_delay(attempt, retry_after=retry_after, rng=rng))
            attempt += 1
            continue
        return response
