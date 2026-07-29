"""Per-host rate limiting and bounded concurrency for APIStrike's HTTP engine.

Politeness is an *ethical and legal* requirement, not a nicety: APIStrike points
real traffic at systems people have authorised us to test, and uncontrolled
concurrency is indistinguishable from a denial-of-service attack. This module
enforces two independent guardrails, keyed per host:

* a **pacer** that spaces request *starts* to at most ``rate`` per second
  (preserving the v1.4 ``scope.rate_limit`` contract), and
* a **semaphore** that caps the number of simultaneously in-flight requests at
  ``concurrency`` so we can hide latency without ever stampeding a host.

Both are injected with a clock (``now``) and ``sleep`` so timing is fully
deterministic under test -- no real wall-clock waits. Pure standard library.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Awaitable, Callable, Dict, Optional


class HostLimiter:
    """Per-host request pacing + concurrency ceiling.

    ``rate`` is requests/second (``<= 0`` disables pacing). ``concurrency`` is
    the maximum number of requests allowed in flight to a single host at once
    (floored at 1).
    """

    def __init__(self, rate: float, concurrency: int, *,
                 now: Optional[Callable[[], float]] = None,
                 sleep: Optional[Callable[[float], Awaitable[None]]] = None):
        self.rate = float(rate) if rate and rate > 0 else 0.0
        self.concurrency = max(1, int(concurrency))
        self._interval = (1.0 / self.rate) if self.rate > 0 else 0.0
        self._now = now or time.monotonic
        self._sleep = sleep or asyncio.sleep
        self._last: Dict[str, float] = {}
        self._pace_locks: Dict[str, asyncio.Lock] = {}
        self._sems: Dict[str, asyncio.Semaphore] = {}
        self._in_flight: Dict[str, int] = {}
        self._peak: Dict[str, int] = {}

    def _sem(self, host: str) -> asyncio.Semaphore:
        sem = self._sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self.concurrency)
            self._sems[host] = sem
        return sem

    def _pace_lock(self, host: str) -> asyncio.Lock:
        lock = self._pace_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._pace_locks[host] = lock
        return lock

    async def _pace(self, host: str) -> None:
        if self._interval <= 0:
            return
        async with self._pace_lock(host):
            last = self._last.get(host)
            now = self._now()
            if last is not None:
                wait = self._interval - (now - last)
                if wait > 0:
                    await self._sleep(wait)
                    now = self._now()
            self._last[host] = now

    @asynccontextmanager
    async def slot(self, host: str):
        """Acquire a concurrency slot for ``host``, then pace the start."""
        sem = self._sem(host)
        await sem.acquire()
        current = self._in_flight.get(host, 0) + 1
        self._in_flight[host] = current
        if current > self._peak.get(host, 0):
            self._peak[host] = current
        try:
            await self._pace(host)
            yield
        finally:
            self._in_flight[host] = self._in_flight.get(host, 1) - 1
            sem.release()

    def peak_concurrency(self, host: str) -> int:
        return self._peak.get(host, 0)
