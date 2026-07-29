"""Tests for the v1.5 HTTP engine: retry policy, per-host rate limiting +
bounded concurrency, and the ScopedHTTPClient glue.

The pure policy/limiter tests run without a network. The ScopedHTTPClient tests
swap in a scripted fake transport (no sockets) so retry/scope/cap behaviour is
deterministic and offline.
"""
import asyncio

import httpx
import pytest

from apistrike.core.retry import RetryPolicy, parse_retry_after, run_with_retry
from apistrike.core.ratelimit import HostLimiter
from apistrike.core.http_client import ScopedHTTPClient, Evidence
from apistrike.core.scope import Scope


# --------------------------------------------------------------------------- #
# retry policy (pure)                                                         #
# --------------------------------------------------------------------------- #
def test_parse_retry_after_seconds():
    assert parse_retry_after("120") == 120.0


def test_parse_retry_after_uncapped_and_none():
    assert parse_retry_after("99999") == 99999.0
    assert parse_retry_after("") is None
    assert parse_retry_after(None) is None


def test_parse_retry_after_http_date_in_past_clamps_to_zero():
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0


def test_compute_delay_exponential_without_jitter():
    p = RetryPolicy(backoff_base=0.5, backoff_max=8.0)
    assert p.compute_delay(0) == 0.5
    assert p.compute_delay(1) == 1.0
    assert p.compute_delay(2) == 2.0
    assert p.compute_delay(10) == 8.0  # capped


def test_compute_delay_retry_after_wins():
    p = RetryPolicy()
    assert p.compute_delay(3, retry_after=2.5) == 2.5


def test_compute_delay_full_jitter_within_bounds():
    p = RetryPolicy(backoff_base=1.0, backoff_max=8.0)
    assert p.compute_delay(2, rng=lambda: 0.0) == 0.0
    assert p.compute_delay(2, rng=lambda: 1.0) == 4.0


def test_should_retry_status_safe_only():
    p = RetryPolicy(max_retries=2)
    assert p.should_retry_status("GET", 503, 0) is True
    assert p.should_retry_status("get", 429, 1) is True
    assert p.should_retry_status("POST", 503, 0) is False   # unsafe method
    assert p.should_retry_status("GET", 404, 0) is False    # not a retryable status
    assert p.should_retry_status("GET", 503, 2) is False    # attempts exhausted


def test_should_retry_exception_gating():
    p = RetryPolicy(max_retries=1)
    assert p.should_retry_exception("GET", 0) is True
    assert p.should_retry_exception("POST", 0) is False
    assert p.should_retry_exception("GET", 1) is False


# --------------------------------------------------------------------------- #
# run_with_retry (pure, transport-agnostic)                                   #
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _Boom(Exception):
    pass


async def _noop_sleep(_):
    return None


def test_run_with_retry_status_then_succeeds():
    scripted = [_Resp(503), _Resp(503), _Resp(200)]
    calls = {"n": 0}

    async def send():
        calls["n"] += 1
        return scripted.pop(0)

    p = RetryPolicy(max_retries=3, backoff_base=0.0)
    resp = asyncio.run(run_with_retry(
        send, "GET", p, is_transient=lambda e: True, sleep=_noop_sleep))
    assert resp.status_code == 200
    assert calls["n"] == 3


def test_run_with_retry_does_not_retry_unsafe_method():
    scripted = [_Resp(503), _Resp(200)]
    calls = {"n": 0}

    async def send():
        calls["n"] += 1
        return scripted.pop(0)

    p = RetryPolicy(max_retries=3, backoff_base=0.0)
    resp = asyncio.run(run_with_retry(
        send, "POST", p, is_transient=lambda e: True, sleep=_noop_sleep))
    assert resp.status_code == 503
    assert calls["n"] == 1


def test_run_with_retry_transient_exception_then_succeeds():
    seq = ["boom", "boom", _Resp(200)]
    calls = {"n": 0}

    async def send():
        calls["n"] += 1
        item = seq.pop(0)
        if item == "boom":
            raise _Boom()
        return item

    p = RetryPolicy(max_retries=3, backoff_base=0.0)
    resp = asyncio.run(run_with_retry(
        send, "GET", p, is_transient=lambda e: isinstance(e, _Boom),
        sleep=_noop_sleep))
    assert resp.status_code == 200
    assert calls["n"] == 3


def test_run_with_retry_reraises_non_transient():
    async def send():
        raise ValueError("nope")

    p = RetryPolicy(max_retries=3, backoff_base=0.0)
    with pytest.raises(ValueError):
        asyncio.run(run_with_retry(
            send, "GET", p, is_transient=lambda e: False, sleep=_noop_sleep))


def test_run_with_retry_honours_retry_after_header():
    scripted = [_Resp(429, {"Retry-After": "5"}), _Resp(200)]
    slept = []

    async def send():
        return scripted.pop(0)

    async def sleep(d):
        slept.append(d)

    p = RetryPolicy(max_retries=2, backoff_base=0.0)
    resp = asyncio.run(run_with_retry(
        send, "GET", p, is_transient=lambda e: True, sleep=sleep))
    assert resp.status_code == 200
    assert slept == [5.0]


def test_run_with_retry_gives_up_when_retry_after_too_long():
    scripted = [_Resp(503, {"Retry-After": "999"}), _Resp(200)]
    slept = []

    async def send():
        return scripted.pop(0)

    async def sleep(d):
        slept.append(d)

    p = RetryPolicy(max_retries=2, backoff_base=0.0, max_retry_after=60.0)
    resp = asyncio.run(run_with_retry(
        send, "GET", p, is_transient=lambda e: True, sleep=sleep))
    assert resp.status_code == 503
    assert slept == []


def test_run_with_retry_on_attempt_can_abort():
    async def send():
        return _Resp(503)

    def on_attempt():
        raise RuntimeError("cap")

    p = RetryPolicy(max_retries=3, backoff_base=0.0)
    with pytest.raises(RuntimeError):
        asyncio.run(run_with_retry(
            send, "GET", p, is_transient=lambda e: True, sleep=_noop_sleep,
            on_attempt=on_attempt))


# --------------------------------------------------------------------------- #
# HostLimiter (pure, fake clock)                                              #
# --------------------------------------------------------------------------- #
def test_host_limiter_caps_concurrency():
    limiter = HostLimiter(rate=0, concurrency=3)
    release = asyncio.Event()

    async def worker():
        async with limiter.slot("h"):
            await release.wait()

    async def scenario():
        tasks = [asyncio.create_task(worker()) for _ in range(10)]
        await asyncio.sleep(0.02)
        peak = limiter.peak_concurrency("h")
        release.set()
        await asyncio.gather(*tasks)
        return peak

    assert asyncio.run(scenario()) == 3


def test_host_limiter_paces_by_rate():
    clock = {"t": 0.0}

    def now():
        return clock["t"]

    async def fake_sleep(d):
        clock["t"] += d

    limiter = HostLimiter(rate=10.0, concurrency=1, now=now, sleep=fake_sleep)

    async def scenario():
        for _ in range(5):
            async with limiter.slot("h"):
                pass

    asyncio.run(scenario())
    # 5 requests at 10/s => 4 inter-request gaps of 0.1s.
    assert round(clock["t"], 5) == 0.4


def test_host_limiter_rate_zero_disables_pacing():
    clock = {"t": 5.0}

    def now():
        return clock["t"]

    async def fake_sleep(d):
        clock["t"] += d

    limiter = HostLimiter(rate=0, concurrency=1, now=now, sleep=fake_sleep)

    async def scenario():
        for _ in range(3):
            async with limiter.slot("h"):
                pass

    asyncio.run(scenario())
    assert clock["t"] == 5.0


# --------------------------------------------------------------------------- #
# ScopedHTTPClient (scripted fake transport -- no sockets)                    #
# --------------------------------------------------------------------------- #
class _FakeReq:
    def __init__(self, url):
        self.url = url
        self.headers = {}


class _FakeElapsed:
    def total_seconds(self):
        return 0.001


class _FakeResponse:
    def __init__(self, status_code, url, headers=None, text="body"):
        self.status_code = status_code
        self.headers = headers or {}
        self.request = _FakeReq(url)
        self.elapsed = _FakeElapsed()
        self.text = text


class _FakeHttpxClient:
    """Stands in for httpx.AsyncClient inside ScopedHTTPClient."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    async def request(self, method, url, **kwargs):
        self.calls += 1
        kind, val = self.script.pop(0)
        if kind == "raise":
            raise val
        return _FakeResponse(val, url)

    async def aclose(self):
        return None


def _scope(**kw):
    base = dict(allowed_hosts=["localhost"], rate_limit=0, safe_mode=True)
    base.update(kw)
    return Scope(**base)


def _client(scope, script):
    c = ScopedHTTPClient(scope)
    c._client = _FakeHttpxClient(script)
    c._policy = RetryPolicy(max_retries=2, backoff_base=0.0)  # instant retries
    return c


def test_client_retries_transient_status_then_succeeds():
    c = _client(_scope(), [("status", 503), ("status", 200)])

    async def go():
        async with c:
            return await c.get("http://localhost/x")

    ev = asyncio.run(go())
    assert isinstance(ev, Evidence)
    assert ev.status_code == 200
    assert c._client.calls == 2
    assert c._count == 2


def test_client_does_not_retry_post():
    c = _client(_scope(), [("status", 503), ("status", 200)])

    async def go():
        async with c:
            return await c.post("http://localhost/x")

    ev = asyncio.run(go())
    assert ev.status_code == 503
    assert c._client.calls == 1


def test_client_enforces_scope():
    c = _client(_scope(), [("status", 200)])

    async def go():
        async with c:
            return await c.get("http://evil.com/x")

    with pytest.raises(Exception):
        asyncio.run(go())


def test_client_request_cap_counts_every_attempt():
    c = _client(_scope(max_requests=1), [("status", 503), ("status", 200)])

    async def go():
        async with c:
            return await c.get("http://localhost/x")

    with pytest.raises(RuntimeError):
        asyncio.run(go())


def test_client_retries_transient_exception():
    err = httpx.ConnectError("boom")
    c = _client(_scope(), [("raise", err), ("status", 200)])

    async def go():
        async with c:
            return await c.get("http://localhost/x")

    ev = asyncio.run(go())
    assert ev.status_code == 200
    assert c._client.calls == 2


def test_client_safe_mode_clamps_concurrency():
    c = ScopedHTTPClient(_scope(concurrency=64, safe_mode=True))
    assert c._concurrency == 4
    c2 = ScopedHTTPClient(_scope(concurrency=64, safe_mode=False))
    assert c2._concurrency == 64
