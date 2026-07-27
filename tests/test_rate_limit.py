"""Socket-free pytest suite for the Rate Limiting module (API4:2023)."""
import asyncio

import pytest

from apistrike.modules.rate_limit import (
    RateLimitModule, RateLimitTarget, OWASP_ID, ALL_CHECKS, RATE_LIMIT_HEADERS,
    _count_items, _summarize_statuses, _resp_headers,
)


class Resp:
    def __init__(self, body="", status=200, headers=None):
        self.body = body
        self.status_code = status
        self.headers = headers or {}
        self.elapsed_ms = 5.0


class OpenClient:
    def __init__(self, body="{}"):
        self.body = body
        self.calls = 0
    async def request(self, method, url, headers=None, params=None, json=None):
        self.calls += 1
        return Resp(self.body, 200)


class ThrottleClient:
    def __init__(self, after=5):
        self.after = after
        self.calls = 0
    async def request(self, method, url, headers=None, params=None, json=None):
        self.calls += 1
        return Resp("{}", 429 if self.calls > self.after else 200)


class HeaderClient:
    def __init__(self):
        self.calls = 0
    async def request(self, method, url, headers=None, params=None, json=None):
        self.calls += 1
        return Resp("{}", 200, headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99"})


class PaginationClient:
    def __init__(self, base_n=3, large_n=200, honor=True):
        self.base_n = base_n
        self.large_n = large_n
        self.honor = honor
        self.calls = 0
    async def request(self, method, url, headers=None, params=None, json=None):
        self.calls += 1
        params = params or {}
        n = self.large_n if (self.honor and any(k in params for k in ("limit", "page_size", "size"))) else self.base_n
        users = ",".join("{\"id\": " + str(i) + "}" for i in range(n))
        return Resp('{"users": [' + users + ']}', 200)


def run(coro):
    return asyncio.run(coro)


def test_taxonomy():
    assert OWASP_ID == "API4:2023"
    assert set(ALL_CHECKS) == {"burst", "pagination"}
    assert "retry-after" in RATE_LIMIT_HEADERS


def test_helpers():
    assert _count_items([1, 2, 3]) == 3
    assert _count_items({"users": [1, 2]}) == 2
    assert _count_items({"a": 1}) is None
    assert _summarize_statuses([200, 200, 429]) == "200x2, 429x1"
    assert _resp_headers(Resp(headers={"X-Foo": "bar"})) == {"x-foo": "bar"}


def test_empty_targets_raise():
    with pytest.raises(ValueError):
        RateLimitModule(OpenClient(), "http://t", [])


def test_invalid_checks_raise():
    with pytest.raises(ValueError):
        RateLimitModule(OpenClient(), "http://t", [RateLimitTarget("/x")], checks=("nope",))


def test_burst_no_rate_limit_finding():
    cli = OpenClient()
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("burst",), burst=10).run())
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.title == "No rate limiting enforced" and f.severity == "medium" and f.cwe == "CWE-770"
    assert cli.calls == 10 and res.requests_made == 10


def test_burst_throttled_by_429_stops_early():
    cli = ThrottleClient(after=5)
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("burst",), burst=25).run())
    assert res.findings == []
    assert any("appears enforced" in n and "429" in n for n in res.notes)
    assert cli.calls == 6


def test_burst_rate_limit_headers_no_finding():
    cli = HeaderClient()
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("burst",), burst=8).run())
    assert res.findings == []
    assert any("headers" in n for n in res.notes)


def test_burst_capped_by_max_requests():
    cli = OpenClient()
    mod = RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("burst",), burst=100, max_requests=7)
    assert mod.burst == 7
    run(mod.run())
    assert cli.calls == 7


def test_pagination_honored_finding():
    cli = PaginationClient(base_n=3, large_n=200, honor=True)
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("pagination",), large_value=1000, min_items=50).run())
    pg = [f for f in res.findings if "page size" in f.title]
    assert len(pg) == 1 and pg[0].severity == "medium"
    assert "200" in pg[0].evidence[0]


def test_pagination_ignored_no_finding():
    cli = PaginationClient(base_n=3, large_n=3, honor=False)
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("pagination",)).run())
    assert not any("page size" in f.title for f in res.findings)


def test_pagination_non_json_skipped():
    cli = OpenClient(body="<html>not json</html>")
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/")], checks=("pagination",)).run())
    assert any("not JSON" in n for n in res.notes)


def test_store_integration_combined():
    class Store:
        def __init__(self):
            self.items = []
        def add(self, f):
            self.items.append(f)
    store = Store()
    cli = PaginationClient(base_n=3, large_n=200, honor=True)
    res = run(RateLimitModule(cli, "http://t", [RateLimitTarget("/users")], checks=("burst", "pagination"), burst=5, min_items=50).run(store=store))
    assert len(store.items) == len(res.findings) and len(res.findings) >= 2
