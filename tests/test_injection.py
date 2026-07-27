"""Tests for the injection module (SQLi / NoSQLi / OS-command)."""

import asyncio

import pytest

from apistrike.modules.injection import (
    InjectionModule,
    InjectionTarget,
    OWASP_ID,
    OWASP_API_TOP_10,
)


class _Resp:
    def __init__(self, status, body="", elapsed_ms=6.0):
        self.status_code = status
        self.body = body
        self.elapsed_ms = elapsed_ms


def _path_of(url):
    p = url.split("://", 1)[-1]
    return p[p.find("/"):] if "/" in p else "/"


class _Client:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    async def request(self, method, url, **kwargs):
        path = _path_of(url)
        self.calls.append((method.upper(), path, kwargs))
        fn = self.routes.get(path)
        if fn is None:
            return _Resp(404, "not found")
        return fn(kwargs.get("params"), kwargs.get("json"))


def _search(params, json_body):
    q = str((params or {}).get("q", ""))
    low = q.lower()
    if "sleep(" in low:
        return _Resp(200, "results: many", elapsed_ms=3200)
    if q.count("'") % 2 == 1:
        return _Resp(500, 'sqlite3.OperationalError: near "' + q + '": syntax error', elapsed_ms=6)
    if "or '1'='1" in low or "or 1=1" in low:
        return _Resp(200, "results: " + ",".join(str(i) for i in range(60)), elapsed_ms=6)
    if "and '1'='2" in low or "and 1=2" in low:
        return _Resp(200, "results: none", elapsed_ms=6)
    return _Resp(200, "results: item-" + q, elapsed_ms=6)


def _ping(params, json_body):
    host = str((params or {}).get("host", ""))
    if "sleep " in host.lower():
        return _Resp(200, "PING ok", elapsed_ms=3200)
    return _Resp(200, "PING " + host, elapsed_ms=6)


def _login(params, json_body):
    u = (json_body or {}).get("username")
    if isinstance(u, dict):
        return _Resp(200, '{"token": "abc123"}', elapsed_ms=7)
    return _Resp(401, '{"error": "invalid credentials"}', elapsed_ms=7)


def _clean(params, json_body):
    return _Resp(200, "static ok", elapsed_ms=6)


ROUTES = {"/search": _search, "/ping": _ping, "/login": _login, "/clean": _clean}

T_SEARCH = InjectionTarget("GET", "/search", "q", "query", benign_value="1")
T_PING = InjectionTarget("GET", "/ping", "host", "query", benign_value="127.0.0.1")
T_LOGIN = InjectionTarget("POST", "/login", "username", "json", base_body={"password": "x"}, benign_value="admin")
T_CLEAN = InjectionTarget("GET", "/clean", "x", "query")


def _mod(targets, **kw):
    return InjectionModule(_Client(ROUTES), "http://t", targets, **kw)


def _run(m):
    return asyncio.run(m.run())


def test_taxonomy_self_registers():
    assert OWASP_ID == "INJECTION"
    assert OWASP_API_TOP_10["INJECTION"] == "Injection (SQLi / NoSQLi / Command)"


def test_target_normalizes_method_path_location():
    t = InjectionTarget("post", "search", "q", "body")
    assert t.method == "POST"
    assert t.path == "/search"
    assert t.location == "json"


def test_time_based_sqli_wins_precedence():
    res = _run(_mod([T_SEARCH]))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "critical" and f.cwe == "CWE-89"
    assert f.confidence == "confirmed"
    assert "time-based" in f.title.lower()
    assert f.owasp_id == "INJECTION"


def test_error_based_sqli_when_time_disabled():
    res = _run(_mod([T_SEARCH], techniques=["error", "boolean"]))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert "error-based" in f.title.lower()
    assert f.severity == "high" and f.cwe == "CWE-89" and f.confidence == "confirmed"


def test_boolean_based_sqli_only():
    res = _run(_mod([T_SEARCH], techniques=["boolean"]))
    assert len(res.findings) == 1
    assert "boolean" in res.findings[0].title.lower()
    assert res.findings[0].confidence == "firm"


def test_command_injection_time_based():
    res = _run(_mod([T_PING]))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.cwe == "CWE-78" and f.severity == "critical" and f.confidence == "confirmed"


def test_nosql_operator_injection():
    res = _run(_mod([T_LOGIN]))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.cwe == "CWE-943" and f.severity == "high" and f.confidence == "firm"


def test_nosql_skipped_for_query_params():
    res = _run(_mod([T_SEARCH], techniques=["nosql"]))
    assert res.findings == []
    assert any("skipped" in n.lower() for n in res.notes)


def test_clean_endpoint_no_false_positives():
    res = _run(_mod([T_CLEAN]))
    assert res.findings == []
    assert any("no injection confirmed" in n.lower() for n in res.notes)


def test_multi_target_aggregates_all_classes():
    res = _run(_mod([T_SEARCH, T_PING, T_LOGIN, T_CLEAN]))
    assert sorted({f.cwe for f in res.findings}) == ["CWE-78", "CWE-89", "CWE-943"]
    assert len(res.findings) == 3
    assert res.requests_made > 0


def test_requires_at_least_one_target():
    with pytest.raises(ValueError):
        InjectionModule(_Client(ROUTES), "http://t", [])
