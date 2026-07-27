"""Tests for the GraphQL security module.

Uses a fake client whose responder inspects the outgoing request and returns
canned GraphQL envelopes (vulnerable vs hardened servers). No network.
"""
import asyncio
import json
from urllib.parse import urlparse, parse_qs

import pytest

from apistrike.modules.graphql import GraphQLModule, UNKNOWN_FIELD

BASE = "http://localhost:5013"


def run(coro):
    return asyncio.run(coro)


class FakeResp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body if isinstance(body, str) else json.dumps(body)
        self.elapsed_ms = 1.0


class FakeClient:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    async def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        status, body = self.responder(method, url, kwargs)
        return FakeResp(status, body)


def get_query(method, url, kwargs):
    if method == "POST":
        body = kwargs.get("json")
        if isinstance(body, dict):
            return body.get("query", ""), body
        return "", body  # list => batch
    q = parse_qs(urlparse(url).query).get("query", [""])[0]
    return q, None


def vulnerable(method, url, kwargs):
    q, body = get_query(method, url, kwargs)
    if isinstance(body, list):
        return 200, [{"data": {"__typename": "Query"}} for _ in body]
    if "__schema" in q:
        return 200, {"data": {"__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [{"name": "User", "kind": "OBJECT"}, {"name": "Query", "kind": "OBJECT"}, {"name": "__Type", "kind": "OBJECT"}],
        }}}
    if UNKNOWN_FIELD in q:
        return 200, {"errors": [{"message": "Cannot query field '" + UNKNOWN_FIELD + "' on type 'Query'. Did you mean 'user'?"}]}
    if method == "GET" and q.strip().startswith("mutation"):
        return 200, {"data": {"__typename": "Mutation"}}
    return 200, {"data": {"__typename": "Query"}}


def hardened(method, url, kwargs):
    q, body = get_query(method, url, kwargs)
    if isinstance(body, list):
        return 400, {"errors": [{"message": "Batching is not supported."}]}
    if "__schema" in q:
        return 200, {"data": {"__schema": None}, "errors": [{"message": "GraphQL introspection is not allowed."}]}
    if UNKNOWN_FIELD in q:
        return 400, {"errors": [{"message": "Cannot query field '" + UNKNOWN_FIELD + "' on type 'Query'."}]}
    if method == "GET" and q.strip().startswith("mutation"):
        return 405, {"errors": [{"message": "Can only perform a mutation operation from a POST request."}]}
    return 200, {"data": {"__typename": "Query"}}


def not_graphql(method, url, kwargs):
    return 404, "<html>Not Found</html>"


def test_vulnerable_all_four():
    res = run(GraphQLModule(FakeClient(vulnerable), BASE).run())
    titles = [f.title for f in res.findings]
    assert any("introspection enabled" in t for t in titles)
    assert any("field suggestions" in t.lower() for t in titles)
    assert any("batching" in t.lower() for t in titles)
    assert any("over HTTP GET" in t for t in titles)
    assert len(res.findings) == 4


def test_owasp_and_cwe():
    res = run(GraphQLModule(FakeClient(vulnerable), BASE).run())
    intro = [f for f in res.findings if "introspection" in f.title][0]
    assert intro.owasp_id == "API8:2023" and intro.cwe == "CWE-200"
    batch = [f for f in res.findings if "batching" in f.title.lower()][0]
    assert batch.owasp_id == "API4:2023" and batch.cwe == "CWE-770"
    getm = [f for f in res.findings if "GET" in f.title][0]
    assert getm.owasp_id == "API8:2023" and getm.cwe == "CWE-352"


def test_hardened_no_findings():
    res = run(GraphQLModule(FakeClient(hardened), BASE).run())
    assert res.findings == []
    assert any("No GraphQL security issues" in n for n in res.notes)


def test_not_graphql_endpoint():
    m = GraphQLModule(FakeClient(not_graphql), BASE)
    res = run(m.run())
    assert res.findings == []
    assert any("No GraphQL endpoint detected" in n for n in res.notes)
    assert res.requests_made == 1


def test_introspection_only():
    res = run(GraphQLModule(FakeClient(vulnerable), BASE, checks=("introspection",)).run())
    assert len(res.findings) == 1 and "introspection" in res.findings[0].title


def test_invalid_checks_raise():
    with pytest.raises(ValueError):
        GraphQLModule(FakeClient(vulnerable), BASE, checks=("bogus",))


def test_store_persist():
    class Store:
        def __init__(self):
            self.items = []
        def add(self, f):
            self.items.append(f)
    store = Store()
    res = run(GraphQLModule(FakeClient(vulnerable), BASE).run(store=store))
    assert len(store.items) == len(res.findings) == 4


def test_custom_endpoint():
    seen = {}
    def responder(method, url, kwargs):
        seen["url"] = url
        return vulnerable(method, url, kwargs)
    run(GraphQLModule(FakeClient(responder), BASE, endpoint="/api/graphql", checks=("introspection",)).run())
    assert "/api/graphql" in seen["url"]


def test_suggestions_without_introspection():
    def responder(method, url, kwargs):
        q, body = get_query(method, url, kwargs)
        if isinstance(body, list):
            return 400, {"errors": [{"message": "no batching"}]}
        if "__schema" in q:
            return 200, {"data": {"__schema": None}}
        if UNKNOWN_FIELD in q:
            return 200, {"errors": [{"message": "Did you mean 'user'?"}]}
        if method == "GET" and q.strip().startswith("mutation"):
            return 405, {"errors": [{"message": "mutation only via POST"}]}
        return 200, {"data": {"__typename": "Query"}}
    res = run(GraphQLModule(FakeClient(responder), BASE).run())
    assert any("field suggestions" in f.title.lower() for f in res.findings)
    assert not any("introspection enabled" in f.title for f in res.findings)


def test_get_mutation_blocked_no_fp():
    # hardened server blocks GET mutation -> no finding
    res = run(GraphQLModule(FakeClient(hardened), BASE, checks=("get_mutation",)).run())
    assert not any("over HTTP GET" in f.title for f in res.findings)


def test_batching_partial_not_flagged():
    # server returns a list but with error envelopes (no data) -> not batching-abusable
    def responder(method, url, kwargs):
        q, body = get_query(method, url, kwargs)
        if isinstance(body, list):
            return 200, [{"errors": [{"message": "nope"}]} for _ in body]
        return 200, {"data": {"__typename": "Query"}}
    res = run(GraphQLModule(FakeClient(responder), BASE, checks=("batching",)).run())
    assert not any("batching" in f.title.lower() for f in res.findings)


def test_request_count_full_run():
    # detection probe + 4 checks = 5 requests on the vulnerable server
    res = run(GraphQLModule(FakeClient(vulnerable), BASE).run())
    assert res.requests_made == 5
