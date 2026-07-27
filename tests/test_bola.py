import asyncio
import json

import pytest

from apistrike.modules.bola import (
    BolaModule,
    BolaIdentity,
    ObjectRef,
    numeric_neighbors,
    _norm_body,
)
from apistrike.core.findings import FindingsStore


class _Ev:
    def __init__(self, status_code, body=""):
        self.status_code = status_code
        self.body = body


class _Client:
    def __init__(self, server):
        self.server = server

    async def get(self, url, headers=None, **kwargs):
        return self.server.handle(url, headers or {})


def _tok(user):
    return f"Bearer tok-{user}"


class _UsersServer:
    """VAmPI-style /users/v1/{username}. mode = vuln | secure | open."""

    def __init__(self, mode):
        self.mode = mode
        self.db = {
            "name1": {"username": "name1", "email": "n1@x", "password": "pass1", "admin": False},
            "name2": {"username": "name2", "email": "n2@x", "password": "pass2", "admin": False},
        }

    def _caller(self, headers):
        a = headers.get("Authorization", "")
        return a[len("Bearer tok-"):] if a.startswith("Bearer tok-") else None

    def handle(self, url, headers):
        uname = url.rstrip("/").split("/")[-1]
        rec = self.db.get(uname)
        if self.mode == "open":
            return _Ev(200, json.dumps(rec, sort_keys=True)) if rec else _Ev(404)
        caller = self._caller(headers)
        if caller is None:
            return _Ev(401)
        if rec is None:
            return _Ev(404)
        if self.mode == "secure" and caller != uname:
            return _Ev(403)
        return _Ev(200, json.dumps(rec, sort_keys=True))


class _BooksServer:
    def __init__(self):
        self.db = {1: {"id": 1, "secret": "s1"}, 2: {"id": 2, "secret": "s2"}, 3: {"id": 3, "secret": "s3"}}

    def handle(self, url, headers):
        tail = url.rstrip("/").split("/")[-1]
        if not tail.isdigit():
            return _Ev(404)
        rec = self.db.get(int(tail))
        if rec is None:
            return _Ev(404)
        if not headers.get("Authorization", "").startswith("Bearer "):
            return _Ev(401)
        return _Ev(200, json.dumps(rec, sort_keys=True))


def _idents():
    return [
        BolaIdentity("name1", {"Authorization": _tok("name1")}, "name1"),
        BolaIdentity("name2", {"Authorization": _tok("name2")}, "name2"),
    ]


def _user_objects():
    return [ObjectRef("/users/v1/name1", "name1"), ObjectRef("/users/v1/name2", "name2")]


def test_numeric_neighbors_basic():
    assert numeric_neighbors("/books/v1/2", 1) == ["/books/v1/1", "/books/v1/3"]
    assert numeric_neighbors("/books/v1/2", 2) == ["/books/v1/1", "/books/v1/3", "/books/v1/4"]


def test_numeric_neighbors_none_for_nonnumeric():
    assert numeric_neighbors("/users/v1/name1", 2) == []
    assert numeric_neighbors("/books/v1/2", 0) == []


def test_norm_body_matches_regardless_of_key_order():
    assert _norm_body({"a": 1, "b": 2}) == _norm_body({"b": 2, "a": 1})


def test_vulnerable_server_two_cross_user_findings():
    store = FindingsStore(":memory:")
    result = asyncio.run(
        BolaModule(_Client(_UsersServer("vuln")), "http://t", _idents(), _user_objects()).run(store=store)
    )
    assert result.cross_user_access == 2
    assert result.unauth_access == 0
    assert len(result.findings) == 2
    assert all(f.owasp_id == "API1:2023" for f in result.findings)
    assert all(f.severity == "high" for f in result.findings)
    assert store.summary()["total"] == 2
    store.close()


def test_secure_server_no_findings():
    store = FindingsStore(":memory:")
    result = asyncio.run(
        BolaModule(_Client(_UsersServer("secure")), "http://t", _idents(), _user_objects()).run(store=store)
    )
    assert result.findings == []
    assert any("No BOLA confirmed" in n for n in result.notes)
    store.close()


def test_unauthenticated_exposure_flagged():
    store = FindingsStore(":memory:")
    result = asyncio.run(
        BolaModule(_Client(_UsersServer("open")), "http://t", _idents(), _user_objects()).run(store=store)
    )
    assert result.unauth_access == 2
    assert any(f.severity == "critical" and f.cwe == "CWE-306" for f in result.findings)
    store.close()


def test_id_enumeration_flagged():
    store = FindingsStore(":memory:")
    objs = [ObjectRef("/books/v1/2", "name1")]
    result = asyncio.run(
        BolaModule(_Client(_BooksServer()), "http://t", _idents(), objs, unauth_check=False, enumerate_spread=1).run(store=store)
    )
    assert result.enumerated_objects >= 2
    assert any("walkable" in f.title for f in result.findings)
    store.close()


def test_requires_at_least_one_object():
    with pytest.raises(ValueError):
        BolaModule(_Client(_UsersServer("vuln")), "http://t", _idents(), [])
