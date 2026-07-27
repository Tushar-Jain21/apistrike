"""Tests for the Mass Assignment / BOPLA module (API3:2023). Socket-free."""

import asyncio
import json

import pytest

from apistrike.modules.mass_assignment import (
    MassAssignmentModule,
    MassAssignmentTarget,
    OWASP_ID,
    OWASP_API_TOP_10,
)


class Resp:
    def __init__(self, status, body=""):
        self.status_code = status
        self.body = body
        self.elapsed_ms = 5.0


def _path(url):
    p = url.split("://", 1)[-1]
    return p[p.find("/"):] if "/" in p else "/"


class VulnDebugServer:
    def __init__(self):
        self.users = {}

    async def request(self, method, url, **kwargs):
        path = _path(url)
        data = kwargs.get("json") or kwargs.get("params") or {}
        if path.endswith("/register") and method == "POST":
            self.users[str(data.get("username"))] = dict(data)
            return Resp(200, json.dumps({"message": "registered"}))
        if path.endswith("/_debug") and method == "GET":
            return Resp(200, json.dumps({"users": list(self.users.values())}))
        return Resp(404, "{}")


class SecureServer:
    def __init__(self):
        self.users = {}

    async def request(self, method, url, **kwargs):
        path = _path(url)
        data = kwargs.get("json") or kwargs.get("params") or {}
        if path.endswith("/register") and method == "POST":
            self.users[str(data.get("username"))] = {
                "username": data.get("username"),
                "email": data.get("email"),
                "admin": False,
            }
            return Resp(200, json.dumps({"message": "registered"}))
        if path.endswith("/_debug") and method == "GET":
            return Resp(200, json.dumps({"users": list(self.users.values())}))
        return Resp(404, "{}")


class AlwaysAdminServer:
    def __init__(self):
        self.users = {}

    async def request(self, method, url, **kwargs):
        path = _path(url)
        data = kwargs.get("json") or kwargs.get("params") or {}
        if path.endswith("/register") and method == "POST":
            rec = dict(data)
            rec["admin"] = True
            self.users[str(data.get("username"))] = rec
            return Resp(200, json.dumps({"message": "registered"}))
        if path.endswith("/_debug") and method == "GET":
            return Resp(200, json.dumps({"users": list(self.users.values())}))
        return Resp(404, "{}")


class EchoOnlyServer:
    async def request(self, method, url, **kwargs):
        path = _path(url)
        data = kwargs.get("json") or kwargs.get("params") or {}
        if path.endswith("/register") and method == "POST":
            return Resp(200, json.dumps({"created": dict(data)}))
        return Resp(404, "{}")


class VulnPathServer:
    def __init__(self):
        self.users = {}

    async def request(self, method, url, **kwargs):
        path = _path(url)
        data = kwargs.get("json") or kwargs.get("params") or {}
        if path.endswith("/register") and method == "POST":
            self.users[str(data.get("username"))] = dict(data)
            return Resp(200, json.dumps({"message": "ok"}))
        if method == "GET" and "/users/v1/" in path and not path.endswith("/_debug"):
            from urllib.parse import unquote
            uname = unquote(path.rsplit("/", 1)[-1])
            rec = self.users.get(uname)
            return Resp(200, json.dumps(rec) if rec else "{}")
        return Resp(404, "{}")


BASE = {"username": "apistrike_ma", "password": "Str1ke_P@ss", "email": "apistrike_ma@example.com"}


def _target(readback_path="/users/v1/_debug", readback_location="none", props=None):
    return MassAssignmentTarget(
        create_path="/users/v1/register",
        id_field="username",
        base_body=dict(BASE),
        readback_path=readback_path,
        readback_location=readback_location,
        props=props if props is not None else {"admin": True},
    )


def run(client, targets, **kw):
    return asyncio.run(MassAssignmentModule(client, "http://t", targets, **kw).run())


def test_taxonomy():
    assert OWASP_ID == "API3:2023"
    assert "API3:2023" in OWASP_API_TOP_10


def test_requires_targets():
    with pytest.raises(ValueError):
        MassAssignmentModule(VulnDebugServer(), "http://t", [])


def test_id_field_must_be_in_base_body():
    with pytest.raises(ValueError):
        MassAssignmentTarget(create_path="/r", id_field="username", base_body={"email": "a@b.c"})


def test_path_readback_requires_marker():
    with pytest.raises(ValueError):
        MassAssignmentTarget(create_path="/r", id_field="u", base_body={"u": "x"}, readback_path="/users/v1/here", readback_location="path")


def test_target_normalizes_and_defaults():
    t = MassAssignmentTarget(create_path="users/v1/register", id_field="u", base_body={"u": "x"})
    assert t.create_path == "/users/v1/register"
    assert t.create_method == "POST"
    assert t.props and "admin" in t.props


def test_vulnerable_confirmed_via_debug():
    res = run(VulnDebugServer(), [_target()])
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity == "high" and f.confidence == "confirmed" and f.cwe == "CWE-915"
    assert f.owasp_id == "API3:2023" and "admin" in f.title


def test_hardened_server_no_finding():
    res = run(SecureServer(), [_target()])
    assert res.findings == []
    assert any("no mass assignment" in n.lower() for n in res.notes)


def test_server_default_is_not_a_false_positive():
    res = run(AlwaysAdminServer(), [_target()])
    assert res.findings == []


def test_echo_only_firm():
    res = run(EchoOnlyServer(), [_target(readback_path="")])
    assert len(res.findings) == 1
    assert res.findings[0].severity == "medium" and res.findings[0].confidence == "firm"


def test_path_readback_confirmed():
    res = run(VulnPathServer(), [_target(readback_path="/users/v1/INJECT", readback_location="path")])
    assert len(res.findings) == 1
    assert res.findings[0].confidence == "confirmed"


def test_multi_property_aggregation():
    res = run(VulnDebugServer(), [_target(props={"admin": True, "role": "admin", "credit": 999999})])
    assert len(res.findings) == 3
    assert all(f.cwe == "CWE-915" for f in res.findings)
    assert res.tests_run == 3 and res.requests_made > 0
