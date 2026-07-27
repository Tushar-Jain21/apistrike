"""Tests for the BFLA module (OWASP API5:2023)."""

import asyncio

import pytest

from apistrike.modules.bfla import (
    BflaIdentity,
    BflaModule,
    Operation,
    SAFE_METHODS,
    DESTRUCTIVE_METHODS,
)


class _Resp:
    def __init__(self, status, body=""):
        self.status_code = status
        self.body = body


def _role_of(headers):
    auth = (headers or {}).get("Authorization", "")
    if "admin" in auth:
        return "admin"
    if auth:
        return "user"
    return "anon"


class _Client:
    def __init__(self, server):
        self.server = server
        self.calls = []

    async def request(self, method, url, headers=None):
        path = url.split("://", 1)[-1]
        path = path[path.find("/"):] if "/" in path else "/"
        self.calls.append((method.upper(), path, _role_of(headers)))
        return self.server(method.upper(), path, headers or {})


def _vampi_like(method, path, headers):
    role = _role_of(headers)
    if path == "/users/v1/_debug" and method == "GET":
        return _Resp(200, '{"users": [{"u": "name1"}]}')
    if path == "/admin/v1/report" and method == "GET":
        if role == "admin":
            return _Resp(200, '{"report": true}')
        if role == "anon":
            return _Resp(401, "auth required")
        return _Resp(403, "forbidden")
    if path.startswith("/users/v1/") and method == "DELETE":
        if role == "anon":
            return _Resp(401, "auth required")
        return _Resp(200, '{"deleted": true}')
    return _Resp(404, "not found")


ADMIN = BflaIdentity("admin", {"Authorization": "Bearer admin-token"}, role="admin")
USER = BflaIdentity("name1", {"Authorization": "Bearer name1-token"}, role="user")


def _run(module):
    return asyncio.run(module.run())


def test_operation_autoclassifies_destructive():
    assert Operation("GET", "/x").destructive is False
    assert Operation("delete", "/x").destructive is True
    assert "DELETE" in DESTRUCTIVE_METHODS and "OPTIONS" in SAFE_METHODS


def test_operation_normalizes_path_and_name():
    op = Operation("get", "users/v1/_debug")
    assert op.method == "GET"
    assert op.path == "/users/v1/_debug"
    assert op.name == "GET /users/v1/_debug"


def test_confirmed_escalation_and_unauth_on_unprotected_privileged_read():
    client = _Client(_vampi_like)
    module = BflaModule(
        client,
        "http://t",
        [ADMIN, USER],
        [Operation("GET", "/users/v1/_debug"), Operation("GET", "/admin/v1/report")],
    )
    res = _run(module)
    assert res.tested_operations == 2
    assert res.escalations == 1
    assert res.unauth_invocations == 1
    assert len(res.findings) == 2
    assert sorted(f.severity for f in res.findings) == ["critical", "high"]
    assert all(f.owasp_id == "API5:2023" for f in res.findings)
    assert all(f.confidence == "confirmed" for f in res.findings)


def test_secure_privileged_op_yields_no_finding():
    client = _Client(_vampi_like)
    module = BflaModule(client, "http://t", [ADMIN, USER], [Operation("GET", "/admin/v1/report")])
    res = _run(module)
    assert res.findings == []
    assert res.escalations == 0 and res.unauth_invocations == 0


def test_escalation_and_unauth_severity_and_cwe():
    client = _Client(_vampi_like)
    module = BflaModule(client, "http://t", [ADMIN, USER], [Operation("GET", "/users/v1/_debug")])
    res = _run(module)
    esc = next(f for f in res.findings if f.severity == "high")
    unauth = next(f for f in res.findings if f.severity == "critical")
    assert esc.cwe == "CWE-285"
    assert unauth.cwe == "CWE-862"


def test_safe_mode_skips_destructive_ops():
    client = _Client(_vampi_like)
    module = BflaModule(client, "http://t", [ADMIN, USER], [Operation("DELETE", "/users/v1/name2")], safe=True)
    res = _run(module)
    assert res.skipped_destructive == 1
    assert res.tested_operations == 0
    assert res.findings == []
    assert all(call[0] != "DELETE" for call in client.calls)


def test_active_mode_fires_destructive_and_flags_escalation():
    client = _Client(_vampi_like)
    module = BflaModule(client, "http://t", [ADMIN, USER], [Operation("DELETE", "/users/v1/name2")], safe=False)
    res = _run(module)
    assert any(call[0] == "DELETE" for call in client.calls)
    assert res.escalations == 1
    assert res.unauth_invocations == 0
    assert res.findings[0].confidence == "confirmed"


def test_without_admin_baseline_confidence_is_firm():
    client = _Client(_vampi_like)
    module = BflaModule(client, "http://t", [USER], [Operation("GET", "/users/v1/_debug")])
    res = _run(module)
    assert res.escalations == 1 and res.unauth_invocations == 1
    assert all(f.confidence == "firm" for f in res.findings)


def test_unauth_check_can_be_disabled():
    client = _Client(_vampi_like)
    module = BflaModule(client, "http://t", [USER], [Operation("GET", "/users/v1/_debug")], unauth_check=False)
    res = _run(module)
    assert res.unauth_invocations == 0
    assert all(call[2] != "anon" for call in client.calls)


def test_requires_at_least_one_operation():
    with pytest.raises(ValueError):
        BflaModule(_Client(_vampi_like), "http://t", [USER], [])


def test_requires_identity_or_unauth_check():
    with pytest.raises(ValueError):
        BflaModule(_Client(_vampi_like), "http://t", [], [Operation("GET", "/x")], unauth_check=False)
