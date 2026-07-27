"""Tests for the Improper Inventory module (API9:2023).

Uses a fake in-memory HTTP client with programmable routes; no network.
"""
import asyncio

import pytest

from apistrike.modules.inventory import (
    InventoryModule,
    DEFAULT_SURFACES,
    _looks_present,
    _versions_in,
)

BASE = "http://localhost:5000"


def run(coro):
    return asyncio.run(coro)


class FakeResp:
    def __init__(self, status_code, body=""):
        self.status_code = status_code
        self.body = body
        self.elapsed_ms = 1.0


class FakeClient:
    def __init__(self, routes, default=(404, "not found")):
        self.routes = routes
        self.default = default
        self.calls = []

    async def request(self, method, url, **kwargs):
        path = url
        for prefix in ("http://", "https://"):
            if path.startswith(prefix):
                rest = path[len(prefix):]
                path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
                break
        self.calls.append((method, path))
        status, body = self.routes.get(path, self.default)
        return FakeResp(status, body)


def test_surface_openapi_flagged():
    client = FakeClient({"/openapi.json": (200, '{"openapi":"3.0"}')})
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert len(res.findings) == 1
    f = res.findings[0]
    assert "OpenAPI" in f.title
    assert f.severity == "medium"
    assert f.owasp_id == "API9:2023"
    assert f.cwe == "CWE-200"


def test_surface_env_high():
    client = FakeClient({"/.env": (200, "SECRET=abc")})
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert any(f.severity == "high" and "Environment" in f.title for f in res.findings)


def test_surface_protected_present():
    client = FakeClient({"/actuator": (401, "unauthorized")})
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert any("Actuator" in f.title for f in res.findings)


def test_surface_no_false_positive_on_404():
    client = FakeClient({})  # everything 404
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert res.findings == []
    assert any("No improper-inventory" in n for n in res.notes)


def test_version_discovery_v2():
    client = FakeClient({"/users/v2/users": (200, '{"users":[]}')})
    m = InventoryModule(client, BASE, documented_paths=["/users/v1/users"], checks=("versions",), max_version=3)
    res = run(m.run())
    assert any("v2" in f.title for f in res.findings)
    f = [f for f in res.findings if "v2" in f.title][0]
    assert f.severity == "medium" and f.owasp_id == "API9:2023" and f.cwe == "CWE-1059"


def test_version_documented_not_reported():
    client = FakeClient({"/users/v1/users": (200, '{"users":[]}')})
    m = InventoryModule(client, BASE, documented_paths=["/users/v1/users"], checks=("versions",))
    res = run(m.run())
    assert not any("/users/v1/users" in f.endpoint for f in res.findings)


def test_version_no_fp_when_siblings_404():
    client = FakeClient({})
    m = InventoryModule(client, BASE, documented_paths=["/users/v1/users"], checks=("versions",))
    res = run(m.run())
    assert res.findings == []


def test_version_skipped_without_paths():
    client = FakeClient({})
    m = InventoryModule(client, BASE, checks=("versions",))
    res = run(m.run())
    assert any("no documented paths" in n.lower() for n in res.notes)


def test_catchall_no_false_positive():
    body = "<html>welcome</html>"
    client = FakeClient({}, default=(200, body))
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert res.findings == []
    assert any("catch-all" in n for n in res.notes)


def test_catchall_divergent_body_flagged():
    client = FakeClient({"/openapi.json": (200, "x" * 5000)}, default=(200, "nope"))
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert any("OpenAPI" in f.title for f in res.findings)


def test_invalid_checks_raises():
    client = FakeClient({})
    with pytest.raises(ValueError):
        InventoryModule(client, BASE, checks=("bogus",))


def test_store_persist_called():
    class Store:
        def __init__(self):
            self.items = []
        def add(self, f):
            self.items.append(f)
    client = FakeClient({"/openapi.json": (200, '{"x":1}'), "/.env": (200, "A=1")})
    m = InventoryModule(client, BASE, checks=("surfaces",))
    store = Store()
    res = run(m.run(store=store))
    assert len(store.items) == len(res.findings) >= 2


def test_request_count_includes_calibration():
    client = FakeClient({"/openapi.json": (200, '{"x":1}')})
    m = InventoryModule(client, BASE, checks=("surfaces",))
    res = run(m.run())
    assert res.requests_made == 1 + len(DEFAULT_SURFACES)


def test_multi_documented_versions_not_reprobed():
    client = FakeClient({"/users/v3/users": (200, '{"users":[]}')})
    m = InventoryModule(client, BASE, documented_paths=["/users/v1/users", "/users/v2/users"], checks=("versions",), max_version=3)
    res = run(m.run())
    probed = [p for (_, p) in client.calls]
    assert "/users/v1/users" not in probed and "/users/v2/users" not in probed
    assert any("v3" in f.title for f in res.findings)


def test_helpers():
    assert _versions_in(["/users/v1/users", "/x/v3/y"]) == {1, 3}
    # normal server: 404 junk -> a 200 candidate is present
    assert _looks_present(200, 100, 404, 20) is True
    # catch-all: 200 with same-ish length -> not present
    assert _looks_present(200, 25, 200, 20) is False
    # protected always present
    assert _looks_present(403, 5, 200, 20) is True
