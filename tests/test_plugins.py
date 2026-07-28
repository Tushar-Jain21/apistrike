"""Tests for the APIStrike plugin API and module registry."""
from __future__ import annotations

import asyncio

import pytest

from apistrike import plugins
from apistrike.plugins import (
    AttackModule,
    ModuleContext,
    ModuleSpec,
    all_specs,
    discover_entry_points,
    get,
    names,
    register,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Isolate every test from the global registry state."""
    saved = dict(plugins.REGISTRY)
    saved_loaded = plugins._ENTRY_POINTS_LOADED
    plugins.REGISTRY.clear()
    plugins._ENTRY_POINTS_LOADED = False
    try:
        yield
    finally:
        plugins.REGISTRY.clear()
        plugins.REGISTRY.update(saved)
        plugins._ENTRY_POINTS_LOADED = saved_loaded


class FakeStore:
    def __init__(self):
        self.added = []

    def add(self, finding):
        self.added.append(finding)


class _Result:
    def __init__(self, notes):
        self.notes = notes
        self.requests_made = 1


class MockModule:
    def __init__(self, ctx, tag="mock"):
        self.ctx = ctx
        self.tag = tag

    async def run(self, store):
        store.add({"title": self.tag, "endpoint": self.ctx.base_url})
        return _Result(notes=["ran " + self.tag])


def _spec(name="mock", **kw):
    return ModuleSpec(name=name, build=lambda ctx: MockModule(ctx), **kw)


def test_register_and_get():
    register(_spec("mock", owasp_id="API8:2023", description="d"))
    spec = get("mock")
    assert spec.name == "mock"
    assert spec.owasp_id == "API8:2023"
    assert "mock" in names()


def test_register_requires_name():
    with pytest.raises(ValueError):
        register(ModuleSpec(name="", build=lambda ctx: MockModule(ctx)))


def test_aliases_resolve_to_same_spec():
    register(_spec("mock", aliases=("m", "mc")))
    assert get("m") is get("mock")
    assert get("mc") is get("mock")
    assert names().count("mock") == 1


def test_get_unknown_raises():
    with pytest.raises(KeyError):
        get("does-not-exist")


def test_all_specs_dedupes_aliases():
    register(_spec("mock", aliases=("m",)))
    register(_spec("other"))
    got = sorted(s.name for s in all_specs())
    assert got == ["mock", "other"]


def test_module_context_helpers():
    ctx = ModuleContext(
        client=None,
        base_url="http://x",
        options={"checks": "a,b", "active": "true"},
    )
    assert ctx.opt("checks") == "a,b"
    assert ctx.opt("missing", "def") == "def"
    assert ctx.flag("active") is True
    assert ctx.flag("nope") is False


def test_build_and_run_persists_to_store():
    register(_spec("mock"))
    ctx = ModuleContext(client=None, base_url="http://target", path="/")
    mod = get("mock").build(ctx)
    assert isinstance(mod, AttackModule)
    store = FakeStore()
    result = asyncio.run(mod.run(store=store))
    assert store.added and store.added[0]["title"] == "mock"
    assert result.notes == ["ran mock"]


class _FakeEP:
    def __init__(self, obj):
        self._obj = obj

    def load(self):
        return self._obj


def test_discover_entry_points_with_spec_instance():
    loaded = discover_entry_points([_FakeEP(_spec("from-ep"))])
    assert loaded == ["from-ep"]
    assert "from-ep" in names()


def test_discover_entry_points_with_factory():
    loaded = discover_entry_points([_FakeEP(lambda: _spec("factory-ep"))])
    assert loaded == ["factory-ep"]
    assert "factory-ep" in names()


def test_discover_entry_points_ignores_bad_entries():
    def _boom():
        raise RuntimeError("boom")

    loaded = discover_entry_points(
        [_FakeEP(_spec("good")), _FakeEP(object()), _FakeEP(_boom)]
    )
    assert loaded == ["good"]


def test_builtin_registers_misconfig():
    plugins.load_builtins()
    assert "misconfig" in names()
    assert get("misconfig").owasp_id == "API8:2023"
