"""APIStrike plugin API and module registry.

This package lets attack modules be discovered and invoked WITHOUT editing
cli.py. A module is described by a :class:`ModuleSpec` (name + metadata + a
``build`` factory). Built-in modules register themselves in
``apistrike.plugins.builtin``; third-party packages register via a Python
entry point in the ``apistrike.modules`` group.

Module contract (matches every existing APIStrike module):

    class MyModule:
        def __init__(self, client, base_url, **opts): ...
        async def run(self, store) -> object: ...

``run(store=...)`` receives an OPEN ``FindingsStore`` and is responsible for
persisting its own findings into it (the CLI reads ``store.summary()``
afterwards). It returns a small result object exposing ``.notes`` and
``.requests_made`` for display. This mirrors how the built-in commands already
call ``await module.run(store=store)``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    Tuple,
    runtime_checkable,
)

ENTRY_POINT_GROUP = "apistrike.modules"


@runtime_checkable
class AttackModule(Protocol):
    """Structural type every runnable module satisfies."""

    async def run(self, store: Any) -> Any:  # pragma: no cover - protocol
        ...


@dataclass
class ModuleContext:
    """Everything a ``build()`` factory needs to construct a module.

    Mirrors how the built-in CLI commands wire a module: an in-scope
    ``ScopedHTTPClient``, the target base URL, a representative path, any auth
    headers already negotiated, the scope's safe-mode flag, and a free-form
    ``options`` dict populated from repeated ``--option key=value`` flags.
    """

    client: Any
    base_url: str
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    safe: bool = True
    options: Dict[str, str] = field(default_factory=dict)

    def opt(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Return a string option or ``default``."""
        return self.options.get(key, default)

    def flag(self, key: str, default: bool = False) -> bool:
        """Return a boolean option (true/1/yes/on are truthy)."""
        val = self.options.get(key)
        if val is None:
            return default
        return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class ModuleSpec:
    """Describes a runnable module for the registry."""

    name: str
    build: Callable[[ModuleContext], AttackModule]
    owasp_id: str = ""
    description: str = ""
    aliases: Tuple[str, ...] = ()


REGISTRY: Dict[str, ModuleSpec] = {}


def register(spec: ModuleSpec) -> ModuleSpec:
    """Register (or replace) a module spec by name and any aliases."""
    if not spec.name:
        raise ValueError("ModuleSpec.name is required")
    REGISTRY[spec.name] = spec
    for alias in spec.aliases:
        REGISTRY[alias] = spec
    return spec


def module(
    name: str,
    *,
    owasp_id: str = "",
    description: str = "",
    aliases: Iterable[str] = (),
) -> Callable[[Callable[[ModuleContext], AttackModule]], Callable[[ModuleContext], AttackModule]]:
    """Decorator: register a build factory as a :class:`ModuleSpec`.

    Example::

        @module("myscan", owasp_id="API1:2023", description="...")
        def build(ctx):
            return MyModule(ctx.client, ctx.base_url, safe=ctx.safe)
    """

    def _decorator(build_fn: Callable[[ModuleContext], AttackModule]):
        register(
            ModuleSpec(
                name=name,
                build=build_fn,
                owasp_id=owasp_id,
                description=description,
                aliases=tuple(aliases),
            )
        )
        return build_fn

    return _decorator


def get(name: str) -> ModuleSpec:
    """Return a spec by name/alias or raise ``KeyError`` with a helpful list."""
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(
            "unknown module '%s' (known: %s)" % (name, ", ".join(names()))
        )


def names() -> List[str]:
    """Sorted list of canonical module names (aliases excluded)."""
    return sorted(spec.name for spec in _unique_specs())


def all_specs() -> List[ModuleSpec]:
    """All registered specs, de-duplicated across aliases."""
    return list(_unique_specs())


def _unique_specs() -> Iterable[ModuleSpec]:
    out: Dict[int, ModuleSpec] = {}
    for spec in REGISTRY.values():
        out[id(spec)] = spec
    return out.values()


_ENTRY_POINTS_LOADED = False


def _coerce_spec(obj: Any) -> Optional[ModuleSpec]:
    """Accept a ModuleSpec instance or a zero-arg factory returning one."""
    if isinstance(obj, ModuleSpec):
        return obj
    if callable(obj):
        try:
            result = obj()
        except Exception:
            return None
        if isinstance(result, ModuleSpec):
            return result
    return None


def discover_entry_points(
    entry_points: Optional[Iterable[Any]] = None,
    *,
    force: bool = False,
) -> List[str]:
    """Load third-party specs from the ``apistrike.modules`` entry-point group.

    Pass ``entry_points`` explicitly (an iterable of objects exposing
    ``.load()``) to test discovery without installing a package. When called
    with no arguments it reads the installed entry points once (idempotent
    unless ``force=True``).
    """
    global _ENTRY_POINTS_LOADED
    loaded: List[str] = []
    if entry_points is None:
        if _ENTRY_POINTS_LOADED and not force:
            return loaded
        entry_points = _iter_installed_entry_points()
        _ENTRY_POINTS_LOADED = True
    for ep in entry_points:
        try:
            obj = ep.load() if hasattr(ep, "load") else ep
        except Exception:
            continue
        spec = _coerce_spec(obj)
        if spec is not None:
            register(spec)
            loaded.append(spec.name)
    return loaded


def _iter_installed_entry_points() -> Iterable[Any]:
    try:
        from importlib.metadata import entry_points as _eps
    except Exception:
        return []
    try:
        eps = _eps()
    except Exception:
        return []
    select = getattr(eps, "select", None)
    if select is not None:  # Python 3.10+ selectable API
        try:
            return list(select(group=ENTRY_POINT_GROUP))
        except Exception:
            return []
    try:  # older mapping API
        return list(eps.get(ENTRY_POINT_GROUP, []))  # type: ignore[attr-defined]
    except Exception:
        return []


def load_builtins() -> None:
    """Import and register the built-in module specs (idempotent)."""
    from apistrike.plugins import builtin  # noqa: F401


__all__ = [
    "AttackModule",
    "ModuleContext",
    "ModuleSpec",
    "ENTRY_POINT_GROUP",
    "REGISTRY",
    "register",
    "module",
    "get",
    "names",
    "all_specs",
    "discover_entry_points",
    "load_builtins",
]
