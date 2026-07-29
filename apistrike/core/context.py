"""Shared Scan Context (blackboard) for APIStrike (v1.4).

A typed, in-scan knowledge store. Modules emit facts and consume facts through
this single object, replacing the implicit linear pipeline with explicit shared
memory. In-memory only (ADR-0006): a ``to_dict`` serialization seam is provided
so a future tranche can add durable/resumable context without touching module
code.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import ClassVar, Iterable, TypeVar, Union

__all__ = [
    "Endpoint",
    "Identity",
    "Token",
    "ObjectRef",
    "Param",
    "Fact",
    "Provenance",
    "ScanContext",
]


@dataclass(frozen=True)
class Endpoint:
    """A discovered API endpoint (templated path)."""

    method: str
    path: str
    source: str = "seed"
    requires_auth: bool = False
    kind: ClassVar[str] = "endpoint"

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass(frozen=True)
class Identity:
    """An authenticated (or candidate) identity."""

    label: str
    username: str = ""
    role: str = ""
    kind: ClassVar[str] = "identity"

    @property
    def key(self) -> str:
        return self.label


@dataclass(frozen=True)
class Token:
    """A captured token plus decoded claims."""

    identity: str
    raw: str = ""
    claims: dict = field(default_factory=dict)
    role: str = ""
    kind: ClassVar[str] = "token"

    @property
    def key(self) -> str:
        return self.identity


@dataclass(frozen=True)
class ObjectRef:
    """A concrete object owned by an identity (for BOLA)."""

    owner: str
    path: str
    kind: ClassVar[str] = "object"

    @property
    def key(self) -> str:
        return f"{self.owner}:{self.path}"


@dataclass(frozen=True)
class Param:
    """A parameter observed on an endpoint."""

    endpoint: str
    name: str
    location: str = "query"
    kind: ClassVar[str] = "param"

    @property
    def key(self) -> str:
        return f"{self.endpoint}:{self.location}:{self.name}"


# A "Fact" is any of the typed records above. They intentionally form a closed,
# small set for v1.4; new kinds are additive.
Fact = Union[Endpoint, Identity, Token, ObjectRef, Param]

T = TypeVar("T")


@dataclass(frozen=True)
class Provenance:
    """Who emitted a fact, when, and under which run."""

    module: str = ""
    at: str = ""
    run_id: str = ""


def _kind_of(kind: Union[str, type]) -> str:
    if isinstance(kind, str):
        return kind
    return getattr(kind, "kind")


class ScanContext:
    """A shared blackboard of typed facts for a single scan.

    Modules ``emit`` facts and query them with ``facts``/``find``. Emission is
    idempotent on a fact's ``(kind, key)`` identity, mirroring the v1.2 finding
    fingerprint model, so re-emitting a known fact refreshes provenance without
    creating a duplicate.
    """

    def __init__(self, run_id: str = "") -> None:
        self.run_id = run_id
        self._facts: dict = {}
        self._prov: dict = {}

    def emit(self, fact, module: str = "") -> bool:
        """Store ``fact``; return True if it was new (not a duplicate)."""
        idkey = (fact.kind, fact.key)
        if idkey in self._facts:
            # First-write-wins: the discovering module owns the fact; later
            # re-emissions are deduplicated and do not clobber richer data.
            return False
        self._facts[idkey] = fact
        self._prov[idkey] = Provenance(
            module=module,
            at=datetime.now(timezone.utc).isoformat(),
            run_id=self.run_id,
        )
        return True

    def emit_many(self, facts: Iterable, module: str = "") -> int:
        """Emit several facts; return how many were new."""
        return sum(1 for f in facts if self.emit(f, module=module))

    def facts(self, kind: Union[str, type]) -> list:
        """Return all facts of ``kind`` (a fact class or its kind string)."""
        want = _kind_of(kind)
        return [f for (k, _), f in self._facts.items() if k == want]

    def find(self, kind: Union[str, type], **filters) -> list:
        """Return facts of ``kind`` whose attributes match ``filters``."""
        out = []
        for f in self.facts(kind):
            if all(getattr(f, attr, None) == val for attr, val in filters.items()):
                out.append(f)
        return out

    def has(self, kind: Union[str, type]) -> bool:
        return bool(self.facts(kind))

    def provenance(self, fact):
        return self._prov.get((fact.kind, fact.key))

    def kinds_present(self) -> set:
        return {k for (k, _) in self._facts}

    def snapshot_counts(self) -> dict:
        counts: dict = {}
        for (k, _) in self._facts:
            counts[k] = counts.get(k, 0) + 1
        return counts

    def __len__(self) -> int:
        return len(self._facts)

    def to_dict(self) -> dict:
        """Serialize the context (seam for future durable/resume support)."""
        return {
            "run_id": self.run_id,
            "facts": [
                {
                    "kind": k,
                    "key": key,
                    "fields": asdict(f),
                    "provenance": asdict(self._prov[(k, key)]),
                }
                for (k, key), f in self._facts.items()
            ],
        }
