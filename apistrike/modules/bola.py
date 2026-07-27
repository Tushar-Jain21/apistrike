"""Broken Object Level Authorization (OWASP API1:2023) checks for APIStrike.

BOLA -- also called IDOR -- is the #1 API risk: an endpoint exposes an object by
an id/name in the URL but fails to verify that the *caller* is allowed to touch
*that* object. So user A can read (or modify) user B's data just by changing the
identifier.

This module confirms BOLA the deterministic way. With two or more authenticated
identities it builds an access matrix: for every object owned by identity A it
replays the exact same request as identity B (and, optionally, with no token at
all). If B receives A's object, that is a confirmed authorization bypass.

Optionally it performs light *horizontal id enumeration*: for an object whose
URL ends in a numeric id, it probes neighbouring ids with the owner's own token
and flags any *different* valid object that comes back -- evidence the id space
is walkable.

Design rules honoured here:
  * No module talks to httpx directly -- every request goes through the injected
    ScopedHTTPClient, so scope + rate limiting always apply.
  * Evidence-driven: a finding is only recorded after a live response proves the
    cross-user (or unauthenticated) access actually succeeded. Body comparison
    keeps confidence high and false positives near zero.
  * Pure standard library -- trivially unit-testable offline with a fake client.

Read-only by default (issues GETs using identities you supplied). Use only
against systems you are authorised to test.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from apistrike.core.findings import Finding


@dataclass
class BolaIdentity:
    """An authenticated caller: a label plus the headers that authenticate it."""
    label: str
    headers: Dict[str, str] = field(default_factory=dict)
    username: str = ""


@dataclass
class ObjectRef:
    """A concrete object exposed at ``path`` and owned by ``owner_label``."""
    path: str
    owner_label: str
    name: str = ""
    method: str = "GET"

    def __post_init__(self):
        if not self.path.startswith("/"):
            self.path = "/" + self.path
        if not self.name:
            self.name = self.path


@dataclass
class BolaResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tested_objects: int = 0
    cross_user_access: int = 0
    unauth_access: int = 0
    enumerated_objects: int = 0


def _norm_body(body) -> str:
    """Normalise a response body to a comparable string."""
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8", "replace")
        except Exception:
            return str(body)
    if isinstance(body, (dict, list)):
        try:
            return json.dumps(body, sort_keys=True, default=str)
        except Exception:
            return str(body)
    return str(body)


_NUM_TAIL = re.compile(r"^(.*?/)(\d+)(/?)$")


def numeric_neighbors(path: str, spread: int) -> List[str]:
    """For a path ending in a numeric segment, return neighbour paths (id +/- 1..spread).

    Returns [] if the path has no trailing numeric id or spread <= 0.
    """
    if spread <= 0:
        return []
    m = _NUM_TAIL.match(path)
    if not m:
        return []
    prefix, num, trailing = m.group(1), int(m.group(2)), m.group(3)
    out: List[str] = []
    for delta in range(1, spread + 1):
        for cand in (num - delta, num + delta):
            if cand >= 1 and cand != num:
                out.append(f"{prefix}{cand}{trailing}")
    return out


class BolaModule:
    OWASP_ID = "API1:2023"

    def __init__(self, client, base_url: str, identities: Sequence[BolaIdentity],
                 objects: Sequence[ObjectRef], *,
                 success_statuses: Sequence[int] = (200, 201, 202, 203, 206),
                 compare_body: bool = True, unauth_check: bool = True,
                 enumerate_spread: int = 0):
        if len(identities) < 2 and not unauth_check:
            raise ValueError("BolaModule needs at least two identities (or unauth_check enabled).")
        if not objects:
            raise ValueError("BolaModule needs at least one ObjectRef to test.")
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.identities = list(identities)
        self.by_label = {i.label: i for i in self.identities}
        self.objects = list(objects)
        self.success_statuses = tuple(success_statuses)
        self.compare_body = compare_body
        self.unauth_check = unauth_check
        self.enumerate_spread = enumerate_spread

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path if path.startswith('/') else '/' + path}"

    async def _fetch(self, path: str, headers: Dict[str, str]):
        return await self.client.get(self._url(path), headers=headers or {})

    def _ok(self, status: int) -> bool:
        return status in self.success_statuses

    def _same_object(self, a, b) -> bool:
        if not self.compare_body:
            return True
        na, nb = _norm_body(a), _norm_body(b)
        return bool(na) and na == nb

    def _evidence(self, check, path, as_label, status, extra=None) -> dict:
        ev = {"check": check, "url": self._url(path), "accessed_as": as_label, "status": status}
        if extra:
            ev.update(extra)
        return ev

    async def _check_object(self, obj: ObjectRef, result: BolaResult) -> None:
        owner = self.by_label.get(obj.owner_label)
        if owner is None:
            result.notes.append(f"Skipped {obj.name}: owner '{obj.owner_label}' not in identities.")
            return
        base = await self._fetch(obj.path, owner.headers)
        if not self._ok(base.status_code):
            result.notes.append(
                f"Skipped {obj.name}: owner '{owner.label}' got HTTP {base.status_code} "
                "(could not establish a baseline)."
            )
            return
        result.tested_objects += 1

        # --- multi-user diffing: can another identity read the owner's object? ---
        for other in self.identities:
            if other.label == owner.label:
                continue
            ev = await self._fetch(obj.path, other.headers)
            if self._ok(ev.status_code) and self._same_object(base.body, ev.body):
                result.cross_user_access += 1
                result.findings.append(Finding(
                    title=f"BOLA: '{other.label}' can access {obj.owner_label}'s object ({obj.path})",
                    severity="high",
                    owasp_id=self.OWASP_ID,
                    endpoint=obj.path,
                    cwe="CWE-639",
                    confidence="confirmed",
                    description=(
                        f"The object at {obj.path} belongs to '{obj.owner_label}', but identity "
                        f"'{other.label}' received the identical object using its own credentials. "
                        "The endpoint authenticates the caller but never checks that the caller is "
                        "authorised for this specific object, so any user can read another user's data "
                        "by changing the identifier in the URL."
                    ),
                    recommendation=(
                        "Enforce object-level authorization on every request: verify the authenticated "
                        "principal owns (or has an explicit grant to) the referenced object before "
                        "returning it. Prefer unguessable identifiers and deny by default."
                    ),
                    evidence=[
                        self._evidence("baseline_owner", obj.path, owner.label, base.status_code),
                        self._evidence("cross_user", obj.path, other.label, ev.status_code, {"body_matched_owner": True}),
                    ],
                ))

        # --- unauthenticated access ---
        if self.unauth_check:
            ev = await self._fetch(obj.path, {})
            if self._ok(ev.status_code) and self._same_object(base.body, ev.body):
                result.unauth_access += 1
                result.findings.append(Finding(
                    title=f"BOLA: {obj.owner_label}'s object is readable without authentication ({obj.path})",
                    severity="critical",
                    owasp_id=self.OWASP_ID,
                    endpoint=obj.path,
                    cwe="CWE-306",
                    confidence="confirmed",
                    description=(
                        f"The object at {obj.path} belongs to '{obj.owner_label}' but was returned to an "
                        "unauthenticated request (no token). The endpoint exposes protected data to anyone "
                        "on the network."
                    ),
                    recommendation=(
                        "Require authentication on this endpoint and enforce object-level authorization "
                        "for the authenticated principal."
                    ),
                    evidence=[
                        self._evidence("baseline_owner", obj.path, owner.label, base.status_code),
                        self._evidence("unauthenticated", obj.path, "<no token>", ev.status_code, {"body_matched_owner": True}),
                    ],
                ))

        # --- horizontal id enumeration (opt-in) ---
        if self.enumerate_spread > 0:
            walked = []
            for npath in numeric_neighbors(obj.path, self.enumerate_spread):
                ev = await self._fetch(npath, owner.headers)
                nb = _norm_body(ev.body)
                if self._ok(ev.status_code) and nb and nb != _norm_body(base.body):
                    walked.append({"path": npath, "status": ev.status_code})
            if walked:
                result.enumerated_objects += len(walked)
                result.findings.append(Finding(
                    title=f"BOLA: object id space is walkable near {obj.path}",
                    severity="high",
                    owasp_id=self.OWASP_ID,
                    endpoint=obj.path,
                    cwe="CWE-639",
                    confidence="confirmed",
                    description=(
                        f"Using '{owner.label}'s own token, {len(walked)} neighbouring numeric id(s) around "
                        f"{obj.path} returned distinct valid objects. Sequential/guessable identifiers combined "
                        "with missing object-level authorization let an attacker enumerate other users' objects."
                    ),
                    recommendation=(
                        "Use non-sequential, unguessable identifiers (e.g. UUIDs) and enforce per-object "
                        "authorization so walking the id space returns 403/404 for objects the caller does not own."
                    ),
                    evidence=[self._evidence("enumeration", w["path"], owner.label, w["status"]) for w in walked],
                ))

    async def run(self, store=None) -> BolaResult:
        result = BolaResult()
        for obj in self.objects:
            await self._check_object(obj, result)
        if not result.findings:
            result.notes.append(
                "No BOLA confirmed: cross-user/unauthenticated requests did not return other users' objects."
            )
        if store is not None:
            for finding in result.findings:
                store.add(finding)
        return result
