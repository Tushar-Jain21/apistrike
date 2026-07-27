"""Mass Assignment / Broken Object Property Level Authorization (API3:2023).

Stdlib-only, transport-agnostic. The engine confirms mass assignment the
deterministic way: it creates an object while smuggling a privileged property
into the request, then **reads the object back** and checks that the injected
value actually persisted. A control object (created without the property) is
read back first, so a server-side default value can never be mistaken for a
client-controlled one -- keeping false positives near zero.

Confirmation ladder (per property, strongest wins):
  * read-back shows injected value AND control default differs  -> confirmed / high
  * create response reflects the client-supplied property        -> firm / medium

The module only ever calls the API's own create/read endpoints; it never sends
destructive verbs. It does create throwaway objects (that is intrinsic to
testing mass assignment), each with a unique nonce so runs stay isolated.
"""
from __future__ import annotations

import json as _json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote

try:  # packaged import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - sandbox/local fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API3:2023"
MARKER = "INJECT"

# Properties a client should almost never be able to set directly. Values are
# the smuggled values the engine will try to make "stick".
PRIVILEGE_PROPS: Dict[str, Any] = {
    "admin": True,
    "is_admin": True,
    "isAdmin": True,
    "role": "admin",
    "roles": ["admin"],
    "is_staff": True,
    "is_superuser": True,
    "superuser": True,
    "verified": True,
    "email_verified": True,
    "is_active": True,
    "account_balance": 999999,
    "balance": 999999,
    "credit": 999999,
}

_MISSING = object()


@dataclass
class MassAssignmentTarget:
    create_path: str
    id_field: str
    base_body: Dict[str, Any]
    create_method: str = "POST"
    create_location: str = "json"  # json | query
    readback_path: str = ""  # "" disables read-back (echo-only confirmation)
    readback_method: str = "GET"
    readback_location: str = "none"  # none (list/debug endpoint) | path (INJECT marker)
    props: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    unique_fields: Sequence[str] = ("username", "email")
    email_domain: str = "example.com"

    def __post_init__(self) -> None:
        self.create_method = self.create_method.upper()
        self.readback_method = self.readback_method.upper()
        if not self.create_path.startswith("/"):
            self.create_path = "/" + self.create_path
        if self.readback_path and not self.readback_path.startswith("/"):
            self.readback_path = "/" + self.readback_path
        if self.create_location not in ("json", "query"):
            raise ValueError("create_location must be 'json' or 'query'")
        if self.readback_location not in ("none", "path"):
            raise ValueError("readback_location must be 'none' or 'path'")
        if not self.base_body:
            raise ValueError("base_body must contain the object's required fields")
        if self.id_field not in self.base_body:
            raise ValueError("id_field must be a key in base_body")
        if (
            self.readback_path
            and self.readback_location == "path"
            and MARKER not in self.readback_path
        ):
            raise ValueError("readback_path with location 'path' must contain the INJECT marker")
        if self.props is None:
            self.props = dict(PRIVILEGE_PROPS)


@dataclass
class MassAssignmentResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tests_run: int = 0
    requests_made: int = 0


def _parse_json(body: Any) -> Any:
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return body
    try:
        return _json.loads(body)
    except Exception:
        return None


def _find_record(data: Any, id_field: str, id_value: Any) -> Optional[Dict[str, Any]]:
    """Recursively locate the dict whose id_field matches id_value."""
    target = str(id_value)
    if isinstance(data, dict):
        if str(data.get(id_field)) == target:
            return data
        for value in data.values():
            found = _find_record(value, id_field, id_value)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_record(item, id_field, id_value)
            if found is not None:
                return found
    return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _equalish(a: Any, b: Any) -> bool:
    if a is None or a is _MISSING:
        return False
    if isinstance(a, bool) or isinstance(b, bool):
        return _as_bool(a) == _as_bool(b)
    if isinstance(b, (list, dict)):
        try:
            return _json.dumps(a, sort_keys=True) == _json.dumps(b, sort_keys=True)
        except Exception:
            return str(a) == str(b)
    return str(a).strip().lower() == str(b).strip().lower()


def _body_str(resp: Any) -> str:
    body = getattr(resp, "body", "") or ""
    if isinstance(body, str):
        return body
    try:
        return _json.dumps(body)
    except Exception:
        return str(body)


def _value_reflected(resp: Any, prop: str, value: Any) -> bool:
    low = _body_str(resp).lower()
    if prop.lower() not in low:
        return False
    if isinstance(value, bool):
        return ("true" if value else "false") in low
    if isinstance(value, (list, dict)):
        return True
    return str(value).lower() in low


def _short(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 48 else text[:45] + "..."


def _nonce(length: int = 8) -> str:
    return uuid.uuid4().hex[:length]


class MassAssignmentModule:
    def __init__(
        self,
        client: Any,
        base_url: str,
        targets: Sequence[MassAssignmentTarget],
        *,
        safe: bool = True,
    ) -> None:
        if not targets:
            raise ValueError("MassAssignmentModule requires at least one target")
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.targets = list(targets)
        self.safe = safe
        self._requests = 0

    async def _send(self, method, path, *, location, body=None, params=None, headers):
        url = self.base_url + path
        kwargs: Dict[str, Any] = {"headers": headers}
        if location == "json" and body is not None:
            kwargs["json"] = body
        elif location == "query" and params is not None:
            kwargs["params"] = params
        resp = await self.client.request(method, url, **kwargs)
        self._requests += 1
        return resp

    def _fresh_body(self, tgt: MassAssignmentTarget):
        body = dict(tgt.base_body)
        nonce = _nonce()
        for fname in tgt.unique_fields:
            if fname in body:
                if "email" in fname.lower():
                    local = str(body.get(fname) or "user").split("@")[0]
                    body[fname] = local + "_" + nonce + "@" + tgt.email_domain
                else:
                    body[fname] = str(body[fname]) + "_" + nonce
        return body, body.get(tgt.id_field)

    async def _create(self, tgt, body, headers):
        if tgt.create_location == "json":
            return await self._send(tgt.create_method, tgt.create_path, location="json", body=body, headers=headers)
        return await self._send(tgt.create_method, tgt.create_path, location="query", params=body, headers=headers)

    def _readback_target_path(self, tgt, id_value):
        if tgt.readback_location == "path":
            return tgt.readback_path.replace(MARKER, quote(str(id_value), safe=""))
        return tgt.readback_path

    async def _readback_record(self, tgt, id_value, headers):
        if not tgt.readback_path:
            return None
        path = self._readback_target_path(tgt, id_value)
        resp = await self._send(tgt.readback_method, path, location="none", headers=headers)
        data = _parse_json(getattr(resp, "body", None))
        if data is None:
            return None
        record = _find_record(data, tgt.id_field, id_value)
        if record is None and isinstance(data, dict):
            record = data  # endpoint returned the object directly
        return record

    async def _scan_target(self, tgt, store):
        findings: List[Finding] = []
        notes: List[str] = []
        tests = 0
        headers = dict(tgt.headers)

        control_record = None
        if tgt.readback_path:
            control_body, control_id = self._fresh_body(tgt)
            await self._create(tgt, control_body, headers)
            control_record = await self._readback_record(tgt, control_id, headers)

        for prop, value in tgt.props.items():
            tests += 1
            body, oid = self._fresh_body(tgt)
            body[prop] = value
            create_resp = await self._create(tgt, body, headers)
            echoed = _value_reflected(create_resp, prop, value)

            confirmed = False
            detail = ""
            if tgt.readback_path:
                record = await self._readback_record(tgt, oid, headers)
                if record is not None and prop in record and _equalish(record.get(prop), value):
                    control_val = control_record.get(prop) if isinstance(control_record, dict) else None
                    if not _equalish(control_val, value):
                        confirmed = True
                        detail = (
                            "read-back of the created object shows "
                            + prop + "=" + _short(record.get(prop))
                            + " (control default: " + _short(control_val) + ")"
                        )

            if confirmed:
                findings.append(self._finding(tgt, prop, value, confidence="confirmed", severity="high", detail=detail))
            elif echoed:
                findings.append(
                    self._finding(
                        tgt,
                        prop,
                        value,
                        confidence="firm",
                        severity="medium",
                        detail="the create response reflected the client-supplied '" + prop + "' property (no read-back available to confirm persistence)",
                    )
                )

        if not findings:
            notes.append(
                "No mass assignment confirmed at " + tgt.create_method + " " + tgt.create_path
                + ": injected privileged properties did not persist on read-back."
            )

        if store is not None:
            for finding in findings:
                store.add(finding)
        return findings, notes, tests

    def _finding(self, tgt, prop, value, *, confidence, severity, detail):
        endpoint = tgt.create_method + " " + tgt.create_path
        return Finding(
            title="Mass assignment: client-controlled '" + prop + "' at " + endpoint,
            severity=severity,
            owasp_id=OWASP_ID,
            endpoint=endpoint,
            description=(
                "The API accepted a client-supplied '" + prop + "' property (value "
                + _short(value) + ") that should not be settable by the caller. " + detail
                + ". This is Broken Object Property Level Authorization (mass assignment): by adding "
                "extra properties to the request body an attacker can escalate privileges or tamper "
                "with server-protected fields."
            ),
            cwe="CWE-915",
            recommendation=(
                "Bind only an explicit allow-list of client-settable properties (a DTO/schema "
                "whitelist). Never hand the raw request body to the ORM/model. Reject or silently "
                "ignore unknown and privileged fields on the server side."
            ),
            confidence=confidence,
            evidence=[detail or ("client-supplied '" + prop + "' reflected in create response")],
        )

    async def run(self, store=None) -> MassAssignmentResult:
        result = MassAssignmentResult()
        for tgt in self.targets:
            findings, notes, tests = await self._scan_target(tgt, store)
            result.findings.extend(findings)
            result.notes.extend(notes)
            result.tests_run += tests
        result.requests_made = self._requests
        return result
