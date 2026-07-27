"""APIStrike BFLA module (OWASP API5:2023 - Broken Function Level Authorization).

BFLA is about *function*-level access control: whether a lower-privilege
identity (or an unauthenticated caller) can invoke a *privileged function* --
an administrative endpoint or a state-changing method that should be restricted
to a higher role.

Confirmation model ("AI advises, engine confirms"):
- When a privileged/admin identity is supplied, the module first confirms the
  operation really is a working privileged function (admin -> success). If a
  lower-role identity then also succeeds, that is a CONFIRMED function-level
  escalation.
- Without an admin baseline the module still flags a lower role (or anon)
  succeeding on an operation the tester explicitly marked privileged, but at
  'firm' confidence rather than 'confirmed'.

Safety:
- Operations are auto-classified by method: GET/HEAD/OPTIONS are
  non-destructive; POST/PUT/PATCH/DELETE are destructive.
- In safe mode destructive operations are NOT invoked -- they are skipped with
  a note. Set safe=False (an explicit, authorized decision, surfaced in the CLI
  as --active) to exercise destructive privileged functions.

The caller declares which operations are privileged; the module trusts that
declaration. It does not guess which endpoints "should" be admin-only.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:  # package import
    from apistrike.core.findings import Finding
except Exception:  # pragma: no cover - fallback for flat layout / verify script
    from findings import Finding  # type: ignore

OWASP_ID = "API5:2023"

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
DESTRUCTIVE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
DEFAULT_SUCCESS_STATUSES = (200, 201, 202, 203, 204, 206)
DEFAULT_FORBIDDEN_STATUSES = (401, 403)


@dataclass
class BflaIdentity:
    """An authenticated (or anonymous) caller with a role label."""

    label: str
    headers: Dict[str, str] = field(default_factory=dict)
    role: str = "user"


@dataclass
class Operation:
    """A privileged function to probe: an HTTP method + path."""

    method: str
    path: str
    name: str = ""
    destructive: Optional[bool] = None

    def __post_init__(self) -> None:
        self.method = self.method.upper().strip()
        if not self.path.startswith("/"):
            self.path = "/" + self.path
        if not self.name:
            self.name = "{0} {1}".format(self.method, self.path)
        if self.destructive is None:
            self.destructive = self.method in DESTRUCTIVE_METHODS


@dataclass
class BflaResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tested_operations: int = 0
    escalations: int = 0
    unauth_invocations: int = 0
    skipped_destructive: int = 0


class BflaModule:
    OWASP_ID = OWASP_ID

    def __init__(
        self,
        client,
        base_url: str,
        identities: List[BflaIdentity],
        operations: List[Operation],
        *,
        admin_label: Optional[str] = None,
        success_statuses=DEFAULT_SUCCESS_STATUSES,
        forbidden_statuses=DEFAULT_FORBIDDEN_STATUSES,
        safe: bool = True,
        unauth_check: bool = True,
    ) -> None:
        if not operations:
            raise ValueError("BflaModule needs at least one Operation to test.")
        identities = list(identities or [])
        if not identities and not unauth_check:
            raise ValueError(
                "BflaModule needs at least one identity or unauth_check enabled."
            )
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.identities = identities
        self.operations = list(operations)
        self.success_statuses = tuple(success_statuses)
        self.forbidden_statuses = tuple(forbidden_statuses)
        self.safe = safe
        self.unauth_check = unauth_check

        self.admin: Optional[BflaIdentity] = None
        if admin_label:
            self.admin = next(
                (i for i in self.identities if i.label == admin_label), None
            )
        if self.admin is None:
            self.admin = next(
                (i for i in self.identities if i.role.lower() == "admin"), None
            )
        self.non_admins = [i for i in self.identities if i is not self.admin]

    # -- helpers -------------------------------------------------------
    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def _ok(self, status: int) -> bool:
        return status in self.success_statuses

    async def _invoke(self, op: Operation, headers: Dict[str, str]):
        return await self.client.request(
            op.method, self._url(op.path), headers=dict(headers or {})
        )

    @staticmethod
    def _status(resp) -> int:
        return int(getattr(resp, "status_code", getattr(resp, "status", 0)) or 0)

    def _evidence(self, check, op, label, role, status):
        return {
            "check": check,
            "method": op.method,
            "url": self._url(op.path),
            "accessed_as": label,
            "role": role,
            "status": status,
        }

    # -- core ----------------------------------------------------------
    async def _check_operation(self, op: Operation, result: BflaResult) -> None:
        if op.destructive and self.safe:
            result.skipped_destructive += 1
            result.notes.append(
                "Skipped destructive op {0} in safe mode (use active mode to test).".format(
                    op.name
                )
            )
            return

        result.tested_operations += 1
        evidence_base = []

        admin_ok: Optional[bool] = None
        if self.admin is not None:
            base = await self._invoke(op, self.admin.headers)
            base_status = self._status(base)
            admin_ok = self._ok(base_status)
            evidence_base.append(
                self._evidence(
                    "privileged_baseline", op, self.admin.label, self.admin.role, base_status
                )
            )
            if not admin_ok:
                result.notes.append(
                    "{0}: privileged identity '{1}' did not succeed (HTTP {2}); "
                    "cannot confirm it is a working privileged function, skipping.".format(
                        op.name, self.admin.label, base_status
                    )
                )
                return

        confidence = "confirmed" if admin_ok else "firm"

        for ident in self.non_admins:
            resp = await self._invoke(op, ident.headers)
            status = self._status(resp)
            if self._ok(status):
                result.escalations += 1
                result.findings.append(
                    Finding(
                        title="BFLA: '{0}' (role={1}) can invoke privileged function {2}".format(
                            ident.label, ident.role, op.name
                        ),
                        severity="high",
                        owasp_id=self.OWASP_ID,
                        endpoint=op.path,
                        cwe="CWE-285",
                        confidence=confidence,
                        description=(
                            "The function {0} is intended for privileged callers, but "
                            "identity '{1}' (role '{2}') invoked it successfully (HTTP {3}). "
                            "The API authenticates the caller but does not enforce that the "
                            "caller's role is authorised for this function, allowing "
                            "function-level privilege escalation.".format(
                                op.name, ident.label, ident.role, status
                            )
                            + (
                                " A privileged identity was confirmed to have access to the "
                                "same function, so this is a genuine authorization gap."
                                if admin_ok
                                else " No privileged baseline was supplied, so this is "
                                "reported at firm confidence."
                            )
                        ),
                        recommendation=(
                            "Enforce function-level authorization on every privileged route "
                            "and method: check the authenticated principal's role/permissions "
                            "server-side and deny by default. Never rely on the client hiding "
                            "administrative functionality."
                        ),
                        evidence=evidence_base
                        + [self._evidence("lower_privilege", op, ident.label, ident.role, status)],
                    )
                )

        if self.unauth_check:
            resp = await self._invoke(op, {})
            status = self._status(resp)
            if self._ok(status):
                result.unauth_invocations += 1
                result.findings.append(
                    Finding(
                        title="BFLA: privileged function {0} is invokable without authentication".format(
                            op.name
                        ),
                        severity="critical",
                        owasp_id=self.OWASP_ID,
                        endpoint=op.path,
                        cwe="CWE-862",
                        confidence=confidence,
                        description=(
                            "The privileged function {0} returned success (HTTP {1}) to an "
                            "unauthenticated request. A function that should require elevated "
                            "privilege is reachable by anyone on the network with no "
                            "credentials at all.".format(op.name, status)
                        ),
                        recommendation=(
                            "Require authentication and enforce function-level authorization "
                            "before executing this operation. Deny unauthenticated and "
                            "unauthorized callers by default."
                        ),
                        evidence=evidence_base
                        + [self._evidence("unauthenticated", op, "<no token>", "anon", status)],
                    )
                )

    async def run(self, store=None) -> BflaResult:
        result = BflaResult()
        for op in self.operations:
            await self._check_operation(op, result)
        if not result.findings:
            result.notes.append(
                "No BFLA confirmed: privileged functions rejected lower-privilege "
                "and unauthenticated callers."
            )
        if store is not None:
            for finding in result.findings:
                store.add(finding)
        return result
