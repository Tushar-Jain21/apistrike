"""Improper Inventory Management module (OWASP API9:2023).

Complements the active crawler by focusing on *inventory* problems rather than
raw endpoint discovery:

* versions  : given documented version-bearing paths (e.g. /users/v1/users),
              probe sibling versions (v0, v2, v3, ...). Any version that
              answers but is not documented is an undocumented / old /
              "zombie" API version still reachable.
* surfaces  : probe a curated list of non-production and documentation
              surfaces (OpenAPI/Swagger specs, GraphQL consoles, actuator,
              .env, debug/console, metrics, ...). Anything live is flagged
              with a severity appropriate to how sensitive it is.

A soft-404 baseline is calibrated first so catch-all servers don't produce
false positives. Every probe is a read-only GET — safe by default.

Content-sensitive surfaces (.env, .git/config, actuator/env, phpinfo, ...) are
additionally *content-verified*: a catch-all / SPA server that returns an HTML
page (HTTP 200) for an unknown dotfile path no longer produces a false HIGH.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:  # packaged import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - sandbox/local fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API9:2023"
ALL_CHECKS = ("versions", "surfaces")

VERSION_RE = re.compile(r"/v(\d+)(?=/|$)")

PRESENT_STATUSES = {200, 201, 202, 203, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500}

# (path, severity, label, cwe)
DEFAULT_SURFACES: List[Tuple[str, str, str, str]] = [
    ("/openapi.json", "medium", "OpenAPI specification", "CWE-200"),
    ("/swagger.json", "medium", "Swagger specification", "CWE-200"),
    ("/swagger", "medium", "Swagger UI", "CWE-200"),
    ("/swagger-ui.html", "medium", "Swagger UI", "CWE-200"),
    ("/ui/", "medium", "Swagger UI (connexion)", "CWE-200"),
    ("/api-docs", "medium", "API documentation", "CWE-200"),
    ("/v2/api-docs", "medium", "Springfox API docs", "CWE-200"),
    ("/docs", "low", "API docs UI", "CWE-200"),
    ("/redoc", "low", "ReDoc UI", "CWE-200"),
    ("/graphql", "low", "GraphQL endpoint", "CWE-200"),
    ("/graphiql", "medium", "GraphiQL console", "CWE-200"),
    ("/.env", "high", "Environment file", "CWE-200"),
    ("/.git/config", "high", "Exposed .git metadata", "CWE-527"),
    ("/actuator", "high", "Spring Boot Actuator", "CWE-200"),
    ("/actuator/env", "high", "Actuator environment", "CWE-200"),
    ("/actuator/health", "low", "Actuator health", "CWE-200"),
    ("/metrics", "low", "Metrics endpoint", "CWE-200"),
    ("/health", "info", "Health endpoint", "CWE-200"),
    ("/debug", "high", "Debug endpoint", "CWE-489"),
    ("/_debug", "high", "Debug endpoint", "CWE-489"),
    ("/console", "high", "Interactive console", "CWE-489"),
    ("/admin", "medium", "Admin surface", "CWE-200"),
    ("/internal", "medium", "Internal surface", "CWE-200"),
    ("/server-status", "medium", "Apache server-status", "CWE-200"),
    ("/phpinfo.php", "high", "phpinfo()", "CWE-200"),
]


def _looks_like_html(body: str) -> bool:
    """True if the body looks like an HTML document (SPA / catch-all page)."""
    head = (body or "")[:600].lstrip().lower()
    return (
        head.startswith("<!doctype html")
        or head.startswith("<html")
        or "<head" in head
        or "<body" in head
    )


# Paths whose *presence* is not sufficient evidence: the response body must
# actually look like the sensitive artifact before we flag it. This removes
# the common false positive where a SPA / catch-all server answers HTTP 200
# with an HTML page for an unknown dotfile path (e.g. crAPI's gateway + /.env).
CONTENT_SIGNATURES: Dict[str, "re.Pattern[str]"] = {
    "/.env": re.compile(r"^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=", re.MULTILINE),
    "/.git/config": re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE),
    "/actuator": re.compile(r'"_links"'),
    "/actuator/env": re.compile(r'"(propertySources|activeProfiles)"'),
    "/phpinfo.php": re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE),
}


def _content_verified(path: str, body: str) -> bool:
    """For content-sensitive surfaces, require a matching body signature and
    reject HTML documents. Paths without a signature are unaffected."""
    sig = CONTENT_SIGNATURES.get(path)
    if sig is None:
        return True
    if _looks_like_html(body):
        return False
    return bool(sig.search(body or ""))


@dataclass
class InventoryResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    requests_made: int = 0


def _body_str(resp: Any) -> str:
    body = getattr(resp, "body", "") or ""
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8", "replace")
        except Exception:
            return str(body)
    return body if isinstance(body, str) else str(body)


def _looks_present(status: int, blen: int, soft_status: int, soft_len: int) -> bool:
    if status not in PRESENT_STATUSES:
        return False
    # Protected or error responses always indicate a real resource.
    if status in (401, 403, 405, 500):
        return True
    # Catch-all server that returns success for junk paths: require the body to
    # diverge meaningfully from the soft-404 body before calling it "present".
    if soft_status < 400:
        tolerance = max(24, int(soft_len * 0.15))
        if abs(blen - soft_len) <= tolerance:
            return False
    return True


def _versions_in(paths: Sequence[str]) -> set:
    found = set()
    for p in paths:
        for m in VERSION_RE.finditer(p):
            found.add(int(m.group(1)))
    return found


class InventoryModule:
    def __init__(
        self,
        client: Any,
        base_url: str,
        *,
        documented_paths: Sequence[str] = (),
        max_version: int = 4,
        surface_paths: Optional[Sequence[Tuple[str, str, str, str]]] = None,
        checks: Sequence[str] = ALL_CHECKS,
        headers: Optional[Dict[str, str]] = None,
        safe: bool = True,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.documented_paths = [p if p.startswith("/") else "/" + p for p in documented_paths]
        self.max_version = int(max_version)
        self.surface_paths = list(surface_paths) if surface_paths is not None else list(DEFAULT_SURFACES)
        self.checks = tuple(c for c in checks if c in ALL_CHECKS)
        if not self.checks:
            raise ValueError("no valid checks selected (choose from: " + ", ".join(ALL_CHECKS) + ")")
        self.base_headers = dict(headers or {})
        self.safe = safe
        self._requests = 0
        self._soft_status = 404
        self._soft_len = 0

    async def _get(self, path: str):
        url = self.base_url + path
        resp = await self.client.request("GET", url, headers=dict(self.base_headers))
        self._requests += 1
        return resp

    async def _calibrate(self) -> None:
        resp = await self._get("/apistrike-nonexistent-9c1f2a7b")
        self._soft_status = int(getattr(resp, "status_code", 404) or 404)
        self._soft_len = len(_body_str(resp))

    def _present(self, resp) -> bool:
        status = int(getattr(resp, "status_code", 0) or 0)
        blen = len(_body_str(resp))
        return _looks_present(status, blen, self._soft_status, self._soft_len)

    async def _check_versions(self, findings: List[Finding], notes: List[str]) -> None:
        if not self.documented_paths:
            notes.append("Version check skipped (no documented paths provided; pass --paths).")
            return
        documented = _versions_in(self.documented_paths)
        version_paths = [p for p in self.documented_paths if VERSION_RE.search(p)]
        if not version_paths:
            notes.append("Version check skipped (no /vN version token found in the documented paths).")
            return
        seen_candidates = set()
        for path in version_paths:
            for k in range(0, self.max_version + 1):
                if k in documented:
                    continue
                candidate = VERSION_RE.sub("/v" + str(k), path, count=1)
                if candidate in seen_candidates or candidate == path:
                    continue
                seen_candidates.add(candidate)
                resp = await self._get(candidate)
                if self._present(resp):
                    status = int(getattr(resp, "status_code", 0) or 0)
                    doc_list = ", ".join("v" + str(v) for v in sorted(documented)) or "(none)"
                    findings.append(Finding(
                        title="Undocumented/alternate API version reachable: " + candidate,
                        severity="medium", owasp_id=OWASP_ID, endpoint="GET " + candidate,
                        description="An alternate API version responds (HTTP " + str(status) + ") at " + candidate + " while only " + doc_list + " is documented. Old or undocumented versions are common sources of unpatched vulnerabilities.",
                        cwe="CWE-1059",
                        recommendation="Inventory every API version; decommission deprecated/zombie versions and document the rest. Route retired versions to a hard 404/410.",
                        confidence="firm",
                        evidence=["documented: " + doc_list + "; reachable: " + candidate + " -> HTTP " + str(status)],
                    ))

    async def _check_surfaces(self, findings: List[Finding], notes: List[str]) -> None:
        for path, severity, label, cwe in self.surface_paths:
            resp = await self._get(path)
            if not self._present(resp):
                continue
            body = _body_str(resp)
            status = int(getattr(resp, "status_code", 0) or 0)
            # A protected/error response (401/403/405/500) already proves the
            # resource exists, so only content-verify inspectable success bodies.
            if status not in (401, 403, 405, 500) and not _content_verified(path, body):
                notes.append(
                    "Skipped " + path + " (responded but body did not match the expected "
                    + label + " signature — likely a catch-all/SPA page, not the real artifact)."
                )
                continue
            findings.append(Finding(
                title="Exposed surface: " + label + " (" + path + ")",
                severity=severity, owasp_id=OWASP_ID, endpoint="GET " + path,
                description="A " + label + " is reachable at " + path + " (HTTP " + str(status) + "). Documentation, debug, and management surfaces should not be exposed in production and expand the attack surface / inventory blind spots.",
                cwe=cwe,
                recommendation="Remove or authenticate this surface in production; keep an accurate inventory of what is exposed.",
                confidence="firm",
                evidence=[path + " -> HTTP " + str(status)],
            ))

    async def run(self, store=None) -> InventoryResult:
        result = InventoryResult()
        findings: List[Finding] = []
        notes: List[str] = []
        await self._calibrate()
        if self._soft_status < 400:
            notes.append("Soft-404 baseline returned HTTP " + str(self._soft_status) + " (catch-all server); using body-length divergence to reduce false positives.")
        if "versions" in self.checks:
            await self._check_versions(findings, notes)
        if "surfaces" in self.checks:
            await self._check_surfaces(findings, notes)
        if not findings:
            notes.append("No improper-inventory issues detected (no undocumented versions or exposed surfaces).")
        if store is not None:
            for finding in findings:
                store.add(finding)
        result.findings = findings
        result.notes = notes
        result.requests_made = self._requests
        return result
