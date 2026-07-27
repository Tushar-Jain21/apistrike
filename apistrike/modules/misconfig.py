"""Security Misconfiguration module (OWASP API8:2023).

Stdlib-only, transport-agnostic, and fully read-only (safe by default). It runs
five independent checks against a representative endpoint and only reports a
finding when the evidence is directly observable in the response:

  * headers : missing recommended security headers (CSP, XCTO, XFO, HSTS, ...)
  * cors    : Access-Control-Allow-Origin reflection / wildcard misconfig
  * errors  : verbose error / stack-trace disclosure (debug mode)
  * methods : HTTP TRACE enabled (Cross-Site Tracing)
  * banner  : Server / X-Powered-By software version disclosure

The HTTP-client response object shape varies, so response headers are read via
a tolerant accessor. If headers cannot be read at all, the header/CORS/banner
checks are skipped with a note rather than emitting false positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

try:  # packaged import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - sandbox/local fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API8:2023"
ALL_CHECKS = ("headers", "cors", "errors", "methods", "banner")

# header key -> human label
SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

BANNER_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

# Substrings that indicate a framework/stack-trace leak in an error body.
ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "werkzeug",
    "sqlalchemy",
    "sqlstate[",
    "java.lang.",
    "org.springframework",
    "system.web.",
    "ora-00",
    '.py", line ',
    "stacktrace",
    "stack trace",
    "psycopg2",
    "pymysql",
)


@dataclass
class MisconfigResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    checks_run: List[str] = field(default_factory=list)
    requests_made: int = 0


def _resp_headers(resp: Any) -> Dict[str, str]:
    raw = getattr(resp, "headers", None)
    if raw is None:
        raw = getattr(resp, "response_headers", None)
    if raw is None:
        return {}
    try:
        items = list(raw.items())
    except AttributeError:
        if isinstance(raw, (list, tuple)):
            items = list(raw)
        else:
            return {}
    out: Dict[str, str] = {}
    for key, value in items:
        out[str(key).lower()] = str(value)
    return out


def _body_str(resp: Any) -> str:
    body = getattr(resp, "body", "") or ""
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8", "replace")
        except Exception:
            return str(body)
    return body if isinstance(body, str) else str(body)


def _snippet(body: str, sig: str, width: int = 180) -> str:
    low = body.lower()
    idx = low.find(sig)
    if idx < 0:
        return body[:width].replace("\n", " ").strip()
    start = max(0, idx - 20)
    return body[start:start + width].replace("\n", " ").strip()


class MisconfigModule:
    def __init__(
        self,
        client: Any,
        base_url: str,
        *,
        probe_paths: Sequence[str] = ("/",),
        evil_origin: str = "https://evil.attacker.test",
        checks: Sequence[str] = ALL_CHECKS,
        headers: Optional[Dict[str, str]] = None,
        safe: bool = True,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.probe_paths = tuple(probe_paths) or ("/",)
        self.evil_origin = evil_origin
        self.checks = tuple(c for c in checks if c in ALL_CHECKS)
        if not self.checks:
            raise ValueError("no valid checks selected (choose from: " + ", ".join(ALL_CHECKS) + ")")
        self.base_headers = dict(headers or {})
        self.safe = safe
        self._requests = 0

    async def _req(self, method, path, *, headers=None, params=None):
        url = self.base_url + path
        merged = dict(self.base_headers)
        if headers:
            merged.update(headers)
        resp = await self.client.request(method, url, headers=merged, params=params)
        self._requests += 1
        return resp

    def _check_headers(self, path, hdrs):
        missing = []
        for key, label in SECURITY_HEADERS.items():
            if key == "strict-transport-security" and not self.base_url.lower().startswith("https"):
                continue  # HSTS is only meaningful over HTTPS
            if key == "x-content-type-options":
                if hdrs.get(key, "").strip().lower() != "nosniff":
                    missing.append(label)
                continue
            if key == "x-frame-options":
                csp = hdrs.get("content-security-policy", "").lower()
                if "frame-ancestors" in csp:
                    continue
                if key not in hdrs:
                    missing.append(label)
                continue
            if key not in hdrs:
                missing.append(label)
        if not missing:
            return []
        endpoint = "GET " + path
        return [Finding(
            title="Missing recommended security headers at " + endpoint,
            severity="low",
            owasp_id=OWASP_ID,
            endpoint=endpoint,
            description=(
                "The response is missing recommended security headers: " + ", ".join(missing)
                + ". These headers harden the API and its consumers against clickjacking, MIME "
                "sniffing, referrer leakage, and (over HTTPS) protocol downgrade."
            ),
            cwe="CWE-693",
            recommendation=(
                "Set the missing headers at the application or gateway layer (Content-Security-Policy, "
                "X-Content-Type-Options: nosniff, X-Frame-Options/frame-ancestors, Referrer-Policy, and "
                "Strict-Transport-Security on HTTPS)."
            ),
            confidence="firm",
            evidence=["missing: " + ", ".join(missing)],
        )]

    def _check_banner(self, path, hdrs):
        leaks = []
        for key in BANNER_HEADERS:
            val = hdrs.get(key)
            if val and any(ch.isdigit() for ch in val):
                leaks.append(key + ": " + val)
        if not leaks:
            return []
        endpoint = "GET " + path
        return [Finding(
            title="Software version disclosure in response headers",
            severity="low",
            owasp_id=OWASP_ID,
            endpoint=endpoint,
            description=(
                "The server discloses software and version details: " + "; ".join(leaks)
                + ". This lets an attacker fingerprint the stack and target known-vulnerable versions."
            ),
            cwe="CWE-200",
            recommendation="Suppress or genericize Server and X-Powered-By headers at the app/gateway layer.",
            confidence="firm",
            evidence=leaks,
        )]

    async def _check_cors(self, path):
        resp = await self._req("GET", path, headers={"Origin": self.evil_origin})
        hdrs = _resp_headers(resp)
        if not hdrs:
            return []
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
        endpoint = "GET " + path
        if acao == self.evil_origin and acac == "true":
            return [Finding(
                title="CORS reflects arbitrary origin with credentials",
                severity="high", owasp_id=OWASP_ID, endpoint=endpoint,
                description=(
                    "The API reflected an attacker-supplied Origin (" + self.evil_origin + ") in "
                    "Access-Control-Allow-Origin AND set Access-Control-Allow-Credentials: true. Any "
                    "malicious site can issue authenticated cross-origin requests and read the responses."
                ),
                cwe="CWE-942",
                recommendation=(
                    "Validate Origin against a strict server-side allow-list. Never reflect the Origin "
                    "header while credentials are enabled, and never combine credentials with a wildcard."
                ),
                confidence="confirmed",
                evidence=["Origin: " + self.evil_origin, "Access-Control-Allow-Origin: " + acao, "Access-Control-Allow-Credentials: true"],
            )]
        if acao == self.evil_origin:
            return [Finding(
                title="CORS reflects arbitrary origin",
                severity="medium", owasp_id=OWASP_ID, endpoint=endpoint,
                description=(
                    "The API reflected an attacker-supplied Origin (" + self.evil_origin + ") in "
                    "Access-Control-Allow-Origin. On credentialed endpoints this enables cross-origin data theft."
                ),
                cwe="CWE-942",
                recommendation="Validate Origin against a strict allow-list instead of reflecting it.",
                confidence="firm",
                evidence=["Access-Control-Allow-Origin: " + acao],
            )]
        if acao == "*" and acac == "true":
            return [Finding(
                title="CORS wildcard origin combined with credentials",
                severity="medium", owasp_id=OWASP_ID, endpoint=endpoint,
                description="Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is an invalid but dangerous configuration.",
                cwe="CWE-942",
                recommendation="Never combine a wildcard origin with credentials; use an explicit allow-list.",
                confidence="firm",
                evidence=["Access-Control-Allow-Origin: *", "Access-Control-Allow-Credentials: true"],
            )]
        if acao == "*":
            return [Finding(
                title="CORS wildcard origin",
                severity="low", owasp_id=OWASP_ID, endpoint=endpoint,
                description="Access-Control-Allow-Origin: * allows any origin to read non-credentialed responses. Acceptable only for genuinely public data.",
                cwe="CWE-942",
                recommendation="Restrict to specific trusted origins if the endpoint returns non-public data.",
                confidence="firm",
                evidence=["Access-Control-Allow-Origin: *"],
            )]
        return []

    async def _check_errors(self, path):
        clean = path.rstrip("/") or ""
        probes = [
            ("GET", path, {"apistrike_err": "%ff'\"<>[]{}"}),
            ("GET", clean + "/%c0%ae%c0%ae", None),
        ]
        for method, probe_path, params in probes:
            resp = await self._req(method, probe_path, params=params)
            body = _body_str(resp)
            low = body.lower()
            for sig in ERROR_SIGNATURES:
                if sig in low:
                    endpoint = method + " " + probe_path
                    return [Finding(
                        title="Verbose error / stack-trace disclosure",
                        severity="medium", owasp_id=OWASP_ID, endpoint=endpoint,
                        description=(
                            "A malformed request elicited a verbose error revealing framework/stack "
                            "details (signature: '" + sig + "'). Debug mode or unhandled exceptions leak "
                            "internal implementation details useful to an attacker."
                        ),
                        cwe="CWE-209",
                        recommendation="Disable debug mode in production, return generic error bodies, and log details server-side only.",
                        confidence="firm",
                        evidence=[_snippet(body, sig)],
                    )]
        return []

    async def _check_methods(self, path):
        try:
            resp = await self._req("TRACE", path)
        except Exception:
            return []
        status = getattr(resp, "status_code", 0)
        body = _body_str(resp)
        if status == 200 and "trace" in body.lower():
            endpoint = "TRACE " + path
            return [Finding(
                title="HTTP TRACE method enabled (Cross-Site Tracing)",
                severity="medium", owasp_id=OWASP_ID, endpoint=endpoint,
                description="The server responded 200 to an HTTP TRACE request and echoed the request, enabling Cross-Site Tracing (XST).",
                cwe="CWE-16",
                recommendation="Disable the TRACE method at the web server / gateway.",
                confidence="firm",
                evidence=["TRACE returned status " + str(status)],
            )]
        return []

    async def run(self, store=None) -> MisconfigResult:
        result = MisconfigResult()
        primary = self.probe_paths[0]
        findings: List[Finding] = []

        header_dependent = any(c in self.checks for c in ("headers", "banner"))
        hdrs: Dict[str, str] = {}
        if header_dependent or "cors" in self.checks:
            base_resp = await self._req("GET", primary)
            hdrs = _resp_headers(base_resp)
            if header_dependent and not hdrs:
                result.notes.append(
                    "Response headers were not exposed by the HTTP client; header and banner checks were skipped."
                )

        if "headers" in self.checks and hdrs:
            findings += self._check_headers(primary, hdrs)
        if "banner" in self.checks and hdrs:
            findings += self._check_banner(primary, hdrs)
        if "cors" in self.checks:
            findings += await self._check_cors(primary)
        if "errors" in self.checks:
            findings += await self._check_errors(primary)
        if "methods" in self.checks:
            findings += await self._check_methods(primary)

        result.checks_run = list(self.checks)
        if not findings:
            result.notes.append("No security misconfigurations detected across the selected checks.")
        if store is not None:
            for finding in findings:
                store.add(finding)
        result.findings = findings
        result.requests_made = self._requests
        return result
