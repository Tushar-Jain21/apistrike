"""Rate limiting / unrestricted resource consumption module (OWASP API4:2023).

Two read-only checks:

  * burst      : send a small, bounded burst of GETs to an endpoint. If none
                 are throttled (no HTTP 429 and no rate-limit response headers),
                 the endpoint has no per-client rate limiting.
  * pagination : request a large client-controlled page size (?limit=, ?size=,
                 ...). If the server honors it and returns far more items (or a
                 far larger body) than the baseline, pagination is uncapped and
                 a client can force unbounded resource consumption.

The burst is bounded (default 25) and further capped by the scope's
max_requests, so the tool never turns into a stress test. Everything is a plain
GET — safe by default.
"""
from __future__ import annotations

import json as _json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

try:  # packaged import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - sandbox/local fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API4:2023"
ALL_CHECKS = ("burst", "pagination")

RATE_LIMIT_HEADERS = (
    "retry-after",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-rate-limit-limit", "x-rate-limit-remaining",
)

DEFAULT_PAGE_PARAMS = ("limit", "page_size", "per_page", "pageSize", "count", "size")


@dataclass
class RateLimitTarget:
    path: str
    method: str = "GET"
    params: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None

    def __post_init__(self):
        self.method = (self.method or "GET").upper()
        if not self.path.startswith("/"):
            self.path = "/" + self.path


@dataclass
class RateLimitResult:
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


def _resp_headers(resp: Any) -> Dict[str, str]:
    raw = getattr(resp, "headers", None)
    if raw is None:
        raw = getattr(resp, "response_headers", None)
    if not raw:
        return {}
    try:
        items = raw.items()
    except Exception:
        return {}
    return {str(k).lower(): str(v) for k, v in items}


def _count_items(parsed: Any) -> Optional[int]:
    if isinstance(parsed, list):
        return len(parsed)
    if isinstance(parsed, dict):
        for value in parsed.values():
            if isinstance(value, list):
                return len(value)
    return None


def _summarize_statuses(statuses: List[int]) -> str:
    counts = Counter(statuses)
    return ", ".join(str(code) + "x" + str(counts[code]) for code in sorted(counts))


class RateLimitModule:
    def __init__(
        self,
        client: Any,
        base_url: str,
        targets: Sequence[RateLimitTarget],
        *,
        checks: Sequence[str] = ALL_CHECKS,
        burst: int = 25,
        page_params: Sequence[str] = DEFAULT_PAGE_PARAMS,
        large_value: int = 1000,
        min_items: int = 50,
        size_multiplier: float = 3.0,
        headers: Optional[Dict[str, str]] = None,
        safe: bool = True,
        max_requests: Optional[int] = None,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.targets = list(targets)
        if not self.targets:
            raise ValueError("no targets provided")
        self.checks = tuple(c for c in checks if c in ALL_CHECKS)
        if not self.checks:
            raise ValueError("no valid checks selected (choose from: " + ", ".join(ALL_CHECKS) + ")")
        self.burst = max(2, int(burst))
        if max_requests:
            self.burst = max(2, min(self.burst, int(max_requests)))
        self.page_params = tuple(page_params)
        self.large_value = int(large_value)
        self.min_items = int(min_items)
        self.size_multiplier = float(size_multiplier)
        self.base_headers = dict(headers or {})
        self.safe = safe
        self._requests = 0

    async def _fetch(self, target: RateLimitTarget, extra_params: Optional[Dict[str, Any]] = None):
        url = self.base_url + target.path
        merged_headers = dict(self.base_headers)
        if target.headers:
            merged_headers.update(target.headers)
        params: Dict[str, Any] = dict(target.params or {})
        if extra_params:
            params.update(extra_params)
        kwargs: Dict[str, Any] = {"headers": merged_headers}
        if params:
            kwargs["params"] = params
        resp = await self.client.request(target.method, url, **kwargs)
        self._requests += 1
        return resp

    async def _check_burst(self, target: RateLimitTarget, endpoint: str, findings: List[Finding], notes: List[str]) -> None:
        statuses: List[int] = []
        throttled = False
        header_seen = False
        for _ in range(self.burst):
            resp = await self._fetch(target)
            status = int(getattr(resp, "status_code", 0) or 0)
            statuses.append(status)
            if status == 429:
                throttled = True
            if any(h in _resp_headers(resp) for h in RATE_LIMIT_HEADERS):
                header_seen = True
            if throttled:
                break
        if throttled or header_seen:
            reason = "HTTP 429" if throttled else "rate-limit headers"
            notes.append("Rate limiting appears enforced at " + endpoint + " (" + reason + " observed).")
            return
        findings.append(Finding(
            title="No rate limiting enforced",
            severity="medium", owasp_id=OWASP_ID, endpoint=endpoint,
            description="Sent " + str(len(statuses)) + " requests to " + endpoint + " in a burst; none were throttled (no HTTP 429 and no rate-limit response headers). A client can send unlimited requests, enabling brute force, scraping, and denial-of-service.",
            cwe="CWE-770",
            recommendation="Enforce per-client/per-IP rate limiting and quotas, and return HTTP 429 with Retry-After when exceeded.",
            confidence="firm",
            evidence=[str(len(statuses)) + " requests sent, status codes: " + _summarize_statuses(statuses)],
        ))

    async def _check_pagination(self, target: RateLimitTarget, endpoint: str, findings: List[Finding], notes: List[str]) -> None:
        base_resp = await self._fetch(target)
        base_text = _body_str(base_resp)
        try:
            base_parsed = _json.loads(base_text)
        except Exception:
            notes.append("Pagination check skipped at " + endpoint + " (baseline response is not JSON).")
            return
        base_items = _count_items(base_parsed)
        base_size = len(base_text)

        param = self.page_params[0]
        large_resp = await self._fetch(target, extra_params={param: self.large_value})
        large_text = _body_str(large_resp)
        try:
            large_parsed = _json.loads(large_text)
        except Exception:
            large_parsed = None
        large_items = _count_items(large_parsed)
        large_size = len(large_text)

        if base_items is not None and large_items is not None and large_items > base_items and large_items >= self.min_items:
            findings.append(Finding(
                title="Client-controlled page size honored (missing pagination cap)",
                severity="medium", owasp_id=OWASP_ID, endpoint=endpoint,
                description="With '?" + param + "=" + str(self.large_value) + "' the server returned " + str(large_items) + " items vs " + str(base_items) + " at baseline. A client can force the server to return arbitrarily large result sets.",
                cwe="CWE-770",
                recommendation="Enforce a server-side maximum page size and ignore/clamp oversized client-supplied limits.",
                confidence="firm",
                evidence=["baseline items: " + str(base_items) + ", with " + param + "=" + str(self.large_value) + ": " + str(large_items)],
            ))
            return

        if base_size > 0 and large_size >= base_size * self.size_multiplier and large_size > 10000:
            findings.append(Finding(
                title="Response size amplification via client-controlled parameter",
                severity="low", owasp_id=OWASP_ID, endpoint=endpoint,
                description="With '?" + param + "=" + str(self.large_value) + "' the response body grew from " + str(base_size) + " to " + str(large_size) + " bytes, suggesting the client can amplify resource consumption.",
                cwe="CWE-770",
                recommendation="Cap result-set and response sizes regardless of client-supplied parameters.",
                confidence="firm",
                evidence=["baseline bytes: " + str(base_size) + ", amplified bytes: " + str(large_size)],
            ))

    async def run(self, store=None) -> RateLimitResult:
        result = RateLimitResult()
        findings: List[Finding] = []
        notes: List[str] = []
        for target in self.targets:
            endpoint = target.method + " " + target.path
            if "burst" in self.checks:
                await self._check_burst(target, endpoint, findings, notes)
            if "pagination" in self.checks:
                await self._check_pagination(target, endpoint, findings, notes)
        if not findings:
            notes.append("No unrestricted resource consumption detected across the scanned endpoints.")
        if store is not None:
            for finding in findings:
                store.add(finding)
        result.findings = findings
        result.notes = notes
        result.requests_made = self._requests
        return result
