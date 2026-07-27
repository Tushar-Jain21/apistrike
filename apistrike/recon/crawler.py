"""APIStrike recon crawler / fuzzer.

Active endpoint & parameter discovery for API targets. Pure stdlib and
transport-agnostic: it drives any async client exposing
``await client.request(method, url, headers=...)`` -- in APIStrike that is the
scope-gated ScopedHTTPClient, so every request is gated by scope.yaml and the
running safe-mode.

What it does
------------
1. Seeds known endpoints from the parsed OpenAPI spec (documented surface).
2. Discovers shadow / undocumented endpoints from a wordlist (a local SecLists
   path, or a small bundled fallback), with soft-404 calibration so catch-all
   responses are not mistaken for real endpoints.
3. Enumerates HTTP methods per live endpoint. In SAFE MODE it only reads the
   ``Allow`` header via ``OPTIONS`` and never fires state-changing verbs;
   active probing that actually sends POST/PUT/PATCH/DELETE is gated behind
   ``safe=False`` (the explicit \"destructive tests\" flag).
4. Light query-parameter fuzzing (read-only GET): adds candidate params and
   looks for status/length deltas versus a baseline to reveal hidden params.

The CrawlResult feeds BOLA / BFLA / injection with more objects & params, and
undocumented live endpoints are recorded as low-severity API9:2023 findings
(Improper Inventory Management).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

try:  # normal package import
    from apistrike.core.findings import Finding
except Exception:  # pragma: no cover - standalone import in the verify sandbox
    from findings import Finding  # type: ignore


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")
DEFAULT_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
DEFAULT_NOT_FOUND = (404, 405, 501)

# Small offline fallback if no SecLists path is supplied.
DEFAULT_PATH_WORDS = (
    "admin", "api", "debug", "status", "health", "metrics", "config",
    "users", "user", "accounts", "login", "logout", "register", "token",
    "books", "orders", "products", "internal", "test", "v1", "v2", "v3",
    "swagger", "openapi", "docs", "graphql", "actuator", "backup", "env",
)
DEFAULT_PARAM_WORDS = (
    "id", "user_id", "username", "email", "page", "limit", "offset",
    "sort", "order", "q", "search", "filter", "debug", "admin", "role",
    "format", "fields", "include", "token", "api_key",
)


def load_wordlist(path: Optional[str], fallback: Sequence[str] = DEFAULT_PATH_WORDS) -> List[str]:
    """Load a newline-delimited wordlist (e.g. a SecLists file).

    Blank lines and ``#`` comments are skipped. Falls back to ``fallback`` when
    ``path`` is None or unreadable. Order preserved, duplicates removed.
    """
    words: List[str] = []
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip()
                    if not w or w.startswith("#"):
                        continue
                    words.append(w)
        except OSError:
            words = []
    if not words:
        words = list(fallback)
    seen: Set[str] = set()
    out: List[str] = []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def candidate_paths(words: Sequence[str], bases: Sequence[str] = ("/",)) -> List[str]:
    """Join wordlist entries under each base prefix -> candidate paths."""
    out: List[str] = []
    seen: Set[str] = set()
    for base in (bases or ("/",)):
        b = "/" + base.strip("/") if base.strip("/") else ""
        for w in words:
            seg = w.strip().strip("/")
            if not seg:
                continue
            path = f"{b}/{seg}" if b else f"/{seg}"
            path = re.sub(r"/+", "/", path)
            if path not in seen:
                seen.add(path)
                out.append(path)
    return out


def _allow_header(headers: Optional[Dict[str, str]]) -> List[str]:
    if not headers:
        return []
    for k, v in headers.items():
        if str(k).lower() == "allow":
            return [m.strip().upper() for m in str(v).split(",") if m.strip()]
    return []


def _body_len(body) -> int:
    if body is None:
        return 0
    if isinstance(body, (bytes, bytearray)):
        return len(body)
    return len(str(body))


@dataclass
class EndpointObservation:
    path: str
    source: str                       # "spec" | "wordlist"
    status: int = 0
    length: int = 0
    documented: bool = False
    methods_allowed: List[str] = field(default_factory=list)
    params_found: List[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    endpoints: List[EndpointObservation] = field(default_factory=list)
    shadow_endpoints: List[str] = field(default_factory=list)
    discovered_params: Dict[str, List[str]] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    requests_made: int = 0
    methods_used: Set[str] = field(default_factory=set)


class Crawler:
    OWASP_ID = "API9:2023"

    def __init__(self, client, base_url: str, *,
                 seed_endpoints: Sequence[str] = (),
                 path_words: Sequence[str] = (),
                 param_words: Sequence[str] = (),
                 bases: Sequence[str] = ("/",),
                 methods: Sequence[str] = DEFAULT_METHODS,
                 fuzz_params: bool = True,
                 method_enum: bool = True,
                 safe: bool = True,
                 not_found_statuses: Sequence[int] = DEFAULT_NOT_FOUND):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.seed = [self._norm_path(p) for p in seed_endpoints]
        self.seed_set = set(self.seed)
        self.path_words = list(path_words)
        self.param_words = list(param_words) or list(DEFAULT_PARAM_WORDS)
        self.bases = tuple(bases) if bases else ("/",)
        self.methods = tuple(m.upper() for m in methods)
        self.fuzz_params = fuzz_params
        self.method_enum = method_enum
        self.safe = safe
        self.not_found_statuses = tuple(not_found_statuses)
        self._soft404: Optional[Tuple[int, int]] = None
        self._requests = 0
        self._methods_used: Set[str] = set()
        self.result = CrawlResult()

    # -- helpers ---------------------------------------------------------
    def _norm_path(self, path: str) -> str:
        p = path if path.startswith("/") else "/" + path
        return re.sub(r"/+", "/", p)

    def _url(self, path: str, query: str = "") -> str:
        u = f"{self.base_url}{self._norm_path(path)}"
        return f"{u}?{query}" if query else u

    async def _fetch(self, method: str, path: str, headers=None, query: str = ""):
        self._requests += 1
        self._methods_used.add(method.upper())
        return await self.client.request(method.upper(), self._url(path, query),
                                         headers=headers or {})

    def _looks_present(self, status: int, length: int) -> bool:
        # 401/403 mean the route exists but is protected -> still "present".
        if status in (401, 403):
            return True
        if status in self.not_found_statuses:
            return False
        if status >= 400:
            return False
        if self._soft404 is not None:
            s404, l404 = self._soft404
            if status == s404 and abs(length - l404) <= max(16, l404 // 20):
                return False
        return True

    # -- discovery -------------------------------------------------------
    async def _calibrate_soft404(self) -> None:
        probe = "/__apistrike_probe_404__"
        r = await self._fetch("GET", probe)
        self._soft404 = (r.status_code, _body_len(r.body))
        self.result.notes.append(
            f"Soft-404 signature: status={r.status_code}, len={self._soft404[1]}")

    async def _enumerate_methods(self, path: str) -> List[str]:
        opt = await self._fetch("OPTIONS", path)
        allowed = set(_allow_header(getattr(opt, "response_headers", None)))
        if self.safe:
            # Never fire state-changing verbs in safe mode.
            if not allowed:
                for m in SAFE_METHODS:
                    r = await self._fetch(m, path)
                    if r.status_code not in self.not_found_statuses:
                        allowed.add(m)
            return sorted(allowed)
        # Active mode (explicit safe=False): probe every configured method.
        for m in self.methods:
            r = await self._fetch(m, path)
            if r.status_code not in self.not_found_statuses:
                allowed.add(m.upper())
        return sorted(allowed)

    async def _fuzz_params(self, path: str, base_status: int, base_length: int) -> List[str]:
        found: List[str] = []
        tol = max(8, base_length // 50)
        for p in self.param_words:
            r = await self._fetch("GET", path, query=f"{p}=1")
            if r.status_code != base_status or abs(_body_len(r.body) - base_length) > tol:
                found.append(p)
        return found

    def _shadow_finding(self, obs: EndpointObservation) -> Finding:
        protected = obs.status in (401, 403)
        desc = (
            f"Undocumented endpoint {obs.path} responded with HTTP {obs.status} but is "
            "not present in the provided API specification. "
            + ("It requires authentication, suggesting a hidden or administrative surface."
               if protected else
               "It is reachable and returns data outside the documented API surface.")
        )
        return Finding(
            title=f"Undocumented (shadow) endpoint: {obs.path}",
            severity="low",
            owasp_id=self.OWASP_ID,
            endpoint=obs.path,
            cwe="CWE-1059",
            confidence="firm",
            description=desc,
            recommendation=(
                "Maintain an accurate API inventory. Remove or formally document this "
                "endpoint, and ensure shadow/zombie routes enforce the same authentication "
                "and authorization as documented ones."
            ),
            evidence=[{
                "check": "shadow_endpoint",
                "url": self._url(obs.path),
                "status": obs.status,
                "methods_allowed": obs.methods_allowed,
                "documented": False,
            }],
        )

    async def _observe(self, path: str, source: str, documented: bool) -> None:
        r = await self._fetch("GET", path)
        status, length = r.status_code, _body_len(r.body)
        present = self._looks_present(status, length)
        if source == "wordlist" and not present:
            return
        obs = EndpointObservation(path=self._norm_path(path), source=source,
                                  status=status, length=length, documented=documented)
        if self.method_enum:
            obs.methods_allowed = await self._enumerate_methods(path)
        if self.fuzz_params and status not in (401, 403) and present:
            obs.params_found = await self._fuzz_params(path, status, length)
            if obs.params_found:
                self.result.discovered_params[obs.path] = obs.params_found
        self.result.endpoints.append(obs)
        if source == "wordlist" and not documented:
            self.result.shadow_endpoints.append(obs.path)
            self.result.findings.append(self._shadow_finding(obs))

    async def run(self, store=None) -> CrawlResult:
        self.result = CrawlResult()
        self._requests = 0
        self._methods_used = set()
        await self._calibrate_soft404()
        for path in self.seed:
            await self._observe(path, source="spec", documented=True)
        cands = candidate_paths(self.path_words, self.bases) if self.path_words else []
        for path in cands:
            if self._norm_path(path) in self.seed_set:
                continue
            await self._observe(path, source="wordlist", documented=False)
        self.result.requests_made = self._requests
        self.result.methods_used = set(self._methods_used)
        if not self.result.endpoints:
            self.result.notes.append("No live endpoints discovered.")
        if store is not None:
            for f in self.result.findings:
                store.add(f)
        return self.result
