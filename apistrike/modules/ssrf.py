"""APIStrike SSRF module (OWASP API7:2023) with a built-in OAST listener.

Server-Side Request Forgery lets an attacker coerce the API server into making
requests to targets of the attacker's choosing (internal services, cloud
metadata, or arbitrary hosts). The strongest proof is *out-of-band*: the server
actually reaches out to a host we control.

This module ships a self-contained, open-source OAST (Out-of-band Application
Security Testing) listener built on the Python standard library, plus a
deterministic detection engine with three techniques:

- oast     : inject a unique callback URL served by our own listener and confirm
             SSRF when the server dials back (CWE-918, confirmed). No external
             service (e.g. Burp Collaborator / interactsh) required.
- metadata : inject cloud-metadata URLs (AWS/GCP/Azure/Alibaba) and confirm when
             the response leaks metadata signatures the baseline never returned
             (CWE-918, confirmed) -- extremely high impact (credential theft).
- timing   : inject non-routable internal hosts and confirm a connect/timeout
             delay versus a fast baseline and control (CWE-918, firm).

All probes are READ-ONLY GET-style requests, so the module is safe to run in
safe mode. Every target request is issued through the scope-gated client; the
OAST listener only *receives* callbacks and records them.

The module is transport-agnostic: the client only needs
`await client.request(method, url, params=?, json=?, headers=?)` returning an
object exposing `.status_code`, `.body`, and `.elapsed_ms`.
"""

import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

try:  # package import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - flat-layout / verify fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API7:2023"  # Server Side Request Forgery (already in the taxonomy)
PATH_MARKER = "INJECT"

ALL_TECHNIQUES = ("oast", "metadata", "timing")

# Cloud instance-metadata endpoints across major providers.
CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",             # GCP
    "http://100.100.100.200/latest/meta-data/",                        # Alibaba
]

# Loopback / internal reachability probes, including classic parser bypasses.
LOCALHOST_URLS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://2130706433/",      # decimal 127.0.0.1
    "http://0x7f000001/",      # hex 127.0.0.1
    "http://0177.0.0.1/",      # octal 127.0.0.1
]

# Non-routable hosts that typically hang until connect-timeout (blind SSRF).
INTERNAL_TIMING_URLS = [
    "http://10.255.255.1/",
    "http://192.168.255.254/",
    "http://169.254.169.254:9",
]

# Substrings that betray a successful server-side metadata fetch.
METADATA_SIGNATURES = [
    "ami-id",
    "instance-id",
    "instance-action",
    "iam/security-credentials",
    "accesskeyid",
    "secretaccesskey",
    "computemetadata",
    "metadata-flavor",
    "placement/availability-zone",
    "local-hostname",
    "public-keys/",
]

# Parameter names that commonly accept a URL/host and are SSRF-prone.
SSRF_PARAM_HINTS = [
    "url", "uri", "link", "callback", "webhook", "dest", "destination",
    "redirect", "redirect_uri", "next", "continue", "return", "returnurl",
    "feed", "host", "domain", "site", "page", "path", "image", "img",
    "imageurl", "avatar", "file", "document", "proxy", "fetch", "load",
    "source", "src", "data", "reference", "ref", "endpoint", "remote",
    "upload", "download", "out", "to", "view", "open",
]

DEFAULT_TIME_THRESHOLD_MS = 3000
DEFAULT_OAST_WAIT_MS = 2000
DEFAULT_LEN_TOLERANCE = 64


# --------------------------------------------------------------------------- #
# OAST callback listener (standard library only)
# --------------------------------------------------------------------------- #
@dataclass
class Interaction:
    method: str
    path: str
    host: str
    remote_addr: str
    headers: Dict[str, str] = field(default_factory=dict)
    received_at: float = 0.0


class InteractionStore:
    """Thread-safe record of inbound OAST callbacks."""

    def __init__(self) -> None:
        self._items: List[Interaction] = []
        self._lock = threading.Lock()

    def record(self, interaction: Interaction) -> None:
        with self._lock:
            self._items.append(interaction)

    def all(self) -> List[Interaction]:
        with self._lock:
            return list(self._items)

    def matching(self, token: str) -> List[Interaction]:
        with self._lock:
            return [i for i in self._items if token in i.path or token in i.host]


class OASTListener:
    """A minimal self-hosted OAST server that records every callback it receives.

    Usage:
        with OASTListener() as oast:
            token = oast.new_token()
            payload = oast.payload_url(token)   # feed this to the target
            ...
            hits = oast.poll(token, wait_ms=2000)
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, public_host: Optional[str] = None) -> None:
        self.host = host
        self.port = port
        self.public_host = public_host
        self.store = InteractionStore()
        self._server = None
        self._thread = None

    def start(self) -> "OASTListener":
        store = self.store

        class _Handler(BaseHTTPRequestHandler):
            def _record(self, method: str) -> None:
                store.record(
                    Interaction(
                        method=method,
                        path=self.path,
                        host=self.headers.get("Host", ""),
                        remote_addr=self.client_address[0],
                        headers={k: v for k, v in self.headers.items()},
                        received_at=time.time(),
                    )
                )
                body = b"apistrike-oast\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def do_GET(self):  # noqa: N802
                self._record("GET")

            def do_POST(self):  # noqa: N802
                self._record("POST")

            def do_PUT(self):  # noqa: N802
                self._record("PUT")

            def do_HEAD(self):  # noqa: N802
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):  # silence default stderr logging
                return

        self._server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            finally:
                self._server = None

    @property
    def base_url(self) -> str:
        host = self.public_host or self.host
        return "http://" + str(host) + ":" + str(self.port)

    def new_token(self) -> str:
        return "oast" + uuid.uuid4().hex[:16]

    def payload_url(self, token: str, path_suffix: str = "") -> str:
        return "{0}/{1}{2}".format(self.base_url, token, path_suffix)

    def poll(self, token: str, wait_ms: int = 0) -> List[Interaction]:
        if wait_ms:
            time.sleep(wait_ms / 1000.0)
        return self.store.matching(token)

    def __enter__(self) -> "OASTListener":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


# --------------------------------------------------------------------------- #
# SSRF detection engine
# --------------------------------------------------------------------------- #
@dataclass
class SSRFTarget:
    method: str
    path: str
    param: str
    location: str = "query"  # "query" | "json" | "path"
    base_params: Dict[str, object] = field(default_factory=dict)
    base_body: Dict[str, object] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    benign_value: str = "http://example.com/"

    def __post_init__(self) -> None:
        self.method = self.method.upper().strip()
        if not self.path.startswith("/"):
            self.path = "/" + self.path
        loc = (self.location or "query").lower()
        if loc == "path":
            self.location = "path"
        elif loc in ("json", "body"):
            self.location = "json"
        else:
            self.location = "query"
        if self.location == "path" and PATH_MARKER not in self.path:
            raise ValueError(
                "path-location target requires the '{0}' marker in the path, "
                "e.g. /fetch/{0}".format(PATH_MARKER)
            )


@dataclass
class SSRFResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tests_run: int = 0
    requests_made: int = 0


class SSRFModule:
    OWASP_ID = OWASP_ID
    PATH_MARKER = PATH_MARKER

    def __init__(
        self,
        client,
        base_url: str,
        targets: List[SSRFTarget],
        *,
        listener: Optional[object] = None,
        techniques=ALL_TECHNIQUES,
        metadata_urls: Optional[List[str]] = None,
        localhost_urls: Optional[List[str]] = None,
        timing_urls: Optional[List[str]] = None,
        time_threshold_ms: int = DEFAULT_TIME_THRESHOLD_MS,
        oast_wait_ms: int = DEFAULT_OAST_WAIT_MS,
        len_tolerance: int = DEFAULT_LEN_TOLERANCE,
        safe: bool = True,
    ) -> None:
        if not targets:
            raise ValueError("SSRFModule needs at least one SSRFTarget.")
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.targets = list(targets)
        self.listener = listener
        self.techniques = tuple(t.strip().lower() for t in techniques if t.strip())
        self.metadata_urls = list(metadata_urls if metadata_urls is not None else CLOUD_METADATA_URLS)
        self.localhost_urls = list(localhost_urls if localhost_urls is not None else LOCALHOST_URLS)
        self.timing_urls = list(timing_urls if timing_urls is not None else INTERNAL_TIMING_URLS)
        self.time_threshold_ms = float(time_threshold_ms)
        self.oast_wait_ms = int(oast_wait_ms)
        self.len_tolerance = int(len_tolerance)
        self.safe = safe
        self._requests = 0

    # -- helpers -------------------------------------------------------
    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    @staticmethod
    def _status(resp) -> int:
        return int(getattr(resp, "status_code", getattr(resp, "status", 0)) or 0)

    @staticmethod
    def _body(resp) -> str:
        return getattr(resp, "body", "") or ""

    @staticmethod
    def _elapsed(resp) -> float:
        return float(getattr(resp, "elapsed_ms", 0) or 0)

    async def _send(self, target: SSRFTarget, value: str):
        kwargs = {}
        if target.headers:
            kwargs["headers"] = dict(target.headers)
        if target.location == "path":
            placed = urllib.parse.quote(str(value), safe="")
            url = self._url(target.path.replace(PATH_MARKER, placed))
        elif target.location == "json":
            body = dict(target.base_body or {})
            body[target.param] = value
            kwargs["json"] = body
            url = self._url(target.path)
        else:
            params = dict(target.base_params or {})
            params[target.param] = value
            kwargs["params"] = params
            url = self._url(target.path)
        resp = await self.client.request(target.method, url, **kwargs)
        self._requests += 1
        return resp

    def _ev(self, check, target, value, status=None, elapsed=None, extra=None):
        d = {
            "check": check,
            "method": target.method,
            "endpoint": self._url(target.path),
            "param": target.param,
            "location": target.location,
            "payload": value,
        }
        if status is not None:
            d["status"] = status
        if elapsed is not None:
            d["elapsed_ms"] = round(float(elapsed), 1)
        if extra:
            d.update(extra)
        return d

    def _finding(self, *, title, severity, confidence, target, description, recommendation, evidence):
        return Finding(
            title=title,
            severity=severity,
            owasp_id=self.OWASP_ID,
            endpoint=target.path,
            cwe="CWE-918",
            confidence=confidence,
            description=description,
            recommendation=recommendation,
            evidence=evidence,
        )

    _REMEDIATION = (
        "Do not fetch user-supplied URLs directly. Enforce an allowlist of schemes "
        "(https only) and destination hosts; resolve and validate the IP, rejecting "
        "loopback, link-local (169.254.0.0/16), and RFC1918 ranges; disable redirects; "
        "and block access to cloud metadata endpoints at the network layer."
    )

    # -- techniques ----------------------------------------------------
    async def _try_oast(self, target, result):
        if not self.listener:
            result.notes.append(
                "OAST technique skipped for '{0}': no callback listener configured.".format(target.param)
            )
            return None
        result.tests_run += 1
        token = self.listener.new_token()
        payload = self.listener.payload_url(token)
        r = await self._send(target, payload)
        hits = self.listener.poll(token, wait_ms=self.oast_wait_ms)
        if hits:
            first = hits[0]
            remote = getattr(first, "remote_addr", "")
            method = getattr(first, "method", "GET")
            return self._finding(
                title="SSRF (out-of-band) via '{0}' at {1} {2}".format(target.param, target.method, target.path),
                severity="critical",
                confidence="confirmed",
                target=target,
                description=(
                    "Injecting an attacker-controlled URL ({0!r}) into {1} '{2}' caused the server to "
                    "issue an out-of-band {3} request back to our OAST listener (correlation token {4}). "
                    "This confirms the server can be coerced into making arbitrary requests (SSRF).".format(
                        payload, self._where(target), target.param, method, token
                    )
                ),
                recommendation=self._REMEDIATION,
                evidence=[
                    self._ev("oast_payload", target, payload, self._status(r), self._elapsed(r), extra={"token": token}),
                    {"check": "oast_callback", "callbacks": len(hits), "method": method, "remote_addr": remote, "token": token},
                ],
            )
        return None

    async def _try_metadata(self, target, base_body_low, result):
        result.tests_run += 1
        for murl in self.metadata_urls:
            r = await self._send(target, murl)
            body_low = self._body(r).lower()
            hit = None
            for sig in METADATA_SIGNATURES:
                if sig in body_low and sig not in base_body_low:
                    hit = sig
                    break
            if hit:
                return self._finding(
                    title="SSRF to cloud metadata via '{0}' at {1} {2}".format(target.param, target.method, target.path),
                    severity="critical",
                    confidence="confirmed",
                    target=target,
                    description=(
                        "Injecting the cloud-metadata URL {0!r} into {1} '{2}' returned a response containing "
                        "the metadata signature {3!r}, which the baseline never returned. The server can reach "
                        "the instance metadata service -- often a direct path to cloud credentials.".format(
                            murl, self._where(target), target.param, hit
                        )
                    ),
                    recommendation=self._REMEDIATION,
                    evidence=[self._ev("metadata_payload", target, murl, self._status(r), extra={"signature": hit})],
                )
        return None

    async def _try_localhost(self, target, baseline, result):
        result.tests_run += 1
        base_status = self._status(baseline)
        base_len = len(self._body(baseline))
        for lurl in self.localhost_urls:
            r = await self._send(target, lurl)
            status = self._status(r)
            reachable = status in (200, 201, 202) and (
                base_status not in (200, 201, 202) or abs(len(self._body(r)) - base_len) > self.len_tolerance
            )
            if reachable:
                return self._finding(
                    title="SSRF to internal host via '{0}' at {1} {2}".format(target.param, target.method, target.path),
                    severity="high",
                    confidence="firm",
                    target=target,
                    description=(
                        "Injecting the loopback/internal URL {0!r} into {1} '{2}' produced a materially different "
                        "response (HTTP {3} vs baseline HTTP {4}), indicating the server fetched an internal "
                        "resource that is not reachable externally (SSRF).".format(
                            lurl, self._where(target), target.param, status, base_status
                        )
                    ),
                    recommendation=self._REMEDIATION,
                    evidence=[
                        self._ev("baseline", target, target.benign_value, base_status, extra={"len": base_len}),
                        self._ev("localhost_payload", target, lurl, status, extra={"len": len(self._body(r))}),
                    ],
                )
        return None

    async def _try_timing(self, target, base_elapsed, result):
        result.tests_run += 1
        for turl in self.timing_urls:
            r = await self._send(target, turl)
            t = self._elapsed(r)
            if (t - base_elapsed) >= self.time_threshold_ms:
                control = await self._send(target, target.benign_value)
                if self._elapsed(control) < self.time_threshold_ms:
                    return self._finding(
                        title="SSRF (blind, timing) via '{0}' at {1} {2}".format(target.param, target.method, target.path),
                        severity="medium",
                        confidence="firm",
                        target=target,
                        description=(
                            "Injecting the non-routable internal URL {0!r} into {1} '{2}' delayed the response to "
                            "~{3:.0f} ms versus a ~{4:.0f} ms baseline (benign control stayed fast). The server "
                            "appears to attempt a connection to the supplied host (blind SSRF).".format(
                                turl, self._where(target), target.param, t, base_elapsed
                            )
                        ),
                        recommendation=self._REMEDIATION,
                        evidence=[
                            self._ev("baseline", target, target.benign_value, elapsed=base_elapsed),
                            self._ev("timing_payload", target, turl, self._status(r), t),
                            self._ev("control", target, target.benign_value, elapsed=self._elapsed(control)),
                        ],
                    )
        return None

    def _where(self, target: SSRFTarget) -> str:
        return "path segment" if target.location == "path" else "parameter"

    async def _scan_target(self, target, result):
        baseline = await self._send(target, target.benign_value)
        base_body_low = self._body(baseline).lower()
        base_elapsed = self._elapsed(baseline)

        finding = None
        if "oast" in self.techniques:
            finding = await self._try_oast(target, result)
        if finding is None and "metadata" in self.techniques:
            finding = await self._try_metadata(target, base_body_low, result)
            if finding is None:
                finding = await self._try_localhost(target, baseline, result)
        if finding is None and "timing" in self.techniques:
            finding = await self._try_timing(target, base_elapsed, result)
        if finding is not None:
            result.findings.append(finding)

    async def run(self, store=None) -> SSRFResult:
        result = SSRFResult()
        for target in self.targets:
            await self._scan_target(target, result)
        result.requests_made = self._requests
        if not result.findings:
            result.notes.append(
                "No SSRF confirmed: no out-of-band callback, no metadata leakage, and no internal "
                "reachability or timing signal was observed."
            )
        if store is not None:
            for finding in result.findings:
                store.add(finding)
        return result
