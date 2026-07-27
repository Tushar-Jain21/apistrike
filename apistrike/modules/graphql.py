"""GraphQL security module.

GraphQL collapses an API onto a single endpoint, so its weakness classes differ
from REST. This module runs a set of read-only probes and maps each finding to
the closest OWASP API Security Top 10 (2023) category:

  * introspection : send the standard __schema introspection query. If the
                    server returns the full type system, the entire API surface
                    is discoverable -> Security Misconfiguration (API8), CWE-200.
                    A short schema dump (type / query / mutation names) is
                    attached as evidence.
  * suggestions   : send a deliberately unknown field. If the server replies
                    "Did you mean ...?", it leaks schema even when introspection
                    is disabled -> API8, CWE-200 (low).
  * batching      : send a JSON array of queries. If the server answers every
                    one in a single request, it enables request batching abuse
                    (brute-force / resource amplification) -> API4, CWE-770.
  * get_mutation  : send `mutation{__typename}` over GET (semantically harmless
                    -- it only echoes a type name, no state change). If the
                    server executes it instead of forcing POST, mutations are
                    reachable via GET -> CSRF surface, API8, CWE-352.

Every probe is read-only and safe by default. Detection is confirmation-based:
a finding is only raised when the server's own response proves the behaviour,
so false positives stay near zero.
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

try:  # packaged import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - sandbox/local fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API8:2023"  # module default; individual findings set their own id
ALL_CHECKS = ("introspection", "suggestions", "batching", "get_mutation")

INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { "
    "queryType { name } mutationType { name } "
    "types { name kind } } }"
)
UNKNOWN_FIELD = "zzUnknownField_apistrike_9c1"
SUGGESTION_QUERY = "{ " + UNKNOWN_FIELD + " }"
PROBE_QUERY = "{ __typename }"
GET_MUTATION_QUERY = "mutation { __typename }"


@dataclass
class GraphQLResult:
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


def _parse(resp: Any):
    """Return the parsed JSON body (dict or list), or None if not JSON."""
    text = _body_str(resp).strip()
    if not text:
        return None
    try:
        return _json.loads(text)
    except Exception:
        return None


def _looks_graphql(obj: Any) -> bool:
    return isinstance(obj, dict) and ("data" in obj or "errors" in obj)


def _error_messages(obj: Any) -> List[str]:
    msgs: List[str] = []
    if isinstance(obj, dict):
        errs = obj.get("errors")
        if isinstance(errs, list):
            for e in errs:
                if isinstance(e, dict) and isinstance(e.get("message"), str):
                    msgs.append(e["message"])
                elif isinstance(e, str):
                    msgs.append(e)
    return msgs


class GraphQLModule:
    def __init__(
        self,
        client: Any,
        base_url: str,
        *,
        endpoint: str = "/graphql",
        checks=ALL_CHECKS,
        headers: Optional[Dict[str, str]] = None,
        safe: bool = True,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.endpoint = endpoint if endpoint.startswith("/") else "/" + endpoint
        self.checks = tuple(c for c in checks if c in ALL_CHECKS)
        if not self.checks:
            raise ValueError("no valid checks selected (choose from: " + ", ".join(ALL_CHECKS) + ")")
        self.base_headers = dict(headers or {})
        self.safe = safe
        self._requests = 0

    @property
    def _url(self) -> str:
        return self.base_url + self.endpoint

    async def _post(self, body: Any):
        headers = dict(self.base_headers)
        headers.setdefault("Content-Type", "application/json")
        resp = await self.client.request("POST", self._url, json=body, headers=headers)
        self._requests += 1
        return resp

    async def _get(self, query: str):
        url = self._url + "?" + urlencode({"query": query})
        resp = await self.client.request("GET", url, headers=dict(self.base_headers))
        self._requests += 1
        return resp

    async def _check_introspection(self, findings, notes):
        resp = await self._post({"query": INTROSPECTION_QUERY})
        obj = _parse(resp)
        schema = None
        if isinstance(obj, dict):
            data = obj.get("data")
            if isinstance(data, dict):
                schema = data.get("__schema")
        if isinstance(schema, dict):
            types = schema.get("types") or []
            type_names = [t.get("name") for t in types if isinstance(t, dict) and t.get("name") and not str(t.get("name")).startswith("__")]
            qt = (schema.get("queryType") or {}).get("name") if isinstance(schema.get("queryType"), dict) else None
            mt = (schema.get("mutationType") or {}).get("name") if isinstance(schema.get("mutationType"), dict) else None
            sample = ", ".join(str(n) for n in type_names[:12])
            findings.append(Finding(
                title="GraphQL introspection enabled",
                severity="medium", owasp_id="API8:2023", endpoint="POST " + self.endpoint,
                description="The GraphQL server answers the __schema introspection query, exposing its entire type system (" + str(len(type_names)) + " user types; queryType=" + str(qt) + ", mutationType=" + str(mt) + "). Introspection should be disabled in production so the API surface is not fully discoverable.",
                cwe="CWE-200",
                recommendation="Disable introspection in production (or restrict it to authenticated internal users). Keep an accurate inventory of the exposed schema.",
                confidence="confirmed",
                evidence=["types: " + str(len(type_names)), "sample: " + sample],
            ))
            return True
        notes.append("Introspection appears disabled (no __schema in response).")
        return False

    async def _check_suggestions(self, findings, notes):
        resp = await self._post({"query": SUGGESTION_QUERY})
        obj = _parse(resp)
        for msg in _error_messages(obj):
            low = msg.lower()
            if "did you mean" in low or "didyoumean" in low:
                findings.append(Finding(
                    title="GraphQL field suggestions leak schema",
                    severity="low", owasp_id="API8:2023", endpoint="POST " + self.endpoint,
                    description="The server returns \"Did you mean\" field suggestions for an unknown field, leaking schema details even if introspection is disabled.",
                    cwe="CWE-200",
                    recommendation="Disable field/type suggestions in production GraphQL error responses.",
                    confidence="confirmed",
                    evidence=[msg[:200]],
                ))
                return True
        notes.append("No field-suggestion leakage detected.")
        return False

    async def _check_batching(self, findings, notes):
        batch = [{"query": PROBE_QUERY}, {"query": PROBE_QUERY}, {"query": PROBE_QUERY}]
        resp = await self._post(batch)
        obj = _parse(resp)
        if isinstance(obj, list) and len(obj) >= 2 and all(_looks_graphql(o) for o in obj):
            answered = sum(1 for o in obj if isinstance(o, dict) and o.get("data") is not None)
            if answered >= 2:
                findings.append(Finding(
                    title="GraphQL query batching enabled",
                    severity="medium", owasp_id="API4:2023", endpoint="POST " + self.endpoint,
                    description="The server executes an array of " + str(len(batch)) + " queries in a single request (" + str(answered) + " answered). Batching lets an attacker amplify brute-force / enumeration and bypass per-request rate limits.",
                    cwe="CWE-770",
                    recommendation="Disable array-based query batching, or apply cost analysis and per-operation rate limiting.",
                    confidence="confirmed",
                    evidence=["batch of " + str(len(batch)) + " -> " + str(answered) + " data responses"],
                ))
                return True
        notes.append("Query batching not accepted (single-query responses only).")
        return False

    async def _check_get_mutation(self, findings, notes):
        resp = await self._get(GET_MUTATION_QUERY)
        obj = _parse(resp)
        data = obj.get("data") if isinstance(obj, dict) else None
        errs = " ".join(_error_messages(obj)).lower()
        blocked = ("mutation" in errs and ("post" in errs or "get" in errs or "not allowed" in errs))
        if isinstance(data, dict) and data.get("__typename") and not blocked:
            findings.append(Finding(
                title="GraphQL mutations allowed over HTTP GET",
                severity="medium", owasp_id="API8:2023", endpoint="GET " + self.endpoint,
                description="A mutation operation executes over an HTTP GET request. GET-reachable mutations can be triggered cross-site (CSRF) and may be cached by intermediaries.",
                cwe="CWE-352",
                recommendation="Reject mutation operations sent over GET; require POST with CSRF protection for all state-changing operations.",
                confidence="firm",
                evidence=["GET mutation{__typename} -> data.__typename=" + str(data.get("__typename"))],
            ))
            return True
        notes.append("Mutations over GET are rejected (good).")
        return False

    async def run(self, store=None) -> GraphQLResult:
        result = GraphQLResult()
        findings: List[Finding] = []
        notes: List[str] = []

        # Confirm the endpoint actually speaks GraphQL before probing.
        probe = await self._post({"query": PROBE_QUERY})
        if not _looks_graphql(_parse(probe)):
            notes.append("No GraphQL endpoint detected at " + self.endpoint + " (response is not a GraphQL envelope). Use --endpoint to point at the right path.")
            result.notes = notes
            result.requests_made = self._requests
            return result

        if "introspection" in self.checks:
            await self._check_introspection(findings, notes)
        if "suggestions" in self.checks:
            await self._check_suggestions(findings, notes)
        if "batching" in self.checks:
            await self._check_batching(findings, notes)
        if "get_mutation" in self.checks:
            await self._check_get_mutation(findings, notes)

        if not findings:
            notes.append("No GraphQL security issues detected across the selected checks.")
        if store is not None:
            for f in findings:
                store.add(f)
        result.findings = findings
        result.notes = notes
        result.requests_made = self._requests
        return result
