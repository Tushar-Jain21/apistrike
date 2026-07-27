"""Excessive Data Exposure module (OWASP API3:2023).

Fetches selected endpoints and scans the response bodies for information an API
should not be returning:

  * secrets : private keys, cloud/API keys, JWTs, password hashes, DB URIs
  * fields  : sensitive JSON properties (password, ssn, api_key, ...)
  * pii     : emails, US SSNs, Luhn-valid payment card numbers
  * entropy : high-entropy strings that look like tokens/secrets

All probes are read-only GET/inspection (safe by default). Evidence values are
masked/redacted so the tool never re-prints a full secret.
"""
from __future__ import annotations

import json as _json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

try:  # packaged import
    from apistrike.core.findings import Finding, OWASP_API_TOP_10
except Exception:  # pragma: no cover - sandbox/local fallback
    from findings import Finding, OWASP_API_TOP_10  # type: ignore

OWASP_ID = "API3:2023"
ALL_CHECKS = ("secrets", "fields", "pii", "entropy")

# (name, regex, severity, cwe)
SECRET_PATTERNS = [
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical", "CWE-321"),
    ("AWS access key id", r"AKIA[0-9A-Z]{16}", "high", "CWE-522"),
    ("AWS secret access key", r'(?i)aws_secret_access_key\s*[=:]\s*["]?[A-Za-z0-9/+]{40}', "high", "CWE-522"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}", "high", "CWE-522"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z\-]{10,48}", "high", "CWE-522"),
    ("JSON Web Token", r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}", "medium", "CWE-200"),
    ("Bcrypt password hash", r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", "high", "CWE-256"),
    ("Database connection string", r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s]+:[^@\s]+@", "high", "CWE-200"),
    ("Hardcoded secret assignment", r'(?i)(?:client[_-]?secret|private[_-]?key|secret[_-]?key)\s*[=:]\s*["][^"]{8,}["]', "medium", "CWE-200"),
]

SENSITIVE_FIELDS = {
    "password": "critical", "passwd": "critical", "pwd": "critical", "pass": "high",
    "secret": "high", "client_secret": "high", "api_key": "high", "apikey": "high",
    "private_key": "critical", "access_token": "high", "refresh_token": "high", "token": "medium",
    "ssn": "high", "social_security_number": "high", "credit_card": "high",
    "card_number": "high", "cardnumber": "high", "cvv": "high", "cvc": "high",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
HASH_RE = re.compile(r"^(?:\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")

_COMPILED_SECRETS = [(name, re.compile(pat), sev, cwe) for name, pat, sev, cwe in SECRET_PATTERNS]


@dataclass
class DataExposureTarget:
    path: str
    method: str = "GET"
    params: Optional[Dict[str, Any]] = None
    body: Optional[Any] = None
    headers: Optional[Dict[str, str]] = None

    def __post_init__(self):
        self.method = (self.method or "GET").upper()
        if not self.path.startswith("/"):
            self.path = "/" + self.path


@dataclass
class DataExposureResult:
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


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _luhn_ok(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        x = int(ch)
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        total += x
        alt = not alt
    return total % 10 == 0


def _mask(value: Any, keep: int = 4) -> str:
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "\u2026[redacted " + str(len(s) - keep) + " chars]"


def _looks_hashed(value: Any) -> bool:
    return bool(HASH_RE.match(str(value).strip()))


def _field_cwe(lk: str) -> str:
    if lk in ("password", "passwd", "pwd", "pass"):
        return "CWE-256"
    if lk in ("ssn", "social_security_number", "credit_card", "card_number", "cardnumber", "cvv", "cvc"):
        return "CWE-359"
    return "CWE-522"


def _walk_json(obj: Any):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            yield from _walk_json(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_json(item)


def _scan_secrets(endpoint: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    for name, rx, sev, cwe in _COMPILED_SECRETS:
        match = rx.search(text)
        if match:
            out.append(Finding(
                title="Secret exposed in response: " + name,
                severity=sev, owasp_id=OWASP_ID, endpoint=endpoint,
                description="The response body contains what appears to be a " + name.lower() + ". APIs must never return secrets or credentials in responses.",
                cwe=cwe,
                recommendation="Remove the secret from the API response and rotate it if it was ever exposed.",
                confidence="confirmed",
                evidence=[name + ": " + _mask(match.group(0))],
            ))
    return out


def _scan_fields(endpoint: str, parsed: Any) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for key, value in _walk_json(parsed):
        lk = str(key).lower()
        if lk not in SENSITIVE_FIELDS:
            continue
        if value is None or value == "" or value == [] or value == {}:
            continue
        if lk in seen:
            continue
        seen.add(lk)
        sev = SENSITIVE_FIELDS[lk]
        note = ""
        if lk in ("password", "passwd", "pwd", "pass") and not isinstance(value, (dict, list)) and not _looks_hashed(value):
            note = " The value appears to be PLAINTEXT (not a hash)."
        out.append(Finding(
            title="Sensitive field exposed in response: '" + str(key) + "'",
            severity=sev, owasp_id=OWASP_ID, endpoint=endpoint,
            description="The response exposes a sensitive object property '" + str(key) + "'." + note + " Object properties should be filtered per the consumer's authorization (property-level authorization).",
            cwe=_field_cwe(lk),
            recommendation="Return only the properties each consumer is authorized to see; never expose credentials, tokens, or secrets.",
            confidence="confirmed",
            evidence=[str(key) + ": " + (_mask(value) if not isinstance(value, (dict, list)) else "<" + type(value).__name__ + ">")],
        ))
    return out


def _scan_pii(endpoint: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    emails = sorted(set(EMAIL_RE.findall(text)))
    if emails:
        out.append(Finding(
            title="Personal data exposed: email address(es)",
            severity="low", owasp_id=OWASP_ID, endpoint=endpoint,
            description="The response contains " + str(len(emails)) + " email address(es). Bulk PII in a response can indicate excessive data exposure.",
            cwe="CWE-359",
            recommendation="Return PII only when necessary and authorized; consider masking or field filtering.",
            confidence="firm",
            evidence=[_mask(e, keep=3) for e in emails[:5]],
        ))
    ssns = sorted(set(SSN_RE.findall(text)))
    if ssns:
        out.append(Finding(
            title="Personal data exposed: SSN-formatted value(s)",
            severity="high", owasp_id=OWASP_ID, endpoint=endpoint,
            description="The response contains " + str(len(ssns)) + " value(s) matching a US Social Security Number format.",
            cwe="CWE-359",
            recommendation="Never return SSNs in API responses; remove or mask them.",
            confidence="firm",
            evidence=[_mask(s, keep=3) for s in ssns[:5]],
        ))
    cards = []
    for cand in CC_CANDIDATE_RE.findall(text):
        digits = re.sub(r"\D", "", cand)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits) and digits not in cards:
            cards.append(digits)
    if cards:
        out.append(Finding(
            title="Personal data exposed: payment card number(s)",
            severity="high", owasp_id=OWASP_ID, endpoint=endpoint,
            description="The response contains " + str(len(cards)) + " Luhn-valid payment-card-shaped number(s).",
            cwe="CWE-359",
            recommendation="Never return full PANs; use tokenization or last-4 only (PCI-DSS).",
            confidence="firm",
            evidence=[_mask(c, keep=6) for c in cards[:5]],
        ))
    return out


def _scan_entropy(endpoint: str, text: str, threshold: float, min_len: int, exclude: set) -> List[Finding]:
    token_re = re.compile(r"[A-Za-z0-9_\-+/=]{" + str(int(min_len)) + ",}")
    flagged: List[str] = []
    for tok in token_re.findall(text):
        if tok in exclude or tok in flagged:
            continue
        if len(tok) < min_len:
            continue
        has_alpha = any(c.isalpha() for c in tok)
        has_digit = any(c.isdigit() for c in tok)
        if has_alpha and has_digit and _entropy(tok) >= threshold:
            flagged.append(tok)
    if not flagged:
        return []
    return [Finding(
        title="High-entropy string(s) in response (possible secret/token)",
        severity="low", owasp_id=OWASP_ID, endpoint=endpoint,
        description="The response contains " + str(len(flagged)) + " high-entropy string(s) that resemble tokens/secrets and did not match a known field or pattern.",
        cwe="CWE-200",
        recommendation="Verify these are not secrets; if they are, remove them from the response.",
        confidence="firm",
        evidence=[_mask(t) for t in flagged[:5]],
    )]


class DataExposureModule:
    def __init__(
        self,
        client: Any,
        base_url: str,
        targets: Sequence[DataExposureTarget],
        *,
        checks: Sequence[str] = ALL_CHECKS,
        entropy_threshold: float = 4.0,
        entropy_min_len: int = 24,
        headers: Optional[Dict[str, str]] = None,
        safe: bool = True,
    ) -> None:
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.targets = list(targets)
        if not self.targets:
            raise ValueError("no targets provided")
        self.checks = tuple(c for c in checks if c in ALL_CHECKS)
        if not self.checks:
            raise ValueError("no valid checks selected (choose from: " + ", ".join(ALL_CHECKS) + ")")
        self.entropy_threshold = float(entropy_threshold)
        self.entropy_min_len = int(entropy_min_len)
        self.base_headers = dict(headers or {})
        self.safe = safe
        self._requests = 0

    async def _fetch(self, target: DataExposureTarget):
        url = self.base_url + target.path
        merged = dict(self.base_headers)
        if target.headers:
            merged.update(target.headers)
        kwargs: Dict[str, Any] = {"headers": merged}
        if target.params:
            kwargs["params"] = target.params
        if target.body is not None:
            kwargs["json"] = target.body
        resp = await self.client.request(target.method, url, **kwargs)
        self._requests += 1
        return resp

    async def run(self, store=None) -> DataExposureResult:
        result = DataExposureResult()
        findings: List[Finding] = []
        for target in self.targets:
            resp = await self._fetch(target)
            text = _body_str(resp)
            endpoint = target.method + " " + target.path
            try:
                parsed = _json.loads(text)
            except Exception:
                parsed = None

            secret_hits: set = set()
            if "secrets" in self.checks:
                for _name, rx, _sev, _cwe in _COMPILED_SECRETS:
                    for m in rx.finditer(text):
                        secret_hits.add(m.group(0))
                findings += _scan_secrets(endpoint, text)
            if "fields" in self.checks and parsed is not None:
                findings += _scan_fields(endpoint, parsed)
            if "pii" in self.checks:
                findings += _scan_pii(endpoint, text)
            if "entropy" in self.checks:
                findings += _scan_entropy(endpoint, text, self.entropy_threshold, self.entropy_min_len, secret_hits)

        if not findings:
            result.notes.append("No excessive data exposure detected across the scanned endpoints.")
        if store is not None:
            for finding in findings:
                store.add(finding)
        result.findings = findings
        result.requests_made = self._requests
        return result
