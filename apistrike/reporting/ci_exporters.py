"""CI-oriented exporters for APIStrike findings: JSON, SARIF 2.1.0, and a
severity gate for pipeline exit codes.

Self-contained and standard-library only. Every function accepts either
``Finding`` dataclass instances (from a live scan's ``result.findings``) or
plain dicts (from ``FindingsStore.all()``), so it works in both contexts.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Iterable, List, Optional

# Ordered low -> high; index gives comparable severity rank.
SEV_ORDER = ("info", "low", "medium", "high", "critical")

# SARIF result levels: error / warning / note / none.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_TOOL_URI = "https://github.com/Tushar-Jain21/apistrike"


def _tool_version() -> str:
    try:
        from apistrike import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - defensive
        return "unknown"


def _get(f, attr: str, default=""):
    """Read an attribute from a Finding object or a dict, uniformly."""
    if isinstance(f, dict):
        return f.get(attr, default)
    return getattr(f, attr, default)


def _severity(f) -> str:
    sev = str(_get(f, "severity", "info")).lower()
    return sev if sev in SEV_ORDER else "info"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Severity gate (CI exit codes)
# ---------------------------------------------------------------------------
def evaluate_gate(findings: Iterable, threshold: str) -> dict:
    """Return {'fail': bool, 'count': int, 'threshold': str}.

    ``count`` = findings whose severity is >= ``threshold``.
    Raises ValueError for an unknown threshold.
    """
    threshold = str(threshold or "").lower()
    if threshold not in SEV_ORDER:
        raise ValueError(
            f"Unknown --fail-on severity {threshold!r}; choose one of {', '.join(SEV_ORDER)}."
        )
    floor = SEV_ORDER.index(threshold)
    count = sum(1 for f in findings if SEV_ORDER.index(_severity(f)) >= floor)
    return {"fail": count > 0, "count": count, "threshold": threshold}


# ---------------------------------------------------------------------------
# Builders (pure)
# ---------------------------------------------------------------------------
def build_json(findings: Iterable, target: str = "N/A") -> dict:
    findings = list(findings)
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[_severity(f)] += 1
    counts["total"] = len(findings)
    return {
        "tool": "APIStrike",
        "version": _tool_version(),
        "target": target,
        "generated_at": _now(),
        "summary": counts,
        "findings": [
            {
                "title": _get(f, "title"),
                "severity": _severity(f),
                "owasp_id": _get(f, "owasp_id"),
                "owasp_name": _get(f, "owasp_name"),
                "cwe": _get(f, "cwe"),
                "endpoint": _get(f, "endpoint"),
                "description": _get(f, "description"),
                "recommendation": _get(f, "recommendation"),
                "confidence": _get(f, "confidence"),
                "fingerprint": _get(f, "fingerprint"),
                "evidence": _get(f, "evidence", []),
            }
            for f in findings
        ],
    }


def build_sarif(findings: Iterable, target: str = "N/A") -> dict:
    findings = list(findings)
    rules = {}
    results = []
    for f in findings:
        owasp_id = _get(f, "owasp_id") or "APISTRIKE"
        if owasp_id not in rules:
            rules[owasp_id] = {
                "id": owasp_id,
                "name": (_get(f, "owasp_name") or owasp_id).replace(" ", ""),
                "shortDescription": {"text": _get(f, "owasp_name") or owasp_id},
                "helpUri": _TOOL_URI,
                "properties": {"tags": ["security", "owasp-api-top-10"]},
            }
        endpoint = _get(f, "endpoint") or "/"
        sev = _severity(f)
        results.append({
            "ruleId": owasp_id,
            "level": _SARIF_LEVEL.get(sev, "warning"),
            "message": {
                "text": f"{_get(f, 'title')}. {_get(f, 'description')}".strip()
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": endpoint.lstrip("/") or "/"}
                }
            }],
            "partialFingerprints": {
                "apistrikeFingerprint": _get(f, "fingerprint") or ""
            },
            "properties": {
                "severity": sev,
                "cwe": _get(f, "cwe"),
                "owaspName": _get(f, "owasp_name"),
                "recommendation": _get(f, "recommendation"),
                "confidence": _get(f, "confidence"),
                "target": target,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "APIStrike",
                "informationUri": _TOOL_URI,
                "version": _tool_version(),
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _write(path: str, payload: dict) -> str:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def export_findings(findings: Iterable, path: str, fmt: str = "json",
                    target: str = "N/A") -> str:
    """Write findings to ``path`` as 'json' or 'sarif'. Returns the path."""
    fmt = (fmt or "json").lower()
    if fmt == "sarif":
        return _write(path, build_sarif(findings, target=target))
    if fmt == "json":
        return _write(path, build_json(findings, target=target))
    raise ValueError(f"Unknown export format {fmt!r} (choose 'json' or 'sarif').")
