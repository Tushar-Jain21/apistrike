"""AI Reporter -- exec summary + per-finding narratives + enriched Markdown report.

GUARANTEED GUARDRAIL: the reporter only summarises confirmed findings from the
deterministic engine. It never invents, upgrades, or adds new findings.

Findings may arrive either as in-memory ``Finding`` dataclass instances (from a
live scan's ``result.findings``) or as plain ``dict`` rows loaded from
``FindingsStore.all()``. All field reads go through ``_fv`` so both shapes work.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

_REPORTER_SYSTEM = (
    "You are a professional penetration tester writing a security report. "
    "Be clear, concise, and actionable."
)

_EXEC_PROMPT = """Write the executive summary of an API penetration test report.

Target : {target}
Date   : {date}
Total  : {total} findings ({critical} critical, {high} high, {medium} medium, {low} low, {info} info)

Top findings:
{top_findings}

Write exactly 3-4 sentences for a non-technical manager.
Mention overall risk level and the two most critical issues. No bullet points."""

_NARRATIVE_PROMPT = """Write a 2-3 sentence business-impact statement for this finding.

Title    : {title}
Severity : {severity}
OWASP    : {owasp_id}
CWE      : {cwe}
Endpoint : {endpoint}
Detail   : {description}

Focus on: what an attacker could do, what is at risk, why fixing it matters. No bullet points."""

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _fv(f: Any, key: str, default: Any = "") -> Any:
    """Read a field from a Finding that may be a dict (FindingsStore.all()) or a
    dataclass/object (in-memory Finding). Missing or None values return default."""
    if isinstance(f, dict):
        v = f.get(key, default)
    else:
        v = getattr(f, key, default)
    return default if v is None else v


@dataclass
class ReportEnrichment:
    exec_summary: str = ""
    narratives: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    ai_used: bool = False


def _counts(findings: Sequence[Any]) -> dict:
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(_fv(f, "severity", "info")).lower()
        c[sev] = c.get(sev, 0) + 1
    return c


def _top_text(findings: Sequence[Any], n: int = 5) -> str:
    ranked = sorted(findings, key=lambda f: _SEV_ORDER.get(str(_fv(f, "severity", "info")).lower(), 99))
    lines = []
    for f in ranked[:n]:
        sev = str(_fv(f, "severity", "?")).upper()
        title = _fv(f, "title", str(f))
        ep = _fv(f, "endpoint", "")
        lines.append(f"  [{sev}] {title}" + (f" @ {ep}" if ep else ""))
    return "\n".join(lines)


def _default_summary(findings: Sequence[Any], target: str, date: str) -> str:
    c = _counts(findings)
    risk = "CRITICAL" if c["critical"] else ("HIGH" if c["high"] else ("MEDIUM" if c["medium"] else "LOW"))
    top = sorted(findings, key=lambda f: _SEV_ORDER.get(str(_fv(f, "severity", "info")).lower(), 99))
    top_titles = "; ".join(_fv(f, "title", "") for f in top[:2] if _fv(f, "title", ""))
    return (
        f"A security assessment of {target} on {date} identified {len(findings)} finding(s), "
        f"indicating an overall {risk} risk posture. "
        + (f"The most critical issues were: {top_titles}. " if top_titles else "")
        + "Prompt remediation of high and critical findings is strongly recommended."
    )


def _default_narrative(finding: Any) -> str:
    severity = _fv(finding, "severity", "medium")
    endpoint = _fv(finding, "endpoint", "")
    desc = _fv(finding, "description", "")
    loc = f" at {endpoint}" if endpoint else ""
    short = desc[:120] + "..." if len(desc) > 120 else desc
    detail = f"indicates {short} " if short else "was confirmed by the engine. "
    return (
        f"This {severity}-severity finding{loc} {detail}"
        f"An attacker exploiting this issue could gain unauthorised access to sensitive data or system functionality. "
        f"Remediation should follow the recommendation in the technical section."
    )


class AIReporter:
    def __init__(self, provider: Any) -> None:
        self.provider = provider

    async def exec_summary(self, findings: Sequence[Any],
                           target: str = "", date: str = "") -> str:
        date = date or datetime.date.today().isoformat()
        target = target or "the target API"
        if not self.provider.is_available:
            return _default_summary(findings, target, date)
        c = _counts(findings)
        prompt = _EXEC_PROMPT.format(
            target=target, date=date, total=len(findings),
            **c, top_findings=_top_text(findings),
        )
        result = await self.provider.complete(prompt, system=_REPORTER_SYSTEM, max_tokens=256)
        return result or _default_summary(findings, target, date)

    async def finding_narrative(self, finding: Any) -> str:
        if not self.provider.is_available:
            return _default_narrative(finding)
        prompt = _NARRATIVE_PROMPT.format(
            title=_fv(finding, "title", ""),
            severity=_fv(finding, "severity", ""),
            owasp_id=_fv(finding, "owasp_id", ""),
            cwe=_fv(finding, "cwe", ""),
            endpoint=_fv(finding, "endpoint", ""),
            description=_fv(finding, "description", ""),
        )
        result = await self.provider.complete(prompt, system=_REPORTER_SYSTEM, max_tokens=128)
        return result or _default_narrative(finding)

    async def enrich_report(self, findings: Sequence[Any],
                            target: str = "", date: str = "") -> ReportEnrichment:
        if not findings:
            return ReportEnrichment(
                exec_summary="No findings were recorded for this assessment.",
                notes=["No findings to enrich."],
            )
        summary = await self.exec_summary(findings, target=target, date=date)
        narratives: dict[str, str] = {}
        for f in findings:
            title = _fv(f, "title", str(f))
            narratives[title] = await self.finding_narrative(f)
        ai_used = self.provider.is_available
        notes = [
            ("AI Reporter: enrichment by " + self.provider.name + ".")
            if ai_used
            else "AI Reporter: template-based enrichment (no LLM available)."
        ]
        return ReportEnrichment(exec_summary=summary, narratives=narratives,
                                notes=notes, ai_used=ai_used)
