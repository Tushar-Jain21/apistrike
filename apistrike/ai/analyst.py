"""AI Analyst -- exploit chain detection + false-positive review.

GUARANTEED GUARDRAIL: the analyst NEVER creates findings. It only annotates
and chains findings already confirmed by the deterministic engine.

Findings may arrive as in-memory ``Finding`` dataclass instances or as plain
``dict`` rows from ``FindingsStore.all()``. All field reads go through ``_fv``.

The LLM section parser is deliberately lenient: small local models (e.g.
llama3.2:3b) tend to wrap headers in markdown (``**CHAINS:**``, ``### CHAINS``)
and use ``*`` or ``1.`` bullets, so we normalise those before matching.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence

_ANALYST_SYSTEM = (
    "You are a senior API penetration tester reviewing confirmed findings. "
    "Be concise, specific, and evidence-based. Do not invent findings."
)

_ANALYST_PROMPT = """Review the following confirmed API security findings.

Target : {target}
Findings ({count} total):
{finding_list}

Provide your analysis in EXACTLY this format (omit a section if nothing applies).
Use these exact section headers on their own line, followed by '- ' bullet lines:

CHAINS:
- <finding title A> -> <finding title B>: <one-line exploit chain>

FALSE_POSITIVES:
- <finding title>: <one-line reason it may be a FP>

ADDITIONAL_CHECKS:
- <specific manual check to perform>

Only reference findings by their EXACT title as listed above."""

_KNOWN_CHAINS = [
    ("API3:2023", "API5:2023",
     "Mass-assignment admin flag -> BFLA: setting admin=true may grant access to privileged functions."),
    ("API1:2023", "API3:2023",
     "BOLA cross-user read -> Data exposure: object leaked via BOLA may contain sensitive fields."),
    ("API2:2023", "API1:2023",
     "Broken auth (alg:none / weak secret) -> BOLA: forged token for another user enables horizontal access."),
    ("API8:2023", "API3:2023",
     "Exposed debug surface -> Data exposure: debug endpoint likely leaks sensitive fields or PII."),
    ("INJECTION", "API1:2023",
     "SQLi in parameterised path -> BOLA: injection in the user/id path segment may access arbitrary objects."),
]

_HEURISTIC_NOTE = "AI Analyst: heuristic analysis (no LLM available)."

# Section header aliases -> canonical bucket. Matched case-insensitively against
# a cleaned, colon-stripped line.
_SECTION_ALIASES = [
    ("chains", ("CHAINS", "EXPLOIT CHAINS", "CHAIN", "ATTACK CHAINS")),
    ("fps", ("FALSE_POSITIVES", "FALSE POSITIVES", "POSSIBLE FALSE POSITIVES", "FALSE POSITIVE")),
    ("checks", ("ADDITIONAL_CHECKS", "ADDITIONAL CHECKS", "RECOMMENDED ADDITIONAL CHECKS",
                "RECOMMENDED CHECKS", "MANUAL CHECKS", "ADDITIONAL CHECK")),
]


def _fv(f: Any, key: str, default: Any = "") -> Any:
    """Read a field from a Finding that may be a dict (FindingsStore.all()) or a
    dataclass/object (in-memory Finding). Missing or None values return default."""
    if isinstance(f, dict):
        v = f.get(key, default)
    else:
        v = getattr(f, key, default)
    return default if v is None else v


@dataclass
class AnalysisResult:
    chains: List[str] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    additional_checks: List[str] = field(default_factory=list)
    raw: str = ""
    notes: List[str] = field(default_factory=list)
    ai_used: bool = False


def _fmt_findings(findings: Sequence[Any]) -> str:
    lines = []
    for f in findings:
        sev = str(_fv(f, "severity", "?")).upper()
        title = _fv(f, "title", str(f))
        owasp = _fv(f, "owasp_id", "")
        ep = _fv(f, "endpoint", "")
        lines.append(f"  [{sev}] {title} ({owasp})" + (f" @ {ep}" if ep else ""))
    return "\n".join(lines)


def _clean_header(line: str) -> str:
    """Strip markdown decoration so a header line can be matched.

    Handles leading '#', surrounding '*'/'_' bold/italic, and a trailing ':'.
    """
    s = line.strip().lstrip("#").strip()
    s = s.strip("*_ ").strip()
    s = s.rstrip(":").strip()
    s = s.strip("*_ ").strip()
    return s


def _strip_bullet(line: str) -> str:
    """Remove a leading list marker ('-', '*', the bullet char, or '1.'/'1)')."""
    s = line.strip()
    s = re.sub(r"^(?:[-*\u2022]|\d+[.)])\s+", "", s)
    # Drop stray surrounding bold markers on the item itself.
    return s.strip("*_ ").strip()


def _detect_section(line: str) -> Optional[str]:
    header = _clean_header(line).upper()
    if not header or len(header) > 40:
        return None
    for bucket, aliases in _SECTION_ALIASES:
        for a in aliases:
            if header == a or header.startswith(a):
                return bucket
    return None


def _parse_analysis(raw: str) -> tuple[list[str], list[str], list[str]]:
    chains: list[str] = []
    fps: list[str] = []
    checks: list[str] = []
    bucket = {"chains": chains, "fps": fps, "checks": checks}
    section: Optional[str] = None
    for line in (raw or "").splitlines():
        if not line.strip():
            continue
        sec = _detect_section(line)
        if sec is not None:
            section = sec
            continue
        if section is None:
            continue  # skip preamble before the first recognised header
        text = _strip_bullet(line)
        if text:
            bucket[section].append(text)
    return chains, fps, checks


def _heuristic_analysis(findings: Sequence[Any], note: str = _HEURISTIC_NOTE) -> AnalysisResult:
    owasp_ids = {_fv(f, "owasp_id", "") for f in findings}
    chains = [desc for id_a, id_b, desc in _KNOWN_CHAINS
               if id_a in owasp_ids and id_b in owasp_ids]
    checks = []
    if "INJECTION" in owasp_ids:
        checks.append("Test whether SQLi in path params can access other users' data (BOLA via injection).")
    if "API8:2023" in owasp_ids:
        checks.append("Manually probe exposed debug/admin surfaces for unauthenticated data or RCE (Werkzeug PIN bypass).")
    return AnalysisResult(
        chains=chains, additional_checks=checks,
        notes=[note],
        ai_used=False,
    )


class AIAnalyst:
    def __init__(self, provider: Any) -> None:
        self.provider = provider

    async def analyse(self, findings: Sequence[Any], target: str = "") -> AnalysisResult:
        if not findings:
            return AnalysisResult(notes=["No findings to analyse."])
        if not self.provider.is_available:
            return _heuristic_analysis(findings)
        prompt = _ANALYST_PROMPT.format(
            target=target or "(unknown)",
            count=len(findings),
            finding_list=_fmt_findings(findings),
        )
        raw = await self.provider.complete(prompt, system=_ANALYST_SYSTEM, max_tokens=512)
        chains, fps, checks = _parse_analysis(raw)
        if not (chains or fps or checks):
            fallback = _heuristic_analysis(
                findings,
                note="AI Analyst: LLM output could not be parsed; used heuristic analysis instead.",
            )
            fallback.raw = raw
            return fallback
        return AnalysisResult(
            chains=chains, false_positives=fps, additional_checks=checks,
            raw=raw, notes=["AI Analyst: analysis by " + self.provider.name + "."],
            ai_used=True,
        )
