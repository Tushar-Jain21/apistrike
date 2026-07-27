"""Markdown report generation for APIStrike.

Consumes the FindingsStore and renders a deterministic, professional Markdown
report. HTML/PDF (Jinja2 + WeasyPrint) build on top of this in Phase 6.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from apistrike.core.findings import FindingsStore, SEVERITIES

# Highest severity first for report ordering.
_SEVERITY_ORDER = list(reversed(SEVERITIES))
_SEVERITY_EMOJI = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED]",
    "low": "[LOW]",
    "info": "[INFO]",
}


def render_markdown(store: FindingsStore, target: str = "N/A") -> str:
    findings = store.all()
    summary = store.summary()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# APIStrike -- API Penetration Test Report")
    lines.append("")
    lines.append(f"- **Target:** {target}")
    lines.append(f"- **Generated:** {generated}")
    lines.append(f"- **Total findings:** {summary['total']}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {_SEVERITY_EMOJI[sev]} {sev.capitalize()} | {summary[sev]} |")
    lines.append("")

    if not findings:
        lines.append("_No findings recorded._")
        return "\n".join(lines) + "\n"

    lines.append("## Findings")
    lines.append("")

    order = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}
    findings.sort(key=lambda f: (order.get(f["severity"], 99), f["id"]))

    for f in findings:
        tag = _SEVERITY_EMOJI.get(f["severity"], "")
        lines.append(f"### {tag} {f['title']}")
        lines.append("")
        lines.append(f"- **OWASP:** {f['owasp_id']} -- {f['owasp_name']}")
        if f.get("cwe"):
            lines.append(f"- **CWE:** {f['cwe']}")
        lines.append(f"- **Endpoint:** `{f['endpoint']}`")
        lines.append(f"- **Confidence:** {f.get('confidence', '')}")
        lines.append("")
        if f.get("description"):
            lines.append(f["description"])
            lines.append("")
        if f.get("recommendation"):
            lines.append(f"**Recommendation:** {f['recommendation']}")
            lines.append("")
        evidence = f.get("evidence") or []
        if evidence:
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(evidence, indent=2, default=str))
            lines.append("```")
            lines.append("")

    return "\n".join(lines) + "\n"


def write_report(store: FindingsStore, path: str | Path, target: str = "N/A") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(store, target=target), encoding="utf-8")
    return path
