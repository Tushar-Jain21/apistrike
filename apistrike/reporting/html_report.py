"""HTML + PDF report generation for APIStrike (Phase 6).

Builds on ``reporting/report.py``: consumes the same ``FindingsStore`` (only its
duck-typed ``.all()`` is required), renders a professional, self-contained,
print-optimised HTML report with Jinja2, and converts it to PDF with WeasyPrint.

Design notes:
- WeasyPrint is imported lazily inside the PDF functions, so HTML/Markdown
  output keeps working on machines without the native PDF libraries.
- The Jinja2 environment uses non-curly delimiters ([[ ]] / [% %]) so the CSS
  braces never collide with the template engine.
- ``autoescape`` is ON: finding titles/descriptions/evidence can contain
  response-derived content, so everything is HTML-escaped to prevent injection
  into the rendered report.
- Findings may be dict rows (from ``FindingsStore.all()``) or objects; every
  field read goes through ``_g``.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Sequence, Union

from jinja2 import Environment

if TYPE_CHECKING:
    from apistrike.core.findings import FindingsStore

try:  # keep ordering in sync with the engine when importable
    from apistrike.core.findings import SEVERITIES
except Exception:  # pragma: no cover - fallback for isolated use/tests
    SEVERITIES = ("info", "low", "medium", "high", "critical")

_SEVERITY_ORDER = list(reversed(SEVERITIES))  # critical -> info

_SEVERITY_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}
_SEVERITY_COLOR = {
    "critical": "#b3123b", "high": "#e8590c", "medium": "#f08c00",
    "low": "#2f9e44", "info": "#1971c2",
}
_DEFAULT_COLOR = "#868e96"


class WeasyPrintNotInstalled(RuntimeError):
    """Raised when PDF output is requested but WeasyPrint is unavailable."""


def _import_weasyprint():
    try:
        from weasyprint import HTML  # type: ignore
        return HTML
    except Exception as exc:  # ImportError or native-lib load failure
        raise WeasyPrintNotInstalled(
            "PDF output requires WeasyPrint and its native libraries "
            "(libpango, libcairo, libgdk-pixbuf). Install with "
            "`pip install weasyprint` plus the system packages, or choose "
            "--format html or --format md."
        ) from exc


def weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


def _g(f: Any, key: str, default: Any = "") -> Any:
    v = f.get(key, default) if isinstance(f, dict) else getattr(f, key, default)
    return default if v is None else v


def _sev(f: Any) -> str:
    return str(_g(f, "severity", "info")).lower()


def _evidence_json(f: Any) -> str:
    ev = _g(f, "evidence", []) or []
    if isinstance(ev, str):
        return ev
    if ev:
        return json.dumps(ev, indent=2, default=str)
    return ""


def _normalise(findings: Sequence[Any]) -> list[dict]:
    order = {sev: i for i, sev in enumerate(_SEVERITY_ORDER)}

    def sort_key(f: Any):
        try:
            fid = int(_g(f, "id", 0) or 0)
        except (TypeError, ValueError):
            fid = 0
        return (order.get(_sev(f), 99), fid)

    out: list[dict] = []
    for f in sorted(findings, key=sort_key):
        sev = _sev(f)
        out.append({
            "severity": sev,
            "label": _SEVERITY_LABEL.get(sev, sev.upper()),
            "color": _SEVERITY_COLOR.get(sev, _DEFAULT_COLOR),
            "title": _g(f, "title", "(untitled finding)"),
            "owasp_id": _g(f, "owasp_id", ""),
            "owasp_name": _g(f, "owasp_name", ""),
            "cwe": _g(f, "cwe", ""),
            "endpoint": _g(f, "endpoint", ""),
            "confidence": _g(f, "confidence", ""),
            "description": _g(f, "description", ""),
            "recommendation": _g(f, "recommendation", ""),
            "evidence_json": _evidence_json(f),
        })
    return out


def _counts(findings: Sequence[Any]) -> dict[str, int]:
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        s = _sev(f)
        if s in counts:
            counts[s] += 1
    return counts


def _overall_risk(counts: dict[str, int]) -> str:
    for sev in _SEVERITY_ORDER:  # critical first
        if counts.get(sev):
            return sev
    return "info"


def _materialise(source: Any) -> list:
    """Accept a live FindingsStore (has .all()) or an already-fetched list.

    ai-report closes its store before rendering, so callers may pass the
    findings list directly to avoid re-querying a closed connection.
    """
    if hasattr(source, "all") and callable(getattr(source, "all")):
        return list(source.all())
    return list(source)


def build_context(store: Any, target: str = "N/A",
                  exec_summary: Optional[str] = None,
                  model: Optional[str] = None) -> dict:
    findings_raw = _materialise(store)
    counts = _counts(findings_raw)
    risk = _overall_risk(counts) if findings_raw else "info"
    summary_rows = [
        {"label": _SEVERITY_LABEL[s], "color": _SEVERITY_COLOR[s], "count": counts.get(s, 0)}
        for s in _SEVERITY_ORDER
    ]
    return {
        "target": target,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total": len(findings_raw),
        "risk_label": _SEVERITY_LABEL[risk],
        "risk_color": _SEVERITY_COLOR[risk],
        "model": model,
        "exec_summary": exec_summary,
        "summary_rows": summary_rows,
        "findings": _normalise(findings_raw),
    }


_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>APIStrike Report -- [[ target ]]</title>
<style>
  @page { size: A4; margin: 18mm 16mm 20mm 16mm;
    @bottom-center { content: "APIStrike -- Confidential -- Page " counter(page) " of " counter(pages); font-size: 8pt; color: #868e96; } }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color:#212529; font-size:11pt; line-height:1.5; margin:0; }
  h1,h2,h3 { color:#0b1f3a; margin:0 0 8px; }
  .band { background:#0b1f3a; color:#fff; padding:22px 26px; border-radius:8px; }
  .band h1 { color:#fff; font-size:21pt; margin:0; }
  .band .sub { color:#9db2d6; font-size:10pt; margin-top:4px; }
  .meta { display:flex; flex-wrap:wrap; gap:6px 28px; margin:16px 0 4px; font-size:10pt; }
  .meta span { color:#868e96; }
  .risk { display:inline-block; padding:3px 12px; border-radius:14px; color:#fff; font-weight:700; font-size:10pt; letter-spacing:.4px; }
  .section-title { border-bottom:2px solid #e9ecef; padding-bottom:6px; margin:26px 0 12px; font-size:14pt; }
  table.summary { border-collapse:collapse; width:100%; margin:8px 0; font-size:10pt; }
  table.summary th, table.summary td { text-align:left; padding:6px 10px; border-bottom:1px solid #e9ecef; }
  .chip { display:inline-block; min-width:72px; text-align:center; padding:2px 8px; border-radius:10px; color:#fff; font-weight:700; font-size:9pt; letter-spacing:.3px; }
  .count { font-variant-numeric: tabular-nums; font-weight:700; }
  .finding { border:1px solid #e9ecef; border-left-width:5px; border-radius:6px; padding:14px 16px; margin:12px 0; page-break-inside: avoid; }
  .finding h3 { font-size:12.5pt; }
  .kv { font-size:9.5pt; color:#495057; margin:6px 0; }
  .kv code { background:#f1f3f5; padding:1px 5px; border-radius:4px; font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; }
  .desc { margin:8px 0; }
  .rec { background:#f8f9fa; border-left:3px solid #1971c2; padding:8px 12px; margin:8px 0; font-size:10pt; }
  pre.evidence { background:#0b1f3a; color:#d0e2ff; padding:10px 12px; border-radius:6px; font-size:8.5pt; white-space:pre-wrap; word-break:break-word; }
  .ethics { margin-top:28px; padding:12px 14px; border:1px dashed #adb5bd; border-radius:6px; font-size:8.5pt; color:#495057; }
  .empty { padding:24px; text-align:center; color:#868e96; font-style:italic; }
</style>
</head>
<body>
  <div class="band">
    <h1>APIStrike &mdash; API Penetration Test Report</h1>
    <div class="sub">Automated OWASP API Security Top 10 assessment</div>
  </div>
  <div class="meta">
    <div><span>Target:</span> <strong>[[ target ]]</strong></div>
    <div><span>Generated:</span> [[ generated ]]</div>
    <div><span>Total findings:</span> [[ total ]]</div>
    <div><span>Overall risk:</span> <span class="risk" style="background:[[ risk_color ]]">[[ risk_label ]]</span></div>
    [% if model %]<div><span>AI model:</span> [[ model ]]</div>[% endif %]
  </div>

  [% if exec_summary %]
  <h2 class="section-title">Executive Summary</h2>
  <div class="desc">[[ exec_summary ]]</div>
  [% endif %]

  <h2 class="section-title">Severity Summary</h2>
  <table class="summary">
    <tr><th>Severity</th><th>Count</th></tr>
    [% for row in summary_rows %]
    <tr>
      <td><span class="chip" style="background:[[ row.color ]]">[[ row.label ]]</span></td>
      <td class="count">[[ row.count ]]</td>
    </tr>
    [% endfor %]
  </table>

  <h2 class="section-title">Findings</h2>
  [% if findings %]
    [% for f in findings %]
    <div class="finding" style="border-left-color:[[ f.color ]]">
      <h3><span class="chip" style="background:[[ f.color ]]">[[ f.label ]]</span> &nbsp;[[ f.title ]]</h3>
      <div class="kv"><strong>OWASP:</strong> [[ f.owasp_id ]][% if f.owasp_name %] &mdash; [[ f.owasp_name ]][% endif %]
        [% if f.cwe %]&nbsp;|&nbsp; <strong>CWE:</strong> [[ f.cwe ]][% endif %]
        [% if f.endpoint %]&nbsp;|&nbsp; <strong>Endpoint:</strong> <code>[[ f.endpoint ]]</code>[% endif %]
        [% if f.confidence %]&nbsp;|&nbsp; <strong>Confidence:</strong> [[ f.confidence ]][% endif %]
      </div>
      [% if f.description %]<div class="desc">[[ f.description ]]</div>[% endif %]
      [% if f.recommendation %]<div class="rec"><strong>Recommendation:</strong> [[ f.recommendation ]]</div>[% endif %]
      [% if f.evidence_json %]<pre class="evidence">[[ f.evidence_json ]]</pre>[% endif %]
    </div>
    [% endfor %]
  [% else %]
    <div class="empty">No findings recorded &mdash; the target resisted all executed checks.</div>
  [% endif %]

  <div class="ethics">
    <strong>Authorized use only.</strong> This report was produced by APIStrike, an automated API security testing tool, for authorized/defensive assessment of systems the operator owns or is explicitly permitted to test. Findings are confirmed by deterministic requests; any AI narrative is advisory. Handle as confidential.
  </div>
</body>
</html>
"""

_env = Environment(
    autoescape=True,
    variable_start_string="[[", variable_end_string="]]",
    block_start_string="[%", block_end_string="%]",
    comment_start_string="[#", comment_end_string="#]",
    trim_blocks=True, lstrip_blocks=True,
)
_compiled = _env.from_string(_TEMPLATE)


def render_html(store: "FindingsStore", target: str = "N/A",
                exec_summary: Optional[str] = None,
                model: Optional[str] = None) -> str:
    return _compiled.render(**build_context(store, target, exec_summary, model))


def write_html(store: "FindingsStore", path: Union[str, Path], target: str = "N/A",
               exec_summary: Optional[str] = None,
               model: Optional[str] = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(store, target, exec_summary, model), encoding="utf-8")
    return path


def render_pdf_bytes(html_string: str, base_url: Optional[str] = None) -> bytes:
    HTML = _import_weasyprint()
    return HTML(string=html_string, base_url=base_url).write_pdf()


def write_pdf(store: "FindingsStore", path: Union[str, Path], target: str = "N/A",
              exec_summary: Optional[str] = None,
              model: Optional[str] = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_pdf_bytes(render_html(store, target, exec_summary, model)))
    return path


def write_report(store: "FindingsStore", path: Union[str, Path], target: str = "N/A",
                 fmt: str = "html", exec_summary: Optional[str] = None,
                 model: Optional[str] = None) -> Path:
    """Unified dispatcher: fmt in {md, html, pdf}."""
    fmt = (fmt or "html").lower()
    if fmt in ("md", "markdown"):
        from apistrike.reporting.report import write_report as _write_md
        return _write_md(store, path, target=target)
    if fmt == "html":
        return write_html(store, path, target, exec_summary, model)
    if fmt == "pdf":
        return write_pdf(store, path, target, exec_summary, model)
    raise ValueError(f"Unknown report format: {fmt!r} (use md, html, or pdf)")
