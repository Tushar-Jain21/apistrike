"""Tests for the Phase 6 HTML/PDF reporter (apistrike/reporting/html_report.py).

Uses a duck-typed FakeStore so these run without the SQLite engine. The PDF
test adapts to whether WeasyPrint is installed, so it passes both in CI-less
sandboxes (no WeasyPrint) and on a fully provisioned box.
"""
from __future__ import annotations

import pytest

from apistrike.reporting.html_report import (
    render_html, write_html, write_pdf, write_report,
    weasyprint_available, WeasyPrintNotInstalled,
)


class FakeStore:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)

    def summary(self):
        d = {"total": len(self._rows)}
        for r in self._rows:
            d[r["severity"]] = d.get(r["severity"], 0) + 1
        return d


FINDS = [
    {"id": 1, "title": "Interactive console exposed", "severity": "high",
     "owasp_id": "API9:2023", "owasp_name": "Improper Inventory Management",
     "cwe": "CWE-489", "endpoint": "GET /console", "confidence": "firm",
     "description": "A Werkzeug console is reachable.",
     "recommendation": "Disable debug mode in production.",
     "evidence": [{"status": 200, "url": "/console"}]},
    {"id": 2, "title": "OpenAPI spec exposed", "severity": "medium",
     "owasp_id": "API9:2023", "owasp_name": "Improper Inventory Management",
     "cwe": "CWE-200", "endpoint": "GET /openapi.json", "confidence": "firm",
     "description": "Spec reachable.", "recommendation": "Restrict access.",
     "evidence": []},
    {"id": 3, "title": "Plaintext password <b>leak</b>", "severity": "critical",
     "owasp_id": "API3:2023", "owasp_name": "Broken Object Property Level Authorization",
     "cwe": "CWE-256", "endpoint": "GET /users/v1/_debug", "confidence": "confirmed",
     "description": "Passwords returned in <script>alert(1)</script> cleartext.",
     "recommendation": "Hash passwords with a strong KDF.",
     "evidence": [{"field": "password", "value": "REDACTED"}]},
]


def test_render_html_contains_core():
    html = render_html(FakeStore(FINDS), target="VAmPI", model="llama3.2:3b")
    assert html.startswith("<!DOCTYPE html>")
    assert "APIStrike" in html
    assert "VAmPI" in html
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert label in html
    assert "Interactive console exposed" in html
    assert "API9:2023" in html
    assert "GET /console" in html
    assert "llama3.2:3b" in html


def test_render_html_autoescapes_response_content():
    html = render_html(FakeStore(FINDS), target="VAmPI")
    # Response-derived markup must be escaped, never rendered.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;leak&lt;/b&gt;" in html


def test_findings_sorted_critical_first():
    html = render_html(FakeStore(FINDS), target="VAmPI")
    i_crit = html.find("Plaintext password")
    i_high = html.find("Interactive console")
    i_med = html.find("OpenAPI spec exposed")
    assert -1 < i_crit < i_high < i_med


def test_overall_risk_badge_is_highest_severity():
    html = render_html(FakeStore(FINDS), target="VAmPI")
    assert 'class="risk"' in html
    # CRITICAL should appear at least twice: summary chip + risk badge.
    assert html.count("CRITICAL") >= 2


def test_exec_summary_included_when_given():
    html = render_html(FakeStore(FINDS), target="VAmPI",
                       exec_summary="Overall HIGH risk posture.")
    assert "Executive Summary" in html
    assert "Overall HIGH risk posture." in html


def test_exec_summary_absent_by_default():
    html = render_html(FakeStore(FINDS), target="VAmPI")
    assert "Executive Summary" not in html


def test_empty_findings_state():
    html = render_html(FakeStore([]), target="Clean")
    assert "No findings recorded" in html
    assert "Total findings:</span> 0" in html


def test_write_html_creates_file(tmp_path):
    p = write_html(FakeStore(FINDS), tmp_path / "sub" / "r.html", target="VAmPI")
    assert p.exists()
    assert p.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_weasyprint_available_returns_bool():
    assert isinstance(weasyprint_available(), bool)


def test_pdf_path_adapts_to_environment(tmp_path):
    store = FakeStore(FINDS)
    out = tmp_path / "r.pdf"
    if weasyprint_available():
        p = write_pdf(store, out, target="VAmPI")
        assert p.exists() and p.stat().st_size > 0
        assert p.read_bytes()[:5] == b"%PDF-"
    else:
        with pytest.raises(WeasyPrintNotInstalled):
            write_pdf(store, out, target="VAmPI")


def test_write_report_dispatch_html(tmp_path):
    p = write_report(FakeStore(FINDS), tmp_path / "r.html", target="VAmPI", fmt="html")
    assert p.exists() and p.suffix == ".html"


def test_write_report_rejects_unknown_format(tmp_path):
    with pytest.raises(ValueError):
        write_report(FakeStore(FINDS), tmp_path / "r.x", target="VAmPI", fmt="docx")
