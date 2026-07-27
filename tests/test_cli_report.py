from typer.testing import CliRunner

from apistrike.cli import app
from apistrike.core.config import Settings
from apistrike.core.findings import Finding, FindingsStore
from apistrike.reporting.report import render_markdown

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "APIStrike" in result.stdout


def test_settings_defaults_and_env(monkeypatch):
    monkeypatch.delenv("APISTRIKE_DB", raising=False)
    assert Settings.load().findings_db == "findings.db"
    monkeypatch.setenv("APISTRIKE_DB", "custom.db")
    assert Settings.load().findings_db == "custom.db"


def test_render_markdown_with_finding(tmp_path):
    db = tmp_path / "f.db"
    with FindingsStore(db) as store:
        store.add(
            Finding(
                title="IDOR on /users/{id}",
                severity="high",
                owasp_id="API1:2023",
                endpoint="/users/{id}",
                cwe="CWE-639",
                recommendation="Enforce object-level auth.",
            )
        )
        md = render_markdown(store, target="http://localhost:8080")
    assert "# APIStrike" in md
    assert "IDOR on /users/{id}" in md
    assert "API1:2023" in md
    assert "http://localhost:8080" in md


def test_scan_refuses_out_of_scope(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("allowed_hosts:\n  - localhost\nrate_limit: 5\n")
    result = runner.invoke(app, ["scan", "https://evil.com", "--scope", str(scope_file)])
    assert result.exit_code == 2
    assert "Refused" in result.stdout
