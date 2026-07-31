"""Offline tests for the CI exporters. Loads the module directly from its file
so it needs no heavy third-party deps and no full package import."""
import importlib.util
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "apistrike" / "reporting" / "ci_exporters.py"
)

spec = importlib.util.spec_from_file_location("ci_exporters", MODULE_PATH)
ce = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ce)


FINDINGS = [
    {
        "title": "JWT RS256->HS256 algorithm confusion accepted",
        "severity": "critical", "owasp_id": "API2:2023",
        "owasp_name": "Broken Authentication", "cwe": "CWE-347",
        "endpoint": "/me", "description": "forged token accepted",
        "recommendation": "pin alg", "confidence": "confirmed",
        "fingerprint": "abc123", "evidence": [{"status": 200}],
    },
    {
        "title": "Verbose error leak", "severity": "low",
        "owasp_id": "API8:2023", "owasp_name": "Security Misconfiguration",
        "cwe": "CWE-209", "endpoint": "/users/{id}", "description": "stack trace",
        "recommendation": "hide errors", "confidence": "firm",
        "fingerprint": "def456", "evidence": [],
    },
]


def test_gate_triggers_at_or_above_threshold():
    g = ce.evaluate_gate(FINDINGS, "high")
    assert g == {"fail": True, "count": 1, "threshold": "high"}


def test_gate_counts_all_at_low():
    g = ce.evaluate_gate(FINDINGS, "low")
    assert g["count"] == 2 and g["fail"] is True


def test_gate_no_fail_when_nothing_meets_threshold():
    g = ce.evaluate_gate(FINDINGS[1:], "critical")
    assert g == {"fail": False, "count": 0, "threshold": "critical"}


def test_gate_rejects_unknown_threshold():
    import pytest
    with pytest.raises(ValueError):
        ce.evaluate_gate(FINDINGS, "bogus")


def test_json_shape_and_counts():
    doc = ce.build_json(FINDINGS, target="https://api.example.com")
    assert doc["tool"] == "APIStrike"
    assert doc["summary"]["critical"] == 1
    assert doc["summary"]["low"] == 1
    assert doc["summary"]["total"] == 2
    assert len(doc["findings"]) == 2
    assert doc["findings"][0]["owasp_id"] == "API2:2023"


def test_sarif_shape_levels_and_rules():
    doc = ce.build_sarif(FINDINGS, target="t")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "APIStrike"
    # two distinct owasp ids -> two rules
    assert len(run["tool"]["driver"]["rules"]) == 2
    results = run["results"]
    assert results[0]["level"] == "error"   # critical
    assert results[1]["level"] == "note"    # low
    assert results[0]["ruleId"] == "API2:2023"
    assert results[0]["partialFingerprints"]["apistrikeFingerprint"] == "abc123"


def test_export_writes_files(tmp_path):
    j = ce.export_findings(FINDINGS, str(tmp_path / "out" / "f.json"), fmt="json")
    s = ce.export_findings(FINDINGS, str(tmp_path / "out" / "f.sarif"), fmt="sarif")
    assert Path(j).exists() and Path(s).exists()


def test_accepts_objects_not_only_dicts():
    class F:
        def __init__(self, **kw):
            self.__dict__.update(kw)
    objs = [F(title="x", severity="medium", owasp_id="API2:2023",
             owasp_name="Broken Authentication", cwe="", endpoint="/a",
             description="", recommendation="", confidence="firm",
             fingerprint="z", evidence=[])]
    g = ce.evaluate_gate(objs, "medium")
    assert g["count"] == 1
    assert ce.build_sarif(objs)["runs"][0]["results"][0]["level"] == "warning"
