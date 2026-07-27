import pytest

from apistrike.core.findings import Finding, FindingsStore, OWASP_API_TOP_10


def make_finding():
    return Finding(
        title="IDOR on /users/{id}",
        severity="high",
        owasp_id="API1:2023",
        endpoint="/users/{id}",
        description="Able to read another user's record.",
        cwe="CWE-639",
        recommendation="Enforce object-level authorization.",
        evidence=[{"method": "GET", "url": "http://localhost/users/2", "status_code": 200}],
    )


def test_finding_validates_and_maps_owasp():
    f = make_finding()
    assert f.owasp_name == OWASP_API_TOP_10["API1:2023"]
    assert f.created_at  # auto-stamped


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        Finding(title="x", severity="bogus", owasp_id="API1:2023", endpoint="/x")


def test_invalid_owasp_rejected():
    with pytest.raises(ValueError):
        Finding(title="x", severity="low", owasp_id="API99:2023", endpoint="/x")


def test_store_add_query_summary(tmp_path):
    db = tmp_path / "findings.db"
    with FindingsStore(db) as store:
        fid = store.add(make_finding())
        assert fid == 1
        all_rows = store.all()
        assert len(all_rows) == 1
        assert all_rows[0]["owasp_name"] == "Broken Object Level Authorization"
        assert all_rows[0]["evidence"][0]["status_code"] == 200
        assert store.by_severity("high")
        summary = store.summary()
        assert summary["high"] == 1
        assert summary["total"] == 1
