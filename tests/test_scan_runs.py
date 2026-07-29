from apistrike.core.findings import Finding, FindingsStore, compute_fingerprint
from apistrike.reporting.report import render_markdown


def _mk(title="IDOR on /users/{id}", severity="high", owasp="API1:2023",
        endpoint="/users/{id}", key="", evidence=None):
    return Finding(title=title, severity=severity, owasp_id=owasp,
                   endpoint=endpoint, key=key, evidence=evidence or [])


def test_fingerprint_stable_and_distinct():
    a = _mk()
    b = _mk()
    assert a.fingerprint == b.fingerprint
    assert _mk(endpoint="/accounts/{id}").fingerprint != a.fingerprint
    assert _mk(key="page").fingerprint != a.fingerprint
    assert a.fingerprint == compute_fingerprint(
        "API1:2023", "/users/{id}", "IDOR on /users/{id}", ""
    )


def test_explicit_run_lifecycle(tmp_path):
    with FindingsStore(tmp_path / "f.db") as store:
        rid = store.begin_run(target="http://localhost:8080", command="scan",
                              modules=["bola"])
        store.add(_mk())
        store.finish_run()

        runs = store.runs()
        assert len(runs) == 1
        assert runs[0]["run_id"] == rid
        assert runs[0]["status"] == "completed"
        assert runs[0]["target"] == "http://localhost:8080"
        assert runs[0]["finished_at"]

        rows = store.all()
        assert len(rows) == 1
        assert rows[0]["run_id"] == rid
        assert rows[0]["fingerprint"]
        assert rows[0]["first_seen_at"]


def test_dedup_within_run_merges_evidence(tmp_path):
    with FindingsStore(tmp_path / "f.db") as store:
        store.begin_run(target="t")
        id1 = store.add(_mk(evidence=[{"url": "/users/2"}]))
        id2 = store.add(_mk(evidence=[{"url": "/users/9"}]))
        assert id1 == id2
        rows = store.all()
        assert len(rows) == 1
        urls = {e.get("url") for e in rows[0]["evidence"]}
        assert {"/users/2", "/users/9"} <= urls


def test_lazy_default_run(tmp_path):
    with FindingsStore(tmp_path / "f.db") as store:
        fid = store.add(_mk())
        assert fid == 1
        assert len(store.runs()) == 1
        assert len(store.all()) == 1


def test_report_defaults_to_latest_run(tmp_path):
    with FindingsStore(tmp_path / "f.db") as store:
        r1 = store.begin_run(target="t1")
        store.add(_mk(title="Old finding", endpoint="/old"))
        store.finish_run()
        store.begin_run(target="t2")
        store.add(_mk(title="New finding", endpoint="/new"))
        store.finish_run()

        latest = store.all()
        assert len(latest) == 1
        assert latest[0]["title"] == "New finding"

        assert len(store.all(all_runs=True)) == 2

        first = store.all(run_id=r1)
        assert len(first) == 1
        assert first[0]["title"] == "Old finding"

        assert store.summary()["total"] == 1
        assert store.summary(all_runs=True)["total"] == 2

        md = render_markdown(store)
        assert "New finding" in md
        assert "Old finding" not in md
        md_all = render_markdown(store, all_runs=True)
        assert "Old finding" in md_all and "New finding" in md_all
