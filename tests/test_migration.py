import json
import sqlite3

from apistrike.core.findings import (
    FindingsStore,
    SCHEMA_VERSION,
    migrate_v0_to_v1,
)

_V0_SCHEMA = """
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    owasp_id TEXT NOT NULL,
    owasp_name TEXT NOT NULL,
    cwe TEXT,
    endpoint TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    confidence TEXT,
    evidence TEXT,
    created_at TEXT NOT NULL
);
"""


def _make_v0_db(path, rows):
    conn = sqlite3.connect(str(path))
    conn.executescript(_V0_SCHEMA)
    for r in rows:
        conn.execute(
            "INSERT INTO findings (title, severity, owasp_id, owasp_name, cwe, "
            "endpoint, description, recommendation, confidence, evidence, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            r,
        )
    conn.execute("PRAGMA user_version = 0")
    conn.commit()
    conn.close()


def _row(title, endpoint, evidence, created_at):
    return (
        title, "high", "API1:2023", "Broken Object Level Authorization",
        "CWE-639", endpoint, "desc", "fix", "firm",
        json.dumps(evidence), created_at,
    )


def test_migrates_legacy_db_nondestructively(tmp_path):
    db = tmp_path / "legacy.db"
    _make_v0_db(db, [
        _row("A", "/users/{id}", [{"url": "/users/2"}], "2026-01-01T00:00:00+00:00"),
        _row("B", "/accounts/{id}", [{"url": "/acc/1"}], "2026-01-02T00:00:00+00:00"),
    ])

    conn = sqlite3.connect(str(db))
    report = migrate_v0_to_v1(conn)
    conn.close()
    assert report["migrated"] is True
    assert report["backfilled"] == 2

    conn = sqlite3.connect(str(db))
    try:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == SCHEMA_VERSION
        cols = {r[1] for r in conn.execute("PRAGMA table_info(findings)")}
        assert {"run_id", "fingerprint", "first_seen_at", "last_seen_at"} <= cols
        runs = conn.execute("SELECT target, status FROM scan_runs").fetchall()
        assert len(runs) == 1
        assert runs[0][0] == "(imported)"
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
        fps = [r[0] for r in conn.execute("SELECT fingerprint FROM findings")]
        assert all(fps)
    finally:
        conn.close()


def test_migration_collapses_duplicates(tmp_path):
    db = tmp_path / "dupes.db"
    _make_v0_db(db, [
        _row("A", "/users/{id}", [{"url": "/users/2"}], "2026-01-01T00:00:00+00:00"),
        _row("A", "/users/{id}", [{"url": "/users/9"}], "2026-01-03T00:00:00+00:00"),
        _row("B", "/accounts/{id}", [{"url": "/acc/1"}], "2026-01-02T00:00:00+00:00"),
    ])

    conn = sqlite3.connect(str(db))
    report = migrate_v0_to_v1(conn)
    conn.close()
    assert report["merged_duplicates"] == 1

    conn = sqlite3.connect(str(db))
    try:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
        ev = conn.execute("SELECT evidence FROM findings WHERE title='A'").fetchone()[0]
        urls = {e.get("url") for e in json.loads(ev)}
        assert {"/users/2", "/users/9"} <= urls
    finally:
        conn.close()


def test_migration_idempotent(tmp_path):
    db = tmp_path / "idem.db"
    _make_v0_db(db, [
        _row("A", "/users/{id}", [{"url": "/users/2"}], "2026-01-01T00:00:00+00:00"),
    ])
    conn = sqlite3.connect(str(db))
    migrate_v0_to_v1(conn)
    conn.close()
    conn = sqlite3.connect(str(db))
    report2 = migrate_v0_to_v1(conn)
    conn.close()
    assert report2["migrated"] is False


def test_store_open_auto_migrates(tmp_path):
    db = tmp_path / "auto.db"
    _make_v0_db(db, [
        _row("A", "/users/{id}", [{"url": "/users/2"}], "2026-01-01T00:00:00+00:00"),
    ])
    with FindingsStore(db) as store:
        rows = store.all(all_runs=True)
        assert len(rows) == 1
        assert rows[0]["fingerprint"]
        assert len(store.runs()) == 1
