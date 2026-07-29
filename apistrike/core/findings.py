"""SQLite-backed findings store for APIStrike.

Every vulnerability the engine confirms is persisted here as a Finding,
mapped to the OWASP API Security Top 10 (2023) and a CWE, and linked to the
raw request/response Evidence that proves it. The rule: AI advises, the engine
confirms, and confirmed findings are recorded here.

v1.2 adds durable *scan-run identity* and a stable per-finding *fingerprint*:

- Every finding belongs to a ``scan_run`` (target, tool version, scope, timing),
  so a saved ``findings.db`` records *what* was scanned, *when*, and under *what*
  version/scope -- not just an anonymous pile of rows.
- ``fingerprint`` = ``sha256(owasp_id | endpoint | title | key)`` gives "the same
  vulnerability" a stable identity across runs. It uses the *templated* endpoint
  the modules already emit (``/users/{id}``) and deliberately excludes volatile
  evidence, so re-scanning dedups instead of duplicating, and a future diff can
  tell new/fixed/regressed apart.
- The database is versioned with ``PRAGMA user_version``. Legacy (v0) databases
  are migrated in place -- non-destructively, transactionally, idempotently --
  the first time they are opened.

Backward compatibility: ``add()`` keeps its one-argument signature. If no run is
active it lazily opens a default run, so existing callers keep working while the
CLI gains explicit ``begin_run()`` / ``finish_run()`` wiring in a later change.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Schema version stored in the database via ``PRAGMA user_version``.
SCHEMA_VERSION = 1

# OWASP API Security Top 10 (2023) -- canonical id -> human label.
OWASP_API_TOP_10 = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_version() -> str:
    """Best-effort read of the running APIStrike version (no hard dependency)."""
    try:
        from apistrike import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - defensive
        return "unknown"


def compute_fingerprint(owasp_id: str, endpoint: str, title: str, key: str = "") -> str:
    """Deterministic identity for a logical finding.

    Stable for "the same vulnerability" across runs, distinct for genuinely
    different issues. Uses the templated endpoint (modules already emit
    ``/users/{id}``) and excludes volatile evidence (timestamps, tokens,
    concrete ids). ``key`` is an optional discriminator (e.g. the vulnerable
    parameter) so two distinct issues on one endpoint don't collide.
    """
    raw = f"{owasp_id}|{endpoint}|{title}|{key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    title: str
    severity: str
    owasp_id: str
    endpoint: str
    description: str = ""
    cwe: str = ""
    recommendation: str = ""
    confidence: str = "firm"  # tentative | firm | confirmed
    evidence: list = field(default_factory=list)  # list of Evidence-like dicts
    created_at: str = ""
    key: str = ""  # optional discriminator for fingerprinting (e.g. param name)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}; expected one of {SEVERITIES}"
            )
        if self.owasp_id not in OWASP_API_TOP_10:
            raise ValueError(f"Unknown OWASP id {self.owasp_id!r}")
        if not self.created_at:
            self.created_at = _utcnow()

    @property
    def owasp_name(self) -> str:
        return OWASP_API_TOP_10[self.owasp_id]

    @property
    def fingerprint(self) -> str:
        return compute_fingerprint(self.owasp_id, self.endpoint, self.title, self.key)


# --- schema (v1) -----------------------------------------------------------

_RUNS_DDL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id        TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    tool_version  TEXT NOT NULL,
    command       TEXT,
    modules       TEXT,
    scope_summary TEXT,
    status        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT
)
"""

_FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT,
    fingerprint    TEXT,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    owasp_id       TEXT NOT NULL,
    owasp_name     TEXT NOT NULL,
    cwe            TEXT,
    endpoint       TEXT NOT NULL,
    description    TEXT,
    recommendation TEXT,
    confidence     TEXT,
    evidence       TEXT,
    created_at     TEXT NOT NULL,
    first_seen_at  TEXT,
    last_seen_at   TEXT
)
"""

_INDEX_DDL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_run_fp ON findings(run_id, fingerprint)",
    "CREATE INDEX IF NOT EXISTS ix_findings_fp ON findings(fingerprint)",
    "CREATE INDEX IF NOT EXISTS ix_findings_run ON findings(run_id)",
)

_FINDING_COLUMNS_V1 = (
    ("run_id", "ALTER TABLE findings ADD COLUMN run_id TEXT"),
    ("fingerprint", "ALTER TABLE findings ADD COLUMN fingerprint TEXT"),
    ("first_seen_at", "ALTER TABLE findings ADD COLUMN first_seen_at TEXT"),
    ("last_seen_at", "ALTER TABLE findings ADD COLUMN last_seen_at TEXT"),
)

_LEGACY_RUN_ID = "legacy-import"


def _load_evidence(raw) -> list:
    if not raw:
        return []
    try:
        v = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return v if isinstance(v, list) else [v]


def _merge_evidence_json(old_raw, new_raw) -> str:
    merged = _load_evidence(old_raw) + _load_evidence(new_raw)
    seen = set()
    out = []
    for e in merged:
        marker = json.dumps(e, sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            out.append(e)
    return json.dumps(out, default=str)


def _user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate_v0_to_v1(conn: sqlite3.Connection) -> dict:
    """Migrate a legacy (schema v0) findings database to v1, in place.

    Non-destructive, transactional, idempotent. Returns a small report:
    ``{"migrated": bool, "backfilled": int, "merged_duplicates": int}``.
    """
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None  # explicit transaction control below
    if _user_version(conn) >= SCHEMA_VERSION:
        return {"migrated": False, "backfilled": 0, "merged_duplicates": 0}

    existing_cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    backfilled = 0
    merged = 0

    conn.execute("BEGIN")
    try:
        conn.execute(_RUNS_DDL)
        for col, ddl in _FINDING_COLUMNS_V1:
            if col not in existing_cols:
                conn.execute(ddl)

        orphans = conn.execute(
            "SELECT id, owasp_id, endpoint, title, created_at, evidence "
            "FROM findings WHERE run_id IS NULL ORDER BY id"
        ).fetchall()

        if orphans:
            min_created = (
                conn.execute("SELECT MIN(created_at) AS m FROM findings").fetchone()["m"]
                or _utcnow()
            )
            conn.execute(
                "INSERT OR IGNORE INTO scan_runs "
                "(run_id, target, tool_version, command, modules, scope_summary, "
                " status, started_at, finished_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    _LEGACY_RUN_ID,
                    "(imported)",
                    _tool_version(),
                    "(legacy import)",
                    None,
                    None,
                    "completed",
                    min_created,
                    _utcnow(),
                ),
            )

            keeper_by_fp = {}
            for row in orphans:
                fp = compute_fingerprint(
                    row["owasp_id"], row["endpoint"], row["title"], ""
                )
                created = row["created_at"] or min_created
                if fp in keeper_by_fp:
                    keeper_id = keeper_by_fp[fp]
                    keep_ev = conn.execute(
                        "SELECT evidence FROM findings WHERE id = ?", (keeper_id,)
                    ).fetchone()["evidence"]
                    conn.execute(
                        "UPDATE findings SET evidence = ?, last_seen_at = ? WHERE id = ?",
                        (_merge_evidence_json(keep_ev, row["evidence"]), created, keeper_id),
                    )
                    conn.execute("DELETE FROM findings WHERE id = ?", (row["id"],))
                    merged += 1
                else:
                    conn.execute(
                        "UPDATE findings SET run_id = ?, fingerprint = ?, "
                        "first_seen_at = ?, last_seen_at = ? WHERE id = ?",
                        (_LEGACY_RUN_ID, fp, created, created, row["id"]),
                    )
                    keeper_by_fp[fp] = row["id"]
                    backfilled += 1

        for stmt in _INDEX_DDL:
            conn.execute(stmt)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    return {"migrated": True, "backfilled": backfilled, "merged_duplicates": merged}


class FindingsStore:
    """SQLite wrapper: persists Findings, scoped to durable scan runs."""

    def __init__(self, path: str | Path = "findings.db"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.isolation_level = None  # autocommit; explicit tx where needed
        self._active_run = None
        self._init_schema()

    # -- schema / migration ------------------------------------------------

    def _init_schema(self) -> None:
        have_findings = (
            self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings'"
            ).fetchone()
            is not None
        )

        if not have_findings:
            self._conn.execute(_RUNS_DDL)
            self._conn.execute(_FINDINGS_DDL)
            for stmt in _INDEX_DDL:
                self._conn.execute(stmt)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            return

        if _user_version(self._conn) < SCHEMA_VERSION:
            migrate_v0_to_v1(self._conn)

        # Ensure runs table + indexes exist even on already-migrated DBs.
        self._conn.execute(_RUNS_DDL)
        for stmt in _INDEX_DDL:
            self._conn.execute(stmt)

    # -- run lifecycle -----------------------------------------------------

    def begin_run(self, target: str, command: str | None = None,
                  modules=None, scope_summary=None) -> str:
        run_id = uuid.uuid4().hex
        self._conn.execute(
            "INSERT INTO scan_runs "
            "(run_id, target, tool_version, command, modules, scope_summary, "
            " status, started_at, finished_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                target,
                _tool_version(),
                command,
                json.dumps(modules) if modules is not None else None,
                json.dumps(scope_summary) if scope_summary is not None else None,
                "running",
                _utcnow(),
                None,
            ),
        )
        self._active_run = run_id
        return run_id

    def finish_run(self, status: str = "completed", run_id: str | None = None) -> None:
        rid = run_id or self._active_run
        if rid is None:
            return
        self._conn.execute(
            "UPDATE scan_runs SET status = ?, finished_at = ? WHERE run_id = ?",
            (status, _utcnow(), rid),
        )
        if rid == self._active_run:
            self._active_run = None

    def _ensure_active_run(self) -> str:
        if self._active_run is None:
            self._active_run = self.begin_run(target="(default)", command="(implicit)")
        return self._active_run

    # -- writes ------------------------------------------------------------

    def add(self, finding: Finding) -> int:
        run_id = self._ensure_active_run()
        fp = finding.fingerprint
        now = finding.created_at or _utcnow()
        evidence_json = json.dumps(finding.evidence, default=str)

        existing = self._conn.execute(
            "SELECT id, evidence FROM findings WHERE run_id = ? AND fingerprint = ?",
            (run_id, fp),
        ).fetchone()
        if existing is not None:
            self._conn.execute(
                "UPDATE findings SET evidence = ?, last_seen_at = ? WHERE id = ?",
                (
                    _merge_evidence_json(existing["evidence"], evidence_json),
                    now,
                    existing["id"],
                ),
            )
            return int(existing["id"])

        cur = self._conn.execute(
            """
            INSERT INTO findings (
                run_id, fingerprint, title, severity, owasp_id, owasp_name, cwe,
                endpoint, description, recommendation, confidence, evidence,
                created_at, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                fp,
                finding.title,
                finding.severity,
                finding.owasp_id,
                finding.owasp_name,
                finding.cwe,
                finding.endpoint,
                finding.description,
                finding.recommendation,
                finding.confidence,
                evidence_json,
                finding.created_at,
                now,
                now,
            ),
        )
        return int(cur.lastrowid)

    # -- run resolution ----------------------------------------------------

    def latest_run(self) -> dict | None:
        r = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return dict(r) if r else None

    def get_run(self, run_id: str) -> dict | None:
        r = self._conn.execute(
            "SELECT * FROM scan_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return dict(r) if r else None

    def runs(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY started_at DESC, rowid DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def _resolve_run_id(self, run_id: str | None) -> str | None:
        if run_id is not None:
            return run_id
        latest = self.latest_run()
        return latest["run_id"] if latest else None

    # -- queries -----------------------------------------------------------

    def all(self, run_id: str | None = None, all_runs: bool = False) -> list[dict]:
        if all_runs:
            rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
            return [self._row_to_dict(r) for r in rows]
        rid = self._resolve_run_id(run_id)
        if rid is None:
            return []
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY id", (rid,)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def by_severity(self, severity: str, run_id: str | None = None,
                    all_runs: bool = False) -> list[dict]:
        if all_runs:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY id", (severity,)
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        rid = self._resolve_run_id(run_id)
        if rid is None:
            return []
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE severity = ? AND run_id = ? ORDER BY id",
            (severity, rid),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def summary(self, run_id: str | None = None, all_runs: bool = False) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        if all_runs:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            ).fetchall()
        else:
            rid = self._resolve_run_id(run_id)
            if rid is None:
                counts["total"] = 0
                return counts
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings "
                "WHERE run_id = ? GROUP BY severity",
                (rid,),
            ).fetchall()
        for r in rows:
            if r["severity"] in counts:
                counts[r["severity"]] = r["n"]
        counts["total"] = sum(counts[s] for s in SEVERITIES)
        return counts

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        if d.get("evidence"):
            try:
                d["evidence"] = json.loads(d["evidence"])
            except (ValueError, TypeError):
                d["evidence"] = []
        return d

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "FindingsStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
