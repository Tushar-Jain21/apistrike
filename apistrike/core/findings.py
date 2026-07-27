"""SQLite-backed findings store for APIStrike.

Every vulnerability the engine confirms is persisted here as a Finding,
mapped to the OWASP API Security Top 10 (2023) and a CWE, and linked to the
raw request/response Evidence that proves it. The rule: AI advises, the engine
confirms, and confirmed findings are recorded here.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


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

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}; expected one of {SEVERITIES}"
            )
        if self.owasp_id not in OWASP_API_TOP_10:
            raise ValueError(f"Unknown OWASP id {self.owasp_id!r}")
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    @property
    def owasp_name(self) -> str:
        return OWASP_API_TOP_10[self.owasp_id]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
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


class FindingsStore:
    """Thin SQLite wrapper for persisting and querying Findings."""

    def __init__(self, path: str | Path = "findings.db"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add(self, finding: Finding) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO findings (
                title, severity, owasp_id, owasp_name, cwe, endpoint,
                description, recommendation, confidence, evidence, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.title,
                finding.severity,
                finding.owasp_id,
                finding.owasp_name,
                finding.cwe,
                finding.endpoint,
                finding.description,
                finding.recommendation,
                finding.confidence,
                json.dumps(finding.evidence, default=str),
                finding.created_at,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def all(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        return [self._row_to_dict(r) for r in rows]

    def by_severity(self, severity: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE severity = ? ORDER BY id", (severity,)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def summary(self) -> dict:
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        counts = {s: 0 for s in SEVERITIES}
        for r in rows:
            counts[r["severity"]] = r["n"]
        counts["total"] = sum(counts[s] for s in SEVERITIES)
        return counts

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
