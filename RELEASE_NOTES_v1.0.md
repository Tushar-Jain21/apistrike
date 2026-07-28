# APIStrike v1.0.0 ⚔️

**APIStrike** is a modular, AI-assisted, fully open-source automated API
penetration-testing framework covering the **OWASP API Security Top 10 (2023)**.
Pure-Python core (cross-platform), deterministic evidence-based findings, local
AI advisory layer (Ollama), and Markdown / HTML / PDF reports — validated live in
CI against **VAmPI** and **crAPI**.

> For **authorized, defensive, and educational use only.** A required `scope.yaml`
> allowlist gates every request; anything outside scope is refused.

## Highlights
- **11 vulnerability modules** across the OWASP API Top 10 (2023) + Injection + GraphQL.
- **AI proposes, the engine confirms** — every reported finding is verified with a real request; AI never creates a finding.
- **Built-in OAST listener** for SSRF out-of-band detection (no paid infra).
- **Evidence is masked** — secrets/PII are redacted in findings and reports.
- **Reports** in Markdown, HTML, and PDF; findings stored in SQLite.
- **CI-validated** against VAmPI on every push; opt-in full-stack crAPI validation workflow.
- **Plugin API** — ship third-party modules as separate pip packages with zero core changes.

## Validated findings
- **VAmPI:** true positives across BOLA, mass assignment, SQLi, rate limiting, data exposure, misconfig, and inventory — zero false positives on clean/hardened endpoints.
- **crAPI:** 6 confirmed findings, including a **HIGH real `.env` credential leak** at `/.env` (Postgres + Mongo creds, content-verified true positive).

## Quick start
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp scope.example.yaml scope.yaml     # edit to list ONLY targets you are authorized to test
python -m apistrike scan http://localhost:5000 --scope scope.yaml -u name1 -p pass1
python -m apistrike report -f html   # or -f pdf
```
Or with Docker:
```bash
make build && make scan
```

## Tests
230 passing.

See `CHANGELOG.md` for the full component breakdown.
