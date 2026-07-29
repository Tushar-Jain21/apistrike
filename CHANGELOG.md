# Changelog

All notable changes to **APIStrike** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] -- 2026-07-29

### Added
- `apistrike.core.normalize_target()` + CLI target normalization: a scheme-less host (e.g. `api.example.com`) is now auto-prefixed with `https://` instead of being silently refused. Targets with an explicit scheme are untouched, so `http://host` still forces plaintext HTTP.

### Notes
- `Scope` stays strict; normalization happens only at the CLI/adapter layer.
- Audited for `asyncio.get_event_loop()` portability (targeted for this milestone) and found none -- all async entry points already use `asyncio.run()` and the SSRF OAST listener is thread-based. No change needed.

## [1.1.0] -- 2026-07-29

### Added
- Packaging via `pyproject.toml` (hatchling): APIStrike is now installable with `pip install -e .` and ships a real `apistrike` console command.
- `apistrike.__version__` is now the single source of truth for the version.

### Changed
- The CLI version string now reads from `apistrike.__version__` instead of a hardcoded literal, removing the version-drift class of bug.

## [1.0.1] — 2026-07-29

Bug-fix release hardening the deterministic scanners against false positives,
verified live against a real production target.

### Fixed
- **Excessive Data Exposure (API3) — entropy false positives.**
  - Inline SVG path/points data, data-URIs, and asset filenames are stripped before the entropy scan, so markup noise (e.g. `1759740674untitleddesign`) is no longer flagged as a secret.
  - URL paths and slugs such as `/upload_images/1759482020` are no longer flagged: candidate tokens are split on `/`, `_`, and `-`, and must contain a random letter+digit segment (>= 8 chars). Genuine secrets — including base64 tokens containing `/` — are still detected.
- **Improper Inventory (API9) — `.git`/`.env` false positives.** Static leak surfaces (`/.env`, `/.git/config`) are confirmed by content signature; a `403`/blocked response is now reported as *not exposed* instead of raising a finding.

### Added
- Regression tests covering the SVG/filename, URL-path/slug, and `.git`/`.env` cases.

### Changed
- Fixed the in-code `__version__` (was `0.1.0`) to track the released version.

### Validation
- Live static site (LiteSpeed): `inventory` 0 findings (`/.git/config` 403 correctly skipped), `dataexpose` reports only a benign public email, `misconfig` reports only missing security headers — zero false positives.

## [1.0.0] — 2026-07-28

First stable release. A modular, AI-assisted, fully open-source automated API
penetration-testing framework covering the OWASP API Security Top 10 (2023),
validated live against **VAmPI** and **crAPI** in CI.

### Core engine
- Scope loader (`scope.yaml`): allowed-hosts allowlist, rate caps, safe mode — gates every request.
- Async HTTP client wrapper (httpx) with a scope-enforcing `ScopedHTTPClient`.
- SQLite findings store with OWASP + CWE mapping.
- Typer CLI with a command per module.
- Markdown / HTML / PDF reporting (Jinja2 + WeasyPrint).

### Recon & auth
- OpenAPI 3.x / Swagger 2.0 parser (URL or file, JSON or YAML).
- Active crawler: soft-404 calibration, shadow/undocumented-endpoint discovery, method enumeration, param fuzzing.
- Multi-identity auth engine (Bearer / JWT / API key) with scope-gated login and JWT decode.

### Vulnerability modules (OWASP API Security Top 10 — 2023)
- **API1 BOLA** — multi-user token diffing, unauth read, opt-in id enumeration, body-match confirmation.
- **API2 Broken Auth** — JWT `alg:none`, weak-secret, and expiry tampering (stdlib-only crypto).
- **API3 Mass Assignment** — privileged-property smuggling with control-object read-back confirmation.
- **API3 Excessive Data Exposure** — secrets / sensitive-field / PII (Luhn-checked) / entropy scan, all evidence masked.
- **API4 Resource Consumption** — bounded burst + pagination abuse, capped by scope `max_requests`.
- **API5 BFLA** — role-based access matrix with optional admin baseline; destructive verbs behind `--active`.
- **API7 SSRF** — built-in stdlib OAST listener + metadata/internal-reachability/timing techniques.
- **API8 Misconfiguration** — security headers, permissive CORS, verbose errors, HTTP TRACE, version banners.
- **API9 Improper Inventory** — version/zombie discovery + ~25 curated exposed-surface probes with content-signature verification.
- **GraphQL** — introspection, field-suggestion leakage, query batching, GET-based mutations.
- **Injection** — error/boolean/time-based SQLi, OS-command, and NoSQL operator injection across query/body/path.

### AI layer (model-agnostic, local-first)
- Pluggable `AIProvider` (Ollama default, NoOp + Mock) with daemon/model state detection.
- AI Planner (spec-driven strategy + heuristic fallback), AI Analyst (false-positive review + exploit chaining), AI Reporter (exec summary + remediation).
- Hard guardrail: AI proposes, the deterministic engine confirms every finding with a real request; AI never creates or mutates a finding.

### Release engineering
- Dockerfile (non-root, WeasyPrint native libs) + Makefile one-command runs.
- GitHub Actions CI: full pytest suite, Buildx image build + entrypoint smoke, and a live VAmPI lab scan uploading reports + `findings.db`.
- Opt-in crAPI validation workflow (weekly cron + manual dispatch) standing up the full crAPI stack.
- Plugin API (`apistrike/plugins/`) with entry-point discovery + `run-module` command; `CONTRIBUTING.md`; SecLists fetch script.

### Validation highlights
- **VAmPI:** confirmed true positives across BOLA, mass assignment, SQLi, rate limiting, data exposure, misconfig, and inventory — with zero false positives on hardened/clean endpoints.
- **crAPI:** 6 confirmed findings including a **HIGH real `.env` exposure** leaking Postgres + Mongo credentials at `/.env` (content-verified true positive); ssrf/graphql/dataexpose correctly returned no false positives.

### Tests
- 230 passing tests.

[1.1.1]: https://github.com/Tushar-Jain21/apistrike/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Tushar-Jain21/apistrike/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/Tushar-Jain21/apistrike/releases/tag/v1.0.1
[1.0.0]: https://github.com/Tushar-Jain21/apistrike/releases/tag/v1.0.0
