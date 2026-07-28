# APIStrike ⚔️

[![CI](https://github.com/Tushar-Jain21/apistrike/actions/workflows/ci.yml/badge.svg)](https://github.com/Tushar-Jain21/apistrike/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Tushar-Jain21/apistrike?sort=semver)](https://github.com/Tushar-Jain21/apistrike/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-230%20passing-brightgreen.svg)](tests/)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%20(2023)-1f6feb.svg)](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/)

> A modular, AI-assisted, **fully open-source** automated **API penetration testing** framework covering the **OWASP API Security Top 10 (2023)**. Pure-Python core, deterministic evidence-based findings, a local-first AI advisory layer, and professional Markdown / HTML / PDF reports — validated live in CI against **VAmPI** and **crAPI**.

<table><tr><td>

⚠️ **Authorized use only.** Run APIStrike **only** against systems you own or are explicitly authorized to test (your own labs, in-scope bug-bounty programs that permit automation, or signed engagements). A required `scope.yaml` allowlist gates **every** request — anything out of scope is refused, and destructive tests stay behind an explicit `--active` flag. For authorized, defensive, and educational use only.

</td></tr></table>

---

## ✨ Why APIStrike

- **Full OWASP API Top 10 (2023) coverage** — dedicated, deterministic modules for API1–API5, API7–API9, plus Injection and GraphQL; API6/API10 are AI-assisted.
- **AI proposes, the engine confirms** — the AI layer only *plans, triages, and narrates*. Every reported finding is verified by a **real HTTP request**; AI never creates or mutates a finding.
- **No paid infrastructure** — ships its own built-in **OAST listener** for out-of-band SSRF detection (no Burp Collaborator / interactsh needed) and a **local Ollama** LLM (offline, private) with a graceful heuristic fallback.
- **Evidence is safe** — secrets, credentials, and PII are **masked/redacted** in findings and reports.
- **Reproducible & cross-platform** — pure-Python core (Linux / macOS / Windows-WSL2), a hardened Docker image, and a `Makefile` for one-command runs.
- **CI-validated** — every push runs the full test suite + a live VAmPI scan; an opt-in workflow stands up the entire crAPI stack.
- **Extensible** — a plugin API lets third parties ship modules as separate pip packages with zero core changes.

---

## 🧩 OWASP API Security Top 10 (2023) coverage

| OWASP ID | Risk | Command | Depth |
|---|---|---|---|
| API1:2023 | Broken Object Level Authorization (BOLA) | `bola` | Deep |
| API2:2023 | Broken Authentication | `scan -u -p` (broken-auth) | Deep |
| API3:2023 | Broken Object Property Level Auth (mass assignment) | `massassign` | Deep |
| API3:2023 | Excessive Data Exposure | `dataexpose` | Deep |
| API4:2023 | Unrestricted Resource Consumption | `ratelimit` | Deep |
| API5:2023 | Broken Function Level Authorization (BFLA) | `bfla` | Deep |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | `ai-plan` (advisory) | Partial + AI |
| API7:2023 | Server-Side Request Forgery (SSRF) | `ssrf` | Deep |
| API8:2023 | Security Misconfiguration | `misconfig` | Deep |
| API9:2023 | Improper Inventory Management | `inventory`, `crawl` | Deep |
| API10:2023 | Unsafe Consumption of APIs | `ai-plan` (advisory) | Partial + AI |
| — | Injection (SQLi / NoSQLi / OS-command) | `inject` | Deep |
| — | GraphQL (introspection / batching / …) | `graphql` | Deep |

---

## 🚀 Install

### From source (recommended for local runs)
```bash
git clone https://github.com/Tushar-Jain21/apistrike.git
cd apistrike
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m apistrike version
```
> **PDF reports** need WeasyPrint's native libs (Pango/Cairo/HarfBuzz/gdk-pixbuf). Markdown and HTML work everywhere; install the system libs only if you want PDF. See the `Dockerfile` for the exact package list.

### With Docker (identical runs anywhere)
```bash
make build          # build the image
make scan           # one-command scan (see Makefile for variables)
```

---

## ⚡ Quick start

```bash
# 1. Create an authorized-scope file and edit it to list ONLY targets you may test
python -m apistrike init-scope            # writes scope.yaml from scope.example.yaml

# 2. Run an authenticated scan against a lab (VAmPI on :5000)
python -m apistrike scan http://localhost:5000 --scope scope.yaml -u name1 -p pass1

# 3. Render a report from the findings database
python -m apistrike report -f html        # or -f pdf / -f md

# 4. (optional) AI-enriched report — exec summary, narratives, exploit chains
python -m apistrike ai-report -f html
```

Run a single module, e.g. improper-inventory / exposed surfaces:
```bash
python -m apistrike inventory http://localhost:5000 --scope scope.yaml
```

**crAPI** (identity field is `email`, gateway on `:8888`):
```bash
python -m apistrike scan http://localhost:8888 --scope scope.yaml \
  -u you@example.com -p 'Str1ke_P@ss' \
  --login-path /identity/api/auth/login --login-field email
```

👉 **Full command reference with examples: [docs/CHEATSHEET.md](docs/CHEATSHEET.md)**

---

## 📄 Reports

Findings are stored in a local SQLite DB (`findings.db`) with OWASP + CWE mapping, then rendered on demand:

- `report` — deterministic Markdown / HTML / PDF from the findings DB.
- `ai-report` — the same, plus an LLM-written executive summary, per-finding impact narratives, and detected exploit chains (falls back to templated text when no model is available).

Evidence values (secrets, tokens, passwords, PII) are always masked before they are written to a finding or report.

---

## 🤖 AI layer (model-agnostic, local-first)

- **Provider interface** — defaults to a local **Ollama** model (`--model`, `--ollama-url`); `NoOp`/heuristic fallback keeps every AI command usable offline.
- **AI Planner** (`ai-plan`) — ranks the riskiest endpoints from a parsed OpenAPI spec.
- **AI Analyst** — false-positive review + exploit chaining over confirmed findings.
- **AI Reporter** (`ai-report`) — executive summary, narratives, remediation.
- **Hard guardrail:** AI proposes → the deterministic engine fires the real request → only confirmed results are reported.

---

## 🧪 Testing, CI & labs

- **230 tests** (`pytest`).
- **`.github/workflows/ci.yml`** — on every push/PR: full test suite, a real Docker image build + entrypoint smoke, and a **live scan against VAmPI** (`erev0s/vampi`) that uploads `report.html`/`report.pdf` + `findings.db` as an artifact.
- **`.github/workflows/crapi.yml`** — opt-in (manual dispatch + weekly cron): stands up the full crAPI stack, seeds a user, runs the unauthenticated sweep + an authenticated scan, and uploads the reports + findings DB.

Validation highlights: on crAPI, APIStrike confirmed a **real HIGH `.env` credential leak** (Postgres + Mongo creds) at `/.env` — a content-verified true positive — with zero false positives from the SSRF/GraphQL/data-exposure checks.

---

## 🔌 Plugin API

Ship your own module as a separate pip package — no core changes:

```bash
python -m apistrike run-module --list                       # list built-in + plugin modules
python -m apistrike run-module misconfig http://localhost:5000 --scope scope.yaml
python -m apistrike run-module my-module http://localhost:5000 -o key=value -o foo=bar
```

Register via the `apistrike.modules` entry-point group (see `CONTRIBUTING.md`).

---

## 📁 Project structure

```text
apistrike/
├─ apistrike/          # package: cli.py, core/, recon/, auth/, modules/, ai/, reporting/, plugins/
├─ tests/             # pytest suite (230 tests)
├─ labs/              # docker-compose for crAPI / VAmPI
├─ scripts/           # crAPI seed/scope helpers, SecLists fetch
├─ docs/              # CHEATSHEET.md and design notes
├─ .github/workflows/ # ci.yml, crapi.yml
├─ scope.example.yaml # authorized-targets template
├─ Dockerfile  Makefile  requirements.txt
└─ README.md  CHANGELOG.md  CONTRIBUTING.md  LICENSE
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small, frequent commits; add tests with each module; keep `main` green.

## 🔒 Ethics & scope

APIStrike is a defensive/educational tool. The mandatory `scope.yaml` allowlist gates every request, destructive verbs require `--active`, and the tool refuses anything outside the hosts you explicitly authorize. **You are responsible for having permission to test your targets.**

## 📜 License

[MIT](LICENSE) © Tushar Jain
