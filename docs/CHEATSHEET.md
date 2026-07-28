# APIStrike Cheatsheet ⚔️

Every command, its key flags, and a copy-paste example. Targets in examples use the
local labs **VAmPI** (`http://localhost:5000`) and **crAPI** (`http://localhost:8888`).

> **Golden rules**
> - Every command needs `--scope scope.yaml`, and the target host must be allow-listed in it.
> - Create one first: `python -m apistrike init-scope` then edit `scope.yaml`.
> - Auth-capable modules take `-u/-p` and `--login-path`; `scan` also takes `--login-field` (use `email` for crAPI).
> - Destructive probes stay behind `--active` (only `crawl` and `bfla`). Everything else is read-only by default.
> - `alias apistrike='python -m apistrike'` to shorten the examples below.

---

## Utility

### `version` — print the version
```bash
python -m apistrike version
```

### `init-scope` — create a scope file
```bash
python -m apistrike init-scope                 # -> scope.yaml
python -m apistrike init-scope --path lab.yaml --force
```
`--path` (default `scope.yaml`) · `--example` (default `scope.example.yaml`) · `--force`

### `recon` — parse a spec, list endpoints (read-only)
```bash
python -m apistrike recon http://localhost:5000/openapi.json
```

### `login` — authenticate, show token + decoded JWT (read-only)
```bash
python -m apistrike login http://localhost:5000 -u name1 -p pass1 --scope scope.yaml
```
Required: `-u/--username`, `-p/--password` · `--login-path` (default `/users/v1/login`)

---

## Orchestration & reporting

### `scan` — validate scope, run broken-auth (API2:2023) when creds are given
```bash
# VAmPI
python -m apistrike scan http://localhost:5000 --scope scope.yaml -u name1 -p pass1
# crAPI (identity field is 'email')
python -m apistrike scan http://localhost:8888 --scope scope.yaml \
  -u you@example.com -p 'Str1ke_P@ss' \
  --login-path /identity/api/auth/login --login-field email
```
`-u/-p` · `--login-path` (def `/users/v1/login`) · `--login-field` (def `username`) · `--probe-path` (def `/me`)

### `report` — render the findings DB (Markdown / HTML / PDF)
```bash
python -m apistrike report -f html
python -m apistrike report -f pdf --output reports/vampi.pdf --target "VAmPI lab"
```
`-f/--format` md|html|pdf (def md) · `--output` (def `reports/report.md`) · `--target`

### `ai-report` — AI exec summary + narratives + exploit chains
```bash
python -m apistrike ai-report -f html --model llama3.2:3b
```
`-f/--format` · `--output` (def `reports/ai_report.md`) · `--model` (def `llama3`) · `--ollama-url` (def `http://localhost:11434`)

### `ai-plan` — rank the top-5 riskiest endpoints from a spec
```bash
python -m apistrike ai-plan http://localhost:5000/openapi.json --model llama3.2:3b
```
`--target` · `--model` · `--ollama-url`  (heuristic fallback when no model is reachable)

---

## Recon (API9:2023)

### `crawl` — shadow endpoints, methods, hidden params
```bash
python -m apistrike crawl http://localhost:5000 --scope scope.yaml \
  --spec http://localhost:5000/openapi.json -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```
`--spec` · `-w/--wordlist` · `--param-wordlist` · `--active` (state-changing verbs, **authorized only**) · `--no-params` · `--no-methods`

### `inventory` — undocumented versions + exposed surfaces
```bash
python -m apistrike inventory http://localhost:8888 --scope scope.yaml
python -m apistrike inventory http://localhost:5000 --scope scope.yaml \
  --paths /users/v1/users --max-version 4 --extra-surfaces /backup,/config.json
```
`--paths` · `--max-version` (def 4) · `--checks` versions,surfaces · `--extra-surfaces` · `-u/-p` · `--login-path`

---

## OWASP attack modules

### `bola` — API1:2023 Broken Object Level Authorization
Needs **two** identities to diff cross-user access.
```bash
python -m apistrike bola http://localhost:5000 --scope scope.yaml \
  -u name1 -p pass1 -U name2 -P pass2 \
  --object-template '/users/v1/{username}' --enum 5
```
Required: `-u/-p` (identity 1), `-U/-P` (identity 2) · `--object-template` (def `/users/v1/{username}`) · `--enum N` (numeric-id neighbours) · `--no-unauth` · `--login-path`

### `massassign` — API3:2023 Mass assignment / BOPLA
Smuggles privileged props into a create request, confirms via read-back.
```bash
python -m apistrike massassign http://localhost:5000 --scope scope.yaml \
  --create-path /users/v1/register --props admin \
  --readback-path /users/v1/_debug --id-field username
```
`--create-path` · `--base` (JSON of legit fields) · `--id-field` · `--create-method` · `--create-location` json|query · `--readback-path` · `--readback-location` none|path · `--props` (csv or JSON) · `-u/-p`

### `dataexpose` — API3:2023 Excessive data exposure
```bash
python -m apistrike dataexpose http://localhost:5000 --scope scope.yaml \
  --paths /users/v1/_debug,/me --checks secrets,fields,pii,entropy
```
`--paths` (def `/`) · `--method` · `--checks` secrets,fields,pii,entropy · `--entropy-threshold` (def 4.0) · `--entropy-min-len` (def 24) · `-u/-p`

### `ratelimit` — API4:2023 Unrestricted resource consumption
```bash
python -m apistrike ratelimit http://localhost:5000 --scope scope.yaml \
  --paths /users/v1 --burst 25 --checks burst,pagination
```
`--paths` · `--method` · `--checks` burst,pagination · `--burst` (def 25, capped by scope `max_requests`) · `--large-value` (def 1000) · `--min-items` (def 50) · `-u/-p`

### `bfla` — API5:2023 Broken Function Level Authorization
```bash
python -m apistrike bfla http://localhost:5000 --scope scope.yaml \
  -u name1 -p pass1 --admin-user admin -p adminpass \
  --ops 'GET /users/v1/_debug; DELETE /users/v1/name2'
```
Required: `-u/-p` (low-priv) · `--admin-user`/`--admin-pass` (optional baseline) · `--ops` ('METHOD /path' list, `;`-separated; def `GET /users/v1/_debug`) · `--active` (destructive verbs) · `--no-unauth`

### `ssrf` — API7:2023 Server-Side Request Forgery
Built-in OAST listener + metadata + timing. Requires `--path` **and** `--param`.
```bash
# Prove the OAST loop locally (no target needed)
python -m apistrike ssrf http://localhost:5000 --scope scope.yaml --selftest
# Query-param SSRF probe
python -m apistrike ssrf http://localhost:5000 --scope scope.yaml \
  --path /import --param url --location query
# JSON-body SSRF against an authenticated endpoint, no OAST (CI-friendly)
python -m apistrike ssrf http://localhost:8888 --scope scope.yaml \
  --path /workshop/api/merchant/contact_mechanic --param mechanic_api \
  --location json --method POST --no-oast
```
Required: `--path`, `--param` · `--location` query|json|path · `--method` · `--benign` · `--techniques` oast,metadata,timing · `--no-oast` · `--oast-host/--oast-port/--oast-public/--oast-wait-ms` · `--threshold-ms` (def 3000) · `--selftest` · `-u/-p`

### `misconfig` — API8:2023 Security misconfiguration
```bash
python -m apistrike misconfig http://localhost:5000 --scope scope.yaml \
  --checks headers,cors,errors,methods,banner
```
`--path` (def `/`) · `--checks` headers,cors,errors,methods,banner · `--evil-origin` · `-u/-p`

### `inject` — Injection (SQLi / NoSQLi / OS-command)
Requires `--path` **and** `--param`. For path injection, put an `INJECT` marker in `--path`.
```bash
# Path-segment SQLi (classic raw-SQL param)
python -m apistrike inject http://localhost:5000 --scope scope.yaml \
  --path /users/v1/INJECT --param username --location path --benign name1
# JSON-body NoSQL operator injection
python -m apistrike inject http://localhost:5000 --scope scope.yaml \
  --path /users/v1/login --param password --location json \
  --techniques nosql,error
```
Required: `--path`, `--param` · `--location` query|json|path · `--method` · `--benign` · `--techniques` error,boolean,time_sql,time_cmd,nosql · `--delay` (def 3) · `--threshold-ms` (def 2500) · `-u/-p`

### `graphql` — GraphQL security checks
```bash
python -m apistrike graphql http://localhost:5013 --scope scope.yaml \
  --endpoint /graphql --checks introspection,suggestions,batching,get_mutation
```
`--endpoint` (def `/graphql`) · `--checks` introspection,suggestions,batching,get_mutation · `-u/-p`

---

## Plugins

### `run-module` — run any registered module (built-in or plugin)
```bash
python -m apistrike run-module --list
python -m apistrike run-module misconfig http://localhost:5000 --scope scope.yaml -o path=/
```
`--list` · `--path` (def `/`) · `-o/--option key=value` (repeatable) · `-u/-p` · `--login-path`

---

## Typical end-to-end run

```bash
python -m apistrike init-scope                                   # 1. authorize targets
$EDITOR scope.yaml                                               #    add localhost:5000
python -m apistrike scan     http://localhost:5000 --scope scope.yaml -u name1 -p pass1
python -m apistrike bola     http://localhost:5000 --scope scope.yaml -u name1 -p pass1 -U name2 -P pass2
python -m apistrike inventory http://localhost:5000 --scope scope.yaml
python -m apistrike dataexpose http://localhost:5000 --scope scope.yaml --paths /users/v1/_debug
python -m apistrike report    -f html                            # deterministic report
python -m apistrike ai-report -f html                            # AI-enriched report
```
All findings accumulate in `findings.db`; both report commands render whatever is in it.
