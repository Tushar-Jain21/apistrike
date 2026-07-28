# crAPI full validation (false-positive tuning)

This is the last engineering item before **v1.0**: run APIStrike end-to-end
against [OWASP crAPI](https://github.com/OWASP/crAPI) — a deliberately
vulnerable, realistic API stack — and use the results to tune false positives.

crAPI is a ~7-container Docker Compose stack (identity, community, workshop,
Mongo, Postgres, MailHog, gateway) that needs ~4 GB RAM. It is **not** wired
into the per-PR CI (`ci.yml`) so normal merges stay fast. Instead it lives in a
dedicated, opt-in workflow.

## How to run it

### In CI (recommended — the box has no local Docker daemon)

1. Push `.github/workflows/crapi.yml` (plus the two helper scripts).
2. GitHub -> **Actions** -> **crAPI validation** -> **Run workflow**.
3. It also runs automatically every Monday 03:00 UTC.
4. When it finishes, download the **`apistrike-crapi-validation`** artifact:
   `report.html` / `report.pdf`, `ai_report.html`, `findings.db`, the patched
   `scope.crapi.yaml`, `crapi_seed.out`, and `crapi-compose.log`.

### Locally (only if you have Docker + Compose)

```bash
git clone --depth 1 https://github.com/OWASP/crAPI.git ../crapi
( cd ../crapi/deploy/docker && docker compose up -d )   # wait ~2-3 min

python -m apistrike init-scope --path scope.crapi.yaml --force
python scripts/crapi_patch_scope.py scope.crapi.yaml
python scripts/crapi_seed.py | tee crapi_seed.out

BASE=http://localhost:8888
python -m apistrike misconfig  "$BASE" --scope scope.crapi.yaml
python -m apistrike inventory  "$BASE" --scope scope.crapi.yaml
python -m apistrike scan       "$BASE" --scope scope.crapi.yaml \
    -u "$(sed -n 's/^EMAIL=//p' crapi_seed.out)" \
    -p "$(sed -n 's/^PASSWORD=//p' crapi_seed.out)" \
    --login-path /identity/api/auth/login
python -m apistrike report -f html
```

## What the workflow does

1. **Stands up crAPI** from the official repo, waits for the gateway on `:8888`.
2. **Scopes it** — `init-scope` generates a scope file, then
   `crapi_patch_scope.py` injects the crAPI hosts and forces `safe_mode`.
3. **Seeds a throwaway user** — `crapi_seed.py` signs up + logs in via
   `/identity/api/auth/*` and prints `EMAIL` / `PASSWORD` / `TOKEN`.
4. **Unauthenticated sweep** — misconfig, inventory, crawl, ratelimit,
   dataexpose, ssrf, graphql (each non-fatal so one failure never sinks the run).
5. **Authenticated scan** — `scan` with the seeded creds against
   `/identity/api/auth/login`.
6. **Renders** HTML + PDF + AI reports and **uploads** everything as an artifact.
7. **Tears down** the stack (`docker compose down -v`).

## Known tuning points (expected on first run)

These are the spots most likely to need a small change after the first CI log:

- **Scope schema.** `crapi_patch_scope.py` is schema-tolerant, but if
  `init-scope` uses a host key it doesn't recognize it prints a loud `NOTE:` and
  falls back to `allowed_hosts`. Check the "generated scope schema" log block and
  adjust `HOST_KEYS` if needed.
- **Login response shape.** `scan`'s auth engine must find the bearer token in
  crAPI's login JSON. `crapi_seed.py` logs the raw login body; if the token
  field isn't `token`/`access_token`, we tune the auth engine's parser.
- **crAPI's known vulns are mostly authenticated + BOLA/JWT/mass-assignment**
  (e.g. reading another user's vehicle by ID, `/workshop/api/mechanic`,
  coupon mass-assignment). Once auth is confirmed working, expand the
  authenticated pass to explicitly target those endpoints with `bola`,
  `broken-auth`, and `massassign`.
- **Expect real findings here** (unlike VAmPI's hardened surface). This is where
  we measure and dial down false positives before tagging v1.0.
