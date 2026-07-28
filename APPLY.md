# APIStrike — crAPI validation fixes (phase-6-crapi-fixes)

Three fixes surfaced by the green crAPI validation run (30345989172):

## 1. Inventory `/.env` HIGH false positive  → FIXED (drop-in)
`apistrike/modules/inventory.py` now content-verifies sensitive dotfile/secret
surfaces before flagging. A catch-all/SPA server answering HTTP 200 with an
HTML page for `/.env`, `/.git/config`, `/actuator/env`, `/actuator`, or
`/phpinfo.php` is no longer reported. Genuine artifacts (KEY=VALUE, `[core]`,
etc.) still flag as before. All other surfaces (openapi/swagger/console/...)
are unchanged.
**Action:** overwrite your file with the one in this zip.

## 2. Configurable login field (crAPI wants `email`, not `username`)  → 2-line edit
`LoginConfig.username_field` already exists, so `scan` just needs to expose it.
Follow `docs/scan-login-field.md` to add `--login-field` to `scan()` in
`apistrike/cli.py` (default stays `username`; nothing else changes).

## 3. crAPI workflow corrections  → drop-in
`.github/workflows/crapi.yml`:
  - `ssrf` step now passes `--path /` (it has no default -> was erroring).
  - authenticated scan now passes `--login-field email`.

## New tests
`tests/test_inventory_content.py` — 8 tests covering the FP gating + login field.

## Verify locally
```bash
pytest -q
python -m apistrike inventory http://localhost:8888 --scope scope.crapi.yaml   # no /.env HIGH
```
