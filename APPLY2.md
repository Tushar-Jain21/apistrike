# crAPI fixes, round 2 (phase-6-crapi-fixes-2)

Three things this patch does:

1. **inventory evidence now carries a redacted body snippet.**
   Every exposed-surface finding records `body[:180]: ...` alongside the
   `-> HTTP <status>` line. KEY=VALUE values are masked (`SECRET_KEY=su...`)
   so we never dump full secrets, but keys stay visible. This makes /.env
   self-adjudicating: the next run's findings.db will show WHAT crAPI serves
   at /.env (a real env file vs. a benign text/catch-all match).

2. **crapi.yml ssrf step fixed.** `ssrf` requires BOTH `--path` and `--param`;
   it now runs `ssrf "$BASE" --path / --param url --no-oast` (no OAST listener
   in CI; metadata + timing techniques still run). Clean negative result
   instead of `Missing option '--param'`.

## Files changed
- apistrike/modules/inventory.py   (+ `_evidence_snippet`, evidence enriched)
- .github/workflows/crapi.yml       (ssrf `--param url --no-oast`)
- tests/test_inventory_content.py   (+2 tests: snippet present, values masked)

## Apply
    unzip -o apistrike-phase6-crapi-fixes2.zip
    pytest -q
    git checkout -b phase-6-crapi-fixes-2
    git add apistrike/modules/inventory.py .github/workflows/crapi.yml tests/test_inventory_content.py APPLY2.md
    git commit -m "crAPI r2: self-adjudicating surface evidence + ssrf --param"
    git push -u origin phase-6-crapi-fixes-2
    gh pr create --fill --base main --head phase-6-crapi-fixes-2
    gh pr merge --squash --delete-branch
    git checkout main && git pull
    gh workflow run crapi.yml

## Still deferred to v1.1
- Authenticated SSRF against crAPI's real endpoint
  (`POST /workshop/api/merchant/contact_mechanic`, json param `mechanic_api`)
  needs `--login-field` propagated to the ssrf/bola/bfla commands (only `scan`
  has it today).
