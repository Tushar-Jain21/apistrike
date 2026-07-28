# Contributing to APIStrike

Thanks for helping build APIStrike — a modular, AI-assisted, fully open-source
API penetration-testing framework. This guide covers local setup, the module
plugin API, and the conventions we follow.

> **Ethics first.** APIStrike is for **authorized, defensive, and educational**
> use only. Every request is gated by a required `scope.yaml` allowlist. Only
> ever run it against systems you own or are explicitly authorized to test.

## Development setup

```bash
git clone https://github.com/Tushar-Jain21/apistrike.git
cd apistrike
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install pytest
```

Run the test suite:

```bash
pytest -q
```

Spin up a local lab (VAmPI) to test against:

```bash
# native (no Docker needed)
git clone https://github.com/erev0s/VAmPI && cd VAmPI
uv run python app.py            # serves http://localhost:5000
# ...or via the bundled labs/docker-compose.yml where Docker is available
```

## Project layout

```
apistrike/
  core/        scope, http client, findings store, settings
  recon/       spec parser, crawler
  auth/        multi-identity auth engine
  modules/     one file per OWASP check (bola, broken_auth, misconfig, ...)
  ai/          provider / planner / analyst
  reporting/   markdown + html/pdf reporters
  plugins/     the plugin API + registry (this doc's focus)
tests/         pytest suite
scripts/       helper scripts (e.g. fetch-wordlists.sh)
```

## Adding a new module (plugin API)

Modules are decoupled from the CLI through `apistrike/plugins`. A module is any
class that satisfies this contract:

```python
class MyModule:
    def __init__(self, client, base_url, **opts):
        self.client = client
        self.base_url = base_url.rstrip("/")
        ...

    async def run(self, store):
        # Do read-only (safe-by-default) probes via self.client, then persist
        # confirmed findings into the OPEN findings store:
        #     store.add(Finding(title=..., severity=..., owasp_id=..., ...))
        # Return a small result object for display.
        return MyResult(notes=[...], requests_made=self._requests)
```

`store` is an open `FindingsStore` (see `apistrike/core/findings.py`); the module
persists its own findings and returns a result with `.notes` / `.requests_made`.
Always confirm a finding with a real response before reporting it — **the engine
verifies, the AI only advises.**

### Option A — ship it as a built-in

Add a `build()` factory + `register(...)` in `apistrike/plugins/builtin.py`:

```python
def _build_myscan(ctx):
    from apistrike.modules.myscan import MyModule
    return MyModule(
        ctx.client,
        base_url=ctx.base_url,
        safe=ctx.safe,
        # map any extra flags the user passed via -o key=value:
        aggressive=ctx.flag("aggressive"),
    )

register(ModuleSpec(
    name="myscan",
    build=_build_myscan,
    owasp_id="API1:2023",
    description="What this module checks.",
))
```

That is the entire wiring — no `cli.py` edit. Run it with:

```bash
python -m apistrike run-module myscan http://localhost:5000 -o aggressive=true
```

### Option B — ship it as a separate pip package (entry point)

External packages can register modules without living in this repo. Expose a
`ModuleSpec` (or a zero-arg factory returning one) under the
`apistrike.modules` entry-point group:

```toml
# pyproject.toml of your plugin package
[project.entry-points."apistrike.modules"]
myscan = "my_pkg.plugin:SPEC"
```

```python
# my_pkg/plugin.py
from apistrike.plugins import ModuleContext, ModuleSpec

def _build(ctx: ModuleContext):
    from my_pkg.module import MyModule
    return MyModule(ctx.client, ctx.base_url, safe=ctx.safe)

SPEC = ModuleSpec(name="myscan", build=_build, owasp_id="API1:2023", description="...")
```

Once the package is installed in the same environment, `run-module --list` and
`run-module myscan ...` pick it up automatically via `discover_entry_points()`.

### The `ModuleContext`

| Field | Meaning |
|-------|---------|
| `client` | in-scope `ScopedHTTPClient` (all requests are scope-gated) |
| `base_url` | target base URL |
| `path` | representative endpoint path (`--path`, default `/`) |
| `headers` | auth headers already negotiated (e.g. `Authorization: Bearer ...`) |
| `safe` | scope safe-mode flag — keep destructive verbs behind this |
| `options` | free-form `dict` from repeated `--option key=value` / `-o` flags |

Helpers: `ctx.opt("key", default)` for strings, `ctx.flag("key")` for booleans.

## Wordlists (SecLists)

Wordlists are **not vendored** (they are large and MIT-licensed upstream). Fetch
a minimal API-fuzzing subset on demand:

```bash
./scripts/fetch-wordlists.sh          # populates ./wordlists/ (git-ignored)
```

## Commit & PR conventions

- **Branch per phase / feature**, keep `main` always green: `git checkout -b feat-myscan`.
- **Conventional commits**: `feat(myscan): ...`, `fix(report): ...`, `ci(actions): ...`, `docs: ...`.
- Add/extend **pytest** coverage for every new module or behavior change.
- Open a PR into `main`; CI (tests + docker build + live lab-scan) must pass before merge.
- Prefer small, frequent, self-describing commits.

## Ground rules for modules

- **Safe by default** — read-only probes unless the user opts into `--active`/unsafe.
- **No false positives** — confirm with observable evidence; calibrate baselines.
- **Redact secrets** in evidence — never re-print a captured credential in full.
- **Stdlib-friendly** — avoid heavy third-party deps where the standard library suffices.
