"""APIStrike command-line interface (Typer).

Commands: version, init-scope, scan, bola, bfla, inject, ssrf, massassign, misconfig, dataexpose, crawl, recon, login, report.

- crawl  : active recon -- discover shadow/undocumented endpoints, enumerate
           HTTP methods, and fuzz for hidden query params (API9:2023).
           Read-only in safe mode (methods read via OPTIONS); state-changing
           verbs are only sent with the explicit --active flag.
- recon  : parse an OpenAPI/Swagger spec and list endpoints (read-only).
- login  : authenticate against a target and show the captured token +
           decoded JWT claims (read-only inspection).
- scan   : validate scope and, when credentials are supplied, run the
           broken-authentication module (API2:2023) against the target.
- bola   : Broken Object Level Authorization (API1:2023) -- log in two
           identities and diff their object access to confirm cross-user reads.
- bfla   : Broken Function Level Authorization (API5:2023) -- confirm that a
           lower-privilege (or unauthenticated) caller can invoke privileged
           functions. Destructive methods are only fired with --active.
- inject : Injection (SQLi / NoSQLi / OS-command) -- confirm injectable
           parameters via error, boolean-blind, time-based and NoSQL-operator
           techniques. All payloads are read/timing only (safe by default).
- ssrf   : Server-Side Request Forgery (API7:2023) -- confirm SSRF via a
           built-in out-of-band OAST callback listener, cloud-metadata
           reachability, and timing. Probes are read-only (safe by default).
           Use --selftest to prove the OAST loop with no target.
- massassign : Mass assignment / Broken Object Property Level Authorization
           (API3:2023) -- smuggle privileged properties (admin, role, balance,
           ...) into a create request, then read the object back to confirm the
           value persisted. A control object rules out server-side defaults, so
           false positives stay near zero.
- misconfig : Security misconfiguration (API8:2023) -- check for missing
           security headers, permissive CORS (origin reflection / wildcard),
           verbose error/stack-trace disclosure, HTTP TRACE (XST), and
           software version banners. All checks are read-only (safe by default).
- dataexpose : Excessive data exposure (API3:2023) -- fetch endpoints and scan
           responses for leaked secrets (keys, tokens, password hashes, DB
           URIs), sensitive JSON fields (password, ssn, api_key, ...), PII
           (emails, SSNs, Luhn-valid card numbers), and high-entropy strings.
           Read-only; evidence values are masked/redacted.

Every network call is routed through the scope-gated ScopedHTTPClient, so an
out-of-scope target is refused before any request is made.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import typer

from apistrike.core.config import Settings
from apistrike.core.findings import FindingsStore
from apistrike.core.scope import Scope, OutOfScopeError
from apistrike.recon.spec_parser import load_spec
from apistrike.reporting.report import write_report

__version__ = "0.1.0"

app = typer.Typer(
    add_completion=False,
    help="APIStrike -- AI-assisted, open-source API penetration testing.",
)


@app.command()
def version() -> None:
    """Print the APIStrike version."""
    typer.echo(f"APIStrike {__version__}")


@app.command("init-scope")
def init_scope(
    path: str = typer.Option("scope.yaml", help="Where to write the scope file."),
    example: str = typer.Option("scope.example.yaml", help="Template to copy from."),
    force: bool = typer.Option(False, "--force", help="Overwrite if it exists."),
) -> None:
    """Create a scope.yaml from the bundled example."""
    dest = Path(path)
    if dest.exists() and not force:
        typer.echo(f"{dest} already exists (use --force to overwrite).")
        raise typer.Exit(code=1)
    src = Path(example)
    if not src.exists():
        typer.echo(f"Template {src} not found.")
        raise typer.Exit(code=1)
    shutil.copyfile(src, dest)
    typer.echo(f"Wrote {dest}. Edit it to list your authorized hosts before scanning.")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Base URL of the API to test."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
    username: str = typer.Option("", "--username", "-u", help="Username for auth-based checks."),
    password: str = typer.Option("", "--password", "-p", help="Password for auth-based checks."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
    probe_path: str = typer.Option("/me", help="Authenticated endpoint used to test tampered tokens."),
) -> None:
    """Run a scan: validate scope, then (with -u/-p) run the broken-auth module."""
    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as e:
        typer.echo(f"Refused: {e}")
        raise typer.Exit(code=2)

    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")

    if not (username and password):
        with FindingsStore(settings.findings_db) as store:
            summary = store.summary()
        typer.echo(
            f"No credentials given (-u/-p). Findings DB ready at {settings.findings_db} "
            f"({summary['total']} existing). Provide -u/-p to run the broken-auth module."
        )
        return

    import asyncio

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.broken_auth import BrokenAuthModule

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            engine = AuthEngine(
                client, base_url=target, login_config=LoginConfig(login_path=login_path)
            )
            ident = engine.add_identity(username, username=username, password=password)
            token = await engine.login(ident)
            typer.echo(f"Authenticated as {username}; running broken-authentication checks...")
            module = BrokenAuthModule(
                client, base_url=target, valid_token=token, probe_path=probe_path
            )
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except Exception as e:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Scan failed: {e}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"Broken-auth checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']})."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def bola(
    target: str = typer.Argument(..., help="Base URL of the API to test."),
    username: str = typer.Option(..., "--username", "-u", help="First identity's username."),
    password: str = typer.Option(..., "--password", "-p", help="First identity's password."),
    username2: str = typer.Option(..., "--username2", "-U", help="Second identity's username."),
    password2: str = typer.Option(..., "--password2", "-P", help="Second identity's password."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
    object_template: str = typer.Option(
        "/users/v1/{username}",
        help="Object path template; '{username}' is filled per identity to build each user's object.",
    ),
    enum: int = typer.Option(0, "--enum", help="Also probe N numeric-id neighbours for horizontal enumeration."),
    no_unauth: bool = typer.Option(False, "--no-unauth", help="Skip the unauthenticated-access check."),
) -> None:
    """Broken Object Level Authorization (API1:2023): multi-user access diffing."""
    import asyncio

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.bola import BolaModule, BolaIdentity, ObjectRef

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as e:
        typer.echo(f"Refused: {e}")
        raise typer.Exit(code=2)

    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")

    creds = [(username, password), (username2, password2)]

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            engine = AuthEngine(
                client, base_url=target, login_config=LoginConfig(login_path=login_path)
            )
            identities = []
            objects = []
            for uname, pw in creds:
                ident = engine.add_identity(uname, username=uname, password=pw)
                token = await engine.login(ident)
                identities.append(
                    BolaIdentity(label=uname, headers={"Authorization": f"Bearer {token}"}, username=uname)
                )
                objects.append(
                    ObjectRef(path=object_template.format(username=uname), owner_label=uname, name=f"{uname}'s object")
                )
            typer.echo(f"Authenticated {len(identities)} identities; running BOLA access-matrix checks...")
            module = BolaModule(
                client, base_url=target, identities=identities, objects=objects,
                unauth_check=not no_unauth, enumerate_spread=enum,
            )
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except Exception as e:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"BOLA scan failed: {e}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"BOLA checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']})."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def recon(
    spec: str = typer.Argument(..., help="URL or path to an OpenAPI/Swagger spec."),
) -> None:
    """Parse an API spec and list its endpoints (read-only, no attacks)."""
    api = load_spec(spec)
    typer.echo(f"{api.title} v{api.version}  ({api.base_url or 'no base url'})")
    typer.echo(f"{len(api)} endpoints discovered:")
    for e in api.endpoints:
        flags = []
        if e.path_params:
            flags.append("path:" + ",".join(p.name for p in e.path_params))
        if e.has_request_body:
            flags.append("body")
        if e.requires_auth:
            flags.append("auth")
        suffix = f"  [{'; '.join(flags)}]" if flags else ""
        typer.echo(f"  {e.method:<6} {e.path}{suffix}")


@app.command()
def login(
    target: str = typer.Argument(..., help="Base URL of the API to authenticate against."),
    username: str = typer.Option(..., "--username", "-u", help="Username to log in with."),
    password: str = typer.Option(..., "--password", "-p", help="Password to log in with."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
) -> None:
    """Log in to a target API and show the captured token + decoded JWT (read-only)."""
    import asyncio
    import json as _json

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig, decode_jwt
    from apistrike.core.http_client import ScopedHTTPClient

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as e:
        typer.echo(f"Refused: {e}")
        raise typer.Exit(code=2)

    async def _run() -> str:
        async with ScopedHTTPClient(sc) as client:
            engine = AuthEngine(
                client, base_url=target, login_config=LoginConfig(login_path=login_path)
            )
            ident = engine.add_identity(username, username=username, password=password)
            return await engine.login(ident)

    try:
        token = asyncio.run(_run())
    except Exception as e:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Login failed: {e}")
        raise typer.Exit(code=1)

    typer.echo(f"Logged in as {username}. Token captured ({len(token)} chars).")
    typer.echo(token)
    try:
        decoded = decode_jwt(token)
        typer.echo("Decoded JWT (unverified -- inspection only):")
        typer.echo(f"  header:  {_json.dumps(decoded['header'])}")
        typer.echo(f"  payload: {_json.dumps(decoded['payload'])}")
    except ValueError:
        typer.echo("(Token is not a decodable JWT -- stored as an opaque token.)")


@app.command()
def report(
    output: str = typer.Option("reports/report.md", help="Where to write the report."),
    target: str = typer.Option("N/A", help="Target label for the report header."),
) -> None:
    """Generate a Markdown report from the findings database."""
    settings = Settings.load()
    with FindingsStore(settings.findings_db) as store:
        path = write_report(store, output, target=target)
    typer.echo(f"Report written to {path}")


@app.command()
def crawl(
    target: str = typer.Argument(..., help="Base URL of the API to crawl."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
    spec: str = typer.Option("", "--spec", help="Optional OpenAPI/Swagger spec to seed documented endpoints and base paths."),
    wordlist: str = typer.Option("", "--wordlist", "-w", help="Path to a path wordlist (e.g. a local SecLists file). Falls back to a small bundled list."),
    param_wordlist: str = typer.Option("", "--param-wordlist", help="Optional path to a parameter wordlist."),
    active: bool = typer.Option(False, "--active", help="Actively probe state-changing methods (POST/PUT/PATCH/DELETE). Only for explicitly authorized engagements."),
    no_params: bool = typer.Option(False, "--no-params", help="Skip query-parameter fuzzing."),
    no_methods: bool = typer.Option(False, "--no-methods", help="Skip HTTP method enumeration."),
) -> None:
    """Recon crawler (API9:2023): discover shadow endpoints, methods and hidden params."""
    import asyncio

    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.recon.crawler import Crawler, load_wordlist

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as e:
        typer.echo(f"Refused: {e}")
        raise typer.Exit(code=2)

    settings = Settings.load()

    # In safe mode we never fire destructive verbs; --active is the explicit opt-in.
    safe = sc.safe_mode and not active
    if active and sc.safe_mode:
        typer.echo("Note: --active overrides safe mode; state-changing methods WILL be sent. Ensure this is authorized.")

    seeds = []
    bases = ["/"]
    if spec:
        try:
            api = load_spec(spec)
            seeds = [e.path for e in api.endpoints]
            prefixes = set()
            for p in seeds:
                parts = [s for s in p.split("/") if s]
                if parts:
                    prefixes.add("/" + parts[0])
                if len(parts) >= 2:
                    prefixes.add("/" + "/".join(parts[:2]))
            if prefixes:
                bases = ["/"] + sorted(prefixes)
        except Exception as e:  # noqa: BLE001
            typer.echo(f"Could not load spec '{spec}': {e}")

    words = load_wordlist(wordlist or None)
    param_words = load_wordlist(param_wordlist, fallback=[]) if param_wordlist else []

    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {safe} (active={active}).")
    typer.echo(f"Seeded {len(seeds)} documented endpoint(s); {len(words)} path words; bases={bases}.")

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            crawler = Crawler(
                client, base_url=target,
                seed_endpoints=seeds, path_words=words, param_words=param_words,
                bases=bases, fuzz_params=not no_params, method_enum=not no_methods,
                safe=safe,
            )
            return await crawler.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            res = asyncio.run(_run(store))
            summary = store.summary()
    except Exception as e:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Crawl failed: {e}")
        raise typer.Exit(code=1)

    for note in res.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"Crawl done: {len(res.endpoints)} live endpoint(s), "
        f"{len(res.shadow_endpoints)} shadow, "
        f"{sum(len(v) for v in res.discovered_params.values())} hidden param(s); "
        f"{res.requests_made} requests."
    )
    for e in res.endpoints:
        tag = "spec" if e.source == "spec" else "SHADOW"
        methods = ",".join(e.methods_allowed) if e.methods_allowed else "?"
        params = ("  params:" + ",".join(e.params_found)) if e.params_found else ""
        typer.echo(f"  [{tag}] {e.path}  ({e.status}; methods={methods}){params}")
    if res.findings:
        typer.echo(f"{len(res.findings)} inventory finding(s) recorded (total in DB: {summary['total']}).")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def bfla(
    target: str = typer.Argument(..., help="Base URL of the API to test."),
    username: str = typer.Option(..., "--username", "-u", help="Lower-privilege identity's username."),
    password: str = typer.Option(..., "--password", "-p", help="Lower-privilege identity's password."),
    admin_user: str = typer.Option("", "--admin-user", help="Optional privileged identity's username (establishes a confirmed baseline)."),
    admin_pass: str = typer.Option("", "--admin-pass", help="Optional privileged identity's password."),
    ops: str = typer.Option(
        "GET /users/v1/_debug",
        "--ops",
        help="Privileged operations to test as 'METHOD /path', separated by ';'.",
    ),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
    active: bool = typer.Option(False, "--active", help="Also invoke destructive privileged functions (POST/PUT/PATCH/DELETE). Only for authorized engagements."),
    no_unauth: bool = typer.Option(False, "--no-unauth", help="Skip the unauthenticated-invocation check."),
) -> None:
    """Broken Function Level Authorization (API5:2023): privileged-function access matrix."""
    import asyncio

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.bfla import BflaModule, BflaIdentity, Operation

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as e:
        typer.echo(f"Refused: {e}")
        raise typer.Exit(code=2)

    operations = []
    for token in ops.split(";"):
        token = token.strip()
        if not token:
            continue
        parts = token.split(None, 1)
        if len(parts) != 2:
            typer.echo(f"Invalid --ops entry '{token}'. Use 'METHOD /path' (e.g. 'GET /users/v1/_debug').")
            raise typer.Exit(code=1)
        operations.append(Operation(parts[0], parts[1]))
    if not operations:
        typer.echo("No operations to test. Provide --ops 'METHOD /path'.")
        raise typer.Exit(code=1)

    settings = Settings.load()
    safe = sc.safe_mode and not active
    if active and sc.safe_mode:
        typer.echo("Note: --active overrides safe mode; destructive privileged functions WILL be invoked. Ensure this is authorized.")
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {safe} (active={active}).")

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            engine = AuthEngine(
                client, base_url=target, login_config=LoginConfig(login_path=login_path)
            )
            identities = []
            low = engine.add_identity(username, username=username, password=password)
            low_token = await engine.login(low)
            identities.append(
                BflaIdentity(label=username, headers={"Authorization": f"Bearer {low_token}"}, role="user")
            )
            admin_label = None
            if admin_user and admin_pass:
                adm = engine.add_identity(admin_user, username=admin_user, password=admin_pass)
                adm_token = await engine.login(adm)
                admin_label = admin_user
                identities.append(
                    BflaIdentity(label=admin_user, headers={"Authorization": f"Bearer {adm_token}"}, role="admin")
                )
            typer.echo(
                f"Authenticated {len(identities)} identity/identities; testing {len(operations)} privileged operation(s)..."
            )
            module = BflaModule(
                client, base_url=target, identities=identities, operations=operations,
                admin_label=admin_label, safe=safe, unauth_check=not no_unauth,
            )
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except Exception as e:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"BFLA scan failed: {e}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"BFLA checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']})."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def inject(
    target: str = typer.Argument(..., help="Base URL of the API to test."),
    path: str = typer.Option(..., "--path", help="Endpoint path to test. For --location path, include the marker INJECT where the value goes, e.g. /users/v1/INJECT."),
    param: str = typer.Option(..., "--param", help="Parameter name (or a label for the injected path segment)."),
    method: str = typer.Option("GET", "--method", help="HTTP method to use."),
    location: str = typer.Option("query", "--location", help="Where the value lives: 'query', 'json' (request body), or 'path' (URL path segment at the INJECT marker)."),
    benign: str = typer.Option("1", "--benign", help="A benign baseline value (for path injection, a valid id such as name1)."),
    techniques: str = typer.Option(
        "error,boolean,time_sql,time_cmd,nosql",
        "--techniques",
        help="Comma-separated techniques: error,boolean,time_sql,time_cmd,nosql.",
    ),
    delay: int = typer.Option(3, "--delay", help="Seconds requested by time-based payloads."),
    threshold_ms: int = typer.Option(2500, "--threshold-ms", help="Minimum extra delay (ms) to treat a time-based response as a hit."),
    username: str = typer.Option("", "--username", "-u", help="Optional username; if set, logs in and injects with a Bearer token."),
    password: str = typer.Option("", "--password", "-p", help="Optional password for --username."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
) -> None:
    """Injection (SQLi / NoSQLi / OS-command): confirm injectable params with real requests."""
    import asyncio

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.injection import InjectionModule, InjectionTarget

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as e:
        typer.echo(f"Refused: {e}")
        raise typer.Exit(code=2)

    techs = [t.strip() for t in techniques.split(",") if t.strip()]
    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")
    typer.echo(f"Testing param '{param}' at {method.upper()} {path} ({location}); techniques={techs}.")

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            headers = {}
            if username and password:
                engine = AuthEngine(
                    client, base_url=target, login_config=LoginConfig(login_path=login_path)
                )
                ident = engine.add_identity(username, username=username, password=password)
                token = await engine.login(ident)
                headers = {"Authorization": f"Bearer {token}"}
                typer.echo(f"Authenticated as {username}; injecting with a Bearer token.")
            tgt = InjectionTarget(
                method=method, path=path, param=param, location=location,
                headers=headers, benign_value=benign,
            )
            module = InjectionModule(
                client, base_url=target, targets=[tgt],
                techniques=techs, time_delay=delay, time_threshold_ms=threshold_ms,
                safe=sc.safe_mode,
            )
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except Exception as e:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Injection scan failed: {e}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"Injection checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']}); {result.requests_made} requests."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def ssrf(
    target: str = typer.Argument(..., help="Base URL of the API to test."),
    path: str = typer.Option(..., "--path", help="Endpoint path. For --location path, include the marker INJECT where the value goes."),
    param: str = typer.Option(..., "--param", help="Parameter that takes a URL/host (or label for the injected path segment)."),
    method: str = typer.Option("GET", "--method", help="HTTP method to use."),
    location: str = typer.Option("query", "--location", help="Where the value lives: 'query', 'json' (body), or 'path'."),
    benign: str = typer.Option("http://example.com/", "--benign", help="A benign external URL used as the baseline value."),
    techniques: str = typer.Option("oast,metadata,timing", "--techniques", help="Comma-separated: oast,metadata,timing."),
    oast_host: str = typer.Option("127.0.0.1", "--oast-host", help="Interface the OAST callback listener binds to."),
    oast_port: int = typer.Option(0, "--oast-port", help="Port for the OAST listener (0 = auto-pick a free port)."),
    oast_public: str = typer.Option("", "--oast-public", help="Host/IP the TARGET can reach the listener at (defaults to --oast-host). Use your LAN IP for containers."),
    oast_wait_ms: int = typer.Option(2000, "--oast-wait-ms", help="Milliseconds to wait for an out-of-band callback."),
    no_oast: bool = typer.Option(False, "--no-oast", help="Disable the OAST listener (metadata/timing only)."),
    threshold_ms: int = typer.Option(3000, "--threshold-ms", help="Extra delay (ms) to treat a timing response as blind SSRF."),
    username: str = typer.Option("", "--username", "-u", help="Optional username; if set, logs in and probes with a Bearer token."),
    password: str = typer.Option("", "--password", "-p", help="Optional password for --username."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
    selftest: bool = typer.Option(False, "--selftest", help="Prove the OAST loop locally: start the listener and fire a loopback request at it (no target needed)."),
) -> None:
    """Server-Side Request Forgery (API7:2023): OAST callback + metadata + timing."""
    import asyncio
    import urllib.request

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.ssrf import OASTListener, SSRFModule, SSRFTarget

    if selftest:
        with OASTListener(host=oast_host, port=oast_port, public_host=(oast_public or None)) as listener:
            tok = listener.new_token()
            url = listener.payload_url(tok)
            typer.echo(f"OAST listener up at {listener.base_url}. Firing loopback probe to {url} ...")
            try:
                urllib.request.urlopen(url, timeout=3).read()
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"Loopback probe error: {exc}")
            hits = listener.poll(tok, wait_ms=oast_wait_ms)
            if hits:
                typer.echo(f"OAST self-test PASSED: captured {len(hits)} callback(s) for token {tok}.")
            else:
                typer.echo("OAST self-test FAILED: no callback captured (check host/port/firewall).")
        raise typer.Exit(code=0)

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as exc:
        typer.echo(f"Refused: {exc}")
        raise typer.Exit(code=2)

    techs = [t.strip() for t in techniques.split(",") if t.strip()]
    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")

    listener = None
    if "oast" in techs and not no_oast:
        listener = OASTListener(host=oast_host, port=oast_port, public_host=(oast_public or None)).start()
        typer.echo(f"OAST callback listener started at {listener.base_url} (target must be able to reach this).")
    typer.echo(f"Probing param '{param}' at {method.upper()} {path} ({location}); techniques={techs}.")

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            headers = {}
            if username and password:
                engine = AuthEngine(client, base_url=target, login_config=LoginConfig(login_path=login_path))
                ident = engine.add_identity(username, username=username, password=password)
                token = await engine.login(ident)
                headers = {"Authorization": f"Bearer {token}"}
                typer.echo(f"Authenticated as {username}; probing with a Bearer token.")
            tgt = SSRFTarget(method=method, path=path, param=param, location=location, headers=headers, benign_value=benign)
            module = SSRFModule(
                client,
                base_url=target,
                targets=[tgt],
                listener=listener,
                techniques=techs,
                time_threshold_ms=threshold_ms,
                oast_wait_ms=oast_wait_ms,
                safe=sc.safe_mode,
            )
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except Exception as exc:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"SSRF scan failed: {exc}")
        raise typer.Exit(code=1)
    finally:
        if listener is not None:
            listener.stop()

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"SSRF checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']}); {result.requests_made} requests."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def massassign(
    target: str = typer.Argument(..., help="Base URL of the API to test."),
    create_path: str = typer.Option("/users/v1/register", "--create-path", help="Endpoint that creates the object."),
    id_field: str = typer.Option("username", "--id-field", help="Field in --base that identifies the created object on read-back."),
    base: str = typer.Option(
        '{"username": "apistrike_ma", "password": "Str1ke_P@ss", "email": "apistrike_ma@example.com"}',
        "--base",
        help="JSON object with the legitimate required fields for creation.",
    ),
    create_method: str = typer.Option("POST", "--create-method", help="HTTP method for creation."),
    create_location: str = typer.Option("json", "--create-location", help="Where the body goes: 'json' or 'query'."),
    readback_path: str = typer.Option("/users/v1/_debug", "--readback-path", help="Endpoint to read the object back. Empty string disables read-back (echo-only). For location 'path', include the INJECT marker."),
    readback_location: str = typer.Option("none", "--readback-location", help="'none' (list/debug endpoint) or 'path' (per-object endpoint using the INJECT marker)."),
    props: str = typer.Option("admin", "--props", help="Comma-separated property names to smuggle, or a JSON object of name:value. Known names get sensible values automatically."),
    username: str = typer.Option("", "--username", "-u", help="Optional username; if set, logs in and tests with a Bearer token."),
    password: str = typer.Option("", "--password", "-p", help="Optional password for --username."),
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
    scope: str = typer.Option("scope.yaml", help="Path to the authorized-scope file."),
) -> None:
    """Mass assignment / BOPLA (API3:2023): smuggle privileged props, confirm via read-back."""
    import asyncio
    import json as _json

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.mass_assignment import (
        MassAssignmentModule,
        MassAssignmentTarget,
        PRIVILEGE_PROPS,
    )

    try:
        base_body = _json.loads(base)
    except Exception:
        typer.echo("--base must be valid JSON, e.g. '" + '{"username": "x", "password": "y", "email": "x@e.com"}' + "'")
        raise typer.Exit(code=1)

    parsed_props = None
    ptext = props.strip()
    if ptext:
        if ptext.startswith("{"):
            try:
                parsed_props = _json.loads(ptext)
            except Exception:
                typer.echo("--props JSON is invalid.")
                raise typer.Exit(code=1)
        else:
            parsed_props = {}
            for name in [p.strip() for p in ptext.split(",") if p.strip()]:
                parsed_props[name] = PRIVILEGE_PROPS.get(name, True)

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file '{scope}' not found. Run: apistrike init-scope")
        raise typer.Exit(code=1)

    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as exc:
        typer.echo(f"Refused: {exc}")
        raise typer.Exit(code=2)

    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")
    typer.echo(
        f"Testing mass assignment at {create_method.upper()} {create_path}; "
        f"read-back via {readback_path or '(none)'}. This creates throwaway objects."
    )

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            headers = {}
            if username and password:
                engine = AuthEngine(client, base_url=target, login_config=LoginConfig(login_path=login_path))
                ident = engine.add_identity(username, username=username, password=password)
                token = await engine.login(ident)
                headers = {"Authorization": f"Bearer {token}"}
                typer.echo(f"Authenticated as {username}; testing with a Bearer token.")
            try:
                tgt = MassAssignmentTarget(
                    create_path=create_path,
                    id_field=id_field,
                    base_body=base_body,
                    create_method=create_method,
                    create_location=create_location,
                    readback_path=readback_path,
                    readback_location=readback_location,
                    props=parsed_props,
                    headers=headers,
                )
            except ValueError as exc:
                typer.echo(f"Invalid target configuration: {exc}")
                raise typer.Exit(code=1)
            module = MassAssignmentModule(client, base_url=target, targets=[tgt], safe=sc.safe_mode)
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Mass assignment scan failed: {exc}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"Mass assignment checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']}); {result.requests_made} requests."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def misconfig(
    target: str = typer.Argument(..., help="Base URL of the target API"),
    path: str = typer.Option("/", "--path", help="Representative endpoint path to probe"),
    checks: str = typer.Option(
        "headers,cors,errors,methods,banner", "--checks",
        help="Comma-separated checks: headers,cors,errors,methods,banner",
    ),
    evil_origin: str = typer.Option(
        "https://evil.attacker.test", "--evil-origin",
        help="Origin header used for the CORS reflection probe",
    ),
    username: str = typer.Option(None, "-u", "--username", help="Optional username to authenticate first"),
    password: str = typer.Option(None, "-p", "--password", help="Optional password to authenticate first"),
    login_path: str = typer.Option("/users/v1/login", "--login-path", help="Login path used when credentials are supplied"),
    scope: str = typer.Option("scope.yaml", "--scope", help="Path to the scope file"),
) -> None:
    """Security misconfiguration checks (OWASP API8:2023)."""
    import asyncio

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.misconfig import MisconfigModule

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file not found: {scope}")
        raise typer.Exit(code=1)
    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as exc:
        typer.echo(f"Target out of scope: {exc}")
        raise typer.Exit(code=2)

    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")

    selected = tuple(c.strip() for c in checks.split(",") if c.strip())

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            headers = {}
            if username and password:
                auth = AuthEngine(client, base_url=target, login_config=LoginConfig(login_path=login_path))
                auth.add_identity("primary", username=username, password=password)
                token = await auth.login("primary")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            try:
                module = MisconfigModule(
                    client,
                    base_url=target,
                    probe_paths=[path],
                    evil_origin=evil_origin,
                    checks=selected,
                    headers=headers,
                    safe=sc.safe_mode,
                )
            except ValueError as exc:
                typer.echo(f"Invalid configuration: {exc}")
                raise typer.Exit(code=1)
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Misconfiguration scan failed: {exc}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"Misconfiguration checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']}); {result.requests_made} requests."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


@app.command()
def dataexpose(
    target: str = typer.Argument(..., help="Base URL of the target API"),
    paths: str = typer.Option("/", "--paths", help="Comma-separated endpoint paths to scan"),
    method: str = typer.Option("GET", "--method", help="HTTP method used for each path"),
    checks: str = typer.Option(
        "secrets,fields,pii,entropy", "--checks",
        help="Comma-separated checks: secrets,fields,pii,entropy",
    ),
    entropy_threshold: float = typer.Option(4.0, "--entropy-threshold", help="Shannon-entropy threshold for the entropy check"),
    entropy_min_len: int = typer.Option(24, "--entropy-min-len", help="Minimum token length for the entropy check"),
    username: str = typer.Option(None, "-u", "--username", help="Optional username to authenticate first"),
    password: str = typer.Option(None, "-p", "--password", help="Optional password to authenticate first"),
    login_path: str = typer.Option("/users/v1/login", "--login-path", help="Login path used when credentials are supplied"),
    scope: str = typer.Option("scope.yaml", "--scope", help="Path to the scope file"),
) -> None:
    """Excessive data exposure scan (OWASP API3:2023)."""
    import asyncio

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient
    from apistrike.modules.data_exposure import DataExposureModule, DataExposureTarget

    try:
        sc = Scope.from_file(scope)
    except FileNotFoundError:
        typer.echo(f"Scope file not found: {scope}")
        raise typer.Exit(code=1)
    try:
        sc.assert_in_scope(target)
    except OutOfScopeError as exc:
        typer.echo(f"Target out of scope: {exc}")
        raise typer.Exit(code=2)

    settings = Settings.load()
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")

    selected = tuple(c.strip() for c in checks.split(",") if c.strip())
    scan_paths = [p.strip() for p in paths.split(",") if p.strip()] or ["/"]
    targets = [DataExposureTarget(path=p, method=method) for p in scan_paths]

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            headers = {}
            if username and password:
                auth = AuthEngine(client, base_url=target, login_config=LoginConfig(login_path=login_path))
                auth.add_identity("primary", username=username, password=password)
                token = await auth.login("primary")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            try:
                module = DataExposureModule(
                    client,
                    base_url=target,
                    targets=targets,
                    checks=selected,
                    entropy_threshold=entropy_threshold,
                    entropy_min_len=entropy_min_len,
                    headers=headers,
                    safe=sc.safe_mode,
                )
            except ValueError as exc:
                typer.echo(f"Invalid configuration: {exc}")
                raise typer.Exit(code=1)
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Data exposure scan failed: {exc}")
        raise typer.Exit(code=1)

    for note in result.notes:
        typer.echo(f"  - {note}")
    typer.echo(
        f"Data exposure checks done: {len(result.findings)} finding(s) recorded "
        f"(total in DB: {summary['total']}); {result.requests_made} requests."
    )
    for f in result.findings:
        typer.echo(f"  [{f.severity.upper()}] {f.title}")
    typer.echo("Run 'apistrike report' to generate the Markdown report.")


if __name__ == "__main__":
    app()
