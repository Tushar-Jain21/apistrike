"""APIStrike command-line interface (Typer).

Commands: version, init-scope, scan, recon, login, report.

- recon  : parse an OpenAPI/Swagger spec and list endpoints (read-only).
- login  : authenticate against a target and show the captured token +
           decoded JWT claims (read-only inspection).
- scan   : validate scope and, when credentials are supplied, run the
           broken-authentication module (API2:2023) against the target and
           record confirmed findings. Without credentials it only validates
           scope and prepares the findings DB.

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


if __name__ == "__main__":
    app()
