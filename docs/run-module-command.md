# Wiring the generic `run-module` command into `cli.py`

The plugin registry is self-contained, but to run modules from the CLI you add
**one** new command. This is additive — it does not change any existing command.

## 1. Paste this command into `apistrike/cli.py`

Add it next to the other command definitions (e.g. right after `misconfig`). Use
the **same decorator style** your other commands use — look at the line directly
above `def misconfig(` (around line 875). If that is `@app.command()`, prefix
this function with `@app.command("run-module")`.

```python
@app.command("run-module")
def run_module(
    name: str = typer.Argument(None, help="Module to run (omit with --list to see all)"),
    target: str = typer.Argument(None, help="Base URL of the target API"),
    path: str = typer.Option("/", "--path", help="Representative endpoint path to probe"),
    option: list = typer.Option(None, "--option", "-o", help="Module option key=value (repeatable)"),
    username: str = typer.Option(None, "-u", "--username", help="Optional username to authenticate first"),
    password: str = typer.Option(None, "-p", "--password", help="Optional password to authenticate first"),
    login_path: str = typer.Option("/users/v1/login", "--login-path", help="Login path when credentials are supplied"),
    scope: str = typer.Option("scope.yaml", "--scope", help="Path to the scope file"),
    list_modules: bool = typer.Option(False, "--list", help="List available modules and exit"),
) -> None:
    """Run any registered attack module (built-in or plugin) by name."""
    import asyncio

    from apistrike.plugins import (
        ModuleContext,
        all_specs,
        discover_entry_points,
        get,
        load_builtins,
    )

    load_builtins()
    discover_entry_points()

    if list_modules or not name:
        typer.echo("Available modules:")
        for spec in sorted(all_specs(), key=lambda s: s.name):
            oid = (" [" + spec.owasp_id + "]") if spec.owasp_id else ""
            typer.echo("  " + spec.name + oid + " - " + (spec.description or ""))
        raise typer.Exit(code=0)

    if not target:
        typer.echo("Missing target URL. Usage: run-module <name> <target> [--option k=v ...]")
        raise typer.Exit(code=1)

    try:
        spec = get(name)
    except KeyError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=1)

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
    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}. Module: {spec.name}")

    options = {}
    for item in (option or []):
        if "=" in item:
            key, value = item.split("=", 1)
            options[key.strip()] = value.strip()
        else:
            options[item.strip()] = "true"

    from apistrike.auth.auth_engine import AuthEngine, LoginConfig
    from apistrike.core.http_client import ScopedHTTPClient

    async def _run(store):
        async with ScopedHTTPClient(sc) as client:
            headers = {}
            if username and password:
                auth = AuthEngine(client, base_url=target, login_config=LoginConfig(login_path=login_path))
                auth.add_identity("primary", username=username, password=password)
                token = await auth.login("primary")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            ctx = ModuleContext(
                client=client,
                base_url=target,
                path=path,
                headers=headers,
                safe=sc.safe_mode,
                options=options,
            )
            module = spec.build(ctx)
            return await module.run(store=store)

    try:
        with FindingsStore(settings.findings_db) as store:
            result = asyncio.run(_run(store))
            summary = store.summary()
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001 -- surface a clean CLI error
        typer.echo(f"Module '{spec.name}' failed: {exc}")
        raise typer.Exit(code=1)

    for note in getattr(result, "notes", []) or []:
        typer.echo(f"  - {note}")
    typer.echo(f"Findings summary: {summary}")
```

> This mirrors your existing `misconfig` command exactly (same `Scope`,
> `OutOfScopeError`, `Settings`, `FindingsStore`, `ScopedHTTPClient`,
> `AuthEngine` usage), so it relies only on names already imported at the top of
> `cli.py`.

## 2. Try it

```bash
python -m apistrike run-module --list
python -m apistrike run-module misconfig http://localhost:5000 --scope scope.yaml
python -m apistrike run-module misconfig http://localhost:5000 -o checks=headers,banner -o evil_origin=https://evil.test
```
