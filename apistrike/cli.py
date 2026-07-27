"""APIStrike command-line interface (Typer).

Phase 1 skeleton: version, init-scope, scan (stub), report. Recon and the
vulnerability modules are wired in during later phases. Nothing here attacks
anything -- scan only validates scope and prepares the findings DB.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import typer

from apistrike.core.config import Settings
from apistrike.core.findings import FindingsStore
from apistrike.core.scope import Scope, OutOfScopeError
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
) -> None:
    """Run a scan (Phase 1 stub: validates scope + prepares findings DB)."""
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
    with FindingsStore(settings.findings_db) as store:
        summary = store.summary()

    typer.echo(f"Target {target} is IN SCOPE. Safe mode: {sc.safe_mode}.")
    typer.echo(
        f"Findings DB ready at {settings.findings_db} ({summary['total']} existing)."
    )
    typer.echo("Recon + vulnerability modules land in later phases. Nothing was attacked.")


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
