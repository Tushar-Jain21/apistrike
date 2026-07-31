"""Offline checks that the scan command exposes the JWT public-key flags and
wires them onto the BrokenAuthModule. Source-based so it needs no heavy deps."""
from pathlib import Path

CLI = Path(__file__).resolve().parents[1] / "apistrike" / "cli.py"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def test_pubkey_flag_declared():
    assert '"--pubkey"' in _src()


def test_jwks_url_flag_declared():
    assert '"--jwks-url"' in _src()


def test_pubkey_read_from_file_as_pem():
    src = _src()
    assert "module.public_key_pem = open(pubkey" in src


def test_jwks_url_wired_onto_module():
    assert "module.jwks_url = jwks_url" in _src()


def test_flags_are_optional_default_empty():
    # Both flags default to "" so existing scans keep working unchanged.
    src = _src()
    assert 'pubkey: str = typer.Option(""' in src
    assert 'jwks_url: str = typer.Option(""' in src
