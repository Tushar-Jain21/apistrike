"""PR-8a: the `auto` command exposes --auth-profile and can load declarative
identities from a scope's `auth:` block.

These tests run in the full dev environment (typer + httpx installed). They do
NOT touch the network. The flag test introspects the Click command object
instead of scraping Rich-rendered `--help` text (which wraps + injects ANSI
escape codes at narrow terminal widths, so a literal substring match is
unreliable across environments).
"""
import pytest

from apistrike.cli import app


def _auto_command():
    """Return the Click command object for `apistrike auto`."""
    from typer.main import get_command

    group = get_command(app)
    commands = getattr(group, "commands", {})
    assert "auto" in commands, f"'auto' command not registered; have: {sorted(commands)}"
    return commands["auto"]


def test_auto_defines_auth_profile_option():
    """Render-independent: the --auth-profile option must exist on `auto`."""
    cmd = _auto_command()
    option_flags = {flag for param in cmd.params for flag in getattr(param, "opts", [])}
    param_names = {param.name for param in cmd.params}
    assert "--auth-profile" in option_flags, f"flags: {sorted(option_flags)}"
    assert "auth_profile" in param_names, f"params: {sorted(param_names)}"


def test_auto_help_renders_cleanly():
    """Smoke test: `auto --help` exits 0 (no width/ANSI assumptions)."""
    from typer.testing import CliRunner

    result = CliRunner().invoke(app, ["auto", "--help"])
    assert result.exit_code == 0, result.output


def test_profiles_helper_is_importable_and_callable():
    from apistrike.auth.profiles import register_scope_identities

    assert callable(register_scope_identities)


class _FakeScope:
    """Duck-typed scope carrying only the `auth:` block auto reads."""

    def __init__(self, auth):
        self.auth = auth


class _FakeEngine:
    """Captures register_identity calls the way AuthEngine would."""

    def __init__(self):
        self.identities = {}
        from apistrike.auth.auth_engine import LoginConfig

        self.config = LoginConfig()

    def register_identity(self, ident):
        self.identities[ident.name] = ident
        return ident

    def profiles(self):
        return list(self.identities.values())


def test_register_scope_identities_builds_multiple(monkeypatch):
    """The exact call auto()'s profile branch makes must register N identities."""
    from apistrike.auth.profiles import register_scope_identities

    monkeypatch.setenv("PR8A_USER_PASS", "pw1")
    monkeypatch.setenv("PR8A_ADMIN_TOKEN", "header.payload.sig")
    scope = _FakeScope(
        [
            {"name": "user1", "type": "password", "username": "name1", "password": "${PR8A_USER_PASS}", "role": "user"},
            {"name": "admin", "type": "token", "token": "${PR8A_ADMIN_TOKEN}", "role": "admin"},
        ]
    )
    engine = _FakeEngine()
    idents = register_scope_identities(engine, scope)

    assert [i.name for i in idents] == ["user1", "admin"]
    assert engine.profiles() == idents
    assert {i.name: i.role for i in idents} == {"user1": "user", "admin": "admin"}
    assert engine.identities["admin"].token == "header.payload.sig"


def test_register_scope_identities_rejects_inline_secret():
    """ADR-0013: secret fields must be env-referenced, never inline literals."""
    from apistrike.auth.auth_engine import AuthError
    from apistrike.auth.profiles import register_scope_identities

    scope = _FakeScope([{"name": "u", "type": "password", "username": "u", "password": "hunter2"}])
    with pytest.raises(AuthError):
        register_scope_identities(_FakeEngine(), scope)


def test_no_profile_when_scope_has_no_auth():
    from apistrike.auth.profiles import register_scope_identities

    idents = register_scope_identities(_FakeEngine(), _FakeScope([]))
    assert idents == []
