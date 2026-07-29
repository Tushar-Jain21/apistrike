"""Tests for CLI-layer target normalization (PR-2 / v1.1.1)."""
from urllib.parse import urlparse

from apistrike.core.scope import Scope, normalize_target


def test_bare_host_gets_https():
    assert normalize_target("quisitivebusinesses.com") == "https://quisitivebusinesses.com"


def test_bare_host_with_port_and_path():
    out = normalize_target("api.example.com:8443/v1")
    assert out == "https://api.example.com:8443/v1"
    assert urlparse(out).hostname == "api.example.com"
    assert urlparse(out).port == 8443


def test_explicit_scheme_preserved():
    assert normalize_target("http://host/x") == "http://host/x"
    assert normalize_target("https://host/x") == "https://host/x"


def test_whitespace_trimmed():
    assert normalize_target("  example.com  ") == "https://example.com"


def test_empty_passthrough():
    assert normalize_target("") == ""
    assert normalize_target(None) is None


def test_scope_accepts_normalized_bare_host():
    sc = Scope(allowed_hosts=["quisitivebusinesses.com"])
    assert sc.host_in_scope(normalize_target("quisitivebusinesses.com")) is True


def test_scope_still_strict_for_out_of_scope():
    sc = Scope(allowed_hosts=["quisitivebusinesses.com"])
    assert sc.host_in_scope(normalize_target("evil.example.org")) is False
