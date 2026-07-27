import pytest

from apistrike.core.scope import Scope, OutOfScopeError


def make_scope():
    return Scope(allowed_hosts=["localhost", "example.com"])


def test_host_in_scope():
    s = make_scope()
    assert s.host_in_scope("http://localhost:8080/api")
    assert s.host_in_scope("https://api.example.com/v1")
    assert not s.host_in_scope("https://evil.com/")


def test_assert_raises_out_of_scope():
    s = make_scope()
    with pytest.raises(OutOfScopeError):
        s.assert_in_scope("https://evil.com/")
