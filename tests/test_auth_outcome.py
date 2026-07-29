"""#91/#101: login attempts are classified by status AND body."""
import json

import pytest

from apistrike.auth.auth_engine import AuthEngine, AuthError, AuthOutcome


def _eng():
    return AuthEngine(client=None, base_url="http://localhost:5000")


def test_vampi_200_fail_is_credentials_rejected():
    # VAmPI returns HTTP 200 + {"status": "fail"} for wrong credentials (#91).
    body = json.dumps({"status": "fail", "message": "Password is not correct for the given username."})
    assert _eng().classify_login(200, body) is AuthOutcome.CREDENTIALS_REJECTED


def test_200_with_token_is_success():
    body = json.dumps({"message": "ok", "auth_token": "TOK"})
    assert _eng().classify_login(200, body) is AuthOutcome.SUCCESS


def test_200_without_token_or_marker_is_token_not_found():
    body = json.dumps({"message": "no token here"})
    assert _eng().classify_login(200, body) is AuthOutcome.TOKEN_NOT_FOUND


def test_401_is_credentials_rejected():
    assert _eng().classify_login(401, "") is AuthOutcome.CREDENTIALS_REJECTED


def test_500_is_transport_error():
    assert _eng().classify_login(500, "boom") is AuthOutcome.TRANSPORT_ERROR


def test_success_marker_false_is_rejected():
    body = json.dumps({"success": False, "detail": "nope"})
    assert _eng().classify_login(200, body) is AuthOutcome.CREDENTIALS_REJECTED


def test_apply_token_response_rejection_message_is_distinct():
    eng = _eng()
    ident = eng.add_identity("u", username="u", password="p")
    with pytest.raises(AuthError) as ei:
        eng._apply_token_response(ident, json.dumps({"status": "fail", "message": "bad creds"}))
    assert ei.value.outcome is AuthOutcome.CREDENTIALS_REJECTED


def test_apply_token_response_missing_is_token_not_found():
    # Backwards compatible: still raises ValueError (AuthError subclasses it).
    eng = _eng()
    ident = eng.add_identity("u", username="u", password="p")
    with pytest.raises(ValueError) as ei:
        eng._apply_token_response(ident, json.dumps({"message": "nothing"}))
    assert ei.value.outcome is AuthOutcome.TOKEN_NOT_FOUND
