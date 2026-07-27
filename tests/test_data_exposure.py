"""Socket-free pytest suite for the Excessive Data Exposure module (API3:2023)."""
import asyncio

import pytest

from apistrike.modules.data_exposure import (
    DataExposureModule, DataExposureTarget, OWASP_ID, ALL_CHECKS,
    _entropy, _luhn_ok, _looks_hashed, _mask,
)


class Resp:
    def __init__(self, body="", status=200):
        self.body = body
        self.status_code = status
        self.elapsed_ms = 5.0


class Client:
    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = []

    async def request(self, method, url, headers=None, params=None, json=None):
        path = url.split("://", 1)[-1]
        slash = path.find("/")
        path = path[slash:] if slash >= 0 else "/"
        self.calls.append((method, path))
        return Resp(self.bodies.get(path, "{}"))


def run(coro):
    return asyncio.run(coro)


DEBUG = '{"users": [{"email": "a@example.com", "password": "pass1"}, {"email": "b@example.com", "password": "pass2"}]}'
HASHED = '{"password": "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"}'
SECRETS = 'k -----BEGIN RSA PRIVATE KEY-----MIIB AKIAABCDEFGHIJKLMNOP eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklm postgres://u:p3w@db:5432/app'
CLEAN = '{"items": [{"id": 1, "name": "widget"}]}'
CARD = '{"card_number": "4111111111111111", "cvv": "123"}'
SSN = 'record 123-45-6789 present'
ENTROPY = '{"blob": "aZ9kQ2mX7pL4vB8nR3tW6yE1uH5sD0fG"}'


def test_taxonomy():
    assert OWASP_ID == "API3:2023"
    assert set(ALL_CHECKS) == {"secrets", "fields", "pii", "entropy"}


def test_helpers():
    assert _luhn_ok("4111111111111111")
    assert not _luhn_ok("4111111111111112")
    assert _entropy("aaaa") == 0.0
    assert _looks_hashed("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW")
    assert not _looks_hashed("pass1")
    assert "redacted" in _mask("supersecretvalue")


def test_empty_targets_raise():
    with pytest.raises(ValueError):
        DataExposureModule(Client({}), "http://t", [])


def test_invalid_checks_raise():
    with pytest.raises(ValueError):
        DataExposureModule(Client({}), "http://t", [DataExposureTarget("/x")], checks=("nope",))


def test_plaintext_password_and_email():
    cli = Client({"/d": DEBUG})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/d")]).run())
    pw = [f for f in res.findings if "password" in f.title]
    assert len(pw) == 1 and pw[0].severity == "critical" and pw[0].cwe == "CWE-256"
    assert "PLAINTEXT" in pw[0].description
    assert "pass1" not in pw[0].evidence[0]
    assert any("email" in f.title for f in res.findings)


def test_hashed_password_no_plaintext_note():
    cli = Client({"/h": HASHED})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/h")], checks=("fields",)).run())
    pw = [f for f in res.findings if "password" in f.title]
    assert len(pw) == 1 and "PLAINTEXT" not in pw[0].description


def test_hard_secrets_detected_and_masked():
    cli = Client({"/s": SECRETS})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/s")], checks=("secrets",)).run())
    names = " ".join(f.title for f in res.findings)
    assert "Private key block" in names
    assert "AWS access key id" in names
    assert "JSON Web Token" in names
    assert "Database connection string" in names
    assert any(f.severity == "critical" for f in res.findings)
    assert all("p3w" not in ev for f in res.findings for ev in f.evidence)


def test_clean_response_no_findings():
    cli = Client({"/c": CLEAN})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/c")]).run())
    assert res.findings == []
    assert any("No excessive data exposure" in n for n in res.notes)


def test_payment_card_luhn():
    cli = Client({"/card": CARD})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/card")]).run())
    cc = [f for f in res.findings if "payment card" in f.title]
    assert len(cc) == 1 and cc[0].severity == "high"
    assert any("card_number" in f.title for f in res.findings)
    assert any("cvv" in f.title for f in res.findings)


def test_ssn_detection():
    cli = Client({"/ssn": SSN})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/ssn")], checks=("pii",)).run())
    ssn = [f for f in res.findings if "SSN" in f.title]
    assert len(ssn) == 1 and ssn[0].severity == "high"
    assert "123-45-6789" not in ssn[0].evidence[0]


def test_entropy_detection():
    cli = Client({"/e": ENTROPY})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/e")], checks=("entropy",), entropy_min_len=24).run())
    assert len(res.findings) == 1 and res.findings[0].severity == "low"


def test_request_count_and_store():
    class Store:
        def __init__(self):
            self.items = []
        def add(self, f):
            self.items.append(f)
    store = Store()
    cli = Client({"/d": DEBUG, "/c": CLEAN})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/d"), DataExposureTarget("/c")]).run(store=store))
    assert res.requests_made == 2
    assert len(store.items) == len(res.findings) and len(res.findings) >= 2
