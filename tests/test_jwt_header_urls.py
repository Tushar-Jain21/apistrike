"""Offline tests for the jku/x5u forging logic. No network, no live target.
Loads the module by path so it works even where the full package can't import."""
import base64
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
MOD = HERE.parent / "apistrike" / "modules" / "jwt_header_urls.py"


def _load():
    spec = importlib.util.spec_from_file_location("jwt_header_urls", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _b64d(seg):
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def _fake_token(payload):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return "aGVhZGVy." + body + ".c2ln"


def test_build_jku_places_url_and_alg():
    m = _load()
    tok = m.build_header_url_jwt("jku", "http://oast.example/j", {"role": "user"}, lambda b: b"sig")
    h, p, s = tok.split(".")
    hd = _b64d(h)
    assert hd["jku"] == "http://oast.example/j"
    assert hd["alg"] == "RS256" and hd["typ"] == "JWT" and hd["kid"] == "apistrike"
    assert _b64d(p)["role"] == "user"
    assert s, "signature segment must be present"


def test_build_x5u_places_url():
    m = _load()
    tok = m.build_header_url_jwt("x5u", "http://oast.example/c.pem", {"a": 1}, lambda b: b"z")
    assert _b64d(tok.split(".")[0])["x5u"] == "http://oast.example/c.pem"


def test_unsupported_field_raises():
    m = _load()
    try:
        m.build_header_url_jwt("jwk", "http://x", {}, lambda b: b"s")
    except ValueError:
        return
    raise AssertionError("expected ValueError for unsupported header field")


def test_payload_of_roundtrip():
    m = _load()
    assert m._payload_of(_fake_token({"sub": "x"}))["sub"] == "x"


def test_admin_payload_forces_admin():
    m = _load()
    p = m._admin_payload(_fake_token({"sub": "x", "role": "user"}))
    assert p.get("role") == "admin" or p.get("is_admin") is True


def test_forge_returns_token_when_crypto_available():
    m = _load()
    if not getattr(m, "_CRYPTO", False):
        return  # skipped where cryptography isn't installed (e.g. offline sandbox)
    forged = m.forge_jku_injection(_fake_token({"sub": "x"}), "http://oast.example/j")
    assert forged and forged.count(".") == 2
    assert _b64d(forged.split(".")[0])["jku"] == "http://oast.example/j"
