"""Tests for the Excessive Data Exposure module (OWASP API3:2023)."""
import asyncio

from apistrike.modules.data_exposure import (
    DataExposureModule,
    DataExposureTarget,
    _entropy,
    _luhn_ok,
    _looks_hashed,
    _mask,
    _strip_markup_noise,
    _is_probable_secret,
)


class Resp:
    def __init__(self, body, status=200):
        self.body = body
        self.status_code = status


class Client:
    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = []

    async def request(self, method, url, headers=None, params=None, json=None):
        self.calls.append((method, url))
        path = url.split("http://t", 1)[-1] or "/"
        for key, body in self.bodies.items():
            if url.endswith(key):
                return Resp(body)
        return Resp(self.bodies.get(path, ""))


def run(coro):
    return asyncio.run(coro)


SECRETS = '{"key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIExx\\n-----END RSA PRIVATE KEY-----"}'
DEBUG = '{"users": [{"email": "a@example.com", "password": "hunter2"}]}'
ENTROPY = '{"blob": "aZ9kQ2mX7pL4vB8nR3tW6yE1uH5sD0fG"}'
CLEAN = '{"status": "ok", "items": [1, 2, 3]}'

# Regression fixture: HTML with inline SVG path data + timestamped asset
# filenames + a token buried in <script>. None of these are secrets and the
# entropy check must stay silent (previously all were false-positives).
SVG_NOISE = (
    '<html><body>'
    '<svg viewBox="0 0 24 24"><path d="M11.2079V11.9043H10.9933C112.217V1146H-1V110.832Z"/></svg>'
    '<img src="/wp-content/uploads/1758701012gemini_generated_image_vje60avje60avje6.png">'
    '<img src="/1759740674untitleddesign.png">'
    '<script>var x="aZ9kQ2mX7pL4vB8nR3tW6yE1uH5sD0fG";</script>'
    '</body></html>'
)


def test_secret_detection():
    cli = Client({"/s": SECRETS})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/s")], checks=("secrets",)).run())
    assert any("Private key" in f.title for f in res.findings)


def test_field_detection_plaintext_password():
    cli = Client({"/d": DEBUG})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/d")], checks=("fields",)).run())
    titles = " ".join(f.title for f in res.findings)
    assert "password" in titles


def test_pii_email_detection():
    cli = Client({"/d": DEBUG})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/d")], checks=("pii",)).run())
    assert any("email" in f.title for f in res.findings)


def test_entropy_detection():
    cli = Client({"/e": ENTROPY})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/e")], checks=("entropy",), entropy_min_len=24).run())
    assert len(res.findings) == 1
    assert "entropy" in res.findings[0].title.lower()


def test_entropy_ignores_svg_and_filenames():
    """SVG path coordinates, asset filenames and <script> blobs must not be
    reported as high-entropy secrets."""
    cli = Client({"/html": SVG_NOISE})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/html")], checks=("entropy",), entropy_min_len=24).run())
    assert res.findings == []


def test_strip_markup_noise_removes_paths_and_scripts():
    cleaned = _strip_markup_noise(SVG_NOISE)
    assert "11.2079V11.9043" not in cleaned
    assert "aZ9kQ2mX7pL4vB8nR3tW6yE1uH5sD0fG" not in cleaned  # inside <script>


def test_is_probable_secret_rejects_wordy_filenames():
    assert _is_probable_secret("aZ9kQ2mX7pL4vB8nR3tW6yE1uH5sD0fG", 4.0) is True
    assert _is_probable_secret("1759740674untitleddesign", 4.0) is False
    assert _is_probable_secret("generatedimage12345678", 4.0) is False


def test_clean_response_no_findings():
    cli = Client({"/c": CLEAN})
    res = run(DataExposureModule(cli, "http://t", [DataExposureTarget("/c")]).run())
    assert res.findings == []
    assert res.notes


def test_helpers():
    assert _entropy("") == 0.0
    assert _luhn_ok("4111111111111111") is True
    assert _luhn_ok("1234567890123") is False
    assert _looks_hashed("5f4dcc3b5aa765d61d8327deb882cf99") is True
    assert _looks_hashed("hunter2") is False
    assert "redacted" in _mask("supersecretvalue123")
