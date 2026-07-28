#!/usr/bin/env python3
"""Seed a disposable crAPI user and print credentials + the login response.

crAPI's identity service lets you sign up and log in directly (no OTP needed
for a password login; OTP/MailHog is only required for the vehicle + forgot
password flows, which we don't need for scanning).

Output (stdout) is machine-parseable by the workflow:
    EMAIL=<email>
    PASSWORD=<password>
    TOKEN=<jwt or empty>
plus the raw HTTP responses for debugging.

Uses only the Python standard library.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("CRAPI_BASE", "http://localhost:8888")
SIGNUP = BASE + "/identity/api/auth/signup"
LOGIN = BASE + "/identity/api/auth/login"


def post_json(url: str, payload: dict) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover
        return 0, f"<request error: {exc}>"


def main() -> int:
    stamp = int(time.time())
    email = f"apistrike+{stamp}@example.com"
    password = "Apistrike!23456"
    number = f"9{stamp % 1000000000:09d}"

    signup_payload = {
        "name": "apistrike scanner",
        "email": email,
        "number": number,
        "password": password,
    }
    s_status, s_body = post_json(SIGNUP, signup_payload)
    print(f"--- signup HTTP {s_status} ---", file=sys.stderr)
    print(s_body, file=sys.stderr)

    # A small pause lets the identity service persist the new user.
    time.sleep(3)

    l_status, l_body = post_json(LOGIN, {"email": email, "password": password})
    print(f"--- login HTTP {l_status} ---", file=sys.stderr)
    print(l_body, file=sys.stderr)

    token = ""
    try:
        parsed = json.loads(l_body)
        if isinstance(parsed, dict):
            token = parsed.get("token") or parsed.get("access_token") or ""
    except Exception:
        pass

    # Machine-parseable lines for the workflow (stdout only).
    print(f"EMAIL={email}")
    print(f"PASSWORD={password}")
    print(f"TOKEN={token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
