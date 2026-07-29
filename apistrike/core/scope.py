"""Authorization scope guardrails for APIStrike.

Every outbound request MUST pass through an in-scope check. This is the
core safety mechanism that keeps the tool authorized-only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
import re

import yaml


class OutOfScopeError(Exception):
    """Raised when a request target is not in the authorized scope."""


@dataclass
class Scope:
    allowed_hosts: list[str] = field(default_factory=list)
    rate_limit: float = 5.0
    max_requests: int = 5000
    safe_mode: bool = True
    allow_destructive: bool = False

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")
        data = yaml.safe_load(path.read_text()) or {}
        return cls(
            allowed_hosts=[str(h).lower() for h in data.get("allowed_hosts", [])],
            rate_limit=float(data.get("rate_limit", 5.0)),
            max_requests=int(data.get("max_requests", 5000)),
            safe_mode=bool(data.get("safe_mode", True)),
            allow_destructive=bool(data.get("allow_destructive", False)),
        )

    def host_in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        for allowed in self.allowed_hosts:
            if host == allowed or host.endswith("." + allowed):
                return True
        return False

    def assert_in_scope(self, url: str) -> None:
        if not self.host_in_scope(url):
            raise OutOfScopeError(
                f"Refusing request to out-of-scope host: {url!r}. "
                f"Allowed hosts: {self.allowed_hosts}"
            )


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_target(raw: str, default_scheme: str = "https") -> str:
    """Normalize a user-supplied target host or URL (CLI/adapter layer only).

    A bare, scheme-less input such as ``api.example.com`` or
    ``api.example.com:8443/base`` gets ``default_scheme`` ("https") prepended so
    it is accepted instead of being silently refused by the scope check. Inputs
    that already carry an explicit scheme are returned unchanged -- so
    ``http://host`` still forces plaintext HTTP. ``Scope`` itself stays strict;
    this helper only makes the CLI forgiving about a missing scheme.
    """
    if not raw:
        return raw
    stripped = raw.strip()
    if not stripped:
        return raw
    if _SCHEME_RE.match(stripped):
        return stripped
    return default_scheme + "://" + stripped
