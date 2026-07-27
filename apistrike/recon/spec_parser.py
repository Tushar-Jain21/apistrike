"""OpenAPI / Swagger spec parser for APIStrike.

Turns an API description (OpenAPI 3.x or Swagger 2.0, from a URL or a local
file, JSON or YAML) into a flat, structured list of endpoints the rest of the
engine can reason about. Deliberately dependency-light: it needs only the
standard library + PyYAML, so it is easy to test and never fails to import.

Deep schema resolution (for injection / mass-assignment payloads) will layer on
top of this later using prance when we actually need full request-body schemas.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

import yaml

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


@dataclass
class Param:
    name: str
    location: str = "query"  # path | query | header | cookie
    required: bool = False
    type: str = "string"


@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: str = ""
    summary: str = ""
    parameters: list = field(default_factory=list)
    has_request_body: bool = False
    security: list = field(default_factory=list)
    tags: list = field(default_factory=list)

    @property
    def path_params(self) -> list:
        return [p for p in self.parameters if p.location == "path"]

    @property
    def requires_auth(self) -> bool:
        return bool(self.security)

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


@dataclass
class APISpec:
    title: str
    version: str
    base_url: str
    endpoints: list = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.endpoints)

    def by_method(self, method: str) -> list:
        m = method.upper()
        return [e for e in self.endpoints if e.method == m]

    def with_path_params(self) -> list:
        return [e for e in self.endpoints if e.path_params]

    def authed(self) -> list:
        return [e for e in self.endpoints if e.requires_auth]


def _looks_like_url(source: str) -> bool:
    return source.startswith(("http://", "https://"))


def _load_raw(source: str) -> dict:
    """Fetch/read a spec from a URL or file path and parse JSON or YAML."""
    if _looks_like_url(source):
        with urlopen(source, timeout=15) as resp:  # noqa: S310 (trusted, in-scope target)
            text = resp.read().decode("utf-8")
    else:
        text = Path(source).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("Spec did not parse into a mapping/object.")
        return data


def _base_url_from_spec(spec: dict) -> str:
    # OpenAPI 3.x
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        if url:
            return url.rstrip("/")
    # Swagger 2.0
    host = spec.get("host")
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        base = spec.get("basePath", "") or ""
        return f"{scheme}://{host}{base}".rstrip("/")
    return ""


def _parse_params(raw) -> list:
    out: list = []
    for p in raw or []:
        if not isinstance(p, dict) or "$ref" in p:
            continue
        schema = p.get("schema", {}) or {}
        out.append(
            Param(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=bool(p.get("required", False)),
                type=schema.get("type", p.get("type", "string")),
            )
        )
    return out


def parse_spec(spec: dict, base_url: str | None = None) -> APISpec:
    """Transform a loaded spec dict into an APISpec (pure, no I/O)."""
    info = spec.get("info", {}) or {}
    title = info.get("title", "Unknown API")
    version = info.get("version", "0.0.0")
    resolved_base = base_url if base_url is not None else _base_url_from_spec(spec)

    global_security = spec.get("security", []) or []
    endpoints: list = []
    paths = spec.get("paths", {}) or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = _parse_params(item.get("parameters", []))
        for method, op in item.items():
            m = method.lower()
            if m not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params = shared + _parse_params(op.get("parameters", []))
            security = op.get("security", global_security)
            endpoints.append(
                Endpoint(
                    method=m.upper(),
                    path=path,
                    operation_id=op.get("operationId", ""),
                    summary=op.get("summary", "") or op.get("description", ""),
                    parameters=params,
                    has_request_body=bool(op.get("requestBody")),
                    security=security or [],
                    tags=op.get("tags", []) or [],
                )
            )
    endpoints.sort(key=lambda e: (e.path, e.method))
    return APISpec(title=title, version=version, base_url=resolved_base, endpoints=endpoints)


def load_spec(source: str, base_url: str | None = None) -> APISpec:
    """Load a spec from a URL or file path and parse it into an APISpec."""
    raw = _load_raw(source)
    if base_url is None:
        derived = _base_url_from_spec(raw)
        if _looks_like_url(source):
            u = urlparse(source)
            origin = f"{u.scheme}://{u.netloc}"
            if not derived:
                base_url = origin
            elif derived.startswith("http"):
                base_url = derived
            else:  # relative server url like "/" or "/api"
                base_url = (origin + derived).rstrip("/")
        else:
            base_url = derived
    return parse_spec(raw, base_url=base_url)
