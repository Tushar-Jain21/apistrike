#!/usr/bin/env python3
"""Patch an apistrike scope file so the crAPI gateway is in scope.

We don't hard-code apistrike's scope schema here because init-scope owns it.
Instead we load whatever init-scope produced and, in a schema-tolerant way:
  * add the crAPI hosts to every list that already looks like a host allowlist
  * force safe_mode on (all crAPI probes in this workflow are read-only)
  * make sure at least one recognizable host key exists

Usage: python scripts/crapi_patch_scope.py scope.crapi.yaml
"""
from __future__ import annotations

import sys

try:
    import yaml  # PyYAML ships as an apistrike dependency
except Exception as exc:  # pragma: no cover
    print(f"PyYAML not available: {exc}", file=sys.stderr)
    raise SystemExit(1)

CRAPI_HOSTS = ["localhost", "127.0.0.1", "localhost:8888", "127.0.0.1:8888"]
HOST_KEYS = {"allowed_hosts", "hosts", "targets", "allowlist", "allowed", "in_scope"}


def looks_like_host_list(value: object) -> bool:
    if not isinstance(value, list):
        return False
    return all(isinstance(v, str) for v in value)


def merge_hosts(existing: list[str]) -> list[str]:
    out = list(existing)
    for h in CRAPI_HOSTS:
        if h not in out:
            out.append(h)
    return out


def patch(node: object) -> bool:
    """Recursively inject hosts. Returns True if any host list was updated."""
    touched = False
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if key in HOST_KEYS and looks_like_host_list(value):
                node[key] = merge_hosts(value)
                touched = True
            elif key in {"safe_mode", "safe"} and isinstance(value, bool):
                node[key] = True
            else:
                touched = patch(value) or touched
    elif isinstance(node, list):
        for item in node:
            touched = patch(item) or touched
    return touched


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: crapi_patch_scope.py <scope.yaml>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    touched = patch(data)

    if not touched:
        # Nothing looked like a host allowlist; add a conventional one and
        # print a loud note so we can tune the key name from the CI log.
        if isinstance(data, dict):
            data["allowed_hosts"] = merge_hosts([])
            data.setdefault("safe_mode", True)
            print(
                "NOTE: no existing host allowlist recognized; added "
                "'allowed_hosts'. If apistrike uses a different key, tell me "
                "the schema and I'll adjust crapi_patch_scope.py.",
                file=sys.stderr,
            )
        else:
            print("ERROR: scope root is not a mapping; cannot patch.", file=sys.stderr)
            return 1

    # Force safe_mode true at the top level too, regardless of nesting.
    if isinstance(data, dict):
        data["safe_mode"] = True

    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, default_flow_style=False)
    print(f"Patched {path}: crAPI hosts added, safe_mode enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
