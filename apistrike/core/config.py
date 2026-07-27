"""Runtime configuration for APIStrike.

Loads settings from environment variables (APISTRIKE_*) with sensible
defaults. Dependency-free so it works everywhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_TRUTHY = ("1", "true", "True", "yes", "on")


@dataclass
class Settings:
    findings_db: str = "findings.db"
    output_dir: str = "reports"
    scope_file: str = "scope.yaml"
    # AI layer (Phase 5) -- local-first, model-agnostic.
    ai_provider: str = "ollama"
    ai_model: str = "llama3"
    ai_base_url: str = "http://localhost:11434"
    ai_enabled: bool = False

    @classmethod
    def load(cls) -> "Settings":
        env = os.environ.get
        return cls(
            findings_db=env("APISTRIKE_DB", "findings.db"),
            output_dir=env("APISTRIKE_OUTPUT", "reports"),
            scope_file=env("APISTRIKE_SCOPE", "scope.yaml"),
            ai_provider=env("APISTRIKE_AI_PROVIDER", "ollama"),
            ai_model=env("APISTRIKE_AI_MODEL", "llama3"),
            ai_base_url=env("APISTRIKE_AI_URL", "http://localhost:11434"),
            ai_enabled=env("APISTRIKE_AI_ENABLED", "0") in _TRUTHY,
        )

    def ensure_output_dir(self) -> Path:
        p = Path(self.output_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p
