"""AI provider interface (model-agnostic, local-first).

Three concrete types:
  OllamaProvider  -- calls http://localhost:11434/api/generate (stdlib urllib
                     in a thread-executor; no extra deps beyond stdlib).
  NoOpProvider    -- always returns ''; safe drop-in when Ollama is absent.
  MockProvider    -- returns a fixed string or callable result (tests/demos).

load_provider()  -- checks Ollama via /api/tags (2 s timeout) and distinguishes
                    three states: daemon unreachable, daemon up but the model
                    isn't installed, and ready. Returns OllamaProvider only when
                    the model is actually present; otherwise NoOpProvider plus a
                    precise, actionable note.

Design rule: providers MUST NOT raise -- they return '' on any error.
"""
from __future__ import annotations

import asyncio
import json
import urllib.request
from abc import ABC, abstractmethod
from typing import Callable, List, Optional, Union

OLLAMA_DEFAULT_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3"


class AIProvider(ABC):
    @abstractmethod
    async def complete(self, prompt: str, *, system: str = "", max_tokens: int = 1024) -> str: ...

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def is_available(self) -> bool:
        return True


class NoOpProvider(AIProvider):
    """Offline stub -- returns '' for every prompt."""
    async def complete(self, prompt: str, *, system: str = "", max_tokens: int = 1024) -> str:
        return ""

    @property
    def is_available(self) -> bool:
        return False


def _model_present(model: str, names: List[str]) -> bool:
    """True if `model` matches an installed Ollama model name.

    Ollama stores a plain pull like `llama3` as `llama3:latest`, so an exact
    match is not enough -- accept the bare name, the `:latest` variant, and any
    tagged variant of the same base when the caller gave no explicit tag.
    """
    if not names:
        return False
    base = model.split(":")[0]
    for n in names:
        if not n:
            continue
        if n == model or n == model + ":latest":
            return True
        if ":" not in model and n.split(":")[0] == base:
            return True
    return False


class OllamaProvider(AIProvider):
    """Calls a local Ollama instance (http://localhost:11434/api/generate)."""

    def __init__(self, model: str = OLLAMA_DEFAULT_MODEL,
                 base_url: str = OLLAMA_DEFAULT_URL,
                 timeout: float = 30.0) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _call_sync(self, payload: dict) -> str:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base_url + "/api/generate",
            data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")).get("response", "")

    async def complete(self, prompt: str, *, system: str = "", max_tokens: int = 1024) -> str:
        payload: dict = {"model": self.model, "prompt": prompt,
                         "stream": False, "options": {"num_predict": max_tokens}}
        if system:
            payload["system"] = system
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._call_sync, payload)
        except Exception:
            return ""

    def list_models(self, timeout: float = 2.0) -> Optional[List[str]]:
        """Return installed model names via GET /api/tags.

        Returns None if the daemon is unreachable (connection refused, timeout,
        DNS, etc.) so callers can tell 'daemon down' apart from 'no models'.
        """
        try:
            req = urllib.request.Request(self.base_url + "/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            return [str(m.get("name", "")) for m in data.get("models", [])]
        except Exception:
            return None

    def probe(self, timeout: float = 2.0) -> bool:
        """Liveness + model check: daemon reachable AND the model is installed."""
        models = self.list_models(timeout=timeout)
        if models is None:
            return False
        return _model_present(self.model, models)


class MockProvider(AIProvider):
    """Returns a canned response (string or callable). For tests and demos."""
    def __init__(self, response: Union[str, Callable[[str], str]]) -> None:
        self._response = response

    async def complete(self, prompt: str, *, system: str = "", max_tokens: int = 1024) -> str:
        return self._response(prompt) if callable(self._response) else str(self._response)


def load_provider(model: Optional[str] = None,
                  base_url: Optional[str] = None,
                  timeout: float = 30.0) -> tuple:
    """Return (provider, notes).

    Distinguishes three states and reports each precisely:
      1. Daemon unreachable        -> NoOpProvider + 'not reachable' note.
      2. Daemon up, model missing  -> NoOpProvider + 'running but model X not
                                       installed; run ollama pull X' note (lists
                                       what IS installed).
      3. Ready                     -> OllamaProvider.
    """
    notes: list[str] = []
    url = base_url or OLLAMA_DEFAULT_URL
    mdl = model or OLLAMA_DEFAULT_MODEL
    probe = OllamaProvider(model=mdl, base_url=url, timeout=timeout)
    models = probe.list_models(timeout=2.0)

    if models is None:
        notes.append(
            "AI: Ollama not reachable at " + url + ". "
            "Start it with `ollama serve` (then `ollama pull " + mdl + "`) to enable AI features. "
            "Continuing without AI (all modules still work normally)."
        )
        return NoOpProvider(), notes

    if not _model_present(mdl, models):
        installed = ", ".join(sorted(n for n in models if n)) if any(models) else "none"
        notes.append(
            "AI: Ollama is running at " + url + " but model '" + mdl + "' is not installed "
            "(installed: " + installed + "). "
            "Run `ollama pull " + mdl + "` to enable AI features. "
            "Continuing without AI (all modules still work normally)."
        )
        return NoOpProvider(), notes

    notes.append("AI: Ollama reachable at " + url + " (model=" + mdl + ").")
    return OllamaProvider(model=mdl, base_url=url, timeout=timeout), notes
