"""Tests for the AI layer -- provider, planner, analyst, reporter.

All offline: NoOpProvider and MockProvider only, no Ollama, no network.
"""
import asyncio
import pytest

from apistrike.ai.provider import NoOpProvider, OllamaProvider, MockProvider, load_provider
from apistrike.ai.planner import AIPlanner, _heuristic_plan, _parse_llm_plan
from apistrike.ai.analyst import AIAnalyst, _heuristic_analysis, _parse_analysis
from apistrike.ai.reporter import AIReporter, _default_summary, _default_narrative


def run(coro):
    return asyncio.run(coro)


class EP:
    def __init__(self, method, path, auth=False, body=False):
        self.method = method; self.path = path
        self.requires_auth = auth; self.has_request_body = body


class F:
    def __init__(self, title, severity, owasp_id, endpoint="", description="", cwe=""):
        self.title = title; self.severity = severity; self.owasp_id = owasp_id
        self.endpoint = endpoint; self.description = description; self.cwe = cwe


EPS = [
    EP("GET",  "/users/v1/{user_id}", auth=True),
    EP("POST", "/users/v1/login"),
    EP("GET",  "/users/v1/_debug", auth=True),
    EP("POST", "/users/v1/register", body=True),
]

FINDS = [
    F("BOLA cross-user read",   "critical", "API1:2023", "GET /users/v1/{user_id}", "User A reads User B.", "CWE-639"),
    F("Mass assignment admin",  "high",     "API3:2023", "POST /users/v1/register", "admin=true accepted.", "CWE-915"),
    F("Exposed debug endpoint", "high",     "API8:2023", "GET /users/v1/_debug",   "Dumps all records.",   "CWE-489"),
]


# ---- Provider ----

def test_noop_empty():
    assert run(NoOpProvider().complete("hi")) == ""
    assert not NoOpProvider().is_available


def test_mock_string():
    p = MockProvider("fixed")
    assert run(p.complete("x")) == "fixed"
    assert p.is_available


def test_mock_callable():
    assert run(MockProvider(lambda p: p[:3]).complete("hello")) == "hel"


def test_ollama_graceful_fail():
    assert run(OllamaProvider(base_url="http://localhost:19999", timeout=0.5).complete("ping")) == ""


def test_load_provider_noop_fallback():
    p, notes = load_provider(base_url="http://localhost:19999")
    assert isinstance(p, NoOpProvider)
    assert any("not reachable" in n for n in notes)


# ---- Planner ----

def test_planner_noop_heuristic():
    r = run(AIPlanner(NoOpProvider()).plan(EPS))
    assert len(r.items) > 0 and not r.ai_used


def test_planner_empty():
    assert run(AIPlanner(NoOpProvider()).plan([])).items == []


def test_heuristic_items_valid():
    items = _heuristic_plan(EPS)
    assert all(i.module for i in items)
    assert all(i.risk in ("HIGH", "MEDIUM", "LOW") for i in items)


def test_planner_mock_parses():
    resp = (
        "1. GET /users/v1/{user_id} | Module: BOLA | Risk: HIGH | Reason: Enumerable IDs.\n"
        "2. POST /users/v1/login | Module: BrokenAuth | Risk: HIGH | Reason: JWT risk.\n"
    )
    r = run(AIPlanner(MockProvider(resp)).plan(EPS))
    assert len(r.items) >= 2 and r.ai_used
    assert r.items[0].module == "BOLA"


def test_planner_unparseable_fallback():
    r = run(AIPlanner(MockProvider("sorry")).plan(EPS))
    assert len(r.items) > 0


# ---- Analyst ----

def test_analyst_noop():
    r = run(AIAnalyst(NoOpProvider()).analyse(FINDS))
    assert not r.ai_used and any("heuristic" in n for n in r.notes)


def test_analyst_known_chain():
    assert len(_heuristic_analysis(FINDS).chains) > 0


def test_analyst_no_findings():
    r = run(AIAnalyst(NoOpProvider()).analyse([]))
    assert r.chains == [] and any("No findings" in n for n in r.notes)


def test_analyst_llm_parsed():
    llm = "CHAINS:\n- A -> B: chain.\nFALSE_POSITIVES:\n- C: maybe FP.\nADDITIONAL_CHECKS:\n- Check X.\n"
    r = run(AIAnalyst(MockProvider(llm)).analyse(FINDS))
    assert r.chains == ["A -> B: chain."] and r.false_positives == ["C: maybe FP."] and r.ai_used


def test_parse_analysis_helper():
    chains, fps, chk = _parse_analysis("CHAINS:\n- A->B\nFALSE_POSITIVES:\nADDITIONAL_CHECKS:\n- do X")
    assert chains == ["A->B"] and fps == [] and chk == ["do X"]


# ---- Reporter ----

def test_reporter_noop_summary():
    s = run(AIReporter(NoOpProvider()).exec_summary(FINDS, target="VAmPI"))
    assert len(s) > 20


def test_reporter_noop_narrative():
    assert len(run(AIReporter(NoOpProvider()).finding_narrative(FINDS[0]))) > 20


def test_reporter_empty_findings():
    assert "No findings" in run(AIReporter(NoOpProvider()).enrich_report([])).exec_summary


def test_reporter_enrich_full():
    r = run(AIReporter(NoOpProvider()).enrich_report(FINDS, target="VAmPI"))
    assert r.exec_summary and len(r.narratives) == len(FINDS) and not r.ai_used


def test_reporter_mock_llm():
    assert run(AIReporter(MockProvider("AI text.")).exec_summary(FINDS, target="T")) == "AI text."


def test_default_summary_severity():
    s = _default_summary(FINDS, "API", "2026-07-27")
    assert any(w in s.upper() for w in ("CRITICAL", "HIGH", "RISK"))


# --- Regression: findings loaded from FindingsStore.all() are dicts, not objects ---
# This is the exact shape returned by the SQLite store (row_factory -> dict).
DICT_FINDS = [
    {"title": "Password hash exposed in user object", "severity": "critical",
     "owasp_id": "API3:2023", "owasp_name": "Broken Object Property Level Authorization",
     "cwe": "CWE-359", "endpoint": "GET /users/v1/{username}",
     "description": "Response includes the bcrypt password hash.", "recommendation": "Strip sensitive fields.",
     "confidence": "confirmed", "evidence": [], "created_at": "2026-07-28T00:00:00+00:00"},
    {"title": "Debug endpoint exposes all users", "severity": "high",
     "owasp_id": "API8:2023", "owasp_name": "Security Misconfiguration",
     "cwe": "CWE-489", "endpoint": "GET /users/v1/_debug",
     "description": "Dumps every account with password hashes.", "recommendation": "Remove debug route.",
     "confidence": "confirmed", "evidence": [], "created_at": "2026-07-28T00:00:00+00:00"},
]


def test_reporter_dict_summary_not_blank():
    s = _default_summary(DICT_FINDS, "VAmPI", "2026-07-28")
    # Must reflect the CRITICAL finding and name the top issue -- never blank.
    assert "CRITICAL" in s.upper()
    assert "Password hash exposed in user object" in s
    assert "; ." not in s  # the old blank-title bug produced "were: ; ."


def test_reporter_dict_narrative_not_blank():
    n = _default_narrative(DICT_FINDS[0])
    assert "critical-severity" in n
    assert "GET /users/v1/{username}" in n


def test_reporter_dict_enrich_full():
    r = run(AIReporter(NoOpProvider()).enrich_report(DICT_FINDS, target="VAmPI"))
    assert len(r.narratives) == 2
    assert all(v and "None" not in v for v in r.narratives.values())
    assert "Password hash exposed in user object" in r.narratives


def test_analyst_dict_chain_detected():
    # API8 + API3 present -> known chain must fire on dict findings.
    res = run(AIAnalyst(NoOpProvider()).analyse(DICT_FINDS, target="VAmPI"))
    assert any("debug" in c.lower() or "data exposure" in c.lower() for c in res.chains)


def test_field_accessor_handles_both_shapes():
    from apistrike.ai.reporter import _fv
    assert _fv({"severity": "high"}, "severity") == "high"
    assert _fv(F("t", "low", "API1:2023"), "severity") == "low"
    assert _fv({"x": None}, "x", "fallback") == "fallback"
    assert _fv({}, "missing", "d") == "d"


# --- Provider: model-presence matching (llama3 <-> llama3:latest trap) ---
def test_model_present_matching():
    from apistrike.ai.provider import _model_present
    # Ollama stores a bare `ollama pull llama3` as `llama3:latest`.
    assert _model_present("llama3", ["llama3:latest"]) is True
    assert _model_present("llama3", ["llama3"]) is True
    assert _model_present("llama3:latest", ["llama3:latest"]) is True
    assert _model_present("llama3.2:3b", ["llama3.2:3b"]) is True
    # Explicit tag must not match a different tag.
    assert _model_present("llama3:70b", ["llama3:8b"]) is False
    # Empty / missing.
    assert _model_present("llama3", []) is False
    assert _model_present("mistral", ["llama3:latest", "qwen2:1.5b"]) is False


def test_load_provider_unreachable_still_noop():
    # Nothing listening -> NoOp + 'not reachable' note (unchanged behaviour).
    p, notes = load_provider(base_url="http://localhost:19998")
    assert not p.is_available
    assert any("not reachable" in n for n in notes)


# --- Analyst parser robustness (small local models add markdown/varied bullets) ---
def test_parse_analysis_plain_format():
    from apistrike.ai.analyst import _parse_analysis
    raw = "CHAINS:\n- A -> B: x\nFALSE_POSITIVES:\n- t: reason\nADDITIONAL_CHECKS:\n- do a check\n"
    chains, fps, checks = _parse_analysis(raw)
    assert chains and fps and checks


def test_parse_analysis_markdown_variants():
    from apistrike.ai.analyst import _parse_analysis
    raw = (
        "Sure! Here is my analysis:\n\n"
        "**CHAINS:**\n"
        "1. BOLA read -> Data exposure: leaks fields.\n"
        "* Broken auth -> BOLA: forged token.\n\n"
        "**FALSE POSITIVES:**\n"
        "- Swagger UI exposure: intended in staging.\n\n"
        "### ADDITIONAL CHECKS\n"
        "- Probe /console for RCE.\n"
    )
    chains, fps, checks = _parse_analysis(raw)
    assert len(chains) == 2, chains
    assert len(fps) == 1, fps
    assert len(checks) == 1, checks


def test_parse_analysis_preamble_ignored():
    from apistrike.ai.analyst import _parse_analysis
    raw = "Here are my thoughts before the format.\nNo headers yet.\nCHAINS:\n- A -> B: y\n"
    chains, fps, checks = _parse_analysis(raw)
    assert chains == ["A -> B: y"]
    assert not fps and not checks


def test_analyst_note_when_llm_unparseable():
    # LLM available but returns junk -> heuristic fallback with a HONEST note.
    res = run(AIAnalyst(MockProvider("total gibberish, no sections here")).analyse(DICT_FINDS, target="VAmPI"))
    assert res.ai_used is False
    assert any("could not be parsed" in n for n in res.notes)
    # Must NOT claim 'no LLM available' -- the LLM WAS available, just unparseable.
    assert not any("no LLM available" in n for n in res.notes)


def test_analyst_llm_parsed_marks_ai_used():
    llm = "**CHAINS:**\n- Debug endpoint -> Data exposure: leaks all users.\n"
    res = run(AIAnalyst(MockProvider(llm)).analyse(DICT_FINDS, target="VAmPI"))
    assert res.ai_used is True
    assert res.chains and "Debug endpoint" in res.chains[0]
