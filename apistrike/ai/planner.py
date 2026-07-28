"""AI Planner -- prioritises test targets from a parsed API spec.

When Ollama is running, asks the LLM to rank the top-5 riskiest endpoints.
When it is not (NoOpProvider), applies a small set of heuristic rules so the
command always produces useful output.

GUARANTEED GUARDRAIL: the planner only SUGGESTS tests; it never fires requests
or creates findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, List, Sequence

_PLAN_SYSTEM = "You are an expert API penetration tester. Be specific, concise, and technical."

_PLAN_PROMPT = """You are planning API security tests for the following API.

API title  : {title}
Base URL   : {base_url}
Endpoints  : {count}

{endpoint_list}

Rank the TOP 5 highest-risk endpoints by vulnerability likelihood.
For EACH entry output exactly this format (no extra prose):

1. METHOD /path | Module: <name> | Risk: <HIGH/MEDIUM/LOW> | Reason: <one sentence>

Module must be one of: BOLA, BrokenAuth, BFLA, Injection, SSRF, MassAssign, Misconfig, DataExpose, RateLimit, Inventory"""

_HEURISTICS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"/(user_?id|item_?id|order_?id|object_?id|\{id\}|\{.*id.*\})", re.I), "BOLA", "parameterised resource ID -> horizontal privilege escalation likely"),
    (re.compile(r"/(login|token|auth|oauth|signin|password|reset)", re.I), "BrokenAuth", "authentication endpoint -> JWT / credential attacks"),
    (re.compile(r"/(admin|internal|_debug|debug|staff|manage)", re.I), "BFLA", "privileged path -> function-level auth bypass"),
    (re.compile(r"/(register|create|signup|new|add)", re.I), "MassAssign", "resource creation -> mass-assignment / property injection"),
    (re.compile(r"/(upload|import|fetch|url|webhook|callback|redirect)", re.I), "SSRF", "URL / callback parameter -> SSRF candidate"),
    (re.compile(r"/(search|query|filter|find|list)", re.I), "Injection", "query / search parameter -> SQLi / NoSQLi"),
    (re.compile(r"/(graphql|gql)", re.I), "GraphQL", "GraphQL endpoint -> introspection / batching"),
]


@dataclass
class PlanItem:
    priority: int
    endpoint: str
    module: str
    risk: str
    reason: str


@dataclass
class PlanResult:
    items: List[PlanItem] = field(default_factory=list)
    raw: str = ""
    notes: List[str] = field(default_factory=list)
    ai_used: bool = False


def _fmt_endpoints(endpoints: Sequence[Any]) -> str:
    lines = []
    for e in endpoints:
        method = getattr(e, "method", "GET").upper()
        path = getattr(e, "path", str(e))
        flags = []
        if getattr(e, "requires_auth", False): flags.append("auth")
        if getattr(e, "has_request_body", False): flags.append("body")
        suffix = "  [" + ",".join(flags) + "]" if flags else ""
        lines.append(f"  {method:<7} {path}{suffix}")
    return "\n".join(lines)


def _parse_llm_plan(raw: str) -> List[PlanItem]:
    items: List[PlanItem] = []
    pat = re.compile(
        r"(\d+)\.\s*([A-Z]+)\s+(/[^|]+)\|\s*Module:\s*([^|]+)\|\s*Risk:\s*(HIGH|MEDIUM|LOW)\s*\|\s*Reason:\s*(.+)",
        re.I,
    )
    for m in pat.finditer(raw):
        items.append(PlanItem(
            priority=int(m.group(1)),
            endpoint=m.group(2).strip() + " " + m.group(3).strip(),
            module=m.group(4).strip(),
            risk=m.group(5).strip().upper(),
            reason=m.group(6).strip(),
        ))
    return items


def _heuristic_plan(endpoints: Sequence[Any]) -> List[PlanItem]:
    items: List[PlanItem] = []
    seen: set[str] = set()
    priority = 1
    for e in endpoints:
        if priority > 5:
            break
        path = getattr(e, "path", str(e))
        method = getattr(e, "method", "GET").upper()
        for pat, module, reason in _HEURISTICS:
            if pat.search(path) and module not in seen:
                items.append(PlanItem(
                    priority=priority,
                    endpoint=method + " " + path,
                    module=module,
                    risk="HIGH" if priority <= 2 else "MEDIUM",
                    reason=reason,
                ))
                seen.add(module)
                priority += 1
                break
    return items


class AIPlanner:
    def __init__(self, provider: Any) -> None:
        self.provider = provider

    async def plan(self, endpoints: Sequence[Any],
                   title: str = "Unknown API", base_url: str = "") -> PlanResult:
        if not endpoints:
            return PlanResult(notes=["No endpoints available for planning."])
        if not self.provider.is_available:
            items = _heuristic_plan(endpoints)
            return PlanResult(
                items=items, ai_used=False,
                notes=["AI Planner: no LLM available; heuristic plan from endpoint patterns.",
                       "Run `ollama serve` + `ollama pull llama3` to enable AI planning."],
            )
        prompt = _PLAN_PROMPT.format(
            title=title, base_url=base_url or "(unknown)",
            count=len(endpoints), endpoint_list=_fmt_endpoints(endpoints),
        )
        raw = await self.provider.complete(prompt, system=_PLAN_SYSTEM, max_tokens=512)
        items = _parse_llm_plan(raw)
        if not items:
            items = _heuristic_plan(endpoints)
            notes = ["AI Planner: LLM response unparseable; heuristic fallback applied."]
        else:
            notes = ["AI Planner: plan generated by " + self.provider.name + "."]
        return PlanResult(items=items, raw=raw, notes=notes, ai_used=bool(raw))
