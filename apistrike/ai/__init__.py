"""APIStrike AI layer -- model-agnostic, local-first (Ollama default).

All AI features degrade gracefully to rule-based defaults when no LLM is
available, so every module continues to work without Ollama.

GUARANTEED GUARDRAIL: AI proposes and annotates; the deterministic engine
already confirmed every finding. AI never has the final say on a finding.
"""
from apistrike.ai.provider import AIProvider, NoOpProvider, OllamaProvider, MockProvider, load_provider
from apistrike.ai.planner import AIPlanner, PlanResult, PlanItem
from apistrike.ai.analyst import AIAnalyst, AnalysisResult
from apistrike.ai.reporter import AIReporter, ReportEnrichment

__all__ = [
    "AIProvider", "NoOpProvider", "OllamaProvider", "MockProvider", "load_provider",
    "AIPlanner", "PlanResult", "PlanItem",
    "AIAnalyst", "AnalysisResult",
    "AIReporter", "ReportEnrichment",
]
