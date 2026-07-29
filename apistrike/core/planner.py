"""Planner: a bounded fixed-point scheduler over the ScanContext (v1.4).

Generic and module-agnostic (ADR-0007): it schedules abstract :class:`Step`
objects that declare which fact *kinds* they consume and produce, running them
in dependency order. Concrete module wiring lives in the CLI ``auto`` command,
so this module imports nothing below ``core`` and keeps the
``cli -> modules -> core`` layering intact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable, Sequence

from apistrike.core.context import ScanContext


@dataclass
class Step:
    """One unit of orchestrated work.

    ``consumes``/``produces`` are sets of fact *kind* strings (e.g. "endpoint").
    ``run`` is an async callable taking the shared :class:`ScanContext`.
    """

    name: str
    run: Callable[[ScanContext], Awaitable[None]]
    consumes: frozenset = frozenset()
    produces: frozenset = frozenset()


@dataclass
class PlanResult:
    order: list = field(default_factory=list)
    rounds: int = 0
    skipped: list = field(default_factory=list)
    notes: list = field(default_factory=list)


class Planner:
    """Runs steps via a bounded fixed-point loop.

    Each round, every pending step whose ``consumes`` are all present in the
    context runs once. The loop repeats so steps unlocked by this round's
    emissions run next, terminating when no pending step is runnable or when
    ``max_rounds`` is hit (guaranteeing termination). Steps whose prerequisites
    are never satisfied are reported in ``skipped``.
    """

    def __init__(self, steps: Sequence[Step], max_rounds: int = 8) -> None:
        self.steps = list(steps)
        self.max_rounds = max_rounds

    async def run(self, ctx: ScanContext) -> PlanResult:
        result = PlanResult()
        pending = list(self.steps)
        for round_no in range(1, self.max_rounds + 1):
            present = ctx.kinds_present()
            runnable = [s for s in pending if set(s.consumes).issubset(present)]
            if not runnable:
                break
            result.rounds = round_no
            for step in runnable:
                await step.run(ctx)
                result.order.append(step.name)
                pending.remove(step)
        result.skipped = [s.name for s in pending]
        result.notes = [
            f"skipped '{s}': prerequisites never satisfied" for s in result.skipped
        ]
        return result
