import asyncio

from apistrike.core.context import Endpoint, Identity, ScanContext
from apistrike.core.planner import Planner, Step


def _mk(name, emits=(), consumes=frozenset(), log=None):
    async def _run(ctx):
        if log is not None:
            log.append(name)
        for f in emits:
            ctx.emit(f, module=name)

    return Step(name=name, run=_run, consumes=frozenset(consumes))


def test_producer_then_consumer_order():
    log = []
    producer = _mk("crawl", emits=[Endpoint("GET", "/a")], log=log)
    consumer = _mk("bfla", consumes={"endpoint"}, log=log)
    result = asyncio.run(Planner([consumer, producer]).run(ScanContext()))
    assert log == ["crawl", "bfla"]
    assert result.order == ["crawl", "bfla"]
    assert result.rounds == 2
    assert result.skipped == []


def test_three_stage_chain():
    log = []
    a = _mk("a", emits=[Endpoint("GET", "/a")], log=log)
    b = _mk("b", emits=[Identity("i")], consumes={"endpoint"}, log=log)
    c = _mk("c", consumes={"identity"}, log=log)
    result = asyncio.run(Planner([a, b, c]).run(ScanContext()))
    assert log == ["a", "b", "c"]
    assert result.rounds == 3


def test_unsatisfiable_step_is_skipped():
    a = _mk("a", emits=[Endpoint("GET", "/a")])
    orphan = _mk("orphan", consumes={"object"})
    result = asyncio.run(Planner([a, orphan]).run(ScanContext()))
    assert result.order == ["a"]
    assert result.skipped == ["orphan"]


def test_max_rounds_cap_terminates():
    a = _mk("a", emits=[Endpoint("GET", "/a")])
    b = _mk("b", emits=[Identity("i")], consumes={"endpoint"})
    c = _mk("c", consumes={"identity"})
    result = asyncio.run(Planner([a, b, c], max_rounds=1).run(ScanContext()))
    assert result.order == ["a"]
    assert set(result.skipped) == {"b", "c"}
    assert result.rounds == 1
