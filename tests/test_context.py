from apistrike.core.context import (
    Endpoint,
    Identity,
    ObjectRef,
    Param,
    ScanContext,
    Token,
)


def test_emit_and_query():
    ctx = ScanContext(run_id="r1")
    assert ctx.emit(Endpoint("GET", "/users/{id}", source="spec"), module="crawl") is True
    assert ctx.emit(Identity("name1", username="name1"), module="auth") is True
    assert [e.path for e in ctx.facts(Endpoint)] == ["/users/{id}"]
    assert ctx.facts("identity")[0].label == "name1"


def test_emit_is_idempotent_on_identity():
    ctx = ScanContext()
    assert ctx.emit(Endpoint("GET", "/users/{id}")) is True
    assert ctx.emit(Endpoint("get", "/users/{id}")) is False
    assert len(ctx.facts(Endpoint)) == 1
    assert len(ctx) == 1


def test_find_filters():
    ctx = ScanContext()
    ctx.emit(Endpoint("GET", "/a", requires_auth=True))
    ctx.emit(Endpoint("POST", "/b", requires_auth=False))
    hits = ctx.find(Endpoint, requires_auth=True)
    assert len(hits) == 1 and hits[0].path == "/a"


def test_provenance_recorded():
    ctx = ScanContext(run_id="run-xyz")
    tok = Token("name1", raw="abc", claims={"role": "user"}, role="user")
    ctx.emit(tok, module="auth")
    prov = ctx.provenance(tok)
    assert prov.module == "auth"
    assert prov.run_id == "run-xyz"
    assert prov.at


def test_snapshot_counts_and_kinds():
    ctx = ScanContext()
    ctx.emit(Endpoint("GET", "/a"))
    ctx.emit(Endpoint("GET", "/b"))
    ctx.emit(Identity("x"))
    ctx.emit(ObjectRef("x", "/users/v1/x"))
    ctx.emit(Param("GET /a", "q"))
    assert ctx.snapshot_counts() == {
        "endpoint": 2,
        "identity": 1,
        "object": 1,
        "param": 1,
    }
    assert ctx.kinds_present() == {"endpoint", "identity", "object", "param"}


def test_to_dict_serializes_facts():
    ctx = ScanContext(run_id="r")
    ctx.emit(Endpoint("GET", "/a", source="shadow"), module="crawl")
    d = ctx.to_dict()
    assert d["run_id"] == "r"
    assert d["facts"][0]["kind"] == "endpoint"
    assert d["facts"][0]["fields"]["path"] == "/a"
    assert d["facts"][0]["provenance"]["module"] == "crawl"
