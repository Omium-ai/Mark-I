"""Retrieval, storeless: signature normalization (pinned against the Go twin), the deterministic
embedding's geometry, the injectable allowlist, and the two routes over a fake pool."""

import math
from contextlib import asynccontextmanager
from typing import Any

import pytest
from app.memory import extract, retrieve
from app.memory.routes import get_pool, router
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = "11111111-1111-1111-1111-111111111111"
RAW = (
    "Exit Code 1\n  FAIL test_x at /home/u/proj/y.py:12   sha 3fa9c2e71 C:\\Users\\me\\a.txt\n"
    "third line is ignored"
)
NORMALIZED = "exit code 0 fail test_x at <path>:0 sha <hex> <path>"
# Pinned in go/mark1d/internal/memory/signature_test.go too: one vector, two languages.
DIGEST = "2f79e42f04bbe23e9adbd014553c6a7fe2ec5c79272129862df66fdd3aa4f753"

PLANTED = "Exit code 1\nFAIL test_retry_backoff: expected 3 attempts, saw 1"
NEAR = "Exit code 1\nFAIL test_retry_backoff: expected 3 attempts, saw none"
FAR = "TypeError: undefined is not a function at handler (/app/src/x.js:10:3)"


def _cos_distance(a: str, b: str) -> float:
    va, vb = (
        retrieve.embed(retrieve.normalize_signature(a)),
        retrieve.embed(retrieve.normalize_signature(b)),
    )
    assert va is not None and vb is not None
    return 1.0 - sum(x * y for x, y in zip(va, vb, strict=True))


def test_normalize_signature_is_the_pinned_vector():
    assert retrieve.normalize_signature(RAW) == NORMALIZED
    assert retrieve.signature_digest(NORMALIZED) == DIGEST


def test_normalize_signature_rules():
    assert retrieve.normalize_signature("") == ""
    assert retrieve.normalize_signature("\n  \n") == ""
    assert retrieve.normalize_signature("A\nB\nC") == "a b"
    assert retrieve.normalize_signature("A\r\nB\rC") == "a b"
    assert retrieve.normalize_signature("Exit code 1\nFAIL x  y\tz\n!") == "exit code 0 fail x y z"
    assert retrieve.normalize_signature("x " * 200)[-1] != " "
    assert len(retrieve.normalize_signature("y" * 500)) == retrieve.SIGNATURE_MAX_CHARS
    assert retrieve.normalize_signature("deadbe facade 0xdeadbeef") == "deadbe facade 0xdeadbeef"
    assert retrieve.normalize_signature("id a1b2c3 and 12 items") == "id <hex> and 0 items"
    assert retrieve.normalize_signature("see /a/b.txt or /one") == "see <path> or /one"


def test_embed_is_deterministic_unit_length_and_none_on_empty():
    v1, v2 = retrieve.embed(NORMALIZED), retrieve.embed(NORMALIZED)
    assert v1 == v2 and len(v1) == retrieve.DIM
    assert math.isclose(sum(x * x for x in v1), 1.0, abs_tol=1e-9)
    assert retrieve.embed("") is None
    assert retrieve.vector_literal([0.5, -0.25]) == "[0.5,-0.25]"


def test_embedding_geometry_backs_the_planted_neighbor_fixture():
    near, far = _cos_distance(PLANTED, NEAR), _cos_distance(PLANTED, FAR)
    assert 0.0 < near <= retrieve.FUZZ_DISTANCE, near
    assert far > retrieve.FUZZ_DISTANCE, far
    assert _cos_distance(PLANTED, PLANTED.replace("3 attempts", "7 attempts")) < 1e-9


def test_injectable_kinds_are_an_allowlist_without_the_routing_hint_class():
    assert retrieve.INJECTABLE_KINDS < extract.KINDS
    assert "preference" not in retrieve.INJECTABLE_KINDS
    assert "routing_hint" not in retrieve.INJECTABLE_KINDS


class FakeConn:
    def __init__(self, rows: list[dict[str, Any]]):
        self.rows = rows
        self.sql: list[str] = []

    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, sql: str, *args: Any) -> None:
        self.sql.append(sql)

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.sql.append(sql)
        return self.rows


class FakePool:
    def __init__(self, conn: FakeConn):
        self.conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self.conn


SVC = "controld-service-token"


@pytest.fixture(autouse=True)
def _service_token(monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", SVC)


def _client(conn: FakeConn, bearer: str | None = SVC) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_pool] = lambda: FakePool(conn)
    headers = {"Authorization": f"Bearer {bearer}"} if bearer is not None else {}
    return TestClient(app, headers=headers)


def _db_row(kind: str, trigger: str = PLANTED, lcb: float = 0.25, distance: float | None = None):
    row = {
        "id": "aaaaaaaa-0000-0000-0000-000000000001",
        "kind": kind,
        "body": f'{{"trigger": {trigger!r}, "guidance": "retry with backoff"}}'.replace("'", '"'),
        "lcb": lcb,
    }
    if distance is not None:
        row["distance"] = distance
    return row


def test_artifacts_route_serves_admitted_rows_under_the_tenant_guc():
    conn = FakeConn([_db_row("pitfall"), _db_row("fix_pattern")])
    resp = _client(conn).get("/v1/memory/artifacts", params={"tenant_id": TENANT})
    assert resp.status_code == 200
    arts = resp.json()["artifacts"]
    assert [a["kind"] for a in arts] == ["pitfall", "fix_pattern"]
    assert arts[0]["error_sig_digest"] == retrieve.signature_digest(
        retrieve.normalize_signature(PLANTED)
    )
    assert "error_sig_digest" not in arts[1]
    assert arts[0]["utility_lcb"] == 0.25 and arts[0]["guidance"] == "retry with backoff"
    assert any("set_config('app.tenant_id'" in s for s in conn.sql)
    assert any("state = 'admitted'" in s for s in conn.sql)


@pytest.mark.parametrize("bearer", [None, "", "wrong", SVC + "x", SVC[:-1]])
def test_both_routes_refuse_without_controld_service_credential(bearer):
    conn = FakeConn([_db_row("pitfall")])
    c = _client(conn, bearer)
    for resp in (
        c.get("/v1/memory/artifacts", params={"tenant_id": TENANT}),
        c.post("/v1/memory/match", json={"tenant_id": TENANT, "error": NEAR}),
    ):
        assert resp.status_code == 403 and resp.json()["error"]["code"] == "M1E-1001"
    assert conn.sql == []


def test_unset_service_token_is_absent_never_open(monkeypatch):
    monkeypatch.delenv("INTEL_QUERYCHOKE_TOKEN")
    conn = FakeConn([_db_row("pitfall")])
    resp = _client(conn, "").get("/v1/memory/artifacts", params={"tenant_id": TENANT})
    assert resp.status_code == 403 and conn.sql == []


def test_artifacts_route_refuses_a_bad_tenant():
    conn = FakeConn([])
    resp = _client(conn).get("/v1/memory/artifacts", params={"tenant_id": "nope"})
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "M1E-2001"
    assert conn.sql == []


def test_match_route_returns_neighbors_within_the_distance_bound():
    conn = FakeConn([_db_row("pitfall", distance=0.05), _db_row("pitfall", distance=0.4)])
    resp = _client(conn).post("/v1/memory/match", json={"tenant_id": TENANT, "error": NEAR})
    assert resp.status_code == 200
    body = resp.json()
    assert [a["distance"] for a in body["artifacts"]] == [0.05]
    assert body["signature_digest"] == retrieve.signature_digest(retrieve.normalize_signature(NEAR))
    assert any("<=>" in s and "LIMIT" in s for s in conn.sql)


def test_match_route_with_an_empty_error_touches_no_store():
    conn = FakeConn([_db_row("pitfall", distance=0.0)])
    resp = _client(conn).post("/v1/memory/match", json={"tenant_id": TENANT, "error": " \n "})
    assert resp.status_code == 200 and resp.json()["artifacts"] == []
    assert conn.sql == []


@pytest.mark.parametrize("bad", [{"tenant_id": TENANT, "error": "x", "limit": 4}, {"error": "x"}])
def test_match_route_validates_its_body(bad):
    resp = _client(FakeConn([])).post("/v1/memory/match", json=bad)
    assert resp.status_code == 422
