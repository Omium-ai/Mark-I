"""GET /v1/reports/tvo priced from the tenant's m1_075 row through app/pricing (real Postgres,
mocked choke): guarantee_grade is TRUE only when the regime is set AND the row it prices from
is in the pinned table -- one positive control, the negatives around it. Only get_pool is
overridden: get_regime -> load_regime -> price_for is the production path."""

import json

import pytest
from app.db import set_local_tenant
from app.pricing import TABLE_PATH, load_table
from app.regime import set_regime
from app.tvo.routes import get_pool
from fastapi import FastAPI
from test_policy_compiler_pg import DSN, REQUIRE_STORES, _mk_tenant
from test_tvo_report_route import CERTIFIED, GOOD_COVERAGE, choke_with, client_for
from test_tvo_report_route import build_app as _build_app
from tests.roles import service_pool

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DSN and not REQUIRE_STORES,
        reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
    ),
]


@pytest.fixture
async def pool():
    if not DSN:
        pytest.fail("M1_TEST_PG_DSN unset under M1_REQUIRE_STORES=1", pytrace=False)
    try:
        p = await service_pool(min_size=1, max_size=3)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(f"{DSN!r} unreachable under M1_REQUIRE_STORES=1: {exc!r}", pytrace=False)
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


def build_app(pg) -> FastAPI:
    app = _build_app(choke_with(GOOD_COVERAGE), cert=CERTIFIED)
    for dep in list(app.dependency_overrides):
        if dep.__name__ in ("get_price_row", "get_shadow_price"):
            del app.dependency_overrides[dep]
    app.dependency_overrides[get_pool] = lambda: pg
    return app


async def _report(app, tenant: str, cost_basis: str = "usd") -> dict:
    async with client_for(app) as client:
        resp = await client.get(
            "/v1/reports/tvo", params={"tenant_id": tenant, "cost_basis": cost_basis}
        )
    assert resp.status_code == 200
    return resp.json()


async def _set(pg, tenant: str, **kwargs) -> None:
    async with pg.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await set_regime(conn, tenant, set_by="ops", v_default=25.0, **kwargs)


async def test_guarantee_grade_needs_a_regime_row_priced_from_the_pinned_table(
    admin, pool, tmp_path, monkeypatch
):
    tenant = await _mk_tenant(admin)
    app = build_app(pool)

    # Negative 1: no regime row -> the usd basis is unresolved, the number still renders.
    body = await _report(app, tenant)
    assert body["guarantee_grade"] is False and body["grade"] == "indicative"
    assert body["refusal"] == "cost basis unresolved: no pinned model_prices row for usd (06 §8.4)"
    assert "price_table_version" not in body and body["tvo"] > 0

    # Positive control: usd regime pinned to a table row -> guarantee-grade, digest stamped.
    await _set(pool, tenant, cost_basis="usd", price_model_id="claude-sonnet-5")
    body = await _report(app, tenant)
    assert body["guarantee_grade"] is True and body["grade"] == "guarantee-grade"
    assert "refusal" not in body
    assert body["price_table_version"] == load_table().version
    assert body["price_table_version"].startswith("model_prices.v1@sha256:")

    # Negative 2: the row's model falls out of the price table (a v2 that drops it) -> the
    # regime cannot resolve a price and the report downgrades; no 500, no stale number.
    doc = json.loads(TABLE_PATH.read_text())
    doc["rows"] = [r for r in doc["rows"] if r["model_id"] != "claude-sonnet-5"]
    v2 = tmp_path / "model_prices.v2.json"
    v2.write_text(json.dumps(doc))
    monkeypatch.setattr("app.regime.price_for", lambda m: load_table(v2).price_for(m))
    body = await _report(app, tenant)
    assert body["guarantee_grade"] is False
    assert body["refusal"].startswith("cost basis unresolved: no pinned model_prices row")
    monkeypatch.undo()

    # Negative 3: a usd tenant asked for the quota basis has no confirmed S (D22).
    body = await _report(app, tenant, cost_basis="quota")
    assert body["guarantee_grade"] is False
    assert body["refusal"] == "cost basis unresolved: shadow price S unconfirmed by tenant (D22)"

    # Not a tenant id at all: no row can exist, so the same downgrade -- never a 500.
    body = await _report(app, "ten-a")
    assert body["guarantee_grade"] is False and "no pinned model_prices row" in body["refusal"]


async def test_quota_regime_confirms_s_and_carries_no_price_pin(admin, pool):
    tenant = await _mk_tenant(admin)
    app = build_app(pool)
    await _set(
        pool, tenant, cost_basis="quota", window_limit_tokens=100_000, shadow_price_usd=150.0
    )
    body = await _report(app, tenant, cost_basis="quota")
    assert body["guarantee_grade"] is True and "refusal" not in body
    assert "price_table_version" not in body  # a quota report never claims a price pin
    body = await _report(app, tenant, cost_basis="usd")  # the other basis stays unresolved
    assert body["guarantee_grade"] is False
    assert body["refusal"] == "cost basis unresolved: no pinned model_prices row for usd (06 §8.4)"
