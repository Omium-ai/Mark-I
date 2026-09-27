"""m1_075 + app/regime on real Postgres: set/load both bases, the basis-inputs CHECK, unpinned
refusal at set time, append-only history (trigger layer as the suite role, privilege layer by
grant), the RLS negative, and the compile positive control -- the nightly job pricing a tenant
from its OWN regime row (no injected Regime) and stamping the price-table digest on the draft.
Same DSN gating as test_policy_compiler_pg.py."""

import asyncpg
import pytest
from app.db import set_local_tenant
from app.policy_compiler import jobs
from app.policy_compiler.cpvs import Regime
from app.pricing import UnpinnedModel, load_table
from app.regime import RegimeUnset, load_regime, set_regime
from choke_mock import MockChoke
from test_policy_compiler_pg import DSN, REQUIRE_STORES, _ctx, _drafts, _mk_tenant, _rows
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


async def test_set_and_load_both_bases_with_history(admin, pool):
    tenant = await _mk_tenant(admin)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(RegimeUnset, match="no regime row"):
            await load_regime(conn, tenant)
        await set_regime(
            conn,
            tenant,
            cost_basis="usd",
            v_default=25.0,
            set_by="ops@omium",
            price_model_id="claude-sonnet-5",
        )
        usd = await load_regime(conn, tenant)
        assert usd == Regime(
            cost_basis="usd", v_default=25.0, price=load_table().price_for("claude-sonnet-5")
        )
        assert usd.price.price_table_version == load_table().version
        # A re-set is an UPDATE of the one row and a second history row; V and S cross over.
        await set_regime(
            conn,
            tenant,
            cost_basis="quota",
            v_default=30.0,
            set_by="tenant-admin",
            window_limit_tokens=100_000,
            shadow_price_usd=250.0,
        )
        quota = await load_regime(conn, tenant)
        assert quota == Regime(
            cost_basis="quota", v_default=30.0, window_limit_tokens=100_000, shadow_price_usd=250.0
        )
        assert quota.price is None
        assert await conn.fetchval("SELECT count(*) FROM m1_tenant_regimes") == 1
        history = await conn.fetch(
            "SELECT cost_basis, price_model_id, shadow_price_usd, set_by, set_at "
            "FROM m1_tenant_regime_history ORDER BY id"
        )
        assert [(h["cost_basis"], h["price_model_id"], h["set_by"]) for h in history] == [
            ("usd", "claude-sonnet-5", "ops@omium"),
            ("quota", None, "tenant-admin"),
        ]
        assert float(history[1]["shadow_price_usd"]) == 250.0
        assert history[1]["set_at"] >= history[0]["set_at"]


async def test_cross_basis_inputs_and_unpinned_models_are_refused(admin, pool):
    tenant = await _mk_tenant(admin)
    bad = [
        dict(cost_basis="usd", v_default=1.0),  # usd without a pinned model
        dict(
            cost_basis="usd", v_default=1.0, price_model_id="claude-sonnet-5", shadow_price_usd=1.0
        ),
        dict(cost_basis="quota", v_default=1.0, shadow_price_usd=1.0),  # no window limit
        dict(cost_basis="quota", v_default=1.0, window_limit_tokens=0, shadow_price_usd=1.0),
        dict(cost_basis="quota", v_default=1.0, window_limit_tokens=10, shadow_price_usd=-1.0),
        dict(cost_basis="quota", v_default=0.0, window_limit_tokens=10, shadow_price_usd=1.0),
        dict(cost_basis="tokens", v_default=1.0, window_limit_tokens=10, shadow_price_usd=1.0),
    ]
    for kwargs in bad:
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            with pytest.raises(asyncpg.CheckViolationError):
                await set_regime(conn, tenant, set_by="ops", **kwargs)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        with pytest.raises(UnpinnedModel, match="gemini-2.5-flash"):
            await set_regime(
                conn,
                tenant,
                cost_basis="usd",
                v_default=1.0,
                set_by="ops",
                price_model_id="gemini-2.5-flash",
            )
        with pytest.raises(RegimeUnset):
            await load_regime(conn, tenant)
        assert await conn.fetchval("SELECT count(*) FROM m1_tenant_regime_history") == 0


async def test_history_is_append_only_and_delete_is_revoked(admin, pool):
    tenant = await _mk_tenant(admin)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await set_regime(
            conn,
            tenant,
            cost_basis="usd",
            v_default=1.0,
            set_by="ops",
            price_model_id="claude-opus-5",
        )
    # Trigger layer, as the suite role that holds ALL on the table: m1_append_only() still refuses.
    for stmt in (
        "UPDATE m1_tenant_regime_history SET set_by = 'forged'",
        "DELETE FROM m1_tenant_regime_history",
        "TRUNCATE m1_tenant_regime_history",
    ):
        async with admin.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            with pytest.raises(asyncpg.InsufficientPrivilegeError, match="append-only"):
                await conn.execute(stmt)
    # Privilege layer, checked independently (07 roles-and-grants): the runtime role's matrix.
    async with pool.acquire() as conn:
        grants = {
            (t, p): await conn.fetchval("SELECT has_table_privilege('intel_app', $1, $2)", t, p)
            for t in ("m1_tenant_regimes", "m1_tenant_regime_history")
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
        }
    assert {k for k, v in grants.items() if v} == {
        ("m1_tenant_regimes", "SELECT"),
        ("m1_tenant_regimes", "INSERT"),
        ("m1_tenant_regimes", "UPDATE"),
        ("m1_tenant_regime_history", "SELECT"),
        ("m1_tenant_regime_history", "INSERT"),
    }


async def test_rls_hides_and_refuses_the_other_tenant(admin, pool):
    tenant, other = await _mk_tenant(admin), await _mk_tenant(admin)
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await set_regime(
            conn,
            tenant,
            cost_basis="usd",
            v_default=1.0,
            set_by="ops",
            price_model_id="claude-opus-5",
        )
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, other)
        with pytest.raises(RegimeUnset):
            await load_regime(conn, tenant)
        assert await conn.fetchval("SELECT count(*) FROM m1_tenant_regimes") == 0
        assert await conn.fetchval("SELECT count(*) FROM m1_tenant_regime_history") == 0
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
            await set_regime(
                conn,
                tenant,
                cost_basis="usd",
                v_default=1.0,
                set_by="ops",
                price_model_id="claude-opus-5",
            )
    async with pool.acquire() as conn:  # GUC unset: NULLIF fail-closed, nothing visible
        assert await conn.fetchval("SELECT count(*) FROM m1_tenant_regimes") == 0


async def test_compile_prices_the_tenant_from_its_own_regime_row(admin, pool, monkeypatch):
    """Positive control through the production mechanism: no injected Regime -- jobs.compile
    reads m1_075 under the tenant GUC, prices through app/pricing, and the draft carries the
    price-table digest. The ledger fixture is quota-stamped, so a quota regime compiles and a usd
    regime is refused as a basis mismatch (CON-014)."""
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    tenant = await _mk_tenant(admin)
    choke = MockChoke()
    choke.templates[jobs.ATTEMPTS_TEMPLATE] = _rows()
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await set_regime(
            conn,
            tenant,
            cost_basis="usd",
            v_default=5.0,
            set_by="ops",
            price_model_id="claude-sonnet-5",
        )
    async with choke.client() as http:
        with pytest.raises(RuntimeError, match="regime basis 'usd' != ledger basis 'quota'"):
            await jobs.compile(_ctx(pool, tenant), http=http)
        assert await _drafts(pool, tenant) == []
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, tenant)
            await set_regime(
                conn,
                tenant,
                cost_basis="quota",
                v_default=5.0,
                set_by="ops",
                window_limit_tokens=100_000,
                shadow_price_usd=200.0,
            )
        assert await jobs.compile(_ctx(pool, tenant), http=http) is None
    (draft,) = await _drafts(pool, tenant)
    assert (draft["state"], draft["knee_gate_ok"]) == ("pending", True)
    assert "knee[quota]" in draft["knee_note"] and "priced by" not in draft["knee_note"]


async def test_usd_draft_carries_the_price_table_digest(admin, pool, monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    tenant = await _mk_tenant(admin)
    choke = MockChoke()
    choke.templates[jobs.ATTEMPTS_TEMPLATE] = [{**r, "cost_basis": "usd"} for r in _rows()]
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await set_regime(
            conn,
            tenant,
            cost_basis="usd",
            v_default=5.0,
            set_by="ops",
            price_model_id="claude-haiku-4-5",
        )
    async with choke.client() as http:
        try:
            await jobs.compile(_ctx(pool, tenant), http=http)
        except jobs.KneeGateViolation:
            pass  # the fixture's knee under haiku usd prices is not this test's claim
    (draft,) = await _drafts(pool, tenant)
    assert draft["knee_note"].endswith(f"; priced by {load_table().version}")
    assert "knee[usd]" in draft["knee_note"]
