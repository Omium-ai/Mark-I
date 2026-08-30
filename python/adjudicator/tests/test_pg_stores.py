"""Real-Postgres round-trip for the m1_020/m1_021 stores, gated on the estate's env
DSN idiom (06 §1.1: "real-PG suites gated on an env DSN (skipif), no testcontainers").
Requires migrations m1_001 + m1_020 + m1_021 applied to $M1_TEST_PG_DSN.

What this suite proves that the unit suites cannot: the tenant-GUC discipline against
live RLS policies, m1_021's frozen-set refusal on the producer side, and that the DB's
certified_is_earned CHECK refuses a dishonest 'certified' row from THIS code path."""

import json
import os
import random
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import asyncpg
import pytest
from app.certs.compute import compute_certificate
from app.certs.store import current_cert, insert_cert
from app.db import _tenant_guc_reset
from app.gold.score import score_agreement
from app.gold.select import add_members, create_gold_set, freeze_gold_set
from app.registry.catalog import list_verifiers

DSN = os.environ.get("M1_TEST_PG_DSN", "")
# The justfile's zero-skip inversion (its head; conformance/tenancy/conftest.py is the
# one implementation, mirrored here): under M1_REQUIRE_STORES=1 — which the justfile
# always exports, so every CI/`just` run gets it — green-because-skipped is impossible:
# a missing/unreachable DSN or an unobservable posture is a hard FAILURE, never a skip.
# Unset (a raw pytest run outside the justfile) keeps 06 §1.1's skipif idiom — one
# deliberate divergence from the conftest's default-1, because the doc idiom is this
# module's stated contract for storeless dev machines and CI can never reach this
# default (the justfile exports the var unconditionally).
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"

pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRE_STORES,
    reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
)


@pytest.fixture
async def pool():
    if not DSN:  # only reachable under M1_REQUIRE_STORES=1 (pytestmark skips otherwise)
        pytest.fail(
            "M1_TEST_PG_DSN is unset and M1_REQUIRE_STORES=1: a missing store is a "
            "failing test, not a skipped one (justfile store contract).",
            pytrace=False,
        )
    # Direct DSN (no sslmode injection): the test harness DSN says what it means.
    # The GUC-reset setup= is kept — it is part of what is under test.
    try:
        p = await asyncpg.create_pool(dsn=DSN, min_size=1, max_size=3, setup=_tenant_guc_reset)
    except Exception as exc:
        if REQUIRE_STORES:
            pytest.fail(
                f"M1_REQUIRE_STORES=1 and {DSN!r} is unreachable: {exc!r}. A store that "
                "is down is a failing test, not a skipped one.",
                pytrace=False,
            )
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield p
    finally:
        await p.close()


async def _mk_tenant(pool: asyncpg.Pool) -> str:
    tag = f"adjtest-{random.randbytes(4).hex()}"
    async with pool.acquire() as conn:
        org = await conn.fetchval(
            "INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id",
            tag,
            f"{tag}.example",
        )
        return str(
            await conn.fetchval(
                "INSERT INTO m1_tenants (org_id, name) VALUES ($1, $2) RETURNING id", org, tag
            )
        )


async def _mk_judge_verifier(pool: asyncpg.Pool) -> UUID:
    # kind='judge': no effective_execution_hash (m1_020's anchor-hash equivalence CHECK).
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """
            INSERT INTO m1_verifiers (verifier_key, kind, version, display_name, definition)
            VALUES ($1, 'judge', 1, 'test judge', $2::jsonb) RETURNING id
            """,
            f"judge:test-{uuid4().hex[:8]}",
            json.dumps({"kind": "judge"}),
        )


async def test_gold_and_cert_round_trip(pool):
    tenant = await _mk_tenant(pool)
    verifier = await _mk_judge_verifier(pool)

    gold_set = await create_gold_set(pool, tenant, "claudecode")
    members = [(random.randbytes(32), "satisfied", "t3") for _ in range(3)] + [
        (random.randbytes(32), "violated", "human")
    ]
    assert await add_members(pool, tenant, gold_set, members) == 4
    await freeze_gold_set(pool, tenant, gold_set)

    # Frozen means frozen: the producer-side refusal, before the DB trigger ever fires.
    with pytest.raises(ValueError, match="frozen"):
        await add_members(pool, tenant, gold_set, [(random.randbytes(32), "satisfied", "t3")])

    comp = compute_certificate(
        score_agreement([("satisfied", "satisfied")] * 3 + [("violated", "violated")])
    )
    cert_id = await insert_cert(
        pool, tenant, verifier, "bootstrapping", comp, gold_set, diagnostics={"phase": 2}
    )
    got = await current_cert(pool, tenant)
    assert got.id == cert_id
    assert got.status == "bootstrapping"

    # A registry read sees the global catalog row (no tenant GUC on m1_verifiers).
    keys = {e.id for e in await list_verifiers(pool)}
    assert verifier in keys


async def test_certified_is_earned_refused_by_the_db(pool):
    """Phase 2 can never mint 'certified' (identifiable=False, no NATARAJAN LCB row):
    the write path must surface m1_021's CHECK, never work around it."""
    tenant = await _mk_tenant(pool)
    verifier = await _mk_judge_verifier(pool)
    gold_set = await create_gold_set(pool, tenant, "claudecode")
    await freeze_gold_set(pool, tenant, gold_set)
    comp = compute_certificate(
        score_agreement([("satisfied", "satisfied")] * 3 + [("violated", "violated")])
    )
    with pytest.raises(asyncpg.CheckViolationError):
        await insert_cert(pool, tenant, verifier, "certified", comp, gold_set)


def _run_leg(target: str, **env_overrides: str) -> subprocess.CompletedProcess:
    here = Path(__file__).resolve()
    env = {**os.environ, "M1_REQUIRE_STORES": "1", **env_overrides}
    return subprocess.run(
        [sys.executable, "-m", "pytest", f"{here}::{target}", "-o", "asyncio_mode=auto", "-q"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(here.parents[1]),
    )


async def test_require_stores_forbids_silent_self_disable(pool):
    """The justfile inversion, proven from outside: under M1_REQUIRE_STORES=1 this
    module must never skip itself green — a missing DSN is a hard failure, and so is
    a bypass-capable role for the RLS test. Each leg is a real sub-run of this file,
    because the defect WAS the skip machinery, so only the skip machinery can prove
    the fix."""
    # Leg 1 — missing DSN: hard failure, never a skip.
    res = _run_leg("test_gold_and_cert_round_trip", M1_TEST_PG_DSN="")
    summary = res.stdout.strip().splitlines()[-1]  # pytest -q tail, e.g. "1 error in 0.1s"
    assert "skipped" not in summary, res.stdout
    assert res.returncode != 0, res.stdout

    # Leg 2 — the RLS test under the CURRENT role: never a skip. Bypass-capable ⇒
    # hard failure (the misconfiguration is surfaced); NOBYPASSRLS ⇒ it just passes.
    async with pool.acquire() as conn:
        bypass = await conn.fetchval(
            "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user"
        )
    res = _run_leg("test_rls_isolation_between_tenants")
    summary = res.stdout.strip().splitlines()[-1]
    assert "skipped" not in summary, res.stdout
    assert (res.returncode != 0) == bool(bypass), res.stdout


async def test_tenant_predicate_holds_under_bypass_role(pool):
    """The store's explicit WHERE tenant_id is the belt to RLS's braces: this test runs
    under WHATEVER role the DSN provides — including BYPASSRLS/superuser, where RLS is
    inert — and must still never see a foreign tenant's certificate. Deliberately no
    bypass-skip: the bypass case is the whole point (the rds_superuser lesson)."""
    tenant_a = await _mk_tenant(pool)
    tenant_b = await _mk_tenant(pool)
    verifier = await _mk_judge_verifier(pool)
    comp = compute_certificate(score_agreement([]))
    await insert_cert(pool, tenant_a, verifier, "bootstrapping", comp, None)
    b_first = await insert_cert(pool, tenant_b, verifier, "uncertified", comp, None)
    b_second = await insert_cert(pool, tenant_b, verifier, "bootstrapping", comp, None)

    # A tenant with no certs reads the honest floor, never someone else's row.
    tenant_c = await _mk_tenant(pool)
    got_c = await current_cert(pool, tenant_c)
    assert got_c.id is None
    assert got_c.status == "uncertified"

    # A tenant with two certs gets its OWN newest — which requires a real validity
    # window on write; all-NULL ORDER BY keys made "newest wins" degenerate.
    got_b = await current_cert(pool, tenant_b)
    assert got_b.id in {b_first, b_second}, "foreign tenant's certificate served"
    assert got_b.id == b_second
    assert got_b.issued_at is not None
    assert got_b.expires_at is not None
    assert got_b.expires_at > got_b.issued_at


async def test_rls_isolation_between_tenants(pool):
    async with pool.acquire() as conn:
        bypass = await conn.fetchval(
            "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user"
        )
    if bypass:
        msg = "test role bypasses RLS — isolation not observable from here"
        if REQUIRE_STORES:
            pytest.fail(
                msg + ". M1_REQUIRE_STORES=1: point M1_TEST_PG_DSN at a NOBYPASSRLS "
                "role (m1_021's FORCE RLS binds even the table owner) — a skipped "
                "isolation test is indistinguishable from a passing one.",
                pytrace=False,
            )
        pytest.skip(msg)
    tenant_a = await _mk_tenant(pool)
    tenant_b = await _mk_tenant(pool)
    verifier = await _mk_judge_verifier(pool)
    comp = compute_certificate(score_agreement([]))
    await insert_cert(pool, tenant_a, verifier, "bootstrapping", comp, None)
    # Tenant B's read must see NOTHING of tenant A's certificate: absence reads as
    # uncertified — the honest floor, not an error.
    got = await current_cert(pool, tenant_b)
    assert got.status == "uncertified"
    assert got.id is None
