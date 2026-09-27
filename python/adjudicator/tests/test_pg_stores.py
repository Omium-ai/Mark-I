"""Real-Postgres round-trip for the m1_020/m1_021 stores, gated on the estate's env
DSN idiom (06 §1.1: "real-PG suites gated on an env DSN (skipif), no testcontainers").
Requires migrations m1_001 + m1_020 + m1_021 applied to $M1_TEST_PG_DSN.

What this suite proves that the unit suites cannot: the tenant-GUC discipline against
live RLS policies, m1_021's frozen-set refusal on the producer side, and that the DB's
certified_is_earned CHECK refuses a dishonest 'certified' row from THIS code path."""

import functools
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from app.certs.compute import compute_certificate
from app.certs.store import RECEIPT_TYPE, ReceiptAppend, current_cert, insert_cert
from app.db import set_local_tenant
from app.gold.score import score_agreement
from app.gold.select import add_members, create_gold_set, freeze_gold_set
from app.judges.cloud_path import Consent, pg_consent_reader
from app.registry.catalog import list_verifiers
from mark1_receipts import ReceiptAppendError, append_server_record
from tests.roles import service_pool

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

# `integration` is what ROUTES this module to the one CI job that has a Postgres.
# Without it the suite was in the worst of both worlds: the storeless `python` job ran
# it and errored 5 (M1_REQUIRE_STORES defaults to 1, so an unreachable DSN is a hard
# failure by design), while the `integration` job — which provisions real stores —
# selected `-m integration` and deselected every test here. The RLS negative tests this
# repo's tenancy story rests on therefore ran in NO job with a database.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not DSN and not REQUIRE_STORES,
        reason="M1_TEST_PG_DSN not set (estate skipif idiom; M1_REQUIRE_STORES=0)",
    ),
]


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
        p = await service_pool(min_size=1, max_size=3)
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
    """Provisioning, not a tenant-scoped write. m1_001's policy on m1_tenants is
    WITH CHECK (id = app.tenant_id), so a DB-assigned id can never satisfy it: the uuid
    is chosen HERE and the GUC set to it before the INSERT. That is the only form the
    m1_060 `GRANT INSERT ON m1_tenants TO controld_app` is usable in, and the form a
    real onboarding path must use (RECONCILIATION ENG-05 — nobody has built one yet).
    The alternative — doing setup as a BYPASSRLS role — is the rds_superuser lesson."""
    tag = f"adjtest-{random.randbytes(4).hex()}"
    tenant = uuid4()
    async with pool.acquire() as conn, conn.transaction():
        org = await conn.fetchval(
            "INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id",
            tag,
            f"{tag}.example",
        )
        await set_local_tenant(conn, str(tenant))
        await conn.execute(
            "INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)", tenant, org, tag
        )
    return str(tenant)


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


class FakeControld:
    """controld's exact append wire (receipts/append.go handleAppend, fixture-locked in
    go/controld/internal/receipts/testdata/receipt_append_body.json): body field set, the
    service bearer, the {receipt_id, seq, receipt_hash, payload} ack, idempotent per key."""

    FIELDS = frozenset({"tenant_id", "record_type", "subject_id", "idempotency_key", "payload"})

    def __init__(self, record_type: str | set[str] = RECEIPT_TYPE) -> None:
        self.record_types = {record_type} if isinstance(record_type, str) else set(record_type)
        self.appended: list[dict] = []
        self.acks: dict[tuple[str, str, str], dict] = {}
        self.fail_with: tuple[int, str, str] | None = None

    def handler(self, req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/internal/v1/receipts/append", req.url.path
        assert req.headers.get("authorization") == "Bearer svc"
        body = json.loads(req.content)
        assert set(body) == self.FIELDS and body["record_type"] in self.record_types, body
        if self.fail_with:
            status, code, message = self.fail_with
            return httpx.Response(status, json={"error": {"code": code, "message": message}})
        key = (body["tenant_id"], body["record_type"], body["idempotency_key"])
        if key not in self.acks:
            self.appended.append(body)
            self.acks[key] = {
                "receipt_id": str(uuid4()),
                "seq": len(self.acks) + 1,
                "receipt_hash": "ab" * 32,
                "payload": json.dumps({**body["payload"], "subject_id": body["subject_id"]}),
            }
        return httpx.Response(200, json=self.acks[key])

    def append(self) -> ReceiptAppend:
        http = httpx.AsyncClient(transport=httpx.MockTransport(self.handler), base_url="http://c")
        return functools.partial(append_server_record, http, "http://controld", "svc")


async def test_gold_and_cert_round_trip(admin, pool):
    tenant = await _mk_tenant(admin)
    verifier = await _mk_judge_verifier(admin)

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
    controld = FakeControld()
    cert_id = await insert_cert(
        pool,
        tenant,
        verifier,
        "bootstrapping",
        comp,
        gold_set,
        diagnostics={"phase": 2},
        append=controld.append(),
    )
    got = await current_cert(pool, tenant)
    assert got.id == cert_id
    assert got.status == "bootstrapping"
    # FR-VERIFY-013: issuance is receipted through controld, and the row carries the id.
    (body,) = controld.appended
    assert (body["tenant_id"], UUID(body["subject_id"])) == (tenant, cert_id)
    assert body["idempotency_key"] == f"certs.recompute:{cert_id}"
    assert body["payload"] == {
        "status": "bootstrapping",
        "verifier_id": str(verifier),
        "gold_set_id": str(gold_set),
        "gold_n": comp.gold_n,
        "rho_plus_micro": round(comp.rho_plus * 1_000_000),
        "rho_minus_micro": round(comp.rho_minus * 1_000_000),
        "natarajan_lcb_micro": round(comp.natarajan_lcb * 1_000_000),
        "identifiable": False,
    }
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        receipt_id = await conn.fetchval(
            "SELECT receipt_id FROM noise_certificates WHERE id = $1", cert_id
        )
    assert str(receipt_id) == next(iter(controld.acks.values()))["receipt_id"]

    # A registry read sees the global catalog row (no tenant GUC on m1_verifiers).
    keys = {e.id for e in await list_verifiers(pool)}
    assert verifier in keys


async def test_certified_is_earned_refused_by_the_db(admin, pool):
    """Phase 2 can never mint 'certified' (identifiable=False, no NATARAJAN LCB row):
    the write path must surface m1_021's CHECK, never work around it."""
    tenant = await _mk_tenant(admin)
    verifier = await _mk_judge_verifier(admin)
    gold_set = await create_gold_set(pool, tenant, "claudecode")
    await freeze_gold_set(pool, tenant, gold_set)
    comp = compute_certificate(
        score_agreement([("satisfied", "satisfied")] * 3 + [("violated", "violated")])
    )
    controld = FakeControld()
    with pytest.raises(asyncpg.CheckViolationError):
        await insert_cert(
            pool, tenant, verifier, "certified", comp, gold_set, append=controld.append()
        )
    # The receipt landed first and the row never did: a harmless orphan, never an unearned cert.
    assert [b["payload"]["status"] for b in controld.appended] == ["certified"]
    assert (await current_cert(pool, tenant)).id is None


async def test_unreceipted_cert_is_never_issued(admin, pool):
    """controld refuses or fails the append ⇒ no noise_certificates row at all (fail-closed);
    the same call succeeds once the chain answers."""
    tenant = await _mk_tenant(admin)
    verifier = await _mk_judge_verifier(admin)
    comp = compute_certificate(score_agreement([]))
    controld = FakeControld()
    for failure, code in (
        ((500, "M1E-9500", "chain append failed"), "M1E-9500"),
        ((403, "M1E-1001", "service credential rejected"), "M1E-1001"),
    ):
        controld.fail_with = failure
        with pytest.raises(ReceiptAppendError) as e:
            await insert_cert(
                pool, tenant, verifier, "bootstrapping", comp, None, append=controld.append()
            )
        assert e.value.code == code and controld.appended == []
        assert (await current_cert(pool, tenant)).id is None
    controld.fail_with = None
    cert_id = await insert_cert(
        pool, tenant, verifier, "bootstrapping", comp, None, append=controld.append()
    )
    assert (await current_cert(pool, tenant)).id == cert_id
    assert [UUID(b["subject_id"]) for b in controld.appended] == [cert_id]


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


async def test_tenant_predicate_holds_under_bypass_role(admin, pool):
    """The store's explicit WHERE tenant_id is the belt to RLS's braces: this test runs
    under WHATEVER role the DSN provides — including BYPASSRLS/superuser, where RLS is
    inert — and must still never see a foreign tenant's certificate. Deliberately no
    bypass-skip: the bypass case is the whole point (the rds_superuser lesson)."""
    tenant_a = await _mk_tenant(admin)
    tenant_b = await _mk_tenant(admin)
    verifier = await _mk_judge_verifier(admin)
    comp = compute_certificate(score_agreement([]))
    append = FakeControld().append()
    await insert_cert(pool, tenant_a, verifier, "bootstrapping", comp, None, append=append)
    b_first = await insert_cert(pool, tenant_b, verifier, "uncertified", comp, None, append=append)
    b_second = await insert_cert(
        pool, tenant_b, verifier, "bootstrapping", comp, None, append=append
    )

    # A tenant with no certs reads the honest floor, never someone else's row.
    tenant_c = await _mk_tenant(admin)
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


async def test_rls_isolation_between_tenants(admin, pool):
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
    tenant_a = await _mk_tenant(admin)
    tenant_b = await _mk_tenant(admin)
    verifier = await _mk_judge_verifier(admin)
    comp = compute_certificate(score_agreement([]))
    a_cert = await insert_cert(
        pool, tenant_a, verifier, "bootstrapping", comp, None, append=FakeControld().append()
    )
    # Tenant B's read must see NOTHING of tenant A's certificate: absence reads as
    # uncertified — the honest floor, not an error.
    got = await current_cert(pool, tenant_b)
    assert got.status == "uncertified"
    assert got.id is None

    # ...but the assertions above observe the BELT, not the braces: current_cert carries
    # an explicit WHERE tenant_id, so they stay green with the policy replaced by
    # USING (true) — measured. Only a predicate-free read can fail when RLS does.
    async with pool.acquire() as conn:
        # GUC unset (the pool's setup= RESETs it): the NULLIF form must match NOTHING.
        assert await conn.fetchval("SELECT count(*) FROM noise_certificates") == 0
        async with conn.transaction():
            await set_local_tenant(conn, tenant_b)
            visible = await conn.fetch("SELECT id FROM noise_certificates")
    assert a_cert not in {r["id"] for r in visible}


async def test_cloud_judge_consent_read_is_tenant_scoped_revocable_and_never_e2(admin, pool):
    """m1_065 as the cloud path reads it (06 §6.5 preconditions 1-4 at the DB layer)."""
    tenant_a, tenant_b = UUID(await _mk_tenant(admin)), UUID(await _mk_tenant(admin))
    jid = "judge:grounded-rubric@2"
    read = pg_consent_reader(pool)

    async def insert(tenant: UUID, max_tier: str):
        async with admin.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(tenant))
            await conn.execute(
                """
                INSERT INTO m1_cloud_judge_consents
                  (tenant_id, judge_id, subprocessor, region, max_tier, consented_by)
                VALUES ($1, $2, 'nebius', 'global', $3, 'test')
                """,
                tenant,
                jid,
                max_tier,
            )

    assert await read(tenant_a, jid) is None  # absence is the default, not an error
    await insert(tenant_a, "E0")
    assert await read(tenant_a, jid) == Consent("nebius", "global", "E0")
    assert await read(tenant_b, jid) is None  # tenant B sees nothing of A's consent
    # E2 never reaches the cloud path: the CHECK refuses the row, not just the read.
    with pytest.raises(asyncpg.CheckViolationError):
        await insert(tenant_b, "E2")
    # Revocation is an UPDATE the read honours; the history row stays.
    async with admin.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, str(tenant_a))
        await conn.execute(
            "UPDATE m1_cloud_judge_consents SET revoked_at = now(), revoked_reason = 'test' "
            "WHERE judge_id = $1",
            jid,
        )
        assert await conn.fetchval("SELECT count(*) FROM m1_cloud_judge_consents") == 1
    assert await read(tenant_a, jid) is None
