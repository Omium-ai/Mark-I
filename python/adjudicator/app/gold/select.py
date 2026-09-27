"""Gold-set selection (06 §5.1): server-side and POST-HOC — candidates are
already-completed tasks read from the ledger, stratified across verdict classes,
agents and repos, with the D14 per-repo cap.

Edge-indistinguishability is STRUCTURAL, not procedural: this module's inputs are
ordinary completed ledger rows and its only outputs are gold_sets/gold_set_members
rows (m1_021), which no edge-facing surface reads; nothing here can mark a task
before or while it runs, because at execution time gold tasks do not exist yet.
There is no wire field to sniff, no timing signal, no sampling seed to steal —
the anti-gaming property holds by construction (m1_021 header restates it)."""

import random
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import asyncpg

from app.db import set_local_tenant

# D14: ≤ 30% of a set from any one (per-tenant HMAC'd) repo digest.
REPO_CAP_FRAC = 0.30


@dataclass(frozen=True)
class CandidateTask:
    """One completed, adjudicated ledger task, as the nightly selection sees it."""

    task_digest: bytes  # per-tenant HMAC of (session_id, task_id) — m1_021's join key
    verdict_class: str  # the stratification axis 06 §5.1 names first
    agent: str  # claudecode | codex | … (gold_sets.agent)
    repo_digest: bytes  # per-tenant HMAC repo digest
    completed_at: datetime


def select_gold_candidates(
    candidates: list[CandidateTask],
    target_n: int,
    rng: random.Random,
) -> list[CandidateTask]:
    """Stratified sample: round-robin across (verdict_class, agent) strata so no class
    or agent dominates, refusing any pick that would push one repo digest past the D14
    cap. May return FEWER than target_n — an under-sized set is honest (the §5.3 size
    gates read it as such); an over-concentrated one is a gamed measurement.

    ponytail: proportional-allocation stratification (vs round-robin) if class
    imbalance in practice starves rare strata."""
    if target_n <= 0:
        raise ValueError("target_n must be positive")
    strata: dict[tuple[str, str], list[CandidateTask]] = {}
    for c in candidates:
        strata.setdefault((c.verdict_class, c.agent), []).append(c)
    for bucket in strata.values():
        rng.shuffle(bucket)
    # Deterministic stratum order under a seeded rng (tests), fair under a real one.
    order = sorted(strata.keys())

    repo_cap = max(1, int(REPO_CAP_FRAC * target_n))
    picked: list[CandidateTask] = []
    per_repo: dict[bytes, int] = {}
    progress = True
    while len(picked) < target_n and progress:
        progress = False
        for key in order:
            if len(picked) >= target_n:
                break
            bucket = strata[key]
            while bucket:
                c = bucket.pop()
                if per_repo.get(c.repo_digest, 0) < repo_cap:
                    picked.append(c)
                    per_repo[c.repo_digest] = per_repo.get(c.repo_digest, 0) + 1
                    progress = True
                    break
                # over-cap candidate is skipped, never swapped in later — the cap is
                # a bound on the SET, not a preference (D14).
    return picked


# ---------------------------------------------------------------------------
# m1_021 writes — all under the tenant GUC inside one transaction (RLS is the
# isolation; set_local_tenant is how this NOBYPASSRLS role passes its policies).
# ---------------------------------------------------------------------------


async def create_gold_set(pool: asyncpg.Pool, tenant_id: str, agent: str) -> UUID:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        row = await conn.fetchrow(
            "INSERT INTO gold_sets (tenant_id, agent) VALUES ($1, $2) RETURNING id",
            UUID(tenant_id),
            agent,
        )
        return row["id"]


async def add_members(
    pool: asyncpg.Pool,
    tenant_id: str,
    gold_set_id: UUID,
    members: list[tuple[bytes, str, str]],  # (task_digest, true_label, label_source)
) -> int:
    """Strong labels land per row with their source recorded (t3 | human |
    batch-readjudication — m1_021's label_source CHECK; the three sources are not
    interchangeable evidence). Re-labeling is an UPDATE, never a duplicate (the
    table's PK), hence the upsert."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        set_row = await conn.fetchrow("SELECT frozen_at FROM gold_sets WHERE id = $1", gold_set_id)
        if set_row is None:
            raise ValueError(f"gold set {gold_set_id} not visible in tenant {tenant_id}")
        if set_row["frozen_at"] is not None:
            # ρ measured against a moving target is not a measurement (m1_021): a
            # frozen set accepts no new members, ever — refuse, never skip silently.
            raise ValueError(f"gold set {gold_set_id} is frozen; open a new set")
        await conn.executemany(
            """
            INSERT INTO gold_set_members
              (gold_set_id, tenant_id, task_digest, true_label, label_source)
            VALUES ($1, $2, $3, $4::verdict, $5)
            ON CONFLICT (gold_set_id, task_digest)
              DO UPDATE SET true_label = EXCLUDED.true_label,
                            label_source = EXCLUDED.label_source,
                            labeled_at = now(),
                            row_seq = DEFAULT
            """,
            [(gold_set_id, UUID(tenant_id), d, label, src) for d, label, src in members],
        )
        return len(members)


async def freeze_gold_set(pool: asyncpg.Pool, tenant_id: str, gold_set_id: UUID) -> None:
    """A certificate may only cite a frozen set (m1_021's trigger enforces it on the
    cert side; this is the producer side)."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        await conn.execute(
            "UPDATE gold_sets SET frozen_at = now(), row_seq = DEFAULT "
            "WHERE id = $1 AND frozen_at IS NULL",
            gold_set_id,
        )
