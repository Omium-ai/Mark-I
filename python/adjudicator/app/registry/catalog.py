"""The durable half of the registry (06 §2): reads of m1_verifiers
(migrations/m1_020_verifier_registry.sql). The table is GLOBAL — no tenant_id, no RLS —
because bundles enable anchors by catalog id and confusion matrices key on
(verifier, version), so every tenant must read the same rows.

Phase 2 note, recorded rather than improvised around: 06 §1.3 says the registry row
carries "current confusion estimate + its provenance", but m1_020's m1_verifiers is an
immutable consent catalog with no confusion columns. Until the Phase 4 spectral
estimator lands (with its own adj_0NN_*.sql owning estimated confusions), confusion
comes from likelihoods.py's literature-CALIBRATED defaults, provenance 'prior' — the
honest Phase 2 posture (06 §4.3's gate-failed degradation is this service's steady
state until spectral exists)."""

from dataclasses import dataclass
from uuid import UUID

import asyncpg

# m1_020's coarse kind CHECK ('anchor'|'judge'|'reward_model'|'consistency') vs the
# handler kinds of 06 §2.1: the DB 'anchor' class covers the four anchor catalog kinds
# (lint/typecheck/compile/test); the fine kind rides in definition->>'kind'.
_DB_KIND_FALLBACK = {
    "judge": "judge",
    "reward_model": "rm",
    "consistency": "consistency",
    # 'anchor' has NO fallback on purpose: an anchor row whose definition does not say
    # which anchor kind it is cannot be normalized honestly — it surfaces as a refusal
    # (handlers.py §2.2), never a guessed likelihood row.
}


@dataclass(frozen=True)
class RegistryEntry:
    """One m1_verifiers row, as the vote normalizers consume it."""

    id: UUID
    verifier_key: str
    version: int
    db_kind: str  # m1_020 CHECK vocabulary
    kind: str | None  # handler kind (06 §2.1 KIND_*), None ⇒ unresolvable ⇒ refusal
    effective_execution_hash: bytes | None  # anchors only (m1_020 equivalence CHECK)
    retired: bool


def entry_from_row(row: asyncpg.Record | dict) -> RegistryEntry:
    definition = row["definition"] or {}
    db_kind = row["kind"]
    return RegistryEntry(
        id=row["id"],
        verifier_key=row["verifier_key"],
        version=row["version"],
        db_kind=db_kind,
        kind=definition.get("kind") or _DB_KIND_FALLBACK.get(db_kind),
        effective_execution_hash=row["effective_execution_hash"],
        retired=row["retired_at"] is not None,
    )


async def list_verifiers(pool: asyncpg.Pool, include_retired: bool = False) -> list[RegistryEntry]:
    """`GET /v1/registry/verifiers` read (06 §1.2, 100 ms budget) — the policy
    compiler's and `mark1 doctor`'s view. Global table: no tenant GUC needed."""
    where = "" if include_retired else "WHERE retired_at IS NULL"
    rows = await pool.fetch(
        f"""
        SELECT id, verifier_key, version, kind, definition, effective_execution_hash,
               retired_at
        FROM m1_verifiers {where}
        ORDER BY verifier_key, version DESC
        """  # noqa: S608 — `where` is one of two literals above, never caller input
    )
    return [entry_from_row(_with_json_definition(r)) for r in rows]


def _with_json_definition(row: asyncpg.Record) -> dict:
    # asyncpg returns jsonb as str unless a codec is registered; decode here so the
    # pool needs no per-connection codec setup for one column.
    import json

    d = dict(row)
    if isinstance(d.get("definition"), str):
        d["definition"] = json.loads(d["definition"])
    return d
