"""06 §12.4 promotion pipeline for learned members (FR-LEARN-004, C12): the Python half
of migrations/m1_069_verifier_promotion.sql, whose trigger IS the state machine."""

import json
import logging
import math
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from statistics import fmean, variance
from typing import Any, Literal

import asyncpg

from app.adjudicate.likelihoods import Confusion
from app.certs.store import ReceiptAppend
from app.db import set_local_tenant
from app.registry.handlers import NormalizedVote

DELTA = 0.05
SHADOW_MIN = 500
SHADOW_TTL = timedelta(days=60)
RECEIPT_TYPE = "verifier_promotion"
SERVING = ("canary", "active")
_BINARY = frozenset({"satisfied", "violated"})

log = logging.getLogger("adjudicator.promotion")

Verdict = Literal["promote", "regress", "insufficient_evidence"]


@dataclass(frozen=True)
class ShadowPair:
    vote: str
    verdict: str
    cert_id: str


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    n: int
    lcb: float
    ucb: float


@dataclass(frozen=True)
class Measurement:
    pairs: Sequence[ShadowPair]
    bar: float = 0.0


@dataclass(frozen=True)
class PromotionReport:
    considered: int
    promoted: int
    regressed: int
    retired: int
    receipt_ids: tuple[uuid.UUID, ...] = ()


def youden(confusion: Confusion) -> float:
    """α − β = P(reject | violated) − P(reject | satisfied); abstain-always scores 0."""
    return confusion[1][1] - confusion[0][1]


def youden_samples(pairs: Iterable[ShadowPair]) -> tuple[list[float], float]:
    """Per-pair influence samples whose mean is exactly TPR̂ − FPR̂, bounded by φ."""
    binary = [p for p in pairs if p.verdict in _BINARY]
    n_v = sum(1 for p in binary if p.verdict == "violated")
    n_s = len(binary) - n_v
    if not n_v or not n_s:
        return [], 0.0
    n = len(binary)
    u = [
        (n / n_v if p.verdict == "violated" else -n / n_s) if p.vote == "reject" else 0.0
        for p in binary
    ]
    return u, n / min(n_v, n_s)


def lcb_ucb(samples: Sequence[float], phi: float, delta: float = DELTA) -> tuple[float, float]:
    """Empirical-Bernstein, the twin of intel app/memory/admit.py lcb_ucb (06 §9.3 line 648)."""
    n = len(samples)
    ln = math.log(2 / delta)
    slack = math.sqrt(2 * variance(samples) * ln / n) + 7 * phi * ln / (3 * (n - 1))
    mean = fmean(samples)
    return mean - slack, mean + slack


def decide(pairs: Sequence[ShadowPair], bar: float, delta: float = DELTA) -> Decision:
    u, phi = youden_samples(pairs)
    n = len(u)
    if n < SHADOW_MIN:
        return Decision("insufficient_evidence", n, math.nan, math.nan)
    lcb, ucb = lcb_ucb(u, phi, delta)
    if lcb > bar:
        return Decision("promote", n, lcb, ucb)
    if ucb < bar:
        return Decision("regress", n, lcb, ucb)
    return Decision("insufficient_evidence", n, lcb, ucb)


def split_shadow(
    votes: Sequence[NormalizedVote], shadow_ids: Iterable[str]
) -> tuple[list[NormalizedVote], list[NormalizedVote]]:
    """(fusion input, shadow votes): a non-serving member's votes never reach adjudicate;
    they are the pairs the measure step scores against the fused certified verdict."""
    drop = set(shadow_ids)
    return [v for v in votes if v.verifier_id not in drop], [
        v for v in votes if v.verifier_id in drop
    ]


async def shadow_ids(conn: asyncpg.Connection, tenant_id: str) -> set[str]:
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT v.verifier_key, v.version FROM m1_verifier_promotions p "
            "JOIN m1_verifiers v ON v.id = p.verifier_id "
            "WHERE p.tenant_id = $1 AND p.state <> ALL($2::promotion_state[])",
            uuid.UUID(tenant_id),
            list(SERVING),
        )
    return {f"{r['verifier_key']}@{r['version']}" for r in rows}


async def register(
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    verifier_id: uuid.UUID,
    incumbent_verifier_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Probation: registered, serves nothing (06 §12.4 row 1); no other birth state exists."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        return await conn.fetchval(
            "INSERT INTO m1_verifier_promotions (tenant_id, verifier_id, incumbent_verifier_id) "
            "VALUES ($1, $2, $3) RETURNING id",
            uuid.UUID(tenant_id),
            verifier_id,
            incumbent_verifier_id,
        )


async def transition(
    conn: asyncpg.Connection,
    append: ReceiptAppend,
    *,
    tenant_id: str,
    promotion_id: uuid.UUID,
    from_state: str,
    to_state: str,
    reason: str,
    evidence: Mapping[str, Any] | None = None,
) -> uuid.UUID:
    """controld appends the verifier_promotion receipt (m1_002 §5: one writer), then the
    ledger row whose trigger moves the head or refuses lands in one transaction."""
    transition_id = uuid.uuid4()
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        ref = await append(
            tenant_id=tenant_id,
            record_type=RECEIPT_TYPE,
            subject_id=transition_id,
            idempotency_key=f"promotion.step:{transition_id}",
            payload={
                "promotion_id": str(promotion_id),
                "from_state": from_state,
                "to_state": to_state,
                "reason": reason,
            },
        )
        receipt_id = ref.receipt_id
        await conn.execute(
            "INSERT INTO m1_verifier_promotion_transitions "
            "(id, tenant_id, promotion_id, from_state, to_state, reason, evidence, receipt_id) "
            "VALUES ($1, $2, $3, $4::promotion_state, $5::promotion_state, $6, $7::jsonb, $8)",
            transition_id,
            uuid.UUID(tenant_id),
            promotion_id,
            from_state,
            to_state,
            reason,
            json.dumps(dict(evidence or {})),
            receipt_id,
        )
    return receipt_id


async def _live_certs(conn: asyncpg.Connection, tenant_id: str, ids: set[str]) -> set[str]:
    if not ids:
        return set()
    rows = await conn.fetch(
        "SELECT id FROM noise_certificates WHERE tenant_id = $1 AND id = ANY($2::uuid[]) "
        "AND status = 'certified' AND expires_at > now()",
        uuid.UUID(tenant_id),
        [uuid.UUID(i) for i in ids],
    )
    return {str(r["id"]) for r in rows}


def _num(x: float) -> Decimal | None:
    return None if math.isnan(x) else Decimal(f"{x:.6f}")


async def measure(
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    promotion_id: uuid.UUID,
    pairs: Sequence[ShadowPair],
    bar: float,
) -> Decision:
    """§5.4 filter (only pairs under a live certified cert) + decide; a shadow head keeps them."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        live = await _live_certs(conn, tenant_id, {p.cert_id for p in pairs})
        certified = [p for p in pairs if p.cert_id in live]
        d = decide(certified, bar)
        await conn.execute(
            "UPDATE m1_verifier_promotions SET shadow_n = $3, lcb = $4, bar = $5, cert_id = $6, "
            "measured_at = now(), updated_at = now() "
            "WHERE id = $1 AND tenant_id = $2 AND state = 'shadow'",
            promotion_id,
            uuid.UUID(tenant_id),
            d.n,
            _num(d.lcb),
            Decimal(f"{bar:.6f}"),
            uuid.UUID(certified[-1].cert_id) if certified else None,
        )
    return d


async def run_promotion(
    conn: asyncpg.Connection,
    append: ReceiptAppend,
    *,
    tenant_id: str,
    measured: Mapping[uuid.UUID, Measurement],
    now: datetime | None = None,
) -> PromotionReport:
    """06 §12.4 rows 2-3 for every shadow head, regression for every serving one, D39 retirement."""
    now = now or datetime.now(UTC)
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id, state, state_since FROM m1_verifier_promotions WHERE tenant_id = $1 "
            "AND state = ANY($2::promotion_state[]) ORDER BY created_at",
            uuid.UUID(tenant_id),
            ["shadow", *SERVING],
        )
    promoted = regressed = retired = 0
    receipts: list[uuid.UUID] = []
    for r in rows:
        m = measured.get(r["id"], Measurement(()))
        d = await measure(conn, tenant_id=tenant_id, promotion_id=r["id"], pairs=m.pairs, bar=m.bar)
        evidence = {"n": d.n, "lcb": d.lcb, "ucb": d.ucb, "bar": m.bar}
        if r["state"] == "shadow" and d.verdict == "promote":
            receipts.append(
                await transition(
                    conn,
                    append,
                    tenant_id=tenant_id,
                    promotion_id=r["id"],
                    from_state="shadow",
                    to_state="lcb_promoted",
                    reason="lcb_promotion",
                )
            )
            promoted += 1
        elif r["state"] == "shadow" and now - r["state_since"] > SHADOW_TTL:
            receipts.append(
                await transition(
                    conn,
                    append,
                    tenant_id=tenant_id,
                    promotion_id=r["id"],
                    from_state="shadow",
                    to_state="retired",
                    reason="shadow_ttl",
                    evidence={"n": d.n},
                )
            )
            retired += 1
        elif r["state"] in SERVING and d.verdict == "regress":
            receipts.append(
                await transition(
                    conn,
                    append,
                    tenant_id=tenant_id,
                    promotion_id=r["id"],
                    from_state=r["state"],
                    to_state="shadow",
                    reason="regression",
                    evidence=evidence,
                )
            )
            regressed += 1
    log.info(
        "promotion %s: %d considered, %d promoted, %d regressed, %d retired",
        tenant_id,
        len(rows),
        promoted,
        regressed,
        retired,
    )
    return PromotionReport(len(rows), promoted, regressed, retired, tuple(receipts))
