"""06 §12.4 promotion pipeline for learned members (FR-LEARN-004, C12): the Python half
of migrations/m1_069_verifier_promotion.sql + m1_094, whose trigger IS the state machine.

16 §L6 amendments: a candidate is measured against the human/T3 gold set and the certified
ledger (never escalations), so the third clique is promotable before anything is certified;
canary fuses the member on a hashed ~10% of tasks for 48 h; a public-data model's head lives
in the global promotion tenant and governs every tenant's fusion."""

import hashlib
import json
import logging
import math
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from statistics import fmean, variance
from typing import Any, Literal
from uuid import UUID

import asyncpg
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.adjudicate.likelihoods import Confusion
from app.certs.store import ReceiptAppend
from app.db import set_local_tenant
from app.registry.catalog import RegistryEntry
from app.registry.handlers import NormalizedVote

DELTA = 0.05
SHADOW_MIN = 500
GOLD_MIN = 200  # D15: gold overlaps that stand in for certified pairs (rm-design §4.4)
SHADOW_TTL = timedelta(days=60)
CANARY_PCT = 10
CANARY_HOLD = timedelta(hours=48)
CANARY_FLIP_MAX = 0.10  # [SPEC] share of canary tasks whose fused verdict the member may flip
RECEIPT_TYPE = "verifier_promotion"
SERVING = ("canary", "active")
LEARNED = "reward_model"
GOLD = "gold"  # ShadowPair.cert_id of a pair measured against a human/T3 gold label
_BINARY = frozenset({"satisfied", "violated"})


class PromotionSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADJ_PROMOTION_", frozen=True)

    global_tenant: str = ""  # holds global-scope heads; empty ⇒ no global member ever serves


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
    gold_n: int = 0


@dataclass(frozen=True)
class CanaryWatch:
    """What the canary slice showed: fused-verdict flips the member caused, and gold agreement
    (agree, n) of the fused verdict with and without it."""

    tasks: int
    flips: int
    gold_with: tuple[int, int] = (0, 0)
    gold_without: tuple[int, int] = (0, 0)

    def healthy(self) -> bool:
        (aw, nw), (ao, no) = self.gold_with, self.gold_without
        return self.flips <= CANARY_FLIP_MAX * self.tasks and aw * no >= ao * nw


@dataclass(frozen=True)
class Measurement:
    pairs: Sequence[ShadowPair]
    bar: float = 0.0
    votes: int | None = None  # the member's votes in the window (D38); None ⇒ the pair count
    canary: CanaryWatch | None = None


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


def decide(
    pairs: Sequence[ShadowPair], bar: float, delta: float = DELTA, votes: int | None = None
) -> Decision:
    """≥ 500 member votes AND (≥ 500 certified pairs OR ≥ 200 gold overlaps), then the LCB."""
    u, phi = youden_samples(pairs)
    n = len(u)
    gold_n = sum(1 for p in pairs if p.cert_id == GOLD and p.verdict in _BINARY)
    shadow = n if votes is None else votes
    if shadow < SHADOW_MIN or n < 2 or (n - gold_n < SHADOW_MIN and gold_n < GOLD_MIN):
        return Decision("insufficient_evidence", shadow, math.nan, math.nan, gold_n)
    lcb, ucb = lcb_ucb(u, phi, delta)
    if lcb > bar:
        return Decision("promote", shadow, lcb, ucb, gold_n)
    if ucb < bar:
        return Decision("regress", shadow, lcb, ucb, gold_n)
    return Decision("insufficient_evidence", shadow, lcb, ucb, gold_n)


def in_canary(task_id: UUID) -> bool:
    """The hashed ~10% slice a canary member fuses on; stable per task, blind to every vote."""
    return int.from_bytes(hashlib.sha256(task_id.bytes).digest()[:8], "big") % 100 < CANARY_PCT


def split_shadow(
    votes: Sequence[NormalizedVote], shadow_ids: Iterable[str], canary_ids: Iterable[str] = ()
) -> tuple[list[NormalizedVote], list[NormalizedVote]]:
    """(fusion input, shadow votes): a non-serving member's votes never reach adjudicate; a
    canary member's reach it only on its hashed slice. Estimation reads every vote (06 §4.4)."""
    drop, canary = set(shadow_ids), set(canary_ids)

    def held(v: NormalizedVote) -> bool:
        return v.verifier_id in drop and not (v.verifier_id in canary and in_canary(v.task_id))

    return [v for v in votes if not held(v)], [v for v in votes if held(v)]


async def fusion_states(conn: asyncpg.Connection, tenant_id: str) -> dict[str, str]:
    """wire id → the promotion state governing this tenant's fusion: its own heads, the global
    tenant's for global-scope members, and 'probation' for a learned row with no head at all."""
    sql = (
        "SELECT v.verifier_key, v.version, v.kind, v.definition->>'scope' AS scope, "
        "p.state::text AS state FROM m1_verifier_promotions p "
        "RIGHT JOIN m1_verifiers v ON v.id = p.verifier_id AND p.tenant_id = $1 "
        "WHERE v.kind = $2 OR p.id IS NOT NULL"
    )
    glob = PromotionSettings().global_tenant
    out: dict[str, str] = {}
    for tenant, scope in ((tenant_id, None), (glob, "global")):
        if not tenant:
            continue
        async with conn.transaction():
            await set_local_tenant(conn, tenant)
            rows = await conn.fetch(sql, uuid.UUID(tenant), LEARNED)
        for r in rows:
            if scope is None or r["scope"] == scope:
                out[f"{r['verifier_key']}@{r['version']}"] = r["state"] or "probation"
    return out


async def shadow_ids(conn: asyncpg.Connection, tenant_id: str) -> set[str]:
    """Every member not `active`: canary included, re-admitted per task by split_shadow."""
    return {v for v, s in (await fusion_states(conn, tenant_id)).items() if s != "active"}


async def canary_ids(conn: asyncpg.Connection, tenant_id: str) -> set[str]:
    return {v for v, s in (await fusion_states(conn, tenant_id)).items() if s == "canary"}


def scope_of(entry: RegistryEntry) -> str:
    return "global" if entry.definition.get("scope") == "global" else "tenant"


async def register_catalog(
    conn: asyncpg.Connection, *, tenant_id: str, entries: Iterable[RegistryEntry]
) -> list[uuid.UUID]:
    """The register caller (06 §12.4 row 1): every live learned catalog row gets a probation
    head where its scope says — the global tenant for a public-data model, each tenant (or the
    one it names) for a tenant fine-tune."""
    glob = PromotionSettings().global_tenant
    mine = [
        e
        for e in entries
        if e.db_kind == LEARNED
        and not e.retired
        and (
            tenant_id == glob
            if scope_of(e) == "global"
            else e.definition.get("tenant_id") in (None, tenant_id)
        )
    ]
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        have = {
            r["verifier_id"]
            for r in await conn.fetch(
                "SELECT verifier_id FROM m1_verifier_promotions WHERE tenant_id = $1",
                uuid.UUID(tenant_id),
            )
        }
    return [
        await register(conn, tenant_id=tenant_id, verifier_id=e.id)
        for e in mine
        if e.id not in have
    ]


def eval_card_complete(definition: Mapping[str, Any]) -> bool:
    """Probation → shadow (06 §12.4 row 1): the sealed artifact's eval card passed RM1–RM7."""
    card = (definition.get("artifact") or {}).get("eval_card") or {}
    return card.get("passed") is True


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
    votes: int | None = None,
) -> Decision:
    """§5.4 filter (gold pairs, or pairs under a live certified cert) + decide; a shadow head
    keeps them."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        ids = {p.cert_id for p in pairs if p.cert_id not in ("", GOLD)}
        live = await _live_certs(conn, tenant_id, _uuids(ids))
        kept = [p for p in pairs if p.cert_id == GOLD or p.cert_id in live]
        certified = [p for p in kept if p.cert_id != GOLD]
        d = decide(kept, bar, votes=votes)
        await conn.execute(
            "UPDATE m1_verifier_promotions SET shadow_n = $3, lcb = $4, bar = $5, cert_id = $6, "
            "gold_n = $7, measured_at = now(), updated_at = now() "
            "WHERE id = $1 AND tenant_id = $2 AND state = 'shadow'",
            promotion_id,
            uuid.UUID(tenant_id),
            d.n,
            _num(d.lcb),
            Decimal(f"{bar:.6f}"),
            uuid.UUID(certified[-1].cert_id) if certified else None,
            d.gold_n,
        )
    return d


def _uuids(ids: Iterable[str]) -> set[str]:
    out = set()
    for i in ids:
        try:
            out.add(str(uuid.UUID(i)))
        except ValueError:
            continue
    return out


async def run_promotion(
    conn: asyncpg.Connection,
    append: ReceiptAppend,
    *,
    tenant_id: str,
    measured: Mapping[uuid.UUID, Measurement],
    now: datetime | None = None,
) -> PromotionReport:
    """06 §12.4 for every head, one edge per night: probation → shadow on a passed eval card,
    shadow → lcb_promoted on the LCB (or retired at D39), lcb_promoted → canary, canary → active
    after 48 h of a healthy slice (else back to shadow), any serving head → shadow on regression."""
    now = now or datetime.now(UTC)
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT p.id, p.state::text AS state, p.state_since, v.definition::text AS definition "
            "FROM m1_verifier_promotions p JOIN m1_verifiers v ON v.id = p.verifier_id "
            "WHERE p.tenant_id = $1 AND p.state <> 'retired' ORDER BY p.created_at",
            uuid.UUID(tenant_id),
        )
    counts: Counter[str] = Counter()
    receipts: list[uuid.UUID] = []

    async def edge(r: Mapping[str, Any], to: str, reason: str, evidence: Mapping | None = None):
        receipts.append(
            await transition(
                conn,
                append,
                tenant_id=tenant_id,
                promotion_id=r["id"],
                from_state=r["state"],
                to_state=to,
                reason=reason,
                evidence=evidence,
            )
        )
        counts[reason] += 1

    for r in rows:
        state, m = r["state"], measured.get(r["id"], Measurement(()))
        if state == "probation":
            if eval_card_complete(json.loads(r["definition"] or "{}")):
                await edge(r, "shadow", "eval_card_complete")
            continue
        if state == "lcb_promoted":
            await edge(r, "canary", "canary_start", {"pct": CANARY_PCT})
            continue
        d = await measure(
            conn, tenant_id=tenant_id, promotion_id=r["id"], pairs=m.pairs, bar=m.bar, votes=m.votes
        )
        evidence = {"n": d.n, "gold_n": d.gold_n, "lcb": d.lcb, "ucb": d.ucb, "bar": m.bar}
        if state == "shadow" and d.verdict == "promote":
            await edge(r, "lcb_promoted", "lcb_promotion")
        elif state == "shadow" and now - r["state_since"] > SHADOW_TTL:
            await edge(r, "retired", "shadow_ttl", {"n": d.n})
        elif state in SERVING and d.verdict == "regress":
            await edge(r, "shadow", "regression", evidence)
        elif (
            state == "canary"
            and now - r["state_since"] >= CANARY_HOLD
            and m.canary
            and m.canary.tasks
        ):
            watch = {**m.canary.__dict__, "healthy": m.canary.healthy()}
            if m.canary.healthy():
                await edge(r, "active", "canary_widened", watch)
            else:
                await edge(r, "shadow", "canary_regression", watch)
    log.info("promotion %s: %d considered, edges=%s", tenant_id, len(rows), dict(counts))
    return PromotionReport(
        len(rows),
        counts["lcb_promotion"],
        counts["regression"] + counts["canary_regression"],
        counts["shadow_ttl"],
        tuple(receipts),
    )
