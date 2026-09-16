"""06 §9.3 ADMIT-LCB: tenant-scope admission, receipt, revocation recheck (FR-REMEMBER-003/007)."""

import json
import logging
import math
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from statistics import fmean, median, variance
from typing import Literal

import asyncpg
from mark1_receipts import ReceiptRef

from app.db import set_local_tenant
from app.memory.extract import live_certs
from app.tvo.reader import QuerychokeReader

DELTA = 0.05
N_MIN = 8
B_QUOTA = 20
OUTCOME_WINDOW = timedelta(days=30)
OUTCOME_TEMPLATE = "artifact_outcomes"
RECEIPT_TYPE = "memory_admission"
_CERTIFIED_STAGES = frozenset({"certified", "revised"})

log = logging.getLogger("intel.memory.admit")

Verdict = Literal["admit", "retire", "hold"]
# partial(append_server_record, http, controld_base_url, service_token); called keyword-only.
ReceiptAppend = Callable[..., Awaitable[ReceiptRef]]


@dataclass(frozen=True)
class Outcome:
    task_id: str
    utility: float
    task_cost: float
    stage: str
    noise_cert_id: str
    device_id: str


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    lcb: float
    ucb: float
    n: int
    phi: float

    @property
    def stored_lcb(self) -> Decimal | None:
        """lcb/φ: dimensionless so it fits numeric(8,6); sign-preserving, all the CHECK reads."""
        if math.isnan(self.lcb) or self.phi <= 0:
            return None
        return Decimal(f"{self.lcb / self.phi:.6f}")


@dataclass(frozen=True)
class AdmitReport:
    considered: int
    admitted: int
    retired: int
    held: int
    refused_revoked: int
    receipt_ids: tuple[uuid.UUID, ...] = ()


def clip(samples: Sequence[float], phi: float) -> list[float]:
    return [max(-phi, min(phi, u)) for u in samples]


def lcb_ucb(samples: Sequence[float], phi: float, delta: float = DELTA) -> tuple[float, float]:
    """Empirical-Bernstein, 06 §9.3 line 648: mean − √(2·Var̂·ln(2/δ)/n) − 7φ·ln(2/δ)/(3(n−1))."""
    n = len(samples)
    ln = math.log(2 / delta)
    slack = math.sqrt(2 * variance(samples) * ln / n) + 7 * phi * ln / (3 * (n - 1))
    mean = fmean(samples)
    return mean - slack, mean + slack


def decide(utilities: Sequence[float], phi: float, delta: float = DELTA) -> Decision:
    n = len(utilities)
    if n < N_MIN:
        return Decision("hold", math.nan, math.nan, n, phi)
    lcb, ucb = lcb_ucb(clip(utilities, phi), phi, delta)
    if lcb > 0:
        return Decision("admit", lcb, ucb, n, phi)
    if ucb < 0:
        return Decision("retire", lcb, ucb, n, phi)
    return Decision("hold", lcb, ucb, n, phi)


async def certified_outcomes(
    reader: QuerychokeReader,
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    artifact_id: uuid.UUID,
    window_start: date,
    window_end: date,
    bearer: str,
) -> list[Outcome]:
    """§5.4 outcome filter + D31 quota: uncertified rows are not evidence, excess is not counted."""
    result = await reader.run_template(
        OUTCOME_TEMPLATE,
        {
            "from": window_start.isoformat(),
            "to": window_end.isoformat(),
            "artifact_id": str(artifact_id),
        },
        bearer=bearer,
    )
    rows = [
        Outcome(
            task_id=str(r["task_id"]),
            utility=float(r["utility"]),
            task_cost=float(r["task_cost"]),
            stage=str(r["verdict_stage"]),
            noise_cert_id=str(r.get("noise_cert_id") or ""),
            device_id=str(r["device_id"]),
        )
        for r in result.rows
    ]
    stamped = [o for o in rows if o.stage in _CERTIFIED_STAGES and o.noise_cert_id]
    live = await live_certs(conn, tenant_id, {o.noise_cert_id for o in stamped})
    return [o for o in stamped if o.noise_cert_id in live][:B_QUOTA]


async def devices_unrevoked(conn: asyncpg.Connection, tenant_id: str, device_ids: set[str]) -> bool:
    """CON-007 fail-closed: every source device must exist in-tenant and be unrevoked."""
    if not device_ids:
        return False
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        n = await conn.fetchval(
            "SELECT count(*) FROM m1_devices WHERE id = ANY($1::uuid[]) AND revoked_at IS NULL",
            [uuid.UUID(d) for d in device_ids],
        )
    return n == len(device_ids)


async def admit_artifact(
    conn: asyncpg.Connection,
    append: ReceiptAppend,
    *,
    tenant_id: str,
    artifact_id: uuid.UUID,
    kind: str,
    lcb: Decimal,
    n_obs: int,
    cert_id: str,
    idempotency_key: str,
) -> uuid.UUID:
    """controld appends the receipt (m1_002 §5: one writer), then the state flip commits in THIS
    transaction with its id: a receipt without a flipped row is a harmless orphan, a flipped row
    without a receipt is the defect."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        ref = await append(
            tenant_id=tenant_id,
            record_type=RECEIPT_TYPE,
            subject_id=artifact_id,
            idempotency_key=idempotency_key,
            payload={
                "kind": kind,
                "lcb_micro": int(lcb * 1_000_000),
                "n_obs": n_obs,
                "cert_id": cert_id,
            },
        )
        receipt_id = ref.receipt_id
        flipped = await conn.fetchval(
            "UPDATE memory_artifacts SET state = 'admitted', lcb = $3, n_obs = $4, cert_id = $5, "
            "admitted_at = now(), receipt_id = $6, updated_at = now() "
            "WHERE id = $1 AND tenant_id = $2 AND state IN ('extracted', 'shadow') RETURNING id",
            artifact_id,
            uuid.UUID(tenant_id),
            lcb,
            n_obs,
            uuid.UUID(cert_id),
            receipt_id,
        )
        if flipped is None:
            raise ValueError(f"artifact {artifact_id} is not admissible from its current state")
    return receipt_id


async def _set_state(
    conn: asyncpg.Connection, tenant_id: str, artifact_id: uuid.UUID, state: str, d: Decision
) -> None:
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        await conn.execute(
            "UPDATE memory_artifacts SET state = $3::admission_state, lcb = $4, n_obs = $5, "
            "updated_at = now() WHERE id = $1 AND tenant_id = $2 "
            "AND state IN ('extracted', 'shadow')",
            artifact_id,
            uuid.UUID(tenant_id),
            state,
            d.stored_lcb,
            d.n,
        )


async def run_admit(
    reader: QuerychokeReader,
    conn: asyncpg.Connection,
    append: ReceiptAppend,
    *,
    tenant_id: str,
    day: date,
    bearer: str,
) -> AdmitReport:
    """Outcomes come from the D31 30-day window closing with `day`; one decision per artifact.
    The receipt key is (job, day, artifact): a crashed run re-appends into the same receipt, a
    later re-admission of a retired artifact is a new act with a new link (m1_072)."""
    window_end = day + timedelta(days=1)
    window_start = window_end - OUTCOME_WINDOW
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id, kind, body FROM memory_artifacts WHERE tenant_id = $1 "
            "AND state IN ('extracted', 'shadow') ORDER BY created_at",
            uuid.UUID(tenant_id),
        )
    admitted = retired = held = refused = 0
    receipts: list[uuid.UUID] = []
    for r in rows:
        body = json.loads(r["body"])
        outcomes = await certified_outcomes(
            reader,
            conn,
            tenant_id=tenant_id,
            artifact_id=r["id"],
            window_start=window_start,
            window_end=window_end,
            bearer=bearer,
        )
        phi = median(o.task_cost for o in outcomes) if outcomes else 0.0
        d = decide([o.utility for o in outcomes], phi)
        if d.verdict == "admit":
            devices = {body["provenance"]["device_id"], *(o.device_id for o in outcomes)}
            if not await devices_unrevoked(conn, tenant_id, devices):
                log.warning("admit %s: refused, revoked device in provenance", r["id"])
                refused += 1
                continue
            receipts.append(
                await admit_artifact(
                    conn,
                    append,
                    tenant_id=tenant_id,
                    artifact_id=r["id"],
                    kind=r["kind"],
                    lcb=d.stored_lcb,
                    n_obs=d.n,
                    cert_id=outcomes[-1].noise_cert_id,
                    idempotency_key=f"memory.admit:{day.isoformat()}:{r['id']}",
                )
            )
            admitted += 1
        elif d.verdict == "retire":
            await _set_state(conn, tenant_id, r["id"], "retired", d)
            retired += 1
        else:
            await _set_state(conn, tenant_id, r["id"], "shadow", d)
            held += 1
    log.info("admit %s: %d considered, %d admitted", tenant_id, len(rows), admitted)
    return AdmitReport(len(rows), admitted, retired, held, refused, tuple(receipts))
