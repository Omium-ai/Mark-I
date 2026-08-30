"""noise_certificates reads/writes (m1_021), tenant GUC discipline throughout.

The DB is the last line, not the only line: m1_021's certified_is_earned CHECK and the
frozen-gold-set trigger will refuse a dishonest row even if this code regresses — this
module never works around them (a raised asyncpg.CheckViolationError is the correct
outcome of a dishonest write attempt)."""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg

from app.certs.compute import CertComputation
from app.db import set_local_tenant


@dataclass(frozen=True)
class CertRow:
    """What `GET /v1/certs/{tenant_id}/current` serves — the shape intel's
    get_cert_provider already consumes (status + the binary projection)."""

    id: UUID | None
    status: str
    rho_plus: float | None
    rho_minus: float | None
    natarajan_lcb: float | None
    issued_at: datetime | None
    expires_at: datetime | None


_UNCERTIFIED = CertRow(None, "uncertified", None, None, None, None, None)

# Certificate validity window (m1_021 defines no DB default, so the write path owns
# it). 30 days = the D16 freshness gate: past it, the ≥50%-fresh-labels claim behind
# the measurement can no longer be asserted without a recompute — and the nightly
# recompute supersedes long before then, so expiry only bites when recomputes stop,
# which is exactly when the cert should lapse.
_VALIDITY = timedelta(days=30)


async def current_cert(pool: asyncpg.Pool, tenant_id: str) -> CertRow:
    """The tenant's current certificate status — the check every §5.4 consumer makes.

    No row is an honest answer: absence reads as `uncertified` (the same downward-only
    degradation intel's cert provider applies when this service is unreachable).

    The explicit tenant_id predicate is belt to RLS's braces: under a BYPASSRLS-capable
    role (the estate's rds_superuser lesson) the GUC policy is inert, and an unfiltered
    LIMIT 1 would serve an arbitrary tenant's certificate.
    ponytail: newest-row-wins across verifiers; m1_021 keys certs per (tenant,
    verifier) while the 06 §1.2 route (and intel, its consumer) is per-tenant — the
    ensemble-cert keying is flagged as a contradiction, not resolved here."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        row = await conn.fetchrow(
            """
            SELECT id, status, rho_plus, rho_minus, natarajan_lcb, issued_at, expires_at
            FROM noise_certificates
            WHERE tenant_id = $1
            ORDER BY (status = 'certified' AND expires_at > now()) DESC,
                     issued_at DESC NULLS LAST
            LIMIT 1
            """,
            UUID(tenant_id),
        )
    if row is None:
        return _UNCERTIFIED
    if row["status"] == "certified" and row["expires_at"] <= _db_now(row):
        # Freshness is enforced at read time, not by a sweeper (m1_021's
        # mark1_assert_certified rule applied to our own read path).
        return _UNCERTIFIED
    return CertRow(
        id=row["id"],
        status=row["status"],
        rho_plus=_f(row["rho_plus"]),
        rho_minus=_f(row["rho_minus"]),
        natarajan_lcb=_f(row["natarajan_lcb"]),
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
    )


def _db_now(row: asyncpg.Record) -> datetime:
    # expires_at is tz-aware; compare in its own timezone to avoid naive-aware mixing.
    return datetime.now(tz=row["expires_at"].tzinfo)


def _f(x: Any) -> float | None:
    return float(x) if x is not None else None  # numeric(7,6) arrives as Decimal


async def insert_cert(
    pool: asyncpg.Pool,
    tenant_id: str,
    verifier_id: UUID,
    status: str,
    computation: CertComputation,
    gold_set_id: UUID | None,
    identifiable: bool = False,  # Phase 2 truth: no spectral run has ever passed §4.3
    diagnostics: dict[str, Any] | None = None,
) -> UUID:
    """One recompute → one NEW row (certificates are immutable; supersession is by
    validity window, 06 §5.2). Rates land exactly as measured — None stays NULL,
    never a fabricated 0.0."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        row = await conn.fetchrow(
            """
            INSERT INTO noise_certificates
              (tenant_id, verifier_id, gold_set_id, status, rho_plus, rho_minus,
               natarajan_lcb, gold_n, identifiable, diagnostics, issued_at, expires_at)
            VALUES ($1, $2, $3, $4::cert_status, $5, $6, $7, $8, $9, $10::jsonb,
                    now(), now() + $11::interval)
            RETURNING id
            """,
            UUID(tenant_id),
            verifier_id,
            gold_set_id,
            status,
            computation.rho_plus,
            computation.rho_minus,
            computation.natarajan_lcb,
            computation.gold_n,
            identifiable,
            json.dumps(diagnostics or {}),
            _VALIDITY,
        )
        return row["id"]
