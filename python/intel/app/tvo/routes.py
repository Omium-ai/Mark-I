"""Intel's internal report-assembly surface: request → reader → engine → report.py → body.

Ownership, determined from 08 §3.3 and 05 §1/§6 and stated here so nobody re-litigates it:
the CUSTOMER-facing `GET /api/v1/reports/tvo` is a `controld` route — 08 §3.3's reads are
"generated and executed exclusively by controld.query-choke", and 05 §1 puts the report
handlers in controld calling querychoke's Runner in-process. Intel is the ASSEMBLER
(06 §8: this engine "assembles reports"; 07 grants `tvo_reports` INSERT to intel_app):
this route produces the exact 08 §3.3 response body — the same JSON that lands in
`tvo_reports.body` — for controld/ops to serve or issue. It reads the ledger only through
the querychoke HTTP contract (reader.py), never ClickHouse.

Tenancy: the bearer token forwarded to the choke is the tenant scope (05 §6.2 — verified
claims, no parameter slot). `tenant_id` here addresses only the adjudicator's per-tenant
noise-certificate route (06 §1.2); it is never sent to the choke."""

import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import asyncpg
import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.db import set_local_tenant
from app.policy_compiler.cpvs import Regime
from app.pricing import UnpinnedModel
from app.regime import RegimeUnset, load_regime
from app.tvo.coverage import coverage_band
from app.tvo.engine import AttemptRow, NoiseCertificate, group_by_task, tvo_from_ledger
from app.tvo.reader import QuerychokeReader
from app.tvo.report import COST_BASIS_QUOTA, COST_BASIS_USD, ModelPrice, assemble_report
from app.tvo.waste import waste_taxonomy

router = APIRouter()

_WINDOW_RE = re.compile(r"^([1-9]\d{0,2})d$")

CertProvider = Callable[[str, str], Awaitable[NoiseCertificate]]


def m1e_error(status: int, code: str, message: str) -> JSONResponse:
    """The 08 §9 wire shape, verbatim: {"error": {"code", "message"}}."""
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def get_reader(request: Request) -> QuerychokeReader:
    return request.state.tvo_reader


def get_cert_provider(request: Request) -> CertProvider:
    """Default: adjudicator-svc `GET /v1/certs/{tenant_id}/current` (06 §1.2). An
    unreachable adjudicator degrades DOWNWARD only (06 §1.2 fail-open posture): the
    cert reads as 'uncertified', which can only remove claims — the report flips to
    `indicative` with the status string on it (§5.4) — never add them."""
    settings = request.state.settings
    http: httpx.AsyncClient = request.state.http

    async def fetch(tenant_id: str, bearer: str) -> NoiseCertificate:
        try:
            resp = await http.get(
                f"{settings.adjudicator_base_url.rstrip('/')}/v1/certs/{tenant_id}/current",
                headers={"Authorization": f"Bearer {bearer}"},
            )
            if resp.status_code == 200:
                data = resp.json()
                return NoiseCertificate(
                    status=data["status"],
                    rho_plus=data.get("rho_plus"),
                    rho_minus=data.get("rho_minus"),
                )
        except httpx.HTTPError:
            pass
        return NoiseCertificate("uncertified")

    return fetch


def get_pool(request: Request) -> asyncpg.Pool:
    return request.state.pool


async def get_regime(
    tenant_id: str, pool: Annotated[asyncpg.Pool, Depends(get_pool)]
) -> Regime | None:
    """The tenant's m1_075 row (app/regime), or None: unset, not a tenant id at all, or pinned
    to a model the current price table no longer carries. Either way the basis stays unresolved
    and the report issues as indicative (06 §8.5) — a downgrade, never a 500, never a guess."""
    try:
        UUID(tenant_id)
    except ValueError:
        return None
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant_id)
        try:
            return await load_regime(conn, tenant_id)
        except (RegimeUnset, UnpinnedModel):
            return None


def get_price_row(regime: Annotated[Regime | None, Depends(get_regime)]) -> ModelPrice | None:
    """The pinned model_prices row for a usd tenant (06 §8.4) — from app/pricing via the
    regime, so its price_table_version is the table digest the report stamps."""
    return regime.price if regime is not None and regime.cost_basis == COST_BASIS_USD else None


def get_shadow_price(
    regime: Annotated[Regime | None, Depends(get_regime)],
) -> tuple[float | None, bool]:
    """(S, confirmed) for the quota basis: confirmed iff the tenant's regime row carries it
    (D22 — the $200 default is a placeholder, never a confirmation)."""
    if regime is not None and regime.cost_basis == COST_BASIS_QUOTA:
        return (regime.shadow_price_usd, True)
    return (None, False)


def _terminal_verdicts(attempts: list[AttemptRow]) -> dict[str, tuple[str, str]]:
    """task → (fused_verdict, verdict_stage) at the highest attempt_n — the terminal pair
    the waste taxonomy and the rollup's tasks_verified both key on."""
    return {
        task: (rows[-1].fused_verdict, rows[-1].verdict_stage)
        for task, rows in group_by_task(attempts).items()
    }


@router.get("/v1/reports/tvo")
async def tvo_report_route(
    request: Request,
    tenant_id: str,
    reader: Annotated[QuerychokeReader, Depends(get_reader)],
    cert_provider: Annotated[CertProvider, Depends(get_cert_provider)],
    price: Annotated[ModelPrice | None, Depends(get_price_row)],
    shadow: Annotated[tuple[float | None, bool], Depends(get_shadow_price)],
    cost_basis: str,
    window: str = "30d",
    cohort: str = "all",
) -> JSONResponse:
    m = _WINDOW_RE.match(window)
    if m is None:
        return m1e_error(400, "M1E-2001", f"bad window {window!r} — expected e.g. '30d'")
    if cohort != "all":
        # ponytail: cohort filtering needs the cohort stamp (C1.9) the read templates do
        # not yet expose; refusing beats silently serving 'all' under a cohort label.
        return m1e_error(400, "M1E-2001", f"cohort {cohort!r} unsupported — only 'all'")
    if cost_basis not in ("usd", "quota"):
        # `auto` splits cohorts per 08 §3.3 — that split is the PUBLIC endpoint's job
        # (controld), keyed on the per-cohort basis stamp; this internal assembly surface
        # computes exactly one basis per call (06 §8.4: never mixed).
        return m1e_error(
            400, "M1E-2001", f"cost_basis {cost_basis!r} — this surface takes 'usd' or 'quota'"
        )

    window_end = datetime.now(UTC).date()
    window_start = window_end - timedelta(days=int(m.group(1)))

    auth = request.headers.get("authorization", "")
    bearer = auth.removeprefix("Bearer ").strip()

    ledger = await reader.attempt_window(window_start, window_end, bearer=bearer)
    if not ledger.attempts:
        # TVO over nothing is not a number (engine refuses); an empty tenant-window is a
        # request problem at this internal surface, stated with the taxonomy's request code.
        return m1e_error(400, "M1E-2001", "empty window — no attempt rows for this tenant/window")

    cov = await reader.coverage_inputs(window_start, window_end, bearer=bearer)
    cert = await cert_provider(tenant_id, bearer)

    attempts = list(ledger.attempts)
    try:
        result = tvo_from_ledger(attempts, cert)
        # Witness-free channels claim zero (06 §8.3 — counterfactual-free by design): the
        # v1 template registry (05 §6.3) exposes no CortexInjection served-set or
        # rung-signal read, so reexploration/over_model have no witnessed alternative.
        waste = waste_taxonomy(attempts, [], {}, [], _terminal_verdicts(attempts))
    except ValueError as exc:
        # The engine REFUSES unmeasurable windows (e.g. zero certified terminal verdicts:
        # p has no denominator) rather than inventing a number — that refusal reaches the
        # wire as the taxonomy's request code, never a bare 500 (08 §9 rule: one
        # taxonomy, every surface).
        return m1e_error(400, "M1E-2001", str(exc))
    band = coverage_band(
        cov.observed_ms,
        cov.bypass_ms,
        cov.disabled_ms,
        cov.dropped_billing,
        cov.events_billing_ingested,
    )

    versions = ledger.task_seg_versions
    shadow_price, shadow_confirmed = shadow
    report = assemble_report(
        result,
        waste,
        band,
        cost_basis=cost_basis,
        task_seg_version=versions[-1],
        task_seg_versions_in_window=versions,
        price=price,
        shadow_price_usd=shadow_price,
        shadow_price_confirmed=shadow_confirmed,
    )
    body = report.to_body()
    # ponytail: trend is per-day TVO and belongs to the tvo_tenant_day rollup — empty
    # until ADR-0010 is signed and the table has rows; [] is honest, a recompute is not.
    body["trend"] = []
    return JSONResponse(status_code=200, content=body)
