"""Intel's internal memory read surface (tvo/routes.py ownership split): `tenant_id` is the RLS
GUC, derived upstream by the public controld route from the verified device token. Only that
route may name a tenant, so both routes verify controld's service credential first (ADR-0010
§2.2, the same INTEL_QUERYCHOKE_TOKEN intel presents to controld; unset ⇒ absent, never open)."""

import hmac
import os
import uuid
from typing import Annotated

import asyncpg
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.memory import retrieve
from app.tvo.routes import m1e_error

router = APIRouter()


def get_pool(request: Request) -> asyncpg.Pool:
    return request.state.pool


class MatchBody(BaseModel):
    tenant_id: str
    error: str = Field(max_length=4096)
    limit: int = Field(default=retrieve.M_INJECT, ge=1, le=retrieve.M_INJECT)


def service_cred(authorization: Annotated[str, Header()] = "") -> JSONResponse | None:
    configured = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    presented = authorization.removeprefix("Bearer ")
    if not configured or not presented or not hmac.compare_digest(configured, presented):
        return m1e_error(403, "M1E-1001", "service credential required")
    return None


Refusal = Annotated[JSONResponse | None, Depends(service_cred)]


def _tenant(tenant_id: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(tenant_id)
    except ValueError:
        return None


@router.get("/v1/memory/artifacts")
async def artifacts_route(
    tenant_id: str, pool: Annotated[asyncpg.Pool, Depends(get_pool)], refused: Refusal
) -> JSONResponse:
    if refused is not None:
        return refused
    if _tenant(tenant_id) is None:
        return m1e_error(400, "M1E-2001", f"bad tenant_id {tenant_id!r}")
    async with pool.acquire() as conn:
        rows = await retrieve.admitted(conn, tenant_id)
    return JSONResponse(status_code=200, content={"artifacts": rows})


@router.post("/v1/memory/match")
async def match_route(
    body: MatchBody, pool: Annotated[asyncpg.Pool, Depends(get_pool)], refused: Refusal
) -> JSONResponse:
    if refused is not None:
        return refused
    if _tenant(body.tenant_id) is None:
        return m1e_error(400, "M1E-2001", f"bad tenant_id {body.tenant_id!r}")
    normalized = retrieve.normalize_signature(body.error)
    async with pool.acquire() as conn:
        rows = await retrieve.fuzzy_match(conn, body.tenant_id, normalized, limit=body.limit)
    return JSONResponse(
        status_code=200,
        content={"artifacts": rows, "signature_digest": retrieve.signature_digest(normalized)},
    )
