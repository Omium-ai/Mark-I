"""Intel's internal memory read surface (tvo/routes.py ownership split): `tenant_id` is the RLS
GUC, derived upstream by the public controld route from the verified device token. Only that
route may name a tenant, so both routes verify controld's service credential first (ADR-0010
§2.2, the same INTEL_QUERYCHOKE_TOKEN intel presents to controld; unset ⇒ absent, never open)."""

import hmac
import logging
import os
import uuid
from functools import partial
from typing import Annotated

import asyncpg
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from mark1_receipts import ReceiptAppendError, append_server_record
from pydantic import BaseModel, Field

from app.memory import admit, retrieve
from app.memory.admit import ReceiptAppend
from app.tvo.routes import m1e_error

router = APIRouter()
log = logging.getLogger("intel.memory.routes")


def get_pool(request: Request) -> asyncpg.Pool:
    return request.state.pool


def get_append(request: Request) -> ReceiptAppend:
    """memory/jobs.py receipt_append, on the lifespan's client: controld's append route under the
    same service credential the job presents."""
    return partial(
        append_server_record,
        request.state.http,
        request.state.settings.querychoke_base_url,
        os.environ.get("INTEL_QUERYCHOKE_TOKEN", ""),
    )


class MatchBody(BaseModel):
    tenant_id: str
    error: str = Field(max_length=4096)
    limit: int = Field(default=retrieve.M_INJECT, ge=1, le=retrieve.M_INJECT)


class TenantBody(BaseModel):
    tenant_id: str


class RetireBody(TenantBody):
    reason: str = Field(min_length=1, max_length=1024)
    by: str = Field(default="", max_length=256)


def service_cred(authorization: Annotated[str, Header()] = "") -> JSONResponse | None:
    configured = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    presented = authorization.removeprefix("Bearer ")
    if not configured or not presented or not hmac.compare_digest(configured, presented):
        return m1e_error(403, "M1E-1001", "service credential required")
    return None


Refusal = Annotated[JSONResponse | None, Depends(service_cred)]


def viewer(request: Request, viewer_subject: str | None = None) -> str | None:
    """Doc 15: controld names the caller's subject on every call; absent = a pre-teams controld,
    served unfiltered as before."""
    if viewer_subject is None:
        log.warning("memory %s without viewer_subject: serving unfiltered", request.url.path)
    return viewer_subject


Viewer = Annotated[str | None, Depends(viewer)]


def owner_refusal(reason: str) -> JSONResponse:
    """m1e_error's shape plus doc 15's `reason` field (not_owner | consent_required)."""
    code = "M1E-1008" if reason == "consent_required" else "M1E-1007"
    error = {"code": code, "message": reason, "reason": reason}
    return JSONResponse(status_code=403, content={"error": error})


def _tenant(tenant_id: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(tenant_id)
    except ValueError:
        return None


@router.get("/v1/memory/artifacts")
async def artifacts_route(
    tenant_id: str,
    pool: Annotated[asyncpg.Pool, Depends(get_pool)],
    refused: Refusal,
    viewer_subject: Viewer,
) -> JSONResponse:
    if refused is not None:
        return refused
    if _tenant(tenant_id) is None:
        return m1e_error(400, "M1E-2001", f"bad tenant_id {tenant_id!r}")
    async with pool.acquire() as conn:
        rows = await retrieve.admitted(conn, tenant_id, viewer_subject)
    return JSONResponse(status_code=200, content={"artifacts": rows})


@router.post("/v1/memory/match")
async def match_route(
    body: MatchBody,
    pool: Annotated[asyncpg.Pool, Depends(get_pool)],
    refused: Refusal,
    viewer_subject: Viewer,
) -> JSONResponse:
    if refused is not None:
        return refused
    if _tenant(body.tenant_id) is None:
        return m1e_error(400, "M1E-2001", f"bad tenant_id {body.tenant_id!r}")
    normalized = retrieve.normalize_signature(body.error)
    async with pool.acquire() as conn:
        rows = await retrieve.fuzzy_match(
            conn, body.tenant_id, normalized, limit=body.limit, viewer=viewer_subject
        )
    return JSONResponse(
        status_code=200,
        content={"artifacts": rows, "signature_digest": retrieve.signature_digest(normalized)},
    )


@router.get("/v1/memory/outcomes")
async def outcomes_route(
    tenant_id: str,
    pool: Annotated[asyncpg.Pool, Depends(get_pool)],
    refused: Refusal,
    viewer_subject: Viewer,
) -> JSONResponse:
    if refused is not None:
        return refused
    if _tenant(tenant_id) is None:
        return m1e_error(400, "M1E-2001", f"bad tenant_id {tenant_id!r}")
    async with pool.acquire() as conn:
        rows = await retrieve.outcomes(conn, tenant_id, viewer_subject)
    return JSONResponse(status_code=200, content={"outcomes": rows})


def _artifact(artifact_id: str) -> uuid.UUID | None:
    return _tenant(artifact_id)


@router.post("/v1/memory/artifacts/{artifact_id}/retire")
async def retire_route(
    artifact_id: str,
    body: RetireBody,
    pool: Annotated[asyncpg.Pool, Depends(get_pool)],
    append: Annotated[ReceiptAppend, Depends(get_append)],
    refused: Refusal,
    viewer_subject: Viewer,
) -> JSONResponse:
    if refused is not None:
        return refused
    if _tenant(body.tenant_id) is None or (aid := _artifact(artifact_id)) is None:
        return m1e_error(400, "M1E-2001", "bad tenant_id or artifact id")
    async with pool.acquire() as conn:
        if reason := await admit.action_refusal(
            conn, tenant_id=body.tenant_id, artifact_id=aid, viewer=viewer_subject
        ):
            return owner_refusal(reason)
        try:
            receipt = await admit.retire_artifact(
                conn,
                append,
                tenant_id=body.tenant_id,
                artifact_id=aid,
                reason=body.reason,
                by=body.by,
            )
        except ReceiptAppendError as exc:
            return m1e_error(502, "M1E-9500", f"retire not receipted: {exc.code}")
    if receipt is None:
        return m1e_error(404, "M1E-2009", "artifact not found")
    return JSONResponse(
        status_code=200,
        content={"artifact_id": str(aid), "state": "retired", "receipt_id": str(receipt)},
    )


# (column, value) per action; the response echoes the column so the app renders without a re-read.
_FLAGS = {
    "pin": ("pinned", True),
    "unpin": ("pinned", False),
    "share": ("scope", "team"),
    "unshare": ("scope", "mine"),
}


@router.post("/v1/memory/artifacts/{artifact_id}/{action}")
async def flag_route(
    artifact_id: str,
    action: str,
    body: TenantBody,
    pool: Annotated[asyncpg.Pool, Depends(get_pool)],
    refused: Refusal,
    viewer_subject: Viewer,
) -> JSONResponse:
    if refused is not None:
        return refused
    if action not in _FLAGS:
        return m1e_error(404, "M1E-2009", "unknown memory action")
    if _tenant(body.tenant_id) is None or (aid := _artifact(artifact_id)) is None:
        return m1e_error(400, "M1E-2001", "bad tenant_id or artifact id")
    column, value = _FLAGS[action]
    async with pool.acquire() as conn:
        if reason := await admit.action_refusal(
            conn,
            tenant_id=body.tenant_id,
            artifact_id=aid,
            viewer=viewer_subject,
            share=action == "share",
        ):
            return owner_refusal(reason)
        ok = await admit.set_flag(
            conn, tenant_id=body.tenant_id, artifact_id=aid, column=column, value=value
        )
    if not ok:
        return m1e_error(404, "M1E-2009", "artifact not found")
    return JSONResponse(status_code=200, content={"artifact_id": str(aid), column: value})
