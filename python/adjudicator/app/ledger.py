"""The adjudicator→ingest seam (06 §1.2): adjudicated verdicts re-enter the ledger as M1P
VerdictEvents through controld's internal service ingest route — the same 05 §2 pipeline a
device batch runs, under the service credential, with the tenant named in a header (the
receipts append shape, ADR-0010 §2.2). One deterministic event_id per (tenant, task, window),
so a rerun collapses in the ledger's ReplacingMergeTree instead of doubling (07 §2)."""

import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
import zstandard
from m1p.v1 import (
    Batch,
    CertificationStatus,
    Event,
    JudgeVote,
    RmScore,
    SdkInfo,
    Verdict,
    VerdictEvent,
    VerdictStage,
)

from app.adjudicate import algorithm
from app.choke import QuerychokeError

INGEST_PATH = "/internal/v1/ingest/service"
TENANT_HEADER = "M1P-Tenant-Id"
# 07 §2: causal order within a session is (session_epoch, seq); the max epoch sorts an
# adjudicated verdict after every daemon boot's events, so readers' argMax picks it.
SERVICE_EPOCH = 0xFFFFFFFF
_CERTIFICATION = {
    "CERTIFIED": CertificationStatus.CERTIFIED,
    "bootstrapping": CertificationStatus.BOOTSTRAPPING,
    "uncertified": CertificationStatus.UNCERTIFIED,
}
_DOMAIN = b"adjudicator/verdict/"
_JUDGE_DOMAIN = b"adjudicator/judge/"
_RM_DOMAIN = b"adjudicator/rm/"


def deterministic_v7(domain: bytes, key: bytes, at: datetime) -> bytes:
    """mark1d route.decisionID's layout: 48-bit unix millis, then SHA-256(domain ‖ key) bits."""
    digest = hashlib.sha256(domain + key).digest()[:16]
    ms = int(at.timestamp() * 1000)
    out = bytearray(ms.to_bytes(6, "big") + digest[6:])
    out[6] = 0x70 | (out[6] & 0x0F)
    out[8] = 0x80 | (out[8] & 0x3F)
    return bytes(out)


def window_close(window_start: datetime) -> datetime:
    """The instant the closed day ended: after every event the window read, deterministic."""
    return window_start + timedelta(days=1)


def event_id(tenant_id: UUID, task_id: UUID, window_start: datetime) -> bytes:
    return deterministic_v7(_DOMAIN, tenant_id.bytes + task_id.bytes, window_close(window_start))


def verdict_wire(
    event: algorithm.VerdictEvent,
    *,
    provisional: str,
    tenant_id: UUID,
    task_id: UUID,
    session_id: UUID,
    window_start: datetime,
    bundle_seq: int,
) -> Event:
    """verify.proto: stage is the pipeline position (REVISED iff the provisional verdict was
    overturned, else the adjudicated CERTIFIED position), certification the D-T claim axis
    algorithm.py's stage vocabulary actually carries."""
    stage = VerdictStage.REVISED if event.verdict != provisional else VerdictStage.CERTIFIED
    at = window_close(window_start)
    return Event(
        event_id=event_id(tenant_id, task_id, window_start),
        seq=int(at.timestamp() * 1000),
        session_id=session_id.bytes,
        task_id=task_id.bytes,
        occurred_at=at,
        session_epoch=SERVICE_EPOCH,
        verdict_event=VerdictEvent(
            stage=stage,
            verdict=Verdict[event.verdict.upper()],
            posterior=list(event.posterior),
            noise_cert_id=event.noise_cert_id,
            bundle_seq=bundle_seq,
            vote_count=event.vote_count,
            certification=_CERTIFICATION[event.stage],
        ),
    )


def judge_vote_wire(
    vote: JudgeVote, *, tenant_id: UUID, task_id: UUID, session_id: UUID, window_start: datetime
) -> Event:
    """The cloud judge's vote as the edge would have spooled it (06 §6.2 step 6), one
    deterministic event_id per (tenant, task, judge), so a re-post collapses like a verdict."""
    at = window_close(window_start)
    return Event(
        event_id=deterministic_v7(
            _JUDGE_DOMAIN, tenant_id.bytes + task_id.bytes + vote.judge_id.encode(), at
        ),
        seq=int(at.timestamp() * 1000),
        session_id=session_id.bytes,
        task_id=task_id.bytes,
        occurred_at=at,
        session_epoch=SERVICE_EPOCH,
        judge_vote=vote,
    )


def rm_score_wire(
    score: RmScore, *, tenant_id: UUID, task_id: UUID, session_id: UUID, window_start: datetime
) -> Event:
    """The cloud RM's score (16 §L6), one deterministic event_id per (tenant, task, model)."""
    at = window_close(window_start)
    return Event(
        event_id=deterministic_v7(
            _RM_DOMAIN, tenant_id.bytes + task_id.bytes + score.model_id.encode(), at
        ),
        seq=int(at.timestamp() * 1000),
        session_id=session_id.bytes,
        task_id=task_id.bytes,
        occurred_at=at,
        session_epoch=SERVICE_EPOCH,
        rm_score=score,
    )


def batch_bytes(tenant_id: UUID, events: list[Event]) -> tuple[UUID, bytes]:
    """A fresh batch identity per POST (a rerun re-lands; the events are what dedupe), zstd."""
    batch_id = deterministic_v7(b"adjudicator/batch/", os.urandom(16), datetime.now(UTC))
    batch = Batch(
        batch_id=batch_id,
        session_id=events[0].session_id,
        sdk=SdkInfo(name="adjudicator-svc", version="0.1.0"),
        sent_at=datetime.now(UTC),
        events=events,
        advisory_tenant_id=tenant_id.bytes,
    )
    return UUID(bytes=batch_id), zstandard.compress(bytes(batch))


async def post_verdicts(
    http: httpx.AsyncClient, base_url: str, bearer: str, tenant_id: UUID, events: list[Event]
) -> dict[str, Any]:
    """POST one batch; the 08 §2.4 ack body back, an M1E-coded error raised on anything else."""
    # ponytail: one batch per night; chunk at the 5000/60s verdict bucket if a tenant outgrows it.
    batch_id, body = batch_bytes(tenant_id, events)
    resp = await http.post(
        f"{base_url.rstrip('/')}{INGEST_PATH}",
        content=body,
        headers={
            "Authorization": f"Bearer {bearer}",
            TENANT_HEADER: str(tenant_id),
            "Content-Type": "application/x-m1p-protobuf",
            "Content-Encoding": "zstd",
            "M1P-Schema": "m1p.v1",
            "M1P-Batch-Id": str(batch_id),
        },
    )
    if resp.status_code // 100 != 2:
        try:
            err = resp.json()["error"]
            code, message = err["code"], err.get("message", "")
        except Exception:
            code, message = "M1E-9500", resp.text[:200]
        raise QuerychokeError(code, message, resp.status_code)
    return dict(resp.json())
