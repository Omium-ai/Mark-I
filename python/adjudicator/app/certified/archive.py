"""The E1 archive reader (FR-VERIFY-016/-017): `evidence_excerpts` names a task's excerpts,
the part is fetched by attachment name and admitted only against its bound m1_077 receipt."""

import base64
import hashlib
import io
import tarfile
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from typing import Any
from uuid import UUID

import asyncpg
import httpx

from app.certified.runner import ArchiveReader
from app.choke import run_template
from app.db import set_local_tenant
from app.judges.specs import refuse

EXCERPTS_TEMPLATE = "evidence_excerpts"

archive_refused_total: Counter[str] = Counter()


@dataclass(frozen=True)
class Excerpt:
    event_id: UUID
    evidence_event_id: UUID
    attachment_name: str
    receipt_id: bytes


@dataclass(frozen=True)
class RedactionReceipt:
    subject_id: UUID
    post_hash: bytes
    excerpt_event_id: UUID | None


AttachmentFetch = Callable[[str], Awaitable[bytes]]
ReceiptReader = Callable[[bytes], Awaitable[RedactionReceipt | None]]


def parse_rows(rows: list[dict[str, Any]]) -> list[Excerpt]:
    """Choke rows → excerpts; an E1 row without a 32-byte receipt id is refused, never read."""
    out = []
    for r in rows:
        receipt = base64.b64decode(str(r["redaction_receipt_id"]) or "")
        subject = base64.b64decode(str(r["evidence_event_id"]) or "")
        if len(receipt) != 32 or len(subject) != 16:
            archive_refused_total["refused_excerpt_unreceipted"] += 1
            continue
        out.append(
            Excerpt(
                event_id=UUID(str(r["event_id"])),
                evidence_event_id=UUID(bytes=subject),
                attachment_name=str(r["attachment_name"]),
                receipt_id=receipt,
            )
        )
    return out


def admit(x: Excerpt, receipt: RedactionReceipt | None, data: bytes) -> str | None:
    """None when the part is exactly what the bound receipt attests; else the refusal reason."""
    if receipt is None:
        return "refused_receipt_unknown"
    if receipt.excerpt_event_id != x.event_id:
        return "refused_receipt_unbound"
    if receipt.subject_id != x.evidence_event_id:
        return "refused_receipt_subject_mismatch"
    if hashlib.sha256(data).digest() != receipt.post_hash:
        return "refused_post_hash_mismatch"
    return None


def pg_receipt_reader(pool: asyncpg.Pool, tenant_id: UUID) -> ReceiptReader:
    async def read(receipt_id: bytes) -> RedactionReceipt | None:
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(tenant_id))
            row = await conn.fetchrow(
                "SELECT subject_id, post_hash, excerpt_event_id FROM m1_redaction_receipts "
                "WHERE tenant_id = $1 AND receipt_id = $2",
                tenant_id,
                receipt_id,
            )
        return RedactionReceipt(**dict(row)) if row else None

    return read


async def read_excerpts(
    http: httpx.AsyncClient,
    base_url: str,
    bearer: str,
    window: tuple[date, date],
    task_id: UUID,
    tier: str,
    fetch: AttachmentFetch,
    receipt_for: ReceiptReader,
    tenant_id: str | None = None,
) -> list[tuple[Excerpt, bytes]]:
    if tier != "E1":
        raise refuse(f"refused_tier_no_archive:{tier}", "only E1 is receipted and served")
    rows = await run_template(
        http,
        base_url,
        EXCERPTS_TEMPLATE,
        {"from": window[0].isoformat(), "to": window[1].isoformat(), "task_id": str(task_id)},
        bearer=bearer,
        tenant_id=tenant_id,
    )
    out = []
    for x in parse_rows(rows):
        receipt = await receipt_for(x.receipt_id)
        data = await fetch(x.attachment_name) if receipt is not None else b""
        if reason := admit(x, receipt, data):
            archive_refused_total[reason] += 1
            continue
        out.append((x, data))
    if not out:
        raise refuse("refused_no_receipted_excerpts", f"task {task_id}")
    return out


def choke_archive_reader(
    http: httpx.AsyncClient,
    base_url: str,
    bearer: str,
    window: tuple[date, date],
    fetch: AttachmentFetch,
    receipt_for: ReceiptReader,
    tenant_id: str | None = None,
) -> ArchiveReader:
    """CertifiedRunner's archive_for: one tar member per admitted part, `<evidence event>.patch`."""

    async def read(task_id: UUID, attempt_id: UUID, tier: str) -> bytes:
        parts = await read_excerpts(
            http, base_url, bearer, window, task_id, tier, fetch, receipt_for, tenant_id
        )
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for x, data in parts:
                info = tarfile.TarInfo(f"{x.evidence_event_id}.patch")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    return read
