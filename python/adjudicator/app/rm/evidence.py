"""An E1 evidence_for over the archive: the admitted, receipted parts of
app/certified/archive.py rendered as one string — the sanitized hunks app/rm/cloud.py sends."""

from datetime import date
from uuid import UUID

import httpx

from app.certified.archive import AttachmentFetch, ReceiptReader, read_excerpts
from app.judges.cloud_path import EvidenceReader


def choke_evidence_reader(
    http: httpx.AsyncClient,
    base_url: str,
    bearer: str,
    window: tuple[date, date],
    fetch: AttachmentFetch,
    receipt_for: ReceiptReader,
    tenant_id: str | None = None,
) -> EvidenceReader:
    async def read(task_id: UUID, attempt_id: UUID, tier: str) -> str:
        parts = await read_excerpts(
            http, base_url, bearer, window, task_id, tier, fetch, receipt_for, tenant_id
        )
        return "\n".join(
            f"--- excerpt {x.evidence_event_id}\n{data.decode('utf-8', errors='replace')}"
            for x, data in parts
        )

    return read
