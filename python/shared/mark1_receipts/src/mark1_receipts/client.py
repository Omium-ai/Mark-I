"""controld's internal receipt-append route: the ONE writer of m1_receipts (m1_002 §5) as the
intelligence services reach it. Fail-closed: any non-2xx raises, so an unreceipted admission,
certificate or export never proceeds. The wire is locked both ways against
go/controld/internal/receipts/testdata/receipt_append_body.json (append.go handleAppend)."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mark1_receipts.canonical import canonical_json

if TYPE_CHECKING:
    import httpx

APPEND_PATH = "/internal/v1/receipts/append"


class ReceiptAppendError(Exception):
    """controld refused or failed the append; carries the 08 §9 M1E code and the HTTP status."""

    def __init__(self, code: str, message: str, http_status: int) -> None:
        self.code, self.message, self.http_status = code, message, http_status
        super().__init__(f"{code} (HTTP {http_status}): {message}")


@dataclass(frozen=True)
class ReceiptRef:
    """The chain position controld answered with; `payload` is the exact signed canonical text."""

    receipt_id: uuid.UUID
    seq: int
    receipt_hash: bytes
    payload: str


async def append_server_record(
    http: httpx.AsyncClient,
    base_url: str,
    service_token: str,
    *,
    tenant_id: str,
    record_type: str,
    subject_id: str | uuid.UUID,
    idempotency_key: str,
    payload: Mapping[str, Any],
) -> ReceiptRef:
    """POST one ServerRecord; a repeat under the same (tenant, record_type, idempotency_key)
    answers the existing receipt (m1_072), so a retried job never mints a second link."""
    if not base_url or not service_token:
        raise ReceiptAppendError("M1E-1001", "controld base URL or service token unset", 0)
    if not idempotency_key:
        raise ReceiptAppendError("M1E-2001", "idempotency_key is required", 0)
    canonical_json(payload)  # integers-only contract, refused here rather than on the wire
    resp = await http.post(
        f"{base_url.rstrip('/')}{APPEND_PATH}",
        json={
            "tenant_id": tenant_id,
            "record_type": record_type,
            "subject_id": str(subject_id),
            "idempotency_key": idempotency_key,
            "payload": dict(payload),
        },
        headers={"Authorization": f"Bearer {service_token}"},
    )
    if resp.status_code // 100 != 2:
        try:
            err = resp.json()["error"]
            code, message = err["code"], err.get("message", "")
        except Exception:
            code, message = "M1E-9500", resp.text[:200]
        raise ReceiptAppendError(code, message, resp.status_code)
    body = resp.json()
    return ReceiptRef(
        receipt_id=uuid.UUID(body["receipt_id"]),
        seq=int(body["seq"]),
        receipt_hash=bytes.fromhex(body["receipt_hash"]),
        payload=str(body["payload"]),
    )
