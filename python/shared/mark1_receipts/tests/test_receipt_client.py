"""The Python half of the append-seam lock (go/controld/internal/receipts/testdata/
receipt_append_body.json): the real client re-derives the fixture's exact body, decodes the
fixture's exact ack, and refuses fail-closed on every non-2xx and on every local precondition."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import httpx
import pytest
from mark1_receipts import (
    NonCanonicalNumberError,
    ReceiptAppendError,
    ReceiptRef,
    append_server_record,
)
from mark1_receipts.client import APPEND_PATH

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[4]
        / "go/controld/internal/receipts/testdata/receipt_append_body.json"
    ).read_text()
)


class FakeControld:
    def __init__(self, status: int = 200, body: dict | None = None) -> None:
        self.status, self.body, self.requests = status, body, []

    def client(self) -> httpx.AsyncClient:
        def handler(req: httpx.Request) -> httpx.Response:
            self.requests.append(
                (req.url.path, req.headers.get("authorization"), json.loads(req.content))
            )
            return httpx.Response(self.status, json=self.body if self.body is not None else {})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://controld")


async def _append(fake: FakeControld, **overrides):
    inputs = {**FIXTURE["inputs"], **overrides}
    async with fake.client() as http:
        return await append_server_record(http, "http://controld", "intel-secret", **inputs)


async def test_body_and_ack_match_the_crosslang_fixture():
    fake = FakeControld(200, FIXTURE["response"])
    ref = await _append(fake)
    ((path, auth, body),) = fake.requests
    assert (path, auth) == (APPEND_PATH, "Bearer intel-secret")
    assert body == FIXTURE["body"]
    assert ref == ReceiptRef(
        receipt_id=uuid.UUID(FIXTURE["response"]["receipt_id"]),
        seq=FIXTURE["response"]["seq"],
        receipt_hash=bytes.fromhex(FIXTURE["response"]["receipt_hash"]),
        payload=FIXTURE["response"]["payload"],
    )


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (500, {"error": {"code": "M1E-9500", "message": "chain append failed"}}, "M1E-9500"),
        (
            403,
            {"error": {"code": "M1E-1001", "message": "service credential rejected"}},
            "M1E-1001",
        ),
        (400, {"error": {"code": "M1E-2001", "message": "record_type"}}, "M1E-2001"),
        (502, None, "M1E-9500"),
    ],
)
async def test_every_non_2xx_raises(status, body, code):
    with pytest.raises(ReceiptAppendError) as e:
        await _append(FakeControld(status, body))
    assert (e.value.code, e.value.http_status) == (code, status)


async def test_local_preconditions_refuse_before_any_request():
    fake = FakeControld(200, FIXTURE["response"])
    inputs = FIXTURE["inputs"]
    async with fake.client() as http:
        with pytest.raises(ReceiptAppendError, match="unset"):
            await append_server_record(http, "", "intel-secret", **inputs)
        with pytest.raises(ReceiptAppendError, match="unset"):
            await append_server_record(http, "http://controld", "", **inputs)
        with pytest.raises(ReceiptAppendError, match="idempotency_key"):
            await append_server_record(
                http, "http://controld", "s", **{**inputs, "idempotency_key": ""}
            )
        with pytest.raises(NonCanonicalNumberError):
            await append_server_record(
                http, "http://controld", "s", **{**inputs, "payload": {"lcb": 0.25}}
            )
    assert fake.requests == []
