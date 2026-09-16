"""The E1 archive readers (FR-VERIFY-016/-017) through the choke's frozen `evidence_excerpts`
rows: a part is served only against its bound receipt, every mismatch is a counted refusal,
E0/E2 never reach the choke, and the two consumers (T3 tar, RM text) read the same admitted
set. Fixture keys locked against go/controld/internal/querychoke/testdata."""

import base64
import hashlib
import io
import json
import tarfile
from datetime import date
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
from app.certified.archive import (
    EXCERPTS_TEMPLATE,
    Excerpt,
    RedactionReceipt,
    admit,
    archive_refused_total,
    choke_archive_reader,
    parse_rows,
    read_excerpts,
)
from app.judges.specs import JudgeRefused
from app.rm.evidence import choke_evidence_reader

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "go/controld/internal/querychoke/testdata/intel_template_rows.json"
    ).read_text()
)
ROWS = FIXTURE["evidence_excerpts"]
WINDOW = (date(2026, 8, 10), date(2026, 8, 10))
TASK = uuid4()
PART = 'diff --git a/cfg.py b/cfg.py\n+KEY = "\u27e8redacted:api_key:00112233\u27e9"\n'.encode()


def excerpt() -> Excerpt:
    (x,) = parse_rows(ROWS)
    return x


def receipt(x: Excerpt, **over) -> RedactionReceipt:
    fields = {
        "subject_id": x.evidence_event_id,
        "post_hash": hashlib.sha256(PART).digest(),
        "excerpt_event_id": x.event_id,
    }
    return RedactionReceipt(**{**fields, **over})


class FakeChoke:
    def __init__(self, rows: list[dict]) -> None:
        self.rows, self.requests = rows, []

    def client(self) -> httpx.AsyncClient:
        def handler(req: httpx.Request) -> httpx.Response:
            body = json.loads(req.content)
            self.requests.append((body["template"], body["params"], req.headers["authorization"]))
            if body["template"] != EXCERPTS_TEMPLATE:
                return httpx.Response(400, json={"error": {"code": "M1E-2008", "message": "?"}})
            return httpx.Response(
                200, json={"rows": self.rows, "template_version": "evidence_excerpts.v1"}
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://choke")


def fetcher(parts: dict[str, bytes]):
    fetched = []

    async def fetch(name: str) -> bytes:
        fetched.append(name)
        return parts[name]

    fetch.fetched = fetched  # type: ignore[attr-defined]
    return fetch


def receipts(table: dict[bytes, RedactionReceipt]):
    async def read(receipt_id: bytes) -> RedactionReceipt | None:
        return table.get(receipt_id)

    return read


def test_fixture_rows_carry_exactly_what_the_reader_reads():
    assert {"event_id", "evidence_event_id", "attachment_name", "redaction_receipt_id"} <= set(
        ROWS[0]
    )
    before = archive_refused_total["refused_excerpt_unreceipted"]
    (x,) = parse_rows(ROWS)  # the second fixture row has no receipt id: refused, never read
    assert archive_refused_total["refused_excerpt_unreceipted"] == before + 1
    assert x.event_id == UUID(ROWS[0]["event_id"])
    assert x.evidence_event_id == UUID(bytes=base64.b64decode(ROWS[0]["evidence_event_id"]))
    assert x.receipt_id == base64.b64decode(ROWS[0]["redaction_receipt_id"])
    assert len(x.receipt_id) == 32 and x.attachment_name == ROWS[0]["attachment_name"]


def test_admit_refuses_every_mismatch_and_admits_the_bound_receipt():
    x = excerpt()
    assert admit(x, receipt(x), PART) is None
    assert admit(x, None, PART) == "refused_receipt_unknown"
    assert admit(x, receipt(x, excerpt_event_id=None), PART) == "refused_receipt_unbound"
    assert admit(x, receipt(x, excerpt_event_id=uuid4()), PART) == "refused_receipt_unbound"
    assert admit(x, receipt(x, subject_id=uuid4()), PART) == "refused_receipt_subject_mismatch"
    assert admit(x, receipt(x), PART + b"x") == "refused_post_hash_mismatch"


async def test_read_excerpts_binds_the_tenant_window_and_task_on_the_wire():
    x = excerpt()
    choke = FakeChoke(ROWS)
    fetch = fetcher({x.attachment_name: PART})
    async with choke.client() as http:
        parts = await read_excerpts(
            http,
            "http://choke",
            "tok",
            WINDOW,
            TASK,
            "E1",
            fetch,
            receipts({x.receipt_id: receipt(x)}),
        )
    assert parts == [(x, PART)]
    assert choke.requests == [
        (
            EXCERPTS_TEMPLATE,
            {"from": "2026-08-10", "to": "2026-08-10", "task_id": str(TASK)},
            "Bearer tok",
        )
    ]
    assert fetch.fetched == [x.attachment_name]


@pytest.mark.parametrize("tier", ["E0", "E2", "E3"])
async def test_only_e1_reaches_the_choke(tier):
    choke = FakeChoke(ROWS)
    fetch = fetcher({})
    async with choke.client() as http:
        with pytest.raises(JudgeRefused) as exc:
            await read_excerpts(
                http, "http://choke", "tok", WINDOW, TASK, tier, fetch, receipts({})
            )
    assert exc.value.reason == f"refused_tier_no_archive:{tier}"
    assert choke.requests == [] and fetch.fetched == []


async def test_an_unreceipted_task_refuses_the_leg_and_fetches_nothing():
    x = excerpt()
    choke = FakeChoke(ROWS)
    fetch = fetcher({x.attachment_name: PART})
    before = archive_refused_total["refused_receipt_unknown"]
    async with choke.client() as http:
        with pytest.raises(JudgeRefused) as exc:
            await read_excerpts(
                http, "http://choke", "tok", WINDOW, TASK, "E1", fetch, receipts({})
            )
    assert exc.value.reason == "refused_no_receipted_excerpts"
    assert archive_refused_total["refused_receipt_unknown"] == before + 1
    assert fetch.fetched == []


async def test_a_tampered_part_is_refused_by_its_receipt():
    x = excerpt()
    choke = FakeChoke(ROWS)
    fetch = fetcher({x.attachment_name: PART + b"\n+leaked = 1\n"})
    before = archive_refused_total["refused_post_hash_mismatch"]
    async with choke.client() as http:
        with pytest.raises(JudgeRefused):
            await read_excerpts(
                http,
                "http://choke",
                "tok",
                WINDOW,
                TASK,
                "E1",
                fetch,
                receipts({x.receipt_id: receipt(x)}),
            )
    assert archive_refused_total["refused_post_hash_mismatch"] == before + 1


async def test_t3_tar_and_rm_text_read_the_same_admitted_set():
    x = excerpt()
    choke = FakeChoke(ROWS)
    table = receipts({x.receipt_id: receipt(x)})
    async with choke.client() as http:
        fetch = fetcher({x.attachment_name: PART})
        archive = await choke_archive_reader(http, "http://choke", "tok", WINDOW, fetch, table)(
            TASK, UUID(int=0), "E1"
        )
        text = await choke_evidence_reader(http, "http://choke", "tok", WINDOW, fetch, table)(
            TASK, UUID(int=0), "E1"
        )
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        (member,) = tar.getmembers()
        assert member.name == f"{x.evidence_event_id}.patch"
        assert tar.extractfile(member).read() == PART
    assert text == f"--- excerpt {x.evidence_event_id}\n{PART.decode()}"
    assert fetch.fetched == [x.attachment_name, x.attachment_name]
