"""app/ledger.py: the adjudicated VerdictEvent as verify.proto spells it (stage from pipeline
position, certification from the D-T axis, posterior exactly 4), a deterministic UUIDv7 per
(tenant, task, window), and controld's exact service-ingest wire (service.go / pipeline.go)."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import httpx
import pytest
import zstandard
from app import ledger
from app.adjudicate.algorithm import VerdictEvent as PyVerdict
from app.choke import QuerychokeError
from m1p.v1 import Batch, CertificationStatus, Verdict, VerdictStage

TENANT, TASK, SESSION = uuid4(), uuid4(), uuid4()
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)
CLOSE = datetime(2026, 9, 16, tzinfo=UTC)
CERT = str(uuid4())


def py_verdict(verdict="violated", stage="bootstrapping") -> PyVerdict:
    return PyVerdict(stage, verdict, (0.12, 0.83, 0.03, 0.02), CERT, 3, provenance="prior")


def wire(verdict="violated", provisional="satisfied", stage="bootstrapping", **kw):
    return ledger.verdict_wire(
        py_verdict(verdict, stage),
        provisional=provisional,
        tenant_id=TENANT,
        task_id=TASK,
        session_id=SESSION,
        window_start=WINDOW,
        bundle_seq=kw.get("bundle_seq", 7),
    )


def test_event_id_is_a_v7_of_the_window_deterministic_per_tenant_task_window():
    a = UUID(bytes=ledger.event_id(TENANT, TASK, WINDOW))
    assert a.version == 7 and a.variant == "specified in RFC 4122"
    assert ledger.window_close(WINDOW) == CLOSE
    assert int.from_bytes(a.bytes[:6], "big") == int(CLOSE.timestamp() * 1000)
    assert a == UUID(bytes=ledger.event_id(TENANT, TASK, WINDOW))
    assert a != UUID(bytes=ledger.event_id(TENANT, TASK, WINDOW + timedelta(days=1)))
    assert a != UUID(bytes=ledger.event_id(TENANT, uuid4(), WINDOW))
    assert a != UUID(bytes=ledger.event_id(uuid4(), TASK, WINDOW))
    # Positive control: the identity is the (tenant, task, window) key, never the verdict.
    assert bytes(wire("violated").event_id) == bytes(wire("satisfied", "violated").event_id)


def test_stage_is_the_pipeline_position_and_certification_the_claim_axis():
    assert wire("violated", provisional="satisfied").verdict_event.stage == VerdictStage.REVISED
    assert wire("violated", provisional="violated").verdict_event.stage == VerdictStage.CERTIFIED
    assert wire("refused", provisional="satisfied").verdict_event.stage == VerdictStage.REVISED
    for py_stage, want in (
        ("CERTIFIED", CertificationStatus.CERTIFIED),
        ("bootstrapping", CertificationStatus.BOOTSTRAPPING),
        ("uncertified", CertificationStatus.UNCERTIFIED),
    ):
        assert wire(stage=py_stage).verdict_event.certification == want
    # Every vocabulary word algorithm._stamp can emit has a distinct, non-zero wire value.
    assert set(ledger._CERTIFICATION) == {"CERTIFIED", "bootstrapping", "uncertified"}
    assert len({v.value for v in ledger._CERTIFICATION.values()}) == 3
    assert CertificationStatus.UNSPECIFIED not in ledger._CERTIFICATION.values()
    with pytest.raises(KeyError):
        wire(stage="certified")


def test_wire_event_carries_the_original_attempt_identity_after_every_edge_event():
    ev = wire(bundle_seq=1757894400)
    assert ev.task_id == TASK.bytes and ev.session_id == SESSION.bytes
    assert ev.session_epoch == ledger.SERVICE_EPOCH == 0xFFFFFFFF
    assert ev.seq == int(CLOSE.timestamp() * 1000) and ev.seq > 0
    assert ev.occurred_at == CLOSE  # after every event the window read, never inside the day
    v = ev.verdict_event
    assert v.verdict == Verdict.VIOLATED and v.posterior == [0.12, 0.83, 0.03, 0.02]
    assert len(v.posterior) == 4 and v.posterior[Verdict.VIOLATED.value - 1] == 0.83
    assert (v.noise_cert_id, v.vote_count, v.bundle_seq) == (CERT, 3, 1757894400)
    assert not ev.tenant_id and not ev.device_id  # the 900-band is the server's, never ours


async def test_post_speaks_controld_service_ingest_wire_exactly():
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"batch_id": req.headers["M1P-Batch-Id"], "accepted": 2})

    events = [wire(), wire("satisfied", "violated")]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        ack = await ledger.post_verdicts(http, "http://controld/", "svc", TENANT, events)
    assert ack["accepted"] == 2
    (req,) = seen
    assert req.url.path == ledger.INGEST_PATH == "/internal/v1/ingest/service"
    assert req.headers["authorization"] == "Bearer svc"
    assert req.headers[ledger.TENANT_HEADER] == str(TENANT)
    assert req.headers["content-type"] == "application/x-m1p-protobuf"
    assert req.headers["content-encoding"] == "zstd"
    assert req.headers["m1p-schema"] == "m1p.v1"
    batch_id = UUID(req.headers["m1p-batch-id"])
    assert batch_id.version == 7
    batch = Batch().parse(zstandard.decompress(req.content))
    assert UUID(bytes=batch.batch_id) == batch_id
    assert batch.advisory_tenant_id == TENANT.bytes and batch.sdk.name == "adjudicator-svc"
    assert batch.session_id == SESSION.bytes
    assert [e.verdict_event.stage for e in batch.events] == [
        VerdictStage.REVISED,
        VerdictStage.REVISED,
    ]
    assert batch.events[0].event_id == events[0].event_id


async def test_post_raises_the_m1e_code_and_never_swallows_a_refusal():
    def refuse(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            422,
            json={"error": {"code": "M1E-2006", "message": "invariant-violating events"}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse)) as http:
        with pytest.raises(QuerychokeError) as exc:
            await ledger.post_verdicts(http, "http://controld", "svc", TENANT, [wire()])
    assert (exc.value.code, exc.value.http_status) == ("M1E-2006", 422)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(503, text="down"))
    ) as http:
        with pytest.raises(QuerychokeError, match="M1E-9500"):
            await ledger.post_verdicts(http, "http://controld", "svc", TENANT, [wire()])
