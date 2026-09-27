"""The E1 read (app/judges/evidence.py): controld's internal route feeds the cloud judge @2 by
default and the cloud RM on request; absent E1 falls back to E0, never to a guess."""

from uuid import UUID, uuid4

import httpx
import pytest
from app.jobs.judge_batch import evidence_of, judge_batch_skipped_total
from app.judges.evidence import EVIDENCE_PATH, e1_reader, fetch_e1, rm_input_reader
from app.judges.specs import JudgeRefused
from app.rm.cloud import RmInput
from m1p.v1 import EvidenceTier
from tests.test_judge_batch import (
    AMBIGUOUS,
    CONSENT,
    MIDBAND,
    SPEC,
    TENANT,
    FakeCloud,
    FakePool,
    _run,
    all_rows,
)

HUNKS = "diff --git a/a.py b/a.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"


def body(task: UUID, intent: str = "make x two") -> dict:
    return {
        "task_id": str(task),
        "tier": "E1",
        "intent": intent,
        "hunks": HUNKS,
        "receipt_id": "ab" * 32,
    }


def controld(served: dict[str, dict], seen: list[httpx.Request], status: int | None = None):
    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if status:
            return httpx.Response(status)
        b = served.get(req.url.path.removeprefix(EVIDENCE_PATH))
        return httpx.Response(200, json=b) if b else httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_fetch_is_service_authenticated_tenant_scoped_and_none_when_absent():
    task, seen = uuid4(), []
    tenant = UUID(TENANT)
    async with controld({str(task): body(task)}, seen) as http:
        e = await fetch_e1(http, "http://controld/", "svc", tenant, task, "judge")
        assert e is not None and e.intent == "make x two" and e.hunks == HUNKS
        assert await fetch_e1(http, "http://controld", "svc", tenant, uuid4(), "judge") is None
    assert seen[0].url.path == f"{EVIDENCE_PATH}{task}"
    assert seen[0].url.params["purpose"] == "judge"
    assert seen[0].headers["authorization"] == "Bearer svc"
    assert seen[0].headers["m1p-tenant-id"] == TENANT


async def test_a_controld_outage_propagates_instead_of_degrading_silently():
    async with controld({}, [], status=503) as http:
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_e1(http, "http://controld", "svc", UUID(TENANT), uuid4(), "judge")


@pytest.mark.parametrize("status", [403, 404])
async def test_a_refusal_or_absence_is_no_evidence_never_a_success(status):
    task = uuid4()
    async with controld({str(task): body(task)}, [], status=status) as http:
        assert await fetch_e1(http, "http://controld", "svc", UUID(TENANT), task, "rm") is None
        with pytest.raises(JudgeRefused, match="refused_no_receipted_excerpts"):
            await e1_reader(http, "http://controld", "svc", UUID(TENANT))(task, task, "E1")
        assert await rm_input_reader(http, "http://controld", "svc", UUID(TENANT))(task) is None


async def test_each_reader_names_its_own_purpose_and_no_other():
    task, seen = uuid4(), []
    async with controld({str(task): body(task)}, seen) as http:
        await e1_reader(http, "http://controld", "svc", UUID(TENANT))(task, task, "E1")
        await rm_input_reader(http, "http://controld", "svc", UUID(TENANT))(task)
        with pytest.raises(ValueError, match="unknown E1 purpose"):
            await fetch_e1(http, "http://controld", "svc", UUID(TENANT), task, "train")  # type: ignore[arg-type]
    assert [r.url.params["purpose"] for r in seen] == ["judge", "rm"]


async def test_evidence_for_returns_e1_when_present_else_the_e0_fallback():
    task, absent = uuid4(), uuid4()
    rows = {
        absent: [
            {
                "verifier_id": "anchor:ruff@1",
                "vote": "satisfied",
                "tamper": False,
                "family": "AnchorVote",
            }
        ]
    }
    async with controld({str(task): body(task)}, []) as http:
        read = e1_reader(http, "http://controld", "svc", UUID(TENANT))
        spec, text = await evidence_of(SPEC, task, {}, read)
        assert (
            spec.evidence_tier == "E1"
            and text == f"<task>\nmake x two\n</task>\n<diff>\n{HUNKS}\n</diff>"
        )
        spec, text = await evidence_of(SPEC, absent, rows, read)
        assert (
            spec.evidence_tier == "E0" and spec.rubric == SPEC.e0_rubric and "anchor:ruff@1" in text
        )
        with pytest.raises(JudgeRefused):
            await read(task, task, "E0")
    assert judge_batch_skipped_total["e1_refused_no_receipted_excerpts"] >= 1


async def test_the_cloud_rm_reads_task_text_and_hunks_only():
    task, seen = uuid4(), []
    async with controld({str(task): body(task)}, seen) as http:
        read = rm_input_reader(http, "http://controld", "svc", UUID(TENANT))
        assert await read(task) == RmInput(task="make x two", hunks=HUNKS)
        assert await read(uuid4()) is None


async def test_judge_batch_reads_controld_e1_by_default():
    cloud = FakeCloud(all_rows(), evidence={str(AMBIGUOUS): body(AMBIGUOUS)})
    recs = await _run(FakePool(consent=CONSENT), cloud)
    user = {b["messages"][1]["content"] for b in cloud.completions}
    assert f"<task>\nmake x two\n</task>\n<diff>\n{HUNKS}\n</diff>" in user
    assert recs[AMBIGUOUS]["evidence_tier"] == "E1" and recs[MIDBAND]["evidence_tier"] == "E0"
    tiers = {UUID(bytes=e.task_id): e.judge_vote.tier_used for e in cloud.events()}
    assert tiers[AMBIGUOUS] == EvidenceTier.E1 and tiers[MIDBAND] == EvidenceTier.E0
