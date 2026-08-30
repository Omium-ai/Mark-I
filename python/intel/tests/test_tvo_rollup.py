"""ADR-0010 driver: deterministic job_key, the unsigned-ADR write guard, the D20 window
gate, tenant-day aggregate arithmetic, and idempotency proven AT THE CONTRACT LEVEL —
the second run with the same job_key reaches the choke (two POSTs to the internal
rollup seam), is acked with the IDENTICAL 200 (module.go: the no-op signal belongs to
the job ledger, not the write seam), and the store holds one logical write."""

import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from app.tvo.reader import QuerychokeReader
from app.tvo.rollup import (
    RollupOutcome,
    job_key,
    run_rollup,
    watermark_for,
    window_close,
)
from choke_mock import MockChoke

BEARER = "op-token-tenant-a"
DAY = date(2026, 8, 1)
AFTER_CLOSE = datetime(2026, 8, 2, 3, 0, tzinfo=UTC)  # past 00:00 UTC + 2 h grace

TVO_ROWS = [
    {
        "task_id": "t1",
        "attempt_n": 1,
        "gen_tokens": 30_000,
        "verifier_tokens": 25_000,
        "fused_verdict": "violated",
        "verdict_stage": "certified",
        "task_seg_version": "task_seg.v1",
        "cost_usd": 0.55,
    },
    {
        "task_id": "t1",
        "attempt_n": 2,
        "gen_tokens": 12_000,
        "verifier_tokens": 25_000,
        "fused_verdict": "satisfied",
        "verdict_stage": "certified",
        "task_seg_version": "task_seg.v1",
        "cost_usd": 0.37,
    },
    {
        "task_id": "t2",
        "attempt_n": 1,
        "gen_tokens": 8_000,
        "verifier_tokens": 2_000,
        "fused_verdict": "satisfied",
        "verdict_stage": "provisional",
        "task_seg_version": "task_seg.v1",
        "cost_usd": 0.10,
    },
]
COVERAGE = [{"observed_ms": 980_000, "bypass_ms": 10_000, "disabled_ms": 10_000}]
DROPS = [{"day": "2026-08-01", "dropped_billing": 2, "events_billing_ingested": 998}]


def make_choke(rows=TVO_ROWS) -> MockChoke:
    choke = MockChoke()
    choke.templates["tvo_task_window"] = rows
    choke.templates["coverage_band"] = COVERAGE
    choke.templates["dropped_by_tenant_day"] = DROPS
    return choke


def _reader(choke: MockChoke) -> QuerychokeReader:
    return QuerychokeReader(choke.client(), "http://choke")


async def _run(choke: MockChoke, **kw) -> list[RollupOutcome]:
    args = dict(
        tenant_id="ten-a",
        day=DAY,
        bearer=BEARER,
        now=AFTER_CLOSE,
        allow_unsigned_write=True,
    )
    args.update(kw)
    return await run_rollup(_reader(choke), **args)


def test_job_key_is_deterministic_and_series_keyed():
    wm = watermark_for(DAY)
    k1 = job_key(DAY, "ten-a", "", wm)
    assert k1 == job_key(DAY, "ten-a", "", wm)  # same job ⇒ same key, across processes
    assert k1.startswith("tvo.rollup_tenant_day:2026-08-01:2026-08-02:")
    # Restatement is a NEW series ⇒ new key (ADR-0010 §6); other tenants/days differ too.
    assert job_key(DAY, "ten-a", "task_seg.v1-restated.2", wm) != k1
    assert job_key(DAY, "ten-b", "", wm) != k1
    assert job_key(date(2026, 8, 2), "ten-a", "", watermark_for(date(2026, 8, 2))) != k1


async def test_unsigned_adr_guard_blocks_by_default():
    choke = make_choke()
    with pytest.raises(RuntimeError, match="ADR-0010 is UNSIGNED"):
        await _run(choke, allow_unsigned_write=False)
    assert choke.requests == []  # refused before any read, let alone the write


async def test_window_not_closed_is_refused():
    choke = make_choke()
    inside_grace = datetime(2026, 8, 2, 1, 0, tzinfo=UTC)  # day over, grace (D20) not
    with pytest.raises(ValueError, match="not yet closed"):
        await _run(choke, now=inside_grace)
    assert window_close(DAY) == datetime(2026, 8, 2, 2, 0, tzinfo=UTC)


async def test_rerun_same_job_key_is_contract_level_noop():
    choke = make_choke()
    (first,) = await _run(choke)
    (second,) = await _run(choke)

    assert first.status == "written"
    # Both runs REACH the choke — idempotency is the token's job, not caller memory —
    # and the second is a dedup-dropped no-op the seam acks IDENTICALLY (module.go:
    # the no-op signal belongs to the driving job's ledger, layer 1, not this seam).
    writes = [r for r in choke.requests if r[0] == "tvo_rollup_tenant_day"]
    assert len(writes) == 2
    assert second.status == "written"
    assert second.job_key == first.job_key
    assert len(choke.rollup_store) == 1  # one logical write survived two runs


async def test_restatement_series_is_a_new_row_never_a_rerun():
    choke = make_choke()
    (original,) = await _run(choke)
    (restated,) = await _run(choke, series="task_seg.v1-restated.2")

    assert restated.job_key != original.job_key
    assert restated.status == "written"
    assert len(choke.rollup_store) == 2  # original row untouched beside the new series
    assert choke.rollup_store[restated.job_key]["series"] == "task_seg.v1-restated.2"


async def test_empty_day_writes_nothing():
    choke = make_choke(rows=[])
    assert await _run(choke) == []
    assert "tvo_rollup_tenant_day" not in [r[0] for r in choke.requests]


async def test_rollup_row_arithmetic_in_template_param_schema():
    choke = make_choke()
    await _run(choke)
    # Flat params, exactly the choke template's declared schema (templates.go):
    # scalars plus the two uniqExact ARRAYS.
    ((_, row, _),) = [r for r in choke.requests if r[0] == "tvo_rollup_tenant_day"]
    assert row["day"] == "2026-08-01"
    assert row["series"] == "task_seg.v1"
    assert row["tokens_total"] == 102_000  # every metered token of both tasks
    assert row["cost_usd"] == pytest.approx(1.02)
    assert row["tasks_verified"] == ["t1"]  # terminal certified-satisfied
    assert row["tasks_unresolved"] == ["t2"]  # provisional terminal ⇒ neither side
    assert row["retry_loop_tokens"] == 37_000  # t1 attempt 2 after a violated attempt 1
    assert row["reexploration_tokens"] == 0 and row["over_model_tokens"] == 0
    assert (row["observed_ms"], row["bypass_ms"], row["disabled_ms"]) == (
        980_000,
        10_000,
        10_000,
    )
    assert row["dropped_billing"] == 2


_CROSSLANG_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "go/controld/internal/querychoke/testdata/rollup_write_body.json"
    ).read_text()
)


async def test_write_body_matches_the_crosslang_fixture():
    """The Python half of the write-seam lock (wave-5 lesson, RECONCILIATION.md:
    stub-tested halves of one contract drift unless one side's tests speak the other
    side's exact wire bytes): re-derive the POST body from the fixture's inputs through
    the REAL driver and compare dict-equal; controld's TestRollupWriteAcceptsIntelExactBody
    replays the same `body` against the REAL handler."""
    fixture = _CROSSLANG_FIXTURE
    inputs = fixture["inputs"]
    choke = MockChoke()
    choke.templates["tvo_task_window"] = inputs["tvo_task_window"]
    choke.templates["coverage_band"] = inputs["coverage_band"]
    choke.templates["dropped_by_tenant_day"] = inputs["dropped_by_tenant_day"]
    await run_rollup(
        _reader(choke),
        tenant_id=inputs["tenant_id"],
        day=date.fromisoformat(inputs["day"]),
        bearer=BEARER,
        now=AFTER_CLOSE,
        allow_unsigned_write=True,
    )
    ((_, body, _),) = [r for r in choke.requests if r[0] == "tvo_rollup_tenant_day"]
    assert body == fixture["body"]


async def test_version_cutover_day_is_two_jobs_two_rows():
    rows = TVO_ROWS + [
        {
            "task_id": "t3",
            "attempt_n": 1,
            "gen_tokens": 1_000,
            "verifier_tokens": 100,
            "fused_verdict": "satisfied",
            "verdict_stage": "certified",
            "task_seg_version": "task_seg.v2",
            "cost_usd": 0.01,
        }
    ]
    choke = make_choke(rows=rows)
    outcomes = await _run(choke)
    assert [o.series for o in outcomes] == ["task_seg.v1", "task_seg.v2"]
    assert len({o.job_key for o in outcomes}) == 2  # one job identity per series
    v1_row = choke.rollup_store[outcomes[0].job_key]
    v2_row = choke.rollup_store[outcomes[1].job_key]
    # Coverage is surface-time, not version-attributable: it rides the latest row only,
    # so a reader summing the cutover day's rows counts each millisecond once.
    assert v1_row["observed_ms"] == 0 and v2_row["observed_ms"] == 980_000
    # And a single restatement label across a cutover day is ambiguous — refused.
    with pytest.raises(ValueError, match="restate each version separately"):
        await _run(choke, series="task_seg.v1-restated.2")
