"""reader.py against an httpx-mocked querychoke speaking 08 §3.3's exact bodies: row →
AttemptRow mapping, the M1E taxonomy crossing as typed errors with the frozen retryable
column, and the structural rule that tenant_id is never a template param (05 §6.2)."""

from datetime import date

import pytest
from app.tvo.reader import QuerychokeError, QuerychokeReader
from choke_mock import MockChoke

WINDOW = (date(2026, 8, 1), date(2026, 8, 31))
BEARER = "op-token-tenant-a"

TASK_WINDOW_ROWS = [
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
]


def _reader(choke: MockChoke) -> QuerychokeReader:
    return QuerychokeReader(choke.client(), "http://choke")


async def test_attempt_window_maps_rows_into_attemptrow_seam():
    choke = MockChoke()
    choke.templates["tvo_task_window"] = TASK_WINDOW_ROWS
    ledger = await _reader(choke).attempt_window(*WINDOW, bearer=BEARER)

    assert [a.task_id for a in ledger.attempts] == ["t1", "t1"]
    assert ledger.attempts[0].gen_tokens == 30_000
    assert ledger.attempts[1].fused_verdict == "satisfied"
    assert ledger.attempts[1].verdict_stage == "certified"
    assert ledger.seg_version_by_task == {"t1": "task_seg.v1"}
    assert ledger.cost_usd_by_task["t1"] == pytest.approx(0.92)
    assert ledger.task_seg_versions == ("task_seg.v1",)

    # The wire request is the §3.3 body exactly: named template + params, bearer auth,
    # and NO tenant slot — the choke binds the tenant predicate from verified claims.
    template, params, auth = choke.requests[0]
    assert template == "tvo_task_window"
    assert params == {"from": "2026-08-01", "to": "2026-08-31"}
    assert auth == f"Bearer {BEARER}"


async def test_coverage_inputs_sums_dropped_days():
    choke = MockChoke()
    choke.templates["coverage_band"] = [
        {"observed_ms": 980_000, "bypass_ms": 10_000, "disabled_ms": 10_000}
    ]
    choke.templates["dropped_by_tenant_day"] = [
        {"day": "2026-08-01", "dropped_billing": 3, "events_billing_ingested": 500},
        {"day": "2026-08-02", "dropped_billing": 1, "events_billing_ingested": 700},
    ]
    cov = await _reader(choke).coverage_inputs(*WINDOW, bearer=BEARER)
    assert (cov.observed_ms, cov.bypass_ms, cov.disabled_ms) == (980_000, 10_000, 10_000)
    assert cov.dropped_billing == 4
    assert cov.events_billing_ingested == 1200


async def test_unknown_template_is_typed_m1e_2008_not_retryable():
    choke = MockChoke()  # registry empty: everything unknown
    with pytest.raises(QuerychokeError) as exc:
        await _reader(choke).attempt_window(*WINDOW, bearer=BEARER)
    assert exc.value.code == "M1E-2008"
    assert exc.value.http_status == 400
    assert exc.value.retryable is False  # 08 §9: refusal, never a retry loop


async def test_5xx_is_retryable_m1e_9500():
    choke = MockChoke()
    choke.fail_with = (503, "M1E-9500", "clickhouse unavailable")
    with pytest.raises(QuerychokeError) as exc:
        await _reader(choke).attempt_window(*WINDOW, bearer=BEARER)
    assert exc.value.code == "M1E-9500"
    assert exc.value.retryable is True


async def test_missing_bearer_is_m1e_1001_fail_closed():
    choke = MockChoke()
    choke.templates["tvo_task_window"] = TASK_WINDOW_ROWS
    with pytest.raises(QuerychokeError) as exc:
        await _reader(choke).attempt_window(*WINDOW, bearer="")
    assert exc.value.code == "M1E-1001"
    assert exc.value.retryable is False


async def test_missing_column_names_template_and_field():
    choke = MockChoke()
    broken = [dict(TASK_WINDOW_ROWS[0])]
    del broken[0]["verdict_stage"]
    choke.templates["tvo_task_window"] = broken
    with pytest.raises(ValueError, match="tvo_task_window.*verdict_stage"):
        await _reader(choke).attempt_window(*WINDOW, bearer=BEARER)


async def test_unstamped_task_is_refused_not_blank_series():
    """A task whose TaskOpen fell outside the window renders task_seg_version '' at the
    choke; rollup.py would otherwise mint a '' series the write template refuses later."""
    choke = MockChoke()
    choke.templates["tvo_task_window"] = [{**TASK_WINDOW_ROWS[0], "task_seg_version": ""}]
    with pytest.raises(ValueError, match="t1.*outside the window"):
        await _reader(choke).attempt_window(*WINDOW, bearer=BEARER)
