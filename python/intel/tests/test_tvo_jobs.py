"""tvo.rollup_verify (06 §7.2, hourly): the not-yet-closed no-op, the unsigned-ADR guard
threading through unchanged in production shape, and the outcomes -> receipt-id mapping —
against a fake reader (MockChoke), never the arithmetic rollup.py already owns."""

from datetime import UTC, datetime

import pytest
from app.jobs.runner import JobContext
from app.tvo import jobs
from app.tvo.rollup import window_close
from choke_mock import MockChoke

DAY = datetime(2026, 8, 1, tzinfo=UTC)
AFTER_CLOSE = datetime(2026, 8, 2, 3, 0, tzinfo=UTC)  # yesterday's D20 grace has passed
INSIDE_GRACE = datetime(2026, 8, 2, 1, 0, tzinfo=UTC)  # UTC day over, 2h grace not yet
EXACT_CLOSE = window_close(DAY.date())  # the closing instant itself: must NOT be a no-op

TVO_ROWS = [
    {
        "task_id": "t1",
        "attempt_n": 1,
        "gen_tokens": 100,
        "verifier_tokens": 50,
        "fused_verdict": "satisfied",
        "verdict_stage": "certified",
        "task_seg_version": "task_seg.v1",
        "cost_usd": 0.1,
    }
]


class _Settings:
    querychoke_base_url = "http://choke"
    http_timeout_s = 5.0


def _ctx(tenant_id: str = "ten-a") -> JobContext:
    return JobContext(pool=None, settings=_Settings(), tenant_id=tenant_id, window_start=DAY)


def _choke(rows=TVO_ROWS) -> MockChoke:
    choke = MockChoke()
    choke.templates["tvo_task_window"] = rows
    choke.templates["coverage_band"] = []
    choke.templates["dropped_by_tenant_day"] = []
    return choke


async def test_inside_grace_window_is_a_clean_noop(monkeypatch):
    monkeypatch.delenv("INTEL_QUERYCHOKE_TOKEN", raising=False)
    choke = _choke()
    async with choke.client() as http:
        result = await jobs.rollup_verify(_ctx(), http=http, now=INSIDE_GRACE)
    assert result is None
    assert choke.requests == []  # never even reached the reader


async def test_exactly_at_close_boundary_is_not_a_noop(monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    choke = _choke()
    async with choke.client() as http:
        with pytest.raises(RuntimeError, match="ADR-0010 is UNSIGNED"):
            await jobs.rollup_verify(_ctx(), http=http, now=EXACT_CLOSE)


async def test_unsigned_adr_guard_still_blocks_by_default(monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    choke = _choke()
    async with choke.client() as http:
        with pytest.raises(RuntimeError, match="ADR-0010 is UNSIGNED"):
            await jobs.rollup_verify(_ctx(), http=http, now=AFTER_CLOSE)
    assert choke.requests == []  # refused before any read, exactly like rollup.py's own guard


async def test_missing_bearer_fails_closed_before_any_call(monkeypatch):
    monkeypatch.delenv("INTEL_QUERYCHOKE_TOKEN", raising=False)
    choke = _choke()
    async with choke.client() as http:
        with pytest.raises(RuntimeError, match="INTEL_QUERYCHOKE_TOKEN"):
            await jobs.rollup_verify(_ctx(), http=http, now=AFTER_CLOSE)
    assert choke.requests == []


async def test_written_outcome_returns_its_job_key(monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    choke = _choke()
    async with choke.client() as http:
        receipt = await jobs.rollup_verify(
            _ctx(), http=http, now=AFTER_CLOSE, allow_unsigned_write=True
        )
    assert receipt is not None
    assert receipt in choke.rollup_store
    assert receipt.startswith("tvo.rollup_tenant_day:2026-08-01:2026-08-02:")


async def test_empty_day_returns_none(monkeypatch):
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "intel-svc")
    choke = _choke(rows=[])
    async with choke.client() as http:
        receipt = await jobs.rollup_verify(
            _ctx(), http=http, now=AFTER_CLOSE, allow_unsigned_write=True
        )
    assert receipt is None
    assert choke.rollup_store == {}
