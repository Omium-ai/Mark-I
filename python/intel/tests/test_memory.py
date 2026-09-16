"""Memory plane, storeless: certified-only input, cascade order, LCB boundaries, batch mock."""

import json
import math
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.memory import admit, extract, jobs
from mark1_receipts import append_server_record

TENANT = "11111111-1111-1111-1111-111111111111"
CERT = "22222222-2222-2222-2222-222222222222"
LN = math.log(2 / admit.DELTA)

# `memory_certified_sessions` wire rows, key set locked to controld's fixture (the Go side
# asserts the template's aliases equal these keys; events are (digest, kind, payload)).
SESSION_ROWS = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "go/controld/internal/querychoke/testdata/intel_template_rows.json"
    ).read_text()
)[extract.SESSION_TEMPLATE]
SESSION_ROW = SESSION_ROWS[0]


def _row(task, stage="certified", cert=CERT, tamper=False, verdict="satisfied", digests=("d1",)):
    row = {
        **SESSION_ROW,
        "session_id": f"s-{task}",
        "task_id": task,
        "verdict": verdict,
        "verdict_stage": stage,
        "noise_cert_id": cert,
        "tamper": int(tamper),
        "events": [{**SESSION_ROW["events"][0], "digest": d, "kind": "ToolUse"} for d in digests],
    }
    assert row.keys() == SESSION_ROW.keys()
    assert all(e.keys() == SESSION_ROW["events"][0].keys() for e in row["events"])
    return row


def test_session_rows_lock_the_ledger_shape():
    """Every fixture row IS what the extractor consumes: the provisional-only task is served
    and refused by stage, the certified one is kept with its cert."""
    kept = extract.ledger_certified(SESSION_ROWS)
    assert [s.task_id for s in kept] == [SESSION_ROW["task_id"]]
    assert kept[0].noise_cert_id == SESSION_ROW["noise_cert_id"]
    assert kept[0].digests == {e["digest"] for e in SESSION_ROW["events"]}
    assert {r["verdict_stage"] for r in SESSION_ROWS} == {"certified", "provisional"}


class FakeBatch:
    def __init__(self, answers):
        self.answers = answers
        self.calls: list[tuple[set[str], list[str]]] = []

    async def run(self, requests):
        self.calls.append(
            ({r["params"]["model"] for r in requests}, [r["custom_id"] for r in requests])
        )
        return {
            r["custom_id"]: json.dumps(self.answers[r["custom_id"]])
            for r in requests
            if r["custom_id"] in self.answers
        }


def test_ledger_certified_refuses_uncertified_sessions():
    rows = [
        _row("ok"),
        _row("revised", stage="revised"),
        _row("provisional", stage="provisional"),
        _row("unstamped", cert=""),
        _row("tampered", tamper=True),
        _row("refused", verdict="refused"),
    ]
    assert {s.task_id for s in extract.ledger_certified(rows)} == {"ok", "revised"}


async def test_cascade_cheap_rung_first_and_only_grounded_escalates():
    sessions = extract.ledger_certified(
        [_row("s1", digests=("d1", "d2")), _row("s2", digests=("d3",))]
    )
    batch = FakeBatch(
        {
            "s1": [
                {
                    "kind": "pitfall",
                    "trigger": "ENOENT",
                    "guidance": "check cwd",
                    "evidence": ["d1"],
                },
                {"kind": "workflow_template", "guidance": "doc-name kind", "evidence": ["d2"]},
                {"kind": "fix_pattern", "guidance": "hallucinated", "evidence": ["zz"]},
                {"kind": "preference", "guidance": "fourth, over the cap", "evidence": ["d1"]},
            ],
            "s2": [
                {"kind": "fix_pattern", "guidance": "trivial", "evidence": ["d3"]},
                {"kind": "pitfall", "guidance": "", "evidence": ["d3"]},
            ],
            "s1:0": {"valid": True, "reason": "grounded"},
            "s2:1": {"valid": "yes", "reason": "not a strict true"},
        }
    )
    artifacts, n_candidates, n_grounded = await extract.cascade(batch, TENANT, sessions)
    assert batch.calls[0] == ({extract.CANDIDATE_MODEL}, ["s1", "s2"])
    assert batch.calls[1] == ({extract.VALIDATE_MODEL}, ["s1:0", "s2:1"])
    assert (n_candidates, n_grounded, len(artifacts)) == (5, 2, 1)
    a = artifacts[0]
    assert (a.kind, a.abstraction, a.cert_id) == ("pitfall", "instance", CERT)
    assert a.body["provenance"]["task_id"] == "s1" and a.body["evidence"] == ["d1"]
    assert a.id == extract.artifact_id(TENANT, "pitfall", "ENOENT", "check cwd")


async def test_cascade_without_grounded_candidates_never_escalates():
    batch = FakeBatch({"s1": [{"kind": "preference", "guidance": "x", "evidence": []}]})
    artifacts, _, _ = await extract.cascade(batch, TENANT, extract.ledger_certified([_row("s1")]))
    assert artifacts == [] and len(batch.calls) == 1


def test_invariant_kind_binds_invariant_abstraction():
    a = extract.Artifact(
        extract.artifact_id(TENANT, "invariant", "", "g"), TENANT, "invariant", {}, CERT
    )
    assert a.abstraction == "invariant"


def test_lcb_formula_pinned():
    lcb, ucb = admit.lcb_ucb([float(i) for i in range(1, 11)], phi=100.0)
    slack = math.sqrt(2 * 9.166666666666666 * LN / 10) + 7 * 100 * LN / 27
    assert lcb == pytest.approx(5.5 - slack) and ucb == pytest.approx(5.5 + slack)


def test_decide_boundaries():
    phi = 1000.0
    assert admit.decide([phi] * 7, phi).verdict == "hold"
    assert admit.decide([phi] * 9, phi).verdict == "hold"
    d = admit.decide([phi * 5] * 10, phi)
    assert d.verdict == "admit" and d.lcb == pytest.approx(phi * (1 - 7 * LN / 27))
    assert float(d.stored_lcb) == pytest.approx(1 - 7 * LN / 27, abs=1e-6)
    assert admit.decide([-phi] * 10, phi).verdict == "retire"
    assert admit.decide([1.0, -1.0] * 5, phi).verdict == "hold"
    zero = admit.decide([0.0] * 10, 0.0)
    assert (zero.verdict, zero.stored_lcb) == ("hold", None)
    assert not math.isnan(admit.decide([phi] * 8, phi).lcb)


async def test_revocation_recheck_fails_closed_on_no_devices():
    assert await admit.devices_unrevoked(None, TENANT, set()) is False


async def test_anthropic_batch_runner_mocked():
    def ok(cid, text):
        content = [SimpleNamespace(type="text", text=text)]
        return SimpleNamespace(
            custom_id=cid,
            result=SimpleNamespace(type="succeeded", message=SimpleNamespace(content=content)),
        )

    async def results(batch_id):
        for r in (
            ok("a", "[]"),
            SimpleNamespace(custom_id="b", result=SimpleNamespace(type="errored")),
        ):
            yield r

    states = iter(["in_progress", "ended"])
    client = SimpleNamespace(
        messages=SimpleNamespace(
            batches=SimpleNamespace(
                create=lambda requests: _aw(
                    SimpleNamespace(id="b1", processing_status=next(states))
                ),
                retrieve=lambda bid: _aw(SimpleNamespace(id=bid, processing_status=next(states))),
                results=lambda bid: _aw(results(bid)),
            )
        )
    )
    out = await extract.AnthropicBatchRunner(client, poll_s=0).run([])
    assert out == {"a": "[]"}


async def _aw(v):
    return v


def test_ordered_enforces_runs_after():
    assert jobs.ordered() == ("memory.extract", "memory.admit")
    with pytest.raises(ValueError, match="runs_after"):
        jobs.ordered((("memory.admit", "memory.extract"), ("memory.extract", None)))


async def test_run_nightly_extracts_before_admitting(monkeypatch):
    order: list[str] = []

    async def fake_extract(*a, **kw):
        order.append("extract")

    async def fake_admit(*a, **kw):
        order.append("admit")

    stamped: list[str] = []

    async def fake_embed(conn, tenant_id):
        assert conn == "conn"
        stamped.append(tenant_id)
        return 0

    monkeypatch.setattr(jobs, "run_extract", fake_extract)
    monkeypatch.setattr(jobs, "run_admit", fake_admit)
    monkeypatch.setattr(jobs, "embed_missing", fake_embed)
    kw = dict(tenant_id=TENANT, day=date(2026, 8, 1), bearer="t")
    with pytest.raises(ValueError, match="not yet closed"):
        await jobs.run_nightly(
            None, None, None, None, now=datetime(2026, 8, 2, 1, tzinfo=UTC), **kw
        )
    assert order == []
    await jobs.run_nightly(None, None, None, None, now=datetime(2026, 8, 2, 3, tzinfo=UTC), **kw)
    assert order == ["extract", "admit"]


class _Pool:
    def acquire(self):
        return _aw_ctx()


class _aw_ctx:
    async def __aenter__(self):
        return "conn"

    async def __aexit__(self, *exc):
        return False


async def test_scheduler_entries_build_from_ctx_and_env(monkeypatch):
    seen: list[tuple[str, str]] = []
    receipt = "44444444-4444-4444-4444-444444444444"

    async def fake_extract(reader, conn, batch, *, tenant_id, day, bearer):
        seen.append(("extract", bearer))
        assert conn == "conn" and isinstance(batch, extract.AnthropicBatchRunner)

    async def fake_admit(reader, conn, append, *, tenant_id, day, bearer):
        # The receipt appender is the shared client bound to controld's URL + this credential.
        assert append.func is append_server_record and append.args[1:] == ("http://choke", bearer)
        seen.append(("admit", bearer))
        return admit.AdmitReport(1, 1, 0, 0, 0, (receipt,))

    stamped: list[str] = []

    async def fake_embed(conn, tenant_id):
        assert conn == "conn"
        stamped.append(tenant_id)
        return 0

    monkeypatch.setattr(jobs, "run_extract", fake_extract)
    monkeypatch.setattr(jobs, "run_admit", fake_admit)
    monkeypatch.setattr(jobs, "embed_missing", fake_embed)
    ctx = SimpleNamespace(
        pool=_Pool(),
        settings=SimpleNamespace(http_timeout_s=1.0, querychoke_base_url="http://choke"),
        tenant_id=TENANT,
        day=date(2026, 8, 1),
    )
    with pytest.raises(RuntimeError, match="INTEL_QUERYCHOKE_TOKEN"):
        await jobs.extract(ctx)
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    assert await jobs.extract(ctx) is None
    assert await jobs.admit(ctx) == receipt
    assert seen == [("extract", "svc"), ("admit", "svc")]
    assert stamped == [ctx.tenant_id]
