"""Memory plane, storeless: certified-only input, cascade order, LCB boundaries, the router
runner (pinned models, no tenant, policy blocks counted), the mem:extract@1 gate and the caps."""

import contextlib
import json
import math
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from app.llm import MARK1_ROUTER_AGENT_ID, RouterClient
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


def completion(content: str, model: str) -> dict:
    return {"model": model, "choices": [{"message": {"content": content}, "finish_reason": "stop"}]}


def fake_router(answer):
    calls: list[dict] = []

    async def handler(req: httpx.Request) -> httpx.Response:
        assert req.url == "http://router/v1/chat/completions"
        assert not [h for h in req.headers if "tenant" in h.lower()], req.headers
        assert "tenant" not in req.content.decode().lower()
        assert req.headers["x-omium-agent-id"] == MARK1_ROUTER_AGENT_ID
        body = json.loads(req.content)
        calls.append(body)
        return answer(body)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return extract.RouterRunner(RouterClient(http, "http://router")), calls


async def test_router_runner_pins_the_model_and_refuses_any_other():
    def answer(body):
        text = body["messages"][1]["content"]
        if text == "off-model":
            return httpx.Response(200, json=completion("[]", "moonshotai/Kimi-K2.7-Code"))
        return httpx.Response(200, json=completion("<think>|</think>[]", body["model"]))

    extract.extract_skipped_total.clear()
    runner, calls = fake_router(answer)
    out = await runner.run(
        [
            extract._request("a", extract.CANDIDATE_MODEL, "sys", "ok"),
            extract._request("b", extract.CANDIDATE_MODEL, "sys", "off-model"),
        ]
    )
    assert out == {"a": "[]"}
    assert extract.extract_skipped_total["refused_model_mismatch"] == 1
    assert calls[0] == {
        "model": "Qwen/Qwen3-30B-A3B-Instruct-2507",
        "max_tokens": 4096,
        "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "ok"}],
    }


async def test_router_runner_counts_a_policy_block_and_never_retries_it():
    extract.extract_skipped_total.clear()
    runner, calls = fake_router(
        lambda body: httpx.Response(403, headers={"X-Omium-Policy-Blocked": "true"})
    )
    assert await runner.run([extract._request("a", extract.VALIDATE_MODEL, "s", "u")]) == {}
    assert len(calls) == 1 and extract.extract_skipped_total["refused_policy_blocked"] == 1


class ConsentConn:
    """The one PG read run_extract makes before anything else: the mem:extract@1 row."""

    def __init__(self, row: dict | None):
        self.row, self.reads, self.spend = row, [], 0  # spend: m1_101 units reserved today

    def transaction(self):
        return contextlib.nullcontext()

    async def execute(self, sql, *args):
        if "UPDATE m1_llm_spend_days" in sql:
            assert args[2] == "mem:extract@1"
            self.spend += args[3]
            return
        assert sql.startswith("SELECT set_config")

    async def fetchrow(self, sql, *args):
        if "INSERT INTO m1_llm_spend_days" in sql:
            return {"day": date(2026, 8, 2), "units": self.spend}
        assert "m1_cloud_judge_consents" in sql and args[1] == "mem:extract@1"
        self.reads.append(args)
        return self.row


class NoReader:
    async def run_template(self, *a, **kw):
        raise AssertionError("an unconsented tenant's sessions were read")


@pytest.mark.parametrize(
    "row",
    [
        None,
        {"subprocessor": "anthropic", "region": "us"},
        {"subprocessor": "nebius", "region": "us"},
    ],
)
async def test_an_unconsented_tenant_makes_zero_router_calls(row):
    runner, calls = fake_router(lambda body: pytest.fail("router called"))
    conn = ConsentConn(row)
    report = await extract.run_extract(
        NoReader(), conn, runner, tenant_id=TENANT, day=date(2026, 8, 1), bearer="t"
    )
    assert report == extract.ExtractReport(0, 0, 0, 0, 0, 0) and calls == [] and conn.reads


async def test_caps_bound_sessions_per_day_and_input_tokens(monkeypatch):
    extract.extract_skipped_total.clear()
    sessions = extract.ledger_certified(
        [_row(f"s{i}", digests=tuple(f"d{i}-{j:02d}" for j in range(40))) for i in range(4)]
    )

    async def certified(*a, **kw):
        return 4, sessions

    async def owners(conn, tenant_id):
        return {}, None

    async def insert(conn, tenant_id, artifacts):
        return len(artifacts)

    monkeypatch.setattr(extract, "certified_sessions", certified)
    monkeypatch.setattr(extract, "device_owners", owners)
    monkeypatch.setattr(extract, "insert_artifacts", insert)
    sent: list[list] = []

    def answer(body):
        sent.append(json.loads(body["messages"][1]["content"])["events"])
        return httpx.Response(200, json=completion("[]", body["model"]))

    runner, _ = fake_router(answer)
    one_event = len(json.dumps(sessions[0].events[0])) + 2
    await extract.run_extract(
        NoReader(),
        ConsentConn({"subprocessor": "nebius", "region": "global"}),
        runner,
        tenant_id=TENANT,
        day=date(2026, 8, 1),
        bearer="t",
        max_sessions=3,
        max_input_tokens=-(-10 * one_event // extract.CHARS_PER_TOKEN),
    )
    assert len(sent) == 3 and extract.extract_skipped_total["sessions_over_run_cap"] == 1
    assert all(len(events) == 10 for events in sent), "the newest events that fit"
    assert [e["digest"] for e in sent[0]] == [f"d0-{j}" for j in range(30, 40)]
    assert extract.extract_skipped_total["events_over_input_cap"] == 90


async def test_extraction_daily_ledger_bounds_reruns_on_the_same_day(monkeypatch):
    """INTEL_MEMORY_MAX_SESSIONS_PER_DAY is per tenant per UTC day (m1_101): a rerun or a second
    window the same day extracts only what the first left of the allowance."""
    extract.extract_skipped_total.clear()
    sessions = extract.ledger_certified([_row(f"s{i}") for i in range(3)])

    async def certified(*a, **kw):
        return 3, sessions

    async def owners(conn, tenant_id):
        return {}, None

    async def insert(conn, tenant_id, artifacts):
        return len(artifacts)

    monkeypatch.setattr(extract, "certified_sessions", certified)
    monkeypatch.setattr(extract, "device_owners", owners)
    monkeypatch.setattr(extract, "insert_artifacts", insert)
    runner, calls = fake_router(
        lambda body: httpx.Response(200, json=completion("[]", body["model"]))
    )
    conn = ConsentConn({"subprocessor": "nebius", "region": "global"})
    kw = dict(tenant_id=TENANT, bearer="t", max_sessions_per_day=4)
    first = await extract.run_extract(NoReader(), conn, runner, day=date(2026, 8, 1), **kw)
    second = await extract.run_extract(NoReader(), conn, runner, day=date(2026, 7, 31), **kw)
    third = await extract.run_extract(NoReader(), conn, runner, day=date(2026, 7, 30), **kw)
    got = (first.sessions_certified, second.sessions_certified, third.sessions_certified)
    assert got == (3, 1, 0)
    assert conn.spend == 4 and len(calls) == 4
    assert extract.extract_skipped_total["sessions_over_daily_cap"] == 2 + 3


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

    async def fake_extract(reader, conn, batch, *, tenant_id, day, bearer, **caps):
        seen.append(("extract", bearer))
        assert conn == "conn" and isinstance(batch, extract.RouterRunner)
        assert caps == {
            "max_sessions": 30,
            "max_input_tokens": 20_000,
            "max_sessions_per_day": 30,
        }

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
        settings=SimpleNamespace(
            http_timeout_s=1.0,
            querychoke_base_url="http://choke",
            llm_router_url="http://router",
            memory_max_sessions_per_day=30,
            memory_max_sessions_per_run=30,
            memory_max_input_tokens=20_000,
        ),
        tenant_id=TENANT,
        day=date(2026, 8, 1),
    )
    with pytest.raises(RuntimeError, match="INTEL_QUERYCHOKE_TOKEN"):
        await jobs.extract(ctx)
    monkeypatch.setenv("INTEL_QUERYCHOKE_TOKEN", "svc")
    assert await jobs.extract(ctx) is None
    assert await jobs.admit(ctx) == receipt
    assert seen == [("extract", "svc"), ("admit", "svc")]
    assert stamped == [ctx.tenant_id]


def test_extraction_names_what_the_subprocessor_register_says():
    """mem:extract@1's processor and region are controld's register row (10 §10.4)."""
    import pathlib

    register = json.loads(
        (
            pathlib.Path(__file__).parents[3] / "desktop/mock/fixtures/controld/register.json"
        ).read_text()
    )
    row = next(r for r in register if r["key"] == extract.CONSENT_ID)
    assert (row["subprocessor"], row["region"], row["max_tier"]) == (
        extract.SUBPROCESSOR,
        extract.REGION,
        "E0",
    )


async def test_only_typed_fields_reach_the_router():
    """mem:extract@1 is E0: text, hashes, ids and unknown fields in a ledger payload never leave."""
    secret = "def leak(): return 'sk-live'"
    events = [
        {
            "digest": "a1",
            "kind": "AnchorVote",
            "payload": json.dumps(
                {
                    "anchor_id": "ruff@cat-1",
                    "vote": "VERDICT_VIOLATED",
                    "evidence": {
                        "tool": "ruff",
                        "diagnostic_code": "F401",
                        "counts": {"errors": 2},
                        "output_hmac": "aGFzaA==",
                        "excerpt": secret,
                    },
                    "integrity": {"tamper": False, "worktree_merkle_root": "cm9vdA=="},
                    "signature": "c2ln",
                }
            ),
        },
        {
            "digest": "c1",
            "kind": "OutcomeContribution",
            "payload": json.dumps(
                {"intent_text_redacted": secret, "diff_redacted": secret, "label_age_days": 30}
            ),
        },
        {
            "digest": "t1",
            "kind": "ToolUse",
            "payload": json.dumps({"tool_name": "Bash", "path": secret}),
        },
        {"digest": "f1", "kind": "FutureEvent", "payload": json.dumps({"text": secret})},
        {"digest": "v1", "kind": "VerdictEvent", "payload": "not json"},
    ]
    row = {**_row("s1"), "events": events}
    sent: list[str] = []

    class Capture:
        async def run(self, requests):
            sent.extend(r["params"]["messages"][0]["content"] for r in requests)
            return {}

    await extract.cascade(Capture(), TENANT, extract.ledger_certified([row]))
    assert len(sent) == 1 and "leak" not in sent[0] and "aGFzaA" not in sent[0]
    assert json.loads(sent[0])["events"] == [
        {
            "digest": "a1",
            "kind": "AnchorVote",
            "payload": {
                "anchor_id": "ruff@cat-1",
                "evidence.counts.errors": 2,
                "evidence.diagnostic_code": "F401",
                "evidence.tool": "ruff",
                "integrity.tamper": False,
                "vote": "VERDICT_VIOLATED",
            },
        },
        {"digest": "c1", "kind": "OutcomeContribution", "payload": {"label_age_days": 30}},
        {"digest": "t1", "kind": "ToolUse", "payload": {"tool_name": "Bash"}},
        {"digest": "f1", "kind": "FutureEvent", "payload": {}},
        {"digest": "v1", "kind": "VerdictEvent", "payload": {}},
    ]


def test_contributions_keep_what_the_subprocessor_register_says():
    """contribute_outcomes' retention is the register row's (10 §10.5a)."""
    from app.corpus import contributions

    register = json.loads(
        (Path(__file__).parents[3] / "desktop/mock/fixtures/controld/register.json").read_text()
    )
    row = next(r for r in register if r["key"] == "contribute_outcomes")
    assert (row["subprocessor"], row["max_tier"], row["retention_days"]) == (
        "aws-s3",
        "contribution",
        contributions.RETENTION_DAYS,
    )
