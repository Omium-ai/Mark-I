"""judge_batch (06 §1.2, §6) through fake choke rows, a fake controld and a fake Batch API:
the D18 selection restricted to tasks lacking the judge's vote, the C4 client-side default
with zero cloud calls, the cloud path only under an admitting m1_065 consent row, one Batch
per (tenant, judge) region-pinned, votes re-entering the ledger as JudgeVote events with a
deterministic event_id, the spent row re-posted and never re-called, and every failure a
counted skip."""

import contextlib
import json
from dataclasses import replace
from datetime import UTC, date, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import betterproto
import httpx
import pytest
import zstandard
from app import ledger
from app.adjudicate.algorithm import adjudicate
from app.choke import QuerychokeError
from app.jobs import judge_batch
from app.jobs.judge_batch import (
    USAGE_COLUMNS,
    e0_evidence,
    judge_batch_skipped_total,
    lacks_vote_from,
)
from app.jobs.readjudicate import NO_ATTEMPT, is_candidate, votes_by_task
from app.judges.cloud_path import AnthropicBatchRunner, message_params
from app.judges.specs import JUDGE_REQUESTS_PATH, JUDGE_SPECS, request_id_for
from m1p.v1 import Batch, EvidenceTier, JudgeLocus, Verdict
from pydantic import SecretStr
from tests.test_certified import ANCHOR
from tests.test_jobs import FakeChoke
from tests.test_readjudicate import AMBIGUOUS, CONFIDENT, MIDBAND, NO_TEST, REGISTRY_ROWS, row, rows

JID = "judge:grounded-rubric@1"
SPEC = JUDGE_SPECS[JID]
TENANT = str(uuid4())
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)
CONSENT = {"subprocessor": "anthropic", "region": "us", "max_tier": "E0"}
JUDGED = uuid4()  # ambiguous, but this judge already voted on it


def all_rows() -> list[dict]:
    return [
        *rows(),
        row(JUDGED, ANCHOR, "AnchorVote", "satisfied"),
        row(JUDGED, JID, "JudgeVote", "violated", seq=2),
    ]


def usage(inp=1200, out=3, created=0, read=1100) -> SimpleNamespace:
    return SimpleNamespace(
        inference_geo="us",
        input_tokens=inp,
        output_tokens=out,
        cache_creation_input_tokens=created,
        cache_read_input_tokens=read,
    )


def message(reply="violated", stop="end_turn", geo="us", **kw) -> SimpleNamespace:
    u = usage(**kw)
    u.inference_geo = geo
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=reply)], stop_reason=stop, usage=u
    )


class FakeBatch:
    """The cloud path's Batch API seam: records every request, answers per custom_id."""

    def __init__(self, answers: dict[str, SimpleNamespace] | None = None, batch_id="msgbatch_1"):
        self.answers, self.batch_id, self.calls = answers, batch_id, []

    async def run(self, requests):
        self.calls.append(list(requests))
        if self.answers is None:
            return self.batch_id, {r["custom_id"]: message() for r in requests}
        return self.batch_id, {
            r["custom_id"]: self.answers[r["custom_id"]]
            for r in requests
            if r["custom_id"] in self.answers
        }


class FakePool:
    """The job's PG reads by table; consent per judge_id, spent judge_dispatches rows, and
    the upserts captured. PG twin in tests/test_judge_batch_pg.py."""

    def __init__(self, *, consent: dict | None = None, spent: list[dict] = ()):
        self.consent, self.spent, self.upserts = consent, list(spent), []

    async def fetch(self, sql, *args):
        if "FROM m1_verifiers" in sql:
            return REGISTRY_ROWS
        if "m1_verifier_promotions" in sql:
            return []
        if "FROM judge_dispatches" in sql:
            return self.spent
        raise AssertionError(sql)

    @contextlib.asynccontextmanager
    async def acquire(self):
        pool = self

        class Conn:
            def transaction(self):
                return contextlib.nullcontext()

            async def execute(self, sql, *args):
                assert sql.startswith("SELECT set_config") or "INSERT INTO judge_dispatches" in sql
                if "judge_dispatches" in sql:
                    pool.upserts.append(args)

            async def fetch(self, sql, *args):
                return await pool.fetch(sql, *args)

            async def fetchrow(self, sql, *args):
                if "FROM noise_certificates" in sql:
                    return None
                if "FROM spectral_runs" in sql:
                    return None
                if "m1_cloud_judge_consents" in sql:
                    return pool.consent
                raise AssertionError(sql)

        yield Conn()


class FakeCloud:
    """One MockTransport for the choke, controld's judge fan-out route and the service ingest."""

    def __init__(self, choke_rows, *, dispatch=200, ingest=200):
        self.choke = FakeChoke(choke_rows)
        self.dispatched: list[dict] = []
        self.ingested: list[httpx.Request] = []
        self.dispatch, self.ingest = dispatch, ingest

    async def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == JUDGE_REQUESTS_PATH:
            assert req.headers["authorization"] == "Bearer svc"
            self.dispatched.append(json.loads(req.content))
            return httpx.Response(self.dispatch, json={"error": {"code": "M1E-2001"}})
        if req.url.path == ledger.INGEST_PATH:
            self.ingested.append(req)
            if self.ingest != 200:
                return httpx.Response(self.ingest, json={"error": {"code": "M1E-9500"}})
            return httpx.Response(200, json={"batch_id": req.headers["M1P-Batch-Id"]})
        return await self.choke.client().send(
            httpx.Request(req.method, req.url, headers=req.headers, content=req.content)
        )

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    def events(self) -> list:
        """The JudgeVote events posted so far (readjudicate's verdicts ride the same route)."""
        out = []
        for req in self.ingested:
            assert req.headers["m1p-tenant-id"]
            out += [
                e
                for e in Batch().parse(zstandard.decompress(req.content)).events
                if betterproto.which_one_of(e, "body")[0] == "judge_vote"
            ]
        return out


def _ctx(pool) -> SimpleNamespace:
    return SimpleNamespace(
        pool=pool,
        settings=SimpleNamespace(
            querychoke_base_url="http://choke",
            querychoke_token=SecretStr("svc"),
            http_timeout_s=1,
            anthropic_api_key=None,
        ),
        tenant_id=TENANT,
        window_start=WINDOW,
        day=date(2026, 9, 15),
    )


@pytest.fixture(autouse=True)
def no_cloud_call(monkeypatch):
    monkeypatch.setattr(
        "anthropic.resources.messages.AsyncMessages.create",
        lambda *a, **kw: pytest.fail("a direct Messages call from judge_batch"),
    )
    monkeypatch.setattr(
        "anthropic.resources.messages.batches.AsyncBatches.create",
        lambda *a, **kw: pytest.fail("a real Batch API call from judge_batch"),
    )
    judge_batch_skipped_total.clear()


async def _run(pool, cloud, batch=None, **kw) -> dict[UUID, dict]:
    await judge_batch.run(_ctx(pool), http=cloud.client(), batch=batch, **kw)
    cols = (
        "tenant_id task_id judge_id request_id window_start locus vote model batch_id "
        + " ".join(USAGE_COLUMNS)
    ).split()
    out = {}
    for args in pool.upserts:
        rec = dict(zip(cols, args, strict=True))
        assert rec["tenant_id"] == UUID(TENANT)
        if rec["judge_id"] == JID:
            out[rec["task_id"]] = rec
    return out


def rid(task: UUID) -> str:
    return request_id_for(JID, task, NO_ATTEMPT)


def test_selection_is_ambiguous_tasks_lacking_this_judges_vote():
    tasks = votes_by_task(all_rows(), {})
    assert lacks_vote_from(tasks[AMBIGUOUS], JID)  # judge:g@1 voted, this judge did not
    assert not lacks_vote_from(tasks[JUDGED], JID)
    costs = judge_batch.Costs()
    bundle = judge_batch.bundle_for([], None)
    chosen = judge_batch.select(tasks, set(), bundle, costs, "", JID)
    # MIDBAND (eta=0.68) is deep in the band, past is_candidate's D18 margin either edge.
    fused_midband = votes_by_task(rows(), {})[MIDBAND]
    assert adjudicate(fused_midband, bundle, costs, "").verdict == "refused"
    assert not is_candidate(adjudicate(fused_midband, bundle, costs, "").posterior[0], costs)
    assert set(chosen) == {AMBIGUOUS, NO_TEST, MIDBAND}
    assert CONFIDENT not in chosen and JUDGED not in chosen


def test_a_bootstrap_refused_task_is_a_candidate_even_off_is_candidates_margin():
    """A clean task's lone anchor-accept fuses to [0.71, 0.23, 0.04, 0.02] — 'refused', but
    0.18 from the nearer edge, past is_candidate's 0.10 D18 margin."""
    task = uuid4()
    bundle, costs = judge_batch.bundle_for([], None), judge_batch.Costs()
    tasks = votes_by_task([row(task, ANCHOR, "AnchorVote", "satisfied")], {})
    event = adjudicate(tasks[task], bundle, costs, "")
    assert event.verdict == "refused"
    assert [round(p, 2) for p in event.posterior] == [0.71, 0.23, 0.04, 0.02]
    assert not is_candidate(event.posterior[0], costs)
    assert judge_batch.select(tasks, set(), bundle, costs, "", JID) == [task]


def test_e0_evidence_is_typed_anchor_facts_only():
    text = e0_evidence(all_rows())
    assert json.loads(text) == [
        {"anchor": ANCHOR, "tamper": False, "vote": "satisfied"},
        {"anchor": ANCHOR, "tamper": False, "vote": "violated"},
        {"anchor": "ruff@cat-1", "tamper": False, "vote": "satisfied"},
        {"anchor": "ruff@cat-1", "tamper": False, "vote": "violated"},
        {"anchor": ANCHOR, "tamper": False, "vote": "satisfied"},
    ]
    assert "session" not in text and "judge" not in text and "/" not in text


async def test_client_side_default_posts_one_request_per_candidate_and_no_cloud_call():
    pool, cloud, batch = FakePool(), FakeCloud(all_rows()), FakeBatch()
    recs = await _run(pool, cloud, batch)
    assert batch.calls == [] and cloud.ingested == []
    assert {d["request"]["requestId"] for d in cloud.dispatched} == {
        rid(AMBIGUOUS),
        rid(NO_TEST),
        rid(MIDBAND),
    }
    for d in cloud.dispatched:
        assert d["tenant_id"] == TENANT
        r = d["request"]
        assert (r["judgeId"], r["model"], r["tier"]) == (JID, SPEC.model, EvidenceTier.E0.value)
        assert r["locus"] == JudgeLocus.CLIENT_SIDE.value and "evidence" not in r
    assert set(recs) == {AMBIGUOUS, NO_TEST, MIDBAND}
    rec = recs[AMBIGUOUS]
    assert (rec["locus"], rec["vote"], rec["model"], rec["window_start"]) == (
        "client_side",
        None,
        None,
        WINDOW,
    )
    assert rec["request_id"] == UUID(rid(AMBIGUOUS))
    assert all(rec[c] is None for c in USAGE_COLUMNS)


async def test_client_side_dispatch_failure_fails_the_run_before_any_row():
    pool, cloud = FakePool(), FakeCloud(all_rows(), dispatch=503)
    with pytest.raises(judge_batch.JudgeRefused, match="refused_dispatch_failed:503"):
        await _run(pool, cloud, FakeBatch())
    assert pool.upserts == []


async def test_cloud_path_runs_one_region_pinned_batch_under_an_admitting_consent():
    pool, cloud, batch = FakePool(consent=CONSENT), FakeCloud(all_rows()), FakeBatch()
    recs = await _run(pool, cloud, batch)
    assert cloud.dispatched == []
    (requests,) = batch.calls
    assert {r["custom_id"] for r in requests} == {rid(AMBIGUOUS), rid(NO_TEST), rid(MIDBAND)}
    by_id = {r["custom_id"]: r["params"] for r in requests}
    p = by_id[rid(AMBIGUOUS)]
    assert p["model"] == SPEC.model and p["inference_geo"] == "us"
    assert p["max_tokens"] == SPEC.token_budget
    assert p["system"] == [
        {"type": "text", "text": SPEC.rubric, "cache_control": {"type": "ephemeral"}}
    ]
    assert p["messages"] == [
        {
            "role": "user",
            "content": e0_evidence(r for r in all_rows() if r["task_id"] == str(AMBIGUOUS)),
        }
    ]
    assert p == message_params(SPEC, p["messages"][0]["content"])
    events = cloud.events()
    assert {UUID(bytes=e.task_id) for e in events} == {AMBIGUOUS, NO_TEST, MIDBAND}
    for e in events:
        assert e.session_epoch == ledger.SERVICE_EPOCH
        assert e.occurred_at == ledger.window_close(WINDOW)
        assert (e.judge_vote.judge_id, e.judge_vote.vote) == (JID, Verdict.VIOLATED)
        assert (e.judge_vote.tier_used, e.judge_vote.locus) == (EvidenceTier.E0, JudgeLocus.CLOUD)
        assert len(e.judge_vote.rubric_hash) == 32
    rec = recs[AMBIGUOUS]
    assert (rec["locus"], rec["vote"], rec["model"], rec["batch_id"]) == (
        "cloud",
        "violated",
        SPEC.model,
        "msgbatch_1",
    )
    assert [rec[c] for c in USAGE_COLUMNS] == [1200, 3, 0, 1100]


@pytest.mark.parametrize(
    ("consent", "reason"),
    [
        ({**CONSENT, "region": "global"}, "cloud_refused_region_mismatch"),
        ({**CONSENT, "subprocessor": "acme"}, "cloud_refused_subprocessor_not_listed"),
    ],
)
async def test_consent_that_does_not_admit_the_judge_falls_back_to_client_side(consent, reason):
    pool, cloud, batch = FakePool(consent=consent), FakeCloud(all_rows()), FakeBatch()
    recs = await _run(pool, cloud, batch)
    assert batch.calls == [] and cloud.ingested == []
    assert len(cloud.dispatched) == 3 and all(r["locus"] == "client_side" for r in recs.values())
    assert judge_batch_skipped_total[reason] == 1


async def test_cloud_tier_above_consent_never_reaches_the_batch(monkeypatch):
    e1 = replace(SPEC, judge_id="judge:hunks@1", evidence_tier="E1")
    monkeypatch.setitem(JUDGE_SPECS, e1.judge_id, e1)
    pool, cloud, batch = FakePool(consent=CONSENT), FakeCloud(all_rows()), FakeBatch()
    await _run(pool, cloud, batch)
    assert judge_batch_skipped_total["cloud_refused_tier_above_consent"] == 1
    assert {d["request"]["judgeId"] for d in cloud.dispatched} == {e1.judge_id}
    assert {r["custom_id"] for r in batch.calls[0]} == {rid(AMBIGUOUS), rid(NO_TEST), rid(MIDBAND)}
    assert {a[2] for a in pool.upserts} == {JID, e1.judge_id}


async def test_e2_has_no_branch_at_either_locus(monkeypatch):
    e2 = replace(SPEC, judge_id="judge:full-diff@1", evidence_tier="E2")
    monkeypatch.setitem(JUDGE_SPECS, e2.judge_id, e2)
    pool, cloud, batch = FakePool(consent=CONSENT), FakeCloud(all_rows()), FakeBatch()
    recs = await _run(pool, cloud, batch)
    assert cloud.dispatched == [] and set(recs) == {AMBIGUOUS, NO_TEST, MIDBAND}
    assert {a[2] for a in pool.upserts} == {JID}
    assert {r["custom_id"] for r in batch.calls[0]} == {rid(AMBIGUOUS), rid(NO_TEST), rid(MIDBAND)}


async def test_cloud_no_vendor_key_is_a_counted_skip_never_a_crash_or_client_side_fallback():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud)  # no batch injected, ctx.settings.anthropic_api_key is None
    assert recs == {} and cloud.ingested == [] and cloud.dispatched == []
    assert judge_batch_skipped_total["cloud_no_vendor_key"] == 1


async def test_vendor_key_builds_the_client_from_settings_never_a_customer_credential(monkeypatch):
    captured: dict = {}

    class SpyAnthropic:
        def __init__(self, **kw):
            captured.update(kw)

    class SpyRunner:
        def __init__(self, client):
            captured["client"] = client

        async def run(self, requests):
            return "batch_spy", {}

    monkeypatch.setattr(judge_batch, "AsyncAnthropic", SpyAnthropic)
    monkeypatch.setattr(judge_batch, "AnthropicBatchRunner", SpyRunner)
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    ctx = _ctx(pool)
    ctx.settings.anthropic_api_key = SecretStr("sk-ant-do-not-log-or-echo")
    await judge_batch.run(ctx, http=cloud.client())
    assert captured["api_key"] == "sk-ant-do-not-log-or-echo"
    assert isinstance(captured["client"], SpyAnthropic)
    assert judge_batch_skipped_total["cloud_no_vendor_key"] == 0


async def test_a_key_the_vendor_refuses_is_a_counted_skip_not_a_failed_night():
    # prod 2026-09-21..23: a placeholder key 401ed the whole nightly three nights
    import anthropic
    import httpx

    class RefusingBatch:
        async def run(self, requests):
            resp = httpx.Response(401, request=httpx.Request("POST", "https://api.anthropic.com"))
            raise anthropic.AuthenticationError("invalid x-api-key", response=resp, body=None)

    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    await judge_batch.run(_ctx(pool), http=cloud.client(), batch=RefusingBatch())
    assert judge_batch_skipped_total["cloud_vendor_key_rejected"] == 1
    assert cloud.ingested == [] and cloud.dispatched == []


async def test_spent_row_is_reposted_under_its_own_window_and_never_recalled():
    spent = {
        "task_id": AMBIGUOUS,
        "judge_id": JID,
        "request_id": UUID(rid(AMBIGUOUS)),
        "window_start": WINDOW.replace(day=14),
        "vote": "satisfied",
        "model": SPEC.model,
        "batch_id": "msgbatch_0",
        "input_tokens": 7,
        "output_tokens": 1,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 6,
    }
    pool, cloud, batch = (
        FakePool(consent=CONSENT, spent=[spent]),
        FakeCloud(all_rows()),
        FakeBatch(),
    )
    recs = await _run(pool, cloud, batch)
    (requests,) = batch.calls
    assert {r["custom_id"] for r in requests} == {rid(NO_TEST), rid(MIDBAND)}
    assert set(recs) == {NO_TEST, MIDBAND}
    by_task = {UUID(bytes=e.task_id): e for e in cloud.events()}
    assert set(by_task) == {AMBIGUOUS, NO_TEST, MIDBAND}
    assert by_task[AMBIGUOUS].judge_vote.vote == Verdict.SATISFIED
    assert by_task[NO_TEST].judge_vote.vote == Verdict.VIOLATED
    original = ledger.judge_vote_wire(
        by_task[AMBIGUOUS].judge_vote,
        tenant_id=UUID(TENANT),
        task_id=AMBIGUOUS,
        session_id=UUID(bytes=by_task[AMBIGUOUS].session_id),
        window_start=WINDOW.replace(day=14),
    )
    assert bytes(by_task[AMBIGUOUS].event_id) == bytes(original.event_id)


async def test_a_bad_batch_result_is_a_counted_skip_with_no_row_and_no_event():
    answers = {
        rid(AMBIGUOUS): message(geo="global"),
        # NO_TEST, MIDBAND: no result at all (errored/expired/canceled)
    }
    pool, cloud, batch = FakePool(consent=CONSENT), FakeCloud(all_rows()), FakeBatch(answers)
    recs = await _run(pool, cloud, batch)
    assert recs == {} and cloud.ingested == []
    assert judge_batch_skipped_total["refused_region_mismatch"] == 1
    assert judge_batch_skipped_total["cloud_result_missing"] == 2


async def test_a_model_refusal_is_the_judges_refusal_and_lands_as_refused():
    answers = {rid(AMBIGUOUS): message("", stop="refusal"), rid(NO_TEST): message("Satisfied.")}
    pool, cloud, batch = FakePool(consent=CONSENT), FakeCloud(all_rows()), FakeBatch(answers)
    recs = await _run(pool, cloud, batch)
    assert recs[AMBIGUOUS]["vote"] == "refused" and recs[NO_TEST]["vote"] == "satisfied"
    votes = {UUID(bytes=e.task_id): e.judge_vote.vote for e in cloud.events()}
    assert votes == {AMBIGUOUS: Verdict.REFUSED, NO_TEST: Verdict.SATISFIED}


async def test_task_without_session_id_is_counted_at_both_loci():
    orphan = uuid4()
    extra = [row(orphan, "ruff@cat-1", "AnchorVote", "violated", session=None)]
    pool, cloud, batch = FakePool(), FakeCloud([*all_rows(), *extra]), FakeBatch()
    recs = await _run(pool, cloud, batch)
    assert orphan not in recs and judge_batch_skipped_total["no_session_id"] == 1
    judge_batch_skipped_total.clear()
    pool, cloud = FakePool(consent=CONSENT), FakeCloud([*all_rows(), *extra])
    recs = await _run(pool, cloud, batch)
    assert orphan not in recs and judge_batch_skipped_total["no_session_id"] == 1
    assert {r["custom_id"] for r in batch.calls[0]} == {rid(AMBIGUOUS), rid(NO_TEST), rid(MIDBAND)}


async def test_ledger_post_failure_fails_the_run_after_the_spent_rows_are_durable():
    pool, cloud, batch = FakePool(consent=CONSENT), FakeCloud(all_rows(), ingest=503), FakeBatch()
    with pytest.raises(QuerychokeError):
        await _run(pool, cloud, batch)
    assert len(pool.upserts) == 3 and len(batch.calls) == 1


async def test_e1_cloud_judge_needs_the_evidence_reader_seam(monkeypatch):
    e1 = replace(SPEC, judge_id="judge:hunks@1", evidence_tier="E1")
    monkeypatch.setitem(JUDGE_SPECS, e1.judge_id, e1)
    monkeypatch.delitem(JUDGE_SPECS, JID)
    consent = {**CONSENT, "max_tier": "E1"}
    pool, cloud, batch = FakePool(consent=consent), FakeCloud(all_rows()), FakeBatch()
    await _run(pool, cloud, batch)
    # JUDGED lacks a vote from THIS judge (candidate again) and MIDBAND is deep in
    assert batch.calls == [] and judge_batch_skipped_total["cloud_no_evidence_reader"] == 4

    async def hunks(task_id, attempt_id, tier):
        return f"{tier} hunks for {task_id}"

    pool, cloud = FakePool(consent=consent), FakeCloud(all_rows())
    await _run(pool, cloud, batch, evidence_for=hunks)
    contents = {r["params"]["messages"][0]["content"] for r in batch.calls[0]}
    assert contents == {f"E1 hunks for {t}" for t in (AMBIGUOUS, NO_TEST, JUDGED, MIDBAND)}
    assert all(e.judge_vote.tier_used == EvidenceTier.E1 for e in cloud.events())


def test_judge_vote_event_id_is_one_per_tenant_task_judge_window():
    vote = judge_batch.judge_vote(SPEC, Verdict.VIOLATED)
    args = dict(tenant_id=UUID(TENANT), task_id=AMBIGUOUS, session_id=uuid4(), window_start=WINDOW)
    a = ledger.judge_vote_wire(vote, **args)
    assert UUID(bytes=a.event_id).version == 7 and a.judge_vote == vote
    assert bytes(a.event_id) == bytes(ledger.judge_vote_wire(vote, **args).event_id)
    other = replace(vote, vote=Verdict.SATISFIED)
    assert bytes(ledger.judge_vote_wire(other, **args).event_id) == bytes(a.event_id)
    renamed = replace(vote, judge_id="judge:other@1")
    assert bytes(ledger.judge_vote_wire(renamed, **args).event_id) != bytes(a.event_id)
    assert bytes(a.event_id) != ledger.event_id(UUID(TENANT), AMBIGUOUS, WINDOW)
    assert bytes(ledger.judge_vote_wire(vote, **{**args, "task_id": NO_TEST}).event_id) != bytes(
        a.event_id
    )


class FakeAnthropic:
    """messages.batches.{create,retrieve,results} as the SDK exposes them."""

    def __init__(self, results, polls=2):
        self.messages = self
        self.batches = self
        self.results_, self.polls, self.retrieved, self.created = results, polls, 0, None

    async def create(self, *, requests):
        self.created = requests
        return SimpleNamespace(id="msgbatch_x", processing_status="in_progress")

    async def retrieve(self, batch_id):
        self.retrieved += 1
        status = "ended" if self.retrieved >= self.polls else "in_progress"
        return SimpleNamespace(id=batch_id, processing_status=status)

    async def results(self, batch_id):
        assert batch_id == "msgbatch_x"

        async def gen():
            for r in self.results_:
                yield r

        return gen()


async def test_anthropic_batch_runner_polls_to_ended_and_keeps_only_succeeded_messages():
    ok = SimpleNamespace(
        custom_id="a", result=SimpleNamespace(type="succeeded", message=message("violated"))
    )
    bad = SimpleNamespace(custom_id="b", result=SimpleNamespace(type="errored", message=None))
    client = FakeAnthropic([ok, bad], polls=3)
    batch_id, out = await AnthropicBatchRunner(client, poll_s=0).run(
        [judge_batch.batch_request(SPEC, "a", "x"), judge_batch.batch_request(SPEC, "b", "y")]
    )
    assert batch_id == "msgbatch_x" and client.retrieved == 3
    assert [r["custom_id"] for r in client.created] == ["a", "b"]
    assert set(out) == {"a"} and out["a"].stop_reason == "end_turn"
