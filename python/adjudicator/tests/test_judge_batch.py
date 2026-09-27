"""judge_batch (06 §1.2, §6; 16 §L1) through fake choke rows, a fake controld and a fake
llm-router on one MockTransport: the D18 selection restricted to tasks lacking the judge's vote,
the edge judge dispatched client-side with zero router calls, the cloud judge only under an
admitting m1_065 consent row, one pinned-model router call per task under the daily cap and
never with a tenant on it, votes re-entering the ledger as JudgeVote events with a
deterministic event_id, the spent row re-posted and never re-called, and every failure a
counted skip."""

import contextlib
import hashlib
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
from app.judges.evidence import EVIDENCE_PATH
from app.judges.specs import JUDGE_REQUESTS_PATH, JUDGE_SPECS, request_id_for
from app.llm import COMPLETIONS_PATH, MARK1_ROUTER_AGENT_ID
from m1p.v1 import Batch, EvidenceTier, JudgeLocus, JudgeTrigger, Verdict
from pydantic import SecretStr
from tests.test_certified import ANCHOR
from tests.test_jobs import VOTE_ROW, FakeChoke
from tests.test_readjudicate import AMBIGUOUS, CONFIDENT, MIDBAND, NO_TEST, REGISTRY_ROWS, row, rows

JID = "judge:grounded-rubric@2"  # the cloud judge
EDGE = "judge:grounded-rubric@1"
SPEC = JUDGE_SPECS[JID]
TENANT = str(uuid4())
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)
CONSENT = {"subprocessor": "nebius", "region": "global", "max_tier": "E1"}
JUDGED = uuid4()  # ambiguous, but this judge already voted on it
DEVICE = UUID(VOTE_ROW["device_id"])  # every fixture row's device
ON = [(DEVICE, True, True)]  # (device, e1, cloud_judge): the member left both on


def all_rows() -> list[dict]:
    return [
        *rows(),
        row(JUDGED, ANCHOR, "AnchorVote", "satisfied"),
        row(JUDGED, JID, "JudgeVote", "violated", seq=2),
    ]


def reply(text="violated", finish="stop", model=None, inp=1200, out=3, cached=1100) -> dict:
    """One OpenAI-shaped router answer, as Nebius Token Factory relays it."""
    return {
        "model": model or SPEC.model,
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": finish}],
        "usage": {
            "prompt_tokens": inp,
            "completion_tokens": out,
            "prompt_tokens_details": {"cached_tokens": cached},
        },
    }


class FakePool:
    """The job's PG reads by table; consent per judge_id, spent judge_dispatches rows, and
    the upserts captured. PG twin in tests/test_judge_batch_pg.py."""

    def __init__(self, *, consent: dict | None = None, spent: list[dict] = (), devices=ON):
        self.consent, self.spent, self.upserts = consent, list(spent), []
        self.devices = devices  # m1_082's rows, oldest first; the latest per device wins
        self.spend: dict[str, int] = {}  # m1_101: spend_key → units reserved today

    async def fetch(self, sql, *args):
        if "FROM m1_verifiers" in sql:
            return REGISTRY_ROWS
        if "m1_verifier_promotions" in sql:
            return []
        if "FROM judge_dispatches" in sql:
            return self.spent
        if "FROM m1_device_consents" in sql:
            assert "DISTINCT ON (device_id)" in sql and "row_seq DESC" in sql
            latest = {d: (e1, cj) for d, e1, cj in self.devices}
            return [{"device_id": d, "e1": e1, "cloud_judge": cj} for d, (e1, cj) in latest.items()]
        raise AssertionError(sql)

    @contextlib.asynccontextmanager
    async def acquire(self):
        pool = self

        class Conn:
            def transaction(self):
                return contextlib.nullcontext()

            async def execute(self, sql, *args):
                if "UPDATE m1_llm_spend_days" in sql:
                    pool.spend[args[2]] += args[3]
                    return
                assert sql.startswith("SELECT set_config") or "INSERT INTO judge_dispatches" in sql
                if "judge_dispatches" in sql:
                    pool.upserts.append(args)

            async def fetch(self, sql, *args):
                return await pool.fetch(sql, *args)

            async def fetchrow(self, sql, *args):
                if "INSERT INTO m1_llm_spend_days" in sql:
                    assert args[0] == UUID(TENANT)
                    return {"day": date(2026, 9, 16), "units": pool.spend.setdefault(args[1], 0)}
                if "FROM noise_certificates" in sql:
                    return None
                if "FROM spectral_runs" in sql:
                    return None
                if "m1_cloud_judge_consents" in sql:
                    assert args[1] == JID, "only the cloud judge reads consent"
                    return pool.consent
                raise AssertionError(sql)

        yield Conn()


class FakeCloud:
    """One MockTransport for the choke, controld's judge fan-out route, the service ingest and
    the llm-router. `router` answers each completion body; every router call is checked for the
    one identity Mark 1 may present."""

    def __init__(self, choke_rows, *, dispatch=200, ingest=200, router=None, evidence=None):
        self.choke = FakeChoke(choke_rows)
        self.evidence: dict[str, dict] = evidence or {}  # task → controld's E1 body, else 404
        self.dispatched: list[dict] = []
        self.ingested: list[httpx.Request] = []
        self.completions: list[dict] = []
        self.dispatch, self.ingest = dispatch, ingest
        self.router = router or (lambda body: httpx.Response(200, json=reply()))

    async def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.host == "router":
            assert req.url.path == COMPLETIONS_PATH
            assert not [h for h in req.headers if "tenant" in h.lower()], req.headers
            assert req.headers["x-omium-agent-id"] == MARK1_ROUTER_AGENT_ID
            assert UUID(req.headers["x-omium-execution-id"])
            body = json.loads(req.content)
            assert "tenant" not in req.content.decode().lower()
            self.completions.append(body)
            return self.router(body)
        if req.url.path == JUDGE_REQUESTS_PATH:
            assert req.headers["authorization"] == "Bearer svc"
            self.dispatched.append(json.loads(req.content))
            status = self.dispatch if isinstance(self.dispatch, int) else next(self.dispatch, 200)
            return httpx.Response(status, json={"error": {"code": "M1E-2001"}})
        if req.url.path.startswith(EVIDENCE_PATH):
            assert req.headers["authorization"] == "Bearer evd" and req.headers["m1p-tenant-id"]
            assert req.url.params["purpose"] == "judge"
            body = self.evidence.get(req.url.path.removeprefix(EVIDENCE_PATH))
            return httpx.Response(200, json=body) if body else httpx.Response(404, json={})
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

    def edge_ids(self) -> set[str]:
        return {d["request"]["judgeId"] for d in self.dispatched}


def settings(**over) -> SimpleNamespace:
    return SimpleNamespace(
        **{
            "querychoke_base_url": "http://choke",
            "querychoke_token": SecretStr("svc"),
            "evidence_token": SecretStr("evd"),
            "http_timeout_s": 1,
            "llm_router_url": "http://router",
            "judge_max_tasks_per_day": 60,
            "judge_max_tasks_per_run": 60,
            **over,
        }
    )


def _ctx(pool, **over) -> SimpleNamespace:
    return SimpleNamespace(
        pool=pool,
        settings=settings(**over),
        tenant_id=TENANT,
        window_start=WINDOW,
        day=date(2026, 9, 15),
    )


@pytest.fixture(autouse=True)
def _clear():
    judge_batch_skipped_total.clear()


async def _run(pool, cloud, jid=JID, settings_over=None, **kw) -> dict[UUID, dict]:
    await judge_batch.run(_ctx(pool, **(settings_over or {})), http=cloud.client(), **kw)
    cols = (
        "tenant_id task_id judge_id request_id window_start locus vote model batch_id "
        + " ".join(USAGE_COLUMNS)
        + " evidence_tier"
    ).split()
    out = {}
    for args in pool.upserts:
        rec = dict(zip(cols, args, strict=True))
        assert rec["tenant_id"] == UUID(TENANT)
        if rec["judge_id"] == jid:
            out[rec["task_id"]] = rec
    return out


def rid(task: UUID, jid: str = JID) -> str:
    return request_id_for(jid, task, NO_ATTEMPT)


CANDIDATES = {AMBIGUOUS, NO_TEST, MIDBAND}  # the edge judge: ambiguous under D18
CLOUD_TASKS = {*CANDIDATES, CONFIDENT}  # the cloud judge: every task lacking its vote


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


async def test_edge_judge_posts_one_request_per_candidate_and_no_router_call():
    pool, cloud = FakePool(), FakeCloud(all_rows())
    recs = await _run(pool, cloud, jid=EDGE)
    assert cloud.completions == [] and cloud.ingested == []
    # JUDGED carries the cloud judge's vote, not the edge judge's: a candidate here
    assert {d["request"]["requestId"] for d in cloud.dispatched} == {
        rid(t, EDGE) for t in (*CANDIDATES, JUDGED)
    }
    edge = JUDGE_SPECS[EDGE]
    for d in cloud.dispatched:
        assert d["tenant_id"] == TENANT
        r = d["request"]
        assert (r["judgeId"], r["model"], r["tier"]) == (EDGE, edge.model, EvidenceTier.E0.value)
        assert r["locus"] == JudgeLocus.CLIENT_SIDE.value and "evidence" not in r
    assert set(recs) == {*CANDIDATES, JUDGED}
    rec = recs[AMBIGUOUS]
    assert (rec["locus"], rec["vote"], rec["model"], rec["window_start"]) == (
        "client_side",
        None,
        None,
        WINDOW,
    )
    assert rec["request_id"] == UUID(rid(AMBIGUOUS, EDGE))
    assert all(rec[c] is None for c in USAGE_COLUMNS)
    assert {a[2] for a in pool.upserts} == {EDGE}, "no consent: the cloud judge writes nothing"


async def test_client_side_dispatch_failure_fails_the_run_before_any_row():
    pool, cloud = FakePool(), FakeCloud(all_rows(), dispatch=503)
    with pytest.raises(judge_batch.JudgeRefused, match="refused_dispatch_failed:503"):
        await _run(pool, cloud)
    assert pool.upserts == [] and cloud.completions == []


async def test_one_tasks_controld_5xx_is_retried_then_skipped_not_the_whole_night():
    # first task: 503 then 200 (retried); second: 502 twice (skipped); third: 200
    pool, cloud = FakePool(), FakeCloud(all_rows(), dispatch=iter([503, 200, 502, 502]))
    recs = await _run(pool, cloud, jid=EDGE)
    assert len(recs) == len({*CANDIDATES, JUDGED}) - 1
    assert len(cloud.dispatched) == len(recs) + 3  # one retry that landed, two that did not
    assert judge_batch_skipped_total["controld_unavailable"] == 1


async def test_cloud_e1_read_5xx_on_one_task_is_a_counted_skip():
    async def hunks(task_id, attempt_id, tier):
        if task_id == MIDBAND:
            req = httpx.Request("GET", "http://choke/e")
            raise httpx.HTTPStatusError(
                "503", request=req, response=httpx.Response(503, request=req)
            )
        raise judge_batch.JudgeRefused("refused_no_receipted_excerpts", str(task_id))

    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud, evidence_for=hunks)
    assert set(recs) == CLOUD_TASKS - {MIDBAND} and len(cloud.completions) == 3
    assert judge_batch_skipped_total["cloud_controld_unavailable"] == 1


async def test_cloud_judge_without_e1_hunks_calls_the_router_on_e0_and_votes_e0():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud)
    assert cloud.edge_ids() == {EDGE}, "the edge judge still runs beside the cloud one"
    assert len(cloud.completions) == 4
    by_user = {b["messages"][1]["content"]: b for b in cloud.completions}
    ambiguous = e0_evidence(r for r in all_rows() if r["task_id"] == str(AMBIGUOUS))
    assert by_user[ambiguous] == {
        "model": "zai-org/GLM-5.2",
        "max_tokens": SPEC.token_budget,
        "messages": [
            {"role": "system", "content": SPEC.e0_rubric},
            {"role": "user", "content": ambiguous},
        ],
    }
    events = cloud.events()
    assert {UUID(bytes=e.task_id) for e in events} == CLOUD_TASKS
    for e in events:
        assert e.session_epoch == ledger.SERVICE_EPOCH
        assert e.occurred_at == ledger.window_close(WINDOW)
        assert (e.judge_vote.judge_id, e.judge_vote.vote) == (JID, Verdict.VIOLATED)
        assert (e.judge_vote.tier_used, e.judge_vote.locus) == (EvidenceTier.E0, JudgeLocus.CLOUD)
        assert e.judge_vote.rubric_hash == hashlib.sha256(SPEC.e0_rubric.encode()).digest()
    rec = recs[AMBIGUOUS]
    assert (rec["locus"], rec["vote"], rec["model"], rec["batch_id"], rec["evidence_tier"]) == (
        "cloud",
        "violated",
        "zai-org/GLM-5.2",
        None,
        "E0",
    )
    assert rec["request_id"] == UUID(rid(AMBIGUOUS))
    assert [rec[c] for c in USAGE_COLUMNS] == [1200, 3, 0, 1100]


async def test_unconsented_tenant_makes_zero_router_calls():
    pool, cloud = FakePool(), FakeCloud(all_rows())
    await _run(pool, cloud)
    assert cloud.completions == [] and judge_batch_skipped_total == {}


@pytest.mark.parametrize(
    ("consent", "reason"),
    [
        ({**CONSENT, "region": "us"}, "cloud_refused_region_mismatch"),
        ({**CONSENT, "subprocessor": "anthropic"}, "cloud_refused_subprocessor_not_listed"),
    ],
)
async def test_consent_that_does_not_admit_the_judge_is_a_counted_skip(consent, reason):
    pool, cloud = FakePool(consent=consent), FakeCloud(all_rows())
    recs = await _run(pool, cloud)
    assert cloud.completions == [] and recs == {} and cloud.ingested == []
    assert cloud.edge_ids() == {EDGE}, "a refused cloud consent never reroutes to the edge"
    assert judge_batch_skipped_total[reason] == 1


async def test_an_e0_consent_admits_only_the_e0_fallback_and_never_reads_hunks():
    async def hunks(task_id, attempt_id, tier):
        raise AssertionError("E1 read under an E0 consent")

    pool, cloud = FakePool(consent={**CONSENT, "max_tier": "E0"}), FakeCloud(all_rows())
    recs = await _run(pool, cloud, evidence_for=hunks)
    assert len(cloud.completions) == 4 and {r["evidence_tier"] for r in recs.values()} == {"E0"}
    assert all(b["messages"][0]["content"] == SPEC.e0_rubric for b in cloud.completions)


async def test_an_e1_only_judge_above_an_e0_consent_never_reaches_the_router(monkeypatch):
    monkeypatch.setitem(JUDGE_SPECS, JID, replace(SPEC, e0_rubric=None))
    pool, cloud = FakePool(consent={**CONSENT, "max_tier": "E0"}), FakeCloud(all_rows())
    await _run(pool, cloud)
    assert judge_batch_skipped_total["cloud_refused_tier_above_consent"] == 1
    assert cloud.completions == []


async def test_e2_has_no_branch_at_either_locus(monkeypatch):
    e2 = replace(SPEC, judge_id="judge:full-diff@1", evidence_tier="E2")
    monkeypatch.setitem(JUDGE_SPECS, e2.judge_id, e2)
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud)
    assert cloud.edge_ids() == {EDGE} and set(recs) == CLOUD_TASKS
    assert {a[2] for a in pool.upserts} == {JID, EDGE}
    assert len(cloud.completions) == 4


async def test_no_router_url_is_a_counted_skip_never_a_crash_or_an_edge_fallback():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud, settings_over={"llm_router_url": ""})
    assert recs == {} and cloud.completions == [] and cloud.ingested == []
    assert judge_batch_skipped_total["cloud_no_router"] == 1


async def test_a_reply_from_any_model_but_the_pinned_one_is_refused_never_a_vote():
    cloud = FakeCloud(
        all_rows(), router=lambda body: httpx.Response(200, json=reply(model="zai-org/GLM-4.6"))
    )
    pool = FakePool(consent=CONSENT)
    recs = await _run(pool, cloud)
    assert recs == {} and cloud.ingested == []
    assert judge_batch_skipped_total["refused_model_mismatch"] == 4


async def test_a_policy_block_is_counted_and_never_retried():
    blocked = {"error": "Request blocked by Omium Policy Engine", "violations": ["Shell Injection"]}
    cloud = FakeCloud(
        all_rows(),
        router=lambda body: httpx.Response(
            403, json=blocked, headers={"X-Omium-Policy-Blocked": "true"}
        ),
    )
    pool = FakePool(consent=CONSENT)
    recs = await _run(pool, cloud)
    assert recs == {} and len(cloud.completions) == 4, "one call per task, no retry"
    assert judge_batch_skipped_total["refused_policy_blocked"] == 4


async def test_the_daily_cap_bounds_router_calls_and_counts_the_rest():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud, settings_over={"judge_max_tasks_per_day": 2})
    assert len(cloud.completions) == 2 and len(recs) == 2
    assert judge_batch_skipped_total["cloud_daily_cap"] == 2
    assert pool.spend == {JID: 2}


async def test_reruns_on_one_day_share_the_ledger_and_never_multiply_spend():
    """A rerun (a failed job retried, a backfilled window) draws on the same UTC-day row: the
    router refused every call, so nothing was recorded, yet the second run calls nothing."""
    blocked = lambda body: httpx.Response(400, json={})  # noqa: E731
    pool = FakePool(consent=CONSENT)
    over = {"judge_max_tasks_per_day": 3}
    await _run(pool, FakeCloud(all_rows(), router=blocked), settings_over=over)
    again = FakeCloud(all_rows())
    assert await _run(pool, again, settings_over=over) == {}
    assert again.completions == [] and pool.spend == {JID: 3}
    assert judge_batch_skipped_total["cloud_daily_cap"] == 1 + 4


async def test_the_per_run_cap_still_bounds_one_run_under_a_larger_day():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    await _run(pool, cloud, settings_over={"judge_max_tasks_per_run": 1})
    assert len(cloud.completions) == 1 and pool.spend == {JID: 1}
    assert judge_batch_skipped_total["cloud_run_cap"] == 3


async def test_spent_row_is_reposted_under_its_own_window_and_never_recalled():
    spent = {
        "task_id": AMBIGUOUS,
        "judge_id": JID,
        "request_id": UUID(rid(AMBIGUOUS)),
        "window_start": WINDOW.replace(day=14),
        "vote": "satisfied",
        "model": SPEC.model,
        "batch_id": None,
        "input_tokens": 7,
        "output_tokens": 1,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 6,
        "evidence_tier": "E1",
    }
    pool, cloud = FakePool(consent=CONSENT, spent=[spent]), FakeCloud(all_rows())
    recs = await _run(pool, cloud)
    assert len(cloud.completions) == 3 and set(recs) == {NO_TEST, MIDBAND, CONFIDENT}
    by_task = {UUID(bytes=e.task_id): e for e in cloud.events()}
    assert set(by_task) == CLOUD_TASKS
    assert by_task[AMBIGUOUS].judge_vote.vote == Verdict.SATISFIED
    assert by_task[AMBIGUOUS].judge_vote.tier_used == EvidenceTier.E1, "re-posted as cast"
    assert by_task[NO_TEST].judge_vote.vote == Verdict.VIOLATED
    original = ledger.judge_vote_wire(
        by_task[AMBIGUOUS].judge_vote,
        tenant_id=UUID(TENANT),
        task_id=AMBIGUOUS,
        session_id=UUID(bytes=by_task[AMBIGUOUS].session_id),
        window_start=WINDOW.replace(day=14),
    )
    assert bytes(by_task[AMBIGUOUS].event_id) == bytes(original.event_id)


async def test_a_model_refusal_is_the_judges_refusal_and_a_reasoning_trace_is_not_the_answer():
    answers = iter(
        [
            reply("", finish="content_filter"),
            reply("<think>anchors disagree | hmm</think>Satisfied."),
            reply("looks fine to me"),
            reply("violated"),
        ]
    )
    cloud = FakeCloud(all_rows(), router=lambda body: httpx.Response(200, json=next(answers)))
    pool = FakePool(consent=CONSENT)
    recs = await _run(pool, cloud)
    assert sorted(r["vote"] for r in recs.values()) == ["error", "refused", "satisfied", "violated"]


async def test_task_without_session_id_is_counted_at_both_loci():
    orphan = uuid4()
    extra = [row(orphan, "ruff@cat-1", "AnchorVote", "violated", session=None)]
    pool, cloud = FakePool(consent=CONSENT), FakeCloud([*all_rows(), *extra])
    recs = await _run(pool, cloud)
    assert orphan not in recs and judge_batch_skipped_total["no_session_id"] == 2
    assert len(cloud.completions) == 4


async def test_ledger_post_failure_fails_the_run_after_the_spent_rows_are_durable():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows(), ingest=503)
    with pytest.raises(QuerychokeError):
        await _run(pool, cloud)
    assert len([a for a in pool.upserts if a[2] == JID]) == 4 and len(cloud.completions) == 4


async def test_the_diff_judge_reads_receipted_hunks_and_falls_back_per_task():
    async def hunks(task_id, attempt_id, tier):
        assert tier == "E1"
        if task_id == MIDBAND:
            raise judge_batch.JudgeRefused("refused_no_receipted_excerpts", str(task_id))
        return f"--- excerpt for {task_id}"

    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows())
    recs = await _run(pool, cloud, evidence_for=hunks)
    by_user = {b["messages"][1]["content"]: b["messages"][0]["content"] for b in cloud.completions}
    assert by_user[f"--- excerpt for {AMBIGUOUS}"] == SPEC.rubric
    assert by_user[e0_evidence(r for r in all_rows() if r["task_id"] == str(MIDBAND))] == (
        SPEC.e0_rubric
    )
    assert {t: r["evidence_tier"] for t, r in recs.items()} == {
        AMBIGUOUS: "E1",
        NO_TEST: "E1",
        CONFIDENT: "E1",
        MIDBAND: "E0",
    }
    tiers = {UUID(bytes=e.task_id): e.judge_vote.tier_used for e in cloud.events()}
    assert tiers == {t: EvidenceTier.E1 for t in CLOUD_TASKS - {MIDBAND}} | {
        MIDBAND: EvidenceTier.E0
    }
    assert {e.judge_vote.trigger for e in cloud.events()} == {JudgeTrigger.ALWAYS}
    assert judge_batch_skipped_total["e1_refused_no_receipted_excerpts"] == 1


def test_the_diff_rubric_never_reads_anchor_output():
    rubric = SPEC.rubric.lower()
    for word in ("anchor", "diagnostic", "lint", "test", "compile", "evidence record"):
        assert word not in rubric, word
    assert "diff hunks" in rubric and "task" in rubric


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


MEMBER = uuid4()  # a teammate's device; the owner's is DEVICE


def on_device(device: UUID, *tasks: UUID) -> list[dict]:
    """all_rows() with `tasks` recorded by `device` instead of the owner's."""
    moved = {str(t) for t in tasks}
    return [{**r, "device_id": str(device)} if r["task_id"] in moved else r for r in all_rows()]


async def never_read(task_id, attempt_id, tier):
    raise AssertionError(f"E1 read for {task_id} past a device that did not consent")


async def test_a_member_who_turned_cloud_judge_off_sends_nothing_at_any_tier():
    pool = FakePool(consent=CONSENT, devices=[*ON, (MEMBER, True, False)])
    cloud = FakeCloud(on_device(MEMBER, AMBIGUOUS, CONFIDENT))
    reads = []

    async def hunks(task_id, attempt_id, tier):
        reads.append(task_id)
        assert task_id not in (AMBIGUOUS, CONFIDENT), "the member's hunks were read"
        return f"--- excerpt for {task_id}"

    recs = await _run(pool, cloud, evidence_for=hunks)
    assert set(recs) == {NO_TEST, MIDBAND} and set(reads) == {NO_TEST, MIDBAND}
    sent = "".join(b["messages"][1]["content"] for b in cloud.completions)
    assert str(AMBIGUOUS) not in sent and str(CONFIDENT) not in sent
    assert len(cloud.completions) == 2
    assert {UUID(bytes=e.task_id) for e in cloud.events()} == {NO_TEST, MIDBAND}
    assert judge_batch_skipped_total["cloud_device_not_consented"] == 2
    assert cloud.edge_ids() == {EDGE}, "the member's own-key edge judge is not this switch"


async def test_the_member_off_also_withholds_the_e0_anchor_facts():
    pool = FakePool(consent={**CONSENT, "max_tier": "E0"}, devices=[(DEVICE, False, False)])
    cloud = FakeCloud(all_rows())
    assert await _run(pool, cloud, evidence_for=never_read) == {}
    assert cloud.completions == [] and cloud.ingested == []


async def test_owner_on_and_member_on_both_go_to_the_judge():
    pool = FakePool(consent=CONSENT, devices=[*ON, (MEMBER, True, True)])
    cloud = FakeCloud(on_device(MEMBER, AMBIGUOUS, CONFIDENT))

    async def hunks(task_id, attempt_id, tier):
        return f"--- excerpt for {task_id}"

    recs = await _run(pool, cloud, evidence_for=hunks)
    assert set(recs) == CLOUD_TASKS and {r["evidence_tier"] for r in recs.values()} == {"E1"}
    assert "cloud_device_not_consented" not in judge_batch_skipped_total


async def test_cloud_judge_on_with_e1_off_sends_the_e0_facts_and_never_the_hunks():
    pool = FakePool(consent=CONSENT, devices=[(DEVICE, False, True)])
    cloud = FakeCloud(all_rows())
    recs = await _run(pool, cloud, evidence_for=never_read)
    assert set(recs) == CLOUD_TASKS and {r["evidence_tier"] for r in recs.values()} == {"E0"}
    assert all(b["messages"][0]["content"] == SPEC.e0_rubric for b in cloud.completions)


@pytest.mark.parametrize(
    ("devices", "sent"),
    [
        ([], False),  # no device row: fail closed
        ([(DEVICE, True, True), (DEVICE, True, False)], False),  # the later withdrawal wins
        ([(DEVICE, True, False), (DEVICE, True, True)], True),  # the later re-grant wins
        ([(uuid4(), True, True)], False),  # another device's consent speaks only for it
    ],
)
async def test_only_the_devices_latest_row_admits_its_tasks(devices, sent):
    pool, cloud = FakePool(consent=CONSENT, devices=devices), FakeCloud(all_rows())
    recs = await _run(pool, cloud, evidence_for=never_read if not sent else None)
    assert bool(cloud.completions) is sent and bool(recs) is sent


async def test_a_task_goes_only_as_far_as_every_device_on_it_consents():
    rows = [
        *on_device(MEMBER, AMBIGUOUS),
        row(AMBIGUOUS, "ruff@cat-1", "AnchorVote", "satisfied", seq=3),  # the owner's device too
    ]
    service = [{**r, "device_id": "00000000-0000-0000-0000-000000000000"} for r in all_rows()]

    async def hunks(task_id, attempt_id, tier):
        assert task_id != AMBIGUOUS, "the member kept e1 off: the owner's switch cannot send it"
        return f"--- excerpt for {task_id}"

    for devices, choke, want in (
        ([*ON, (MEMBER, True, False)], rows, CLOUD_TASKS - {AMBIGUOUS}),
        ([*ON, (MEMBER, False, True)], rows, CLOUD_TASKS),
        (ON, service, set()),  # a service-ingested row speaks for no device
    ):
        judge_batch_skipped_total.clear()
        pool, cloud = FakePool(consent=CONSENT, devices=devices), FakeCloud(choke)
        recs = await _run(pool, cloud, evidence_for=hunks)
        assert set(recs) == want
        tiers = {t: r["evidence_tier"] for t, r in recs.items()}
        assert all(tier == ("E0" if t == AMBIGUOUS else "E1") for t, tier in tiers.items())


async def test_without_the_evidence_token_the_judge_never_reads_e1_and_votes_e0():
    pool, cloud = FakePool(consent=CONSENT), FakeCloud(all_rows(), evidence={str(AMBIGUOUS): {}})
    reads = []
    handler = cloud.handler

    async def spy(req):
        if req.url.path.startswith(EVIDENCE_PATH):
            reads.append(req)
        return await handler(req)

    cloud.handler = spy
    recs = await _run(pool, cloud, settings_over={"evidence_token": SecretStr("")})
    assert reads == [] and {r["evidence_tier"] for r in recs.values()} == {"E0"}
