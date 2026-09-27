"""The cloud RM path (16 §L6) through httpx MockTransport: the Baseten request carries the task and
the E1 hunks and nothing else, a reply is exactly the pinned model's score or nothing, consent is
m1_073's rm: row naming Baseten at E1 plus the device's cloud_rm choice, the key never reaches a
log, and a scored task re-enters the ledger once as RmScore."""

import contextlib
import dataclasses
import json
import logging
import math
from datetime import UTC, date, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
import zstandard
from app import ledger
from app.judges.cloud_path import Consent
from app.rm import cloud, render
from app.rm.cloud import (
    MODEL_ID,
    CloudRm,
    RmCloudSettings,
    RmInput,
    admit,
    parse,
    prompt,
    rm_cloud_skipped_total,
)
from m1p.v1 import Batch, RmScore
from pydantic import SecretStr
from tests.test_jobs import VOTE_ROW
from tests.test_rm import KEY

URL = "https://model-rm.api.baseten.co/environments/production/predict"
SETTINGS = RmCloudSettings(endpoint_url=URL, api_key=KEY, deadline_s=0.5)
CONSENT = Consent(subprocessor="baseten", region="us", max_tier="E1")
INPUT = RmInput(task="Fix the off-by-one in paginate()", hunks="@@ -1 +1 @@\n-a\n+b\n")
XH = "ab" * 32
GOOD = {
    "model_id": MODEL_ID,
    "logit": 1.7,
    "calibration_version": "rm-a-cal@1",
    "execution_hash": XH,
    "n_tokens": 120,
}
SCORE = 1 / (1 + math.exp(-1.7))
BODY = {"model_id": MODEL_ID, "prefix": render.render(INPUT.task, INPUT.hunks).prefix}
TENANT = str(uuid4())
DEVICE, OTHER_DEVICE = uuid4(), uuid4()
WINDOW = datetime(2026, 9, 25, tzinfo=UTC)


def baseten(reply=GOOD, status=200):
    calls = []

    async def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if callable(reply):
            return await reply(req)
        return httpx.Response(status, json=reply)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), calls


def test_the_rm_reads_only_the_task_and_the_diff():
    """16 §Independence: the input type has two fields; there is nowhere to put anchor output,
    evidence records, the trajectory or a judge's words."""
    assert [f.name for f in dataclasses.fields(RmInput)] == ["task", "hunks"]
    r = prompt(INPUT)
    assert r == render.render(INPUT.task, INPUT.hunks) and r.abstain is None
    assert r.prefix.startswith("<|task|>\nFix the off-by-one in paginate()\n<|meta|> lang=")
    assert r.text.endswith(render.SUFFIX)


async def test_request_is_pinned_and_the_score_comes_back_as_rmscore():
    client, calls = baseten()
    got = await CloudRm(SETTINGS, client).score(INPUT)
    assert (got.model_id, got.calibration_version) == (MODEL_ID, "rm-a-cal@1")
    assert abs(got.score - SCORE) < 1e-12 and got.execution_hash == bytes.fromhex(XH)
    (req,) = calls
    assert str(req.url) == URL and req.headers["authorization"] == f"Api-Key {KEY}"
    assert json.loads(req.content) == BODY
    if "locus" in RmScore.__dataclass_fields__:
        assert got.locus.name == "CLOUD"


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ({**GOOD, "model_id": "rm:other@1"}, "rm_cloud_off_model"),
        ({**GOOD, "logit": float("nan")}, "rm_cloud_malformed"),
        ({**GOOD, "logit": float("inf")}, "rm_cloud_malformed"),
        ({**GOOD, "logit": True}, "rm_cloud_malformed"),
        ({**GOOD, "logit": "1.7"}, "rm_cloud_malformed"),
        ({**GOOD, "calibration_version": ""}, "rm_cloud_malformed"),
        ({**GOOD, "execution_hash": "AB" * 32}, "rm_cloud_malformed"),
        ({**GOOD, "execution_hash": "ab" * 31}, "rm_cloud_malformed"),
        ({**GOOD, "n_tokens": 4097}, "rm_cloud_malformed"),
        ({**GOOD, "n_tokens": 0}, "rm_cloud_malformed"),
        ({**GOOD, "score": 0.9}, "rm_cloud_malformed"),
        ({**GOOD, "rationale": "trust me"}, "rm_cloud_malformed"),
        ({"logit": 1.7}, "rm_cloud_malformed"),
        ([1.7], "rm_cloud_malformed"),
    ],
)
def test_a_reply_is_the_pinned_models_score_or_nothing(body, reason):
    before = rm_cloud_skipped_total[reason]
    assert parse(body, MODEL_ID) is None
    assert rm_cloud_skipped_total[reason] == before + 1


def test_sigma_never_overflows():
    for logit, want in ((1e6, 1.0), (-1e6, 0.0), (0, 0.5)):
        assert parse({**GOOD, "logit": logit}, MODEL_ID).score == want


async def test_an_input_the_renderer_abstains_on_never_leaves():
    client, calls = baseten()
    lock = RmInput(
        task="Bump deps.", hunks="--- a/yarn.lock\n+++ b/yarn.lock\n@@ -1 +1 @@\n-a\n+b\n"
    )
    before = rm_cloud_skipped_total["rm_cloud_abstain"]
    assert await CloudRm(SETTINGS, client).score(lock) is None
    assert calls == [] and rm_cloud_skipped_total["rm_cloud_abstain"] == before + 1


async def _slow(req):
    raise httpx.ReadTimeout("slow", request=req)


@pytest.mark.parametrize(
    ("reply", "status", "reason"),
    [(_slow, 200, "rm_cloud_timeout"), (GOOD, 503, "rm_cloud_unavailable")],
)
async def test_timeout_or_outage_is_no_score_and_counted(reply, status, reason, caplog):
    caplog.set_level(logging.DEBUG)
    before = rm_cloud_skipped_total[reason]
    client, _ = baseten(reply, status)
    assert await CloudRm(SETTINGS, client).score(INPUT) is None
    assert rm_cloud_skipped_total[reason] == before + 1
    assert KEY not in caplog.text and "SECRET" not in repr(SETTINGS)


@pytest.mark.parametrize(
    ("consent", "reason"),
    [
        (None, "refused_no_cloud_consent"),
        (
            dataclasses.replace(CONSENT, subprocessor="nebius"),
            "refused_subprocessor_not_listed:baseten",
        ),
        (dataclasses.replace(CONSENT, region="eu"), "refused_region_mismatch:us"),
        (dataclasses.replace(CONSENT, max_tier="E0"), "refused_tier_not_e1"),
        (CONSENT, None),
    ],
)
def test_admission_is_m1_073s_rm_row_naming_baseten_at_e1(consent, reason):
    assert admit(SETTINGS, consent) == reason


class FakePool:
    """The job's two PG reads: the rm: consent row and the devices' latest consent records."""

    def __init__(
        self, consent=CONSENT, devices=((DEVICE, True, True), (OTHER_DEVICE, True, False))
    ):
        self.consent, self.devices = consent, devices
        self.spend = 0  # m1_101 units reserved today under MODEL_ID

    @contextlib.asynccontextmanager
    async def acquire(self):
        pool = self

        class Conn:
            def transaction(self):
                return contextlib.nullcontext()

            async def execute(self, sql, *args):
                if "UPDATE m1_llm_spend_days" in sql:
                    assert args[2] == MODEL_ID
                    pool.spend += args[3]
                    return
                assert sql.startswith("SELECT set_config"), sql

            async def fetchrow(self, sql, *args):
                if "INSERT INTO m1_llm_spend_days" in sql:
                    return {"day": date(2026, 9, 26), "units": pool.spend}
                assert "m1_cloud_judge_consents" in sql and args[1] == MODEL_ID
                return None if pool.consent is None else dataclasses.asdict(pool.consent)

            async def fetch(self, sql, *args):
                assert "FROM m1_device_consents" in sql and "DISTINCT ON (device_id)" in sql
                return [{"device_id": d, "e1": e1, "cloud_rm": c} for d, e1, c in pool.devices]

        yield Conn()


def vote(task, device, family="AnchorVote", verifier="ruff@cat-1"):
    return {
        **VOTE_ROW,
        "task_id": str(task),
        "session_id": str(task),
        "device_id": str(device),
        "family": family,
        "verifier_id": verifier,
    }


class Cloud:
    def __init__(self, rows):
        self.rows, self.baseten, self.ingested, self.choke = rows, [], [], []

    async def handler(self, req: httpx.Request) -> httpx.Response:
        if req.url.host == "model-rm.api.baseten.co":
            self.baseten.append(json.loads(req.content))
            return httpx.Response(200, json=GOOD)
        if req.url.path == ledger.INGEST_PATH:
            self.ingested.append(Batch().parse(zstandard.decompress(req.content)))
            return httpx.Response(200, json={"accepted": 1})
        body = json.loads(req.content)
        self.choke.append((body["template"], body["params"]))
        return httpx.Response(200, json={"rows": self.rows, "template_version": "x.v3"})

    def client(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def ctx(pool):
    return SimpleNamespace(
        pool=pool,
        settings=SimpleNamespace(
            querychoke_base_url="http://choke",
            querychoke_token=SecretStr("svc"),
            http_timeout_s=1,
            evidence_token=SecretStr("evd"),
        ),
        tenant_id=TENANT,
        window_start=WINDOW,
        day=date(2026, 9, 25),
    )


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ADJ_RM_ENDPOINT_URL", URL)
    monkeypatch.setenv("ADJ_RM_API_KEY", KEY)


async def test_run_scores_each_consented_unscored_task_once_and_posts_rmscore(env, caplog):
    caplog.set_level(logging.DEBUG)
    fresh, scored, other = uuid4(), uuid4(), uuid4()
    rows = [
        vote(fresh, DEVICE),
        vote(scored, DEVICE),
        vote(scored, DEVICE, "RmScore", MODEL_ID),
        vote(other, OTHER_DEVICE),  # that device chose Local: nothing of it leaves
    ]
    seen = []

    async def input_for(task_id):
        seen.append(task_id)
        return INPUT

    c = Cloud(rows)
    await cloud.run(ctx(FakePool()), http=c.client(), input_for=input_for)
    assert seen == [fresh] and c.baseten == [BODY]
    assert c.choke == [("adjudication_votes", {"from": "2026-09-24", "to": "2026-09-25"})]
    ((event,),) = [b.events for b in c.ingested]
    assert UUID(bytes=event.task_id) == fresh and event.rm_score.model_id == MODEL_ID
    assert abs(event.rm_score.score - SCORE) < 1e-12
    assert event.rm_score.calibration_version == "rm-a-cal@1"
    assert event.rm_score.execution_hash == bytes.fromhex(XH)
    assert (
        event.event_id
        == ledger.rm_score_wire(
            event.rm_score,
            tenant_id=UUID(TENANT),
            task_id=fresh,
            session_id=fresh,
            window_start=WINDOW,
        ).event_id
    )
    assert KEY not in caplog.text


@pytest.mark.parametrize(
    ("pool", "reason"),
    [
        (FakePool(consent=None), None),
        (FakePool(consent=dataclasses.replace(CONSENT, max_tier="E0")), "refused_tier_not_e1"),
    ],
)
async def test_nothing_leaves_without_consent(env, pool, reason):
    before = dict(rm_cloud_skipped_total)

    async def input_for(task_id):
        return INPUT

    c = Cloud([vote(uuid4(), DEVICE)])
    await cloud.run(ctx(pool), http=c.client(), input_for=input_for)
    assert c.baseten == [] and c.ingested == [] and c.choke == []
    if reason:
        assert rm_cloud_skipped_total[reason] == before.get(reason, 0) + 1


async def test_default_input_is_controlds_e1_read_and_absent_e1_sends_nothing(env):
    """Without a seam the job reads GET /internal/v1/evidence/{task}: intent + hunks become the
    RM's input; a task controld holds no E1 part for (404) is a counted skip, never a call."""
    with_e1, without = uuid4(), uuid4()
    c = Cloud([vote(with_e1, DEVICE), vote(without, DEVICE)])
    handler = c.handler

    async def routed(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/internal/v1/evidence/"):
            assert req.headers["authorization"] == "Bearer evd", "the E1 read's own credential"
            assert req.url.params["purpose"] == "rm"
            task = req.url.path.rsplit("/", 1)[-1]
            if task != str(with_e1):
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "tier": "E1",
                    "task_id": task,
                    "intent": INPUT.task,
                    "hunks": INPUT.hunks,
                    "receipt_id": "r",
                },
            )
        return await handler(req)

    before = rm_cloud_skipped_total["rm_cloud_no_e1_hunks"]
    http = httpx.AsyncClient(transport=httpx.MockTransport(routed))
    await cloud.run(ctx(FakePool()), http=http)
    assert c.baseten == [BODY]
    assert rm_cloud_skipped_total["rm_cloud_no_e1_hunks"] == before + 1


async def test_the_cloud_rm_daily_ledger_bounds_reruns_on_the_same_day(env, monkeypatch):
    """ADJ_RM_MAX_TASKS_PER_DAY is per tenant per UTC day (m1_101): a second run the same day
    scores only what the first left of the allowance, however many tasks are unscored."""
    monkeypatch.setenv("ADJ_RM_MAX_TASKS_PER_DAY", "3")
    pool = FakePool()

    async def input_for(task_id):
        return INPUT

    first = Cloud([vote(uuid4(), DEVICE) for _ in range(2)])
    await cloud.run(ctx(pool), http=first.client(), input_for=input_for)
    before = rm_cloud_skipped_total["rm_cloud_daily_cap"]
    second = Cloud([vote(uuid4(), DEVICE) for _ in range(4)])
    await cloud.run(ctx(pool), http=second.client(), input_for=input_for)
    assert (len(first.baseten), len(second.baseten), pool.spend) == (2, 1, 3)
    assert rm_cloud_skipped_total["rm_cloud_daily_cap"] == before + 3


async def test_without_the_evidence_token_the_rm_reads_nothing_and_sends_nothing(env):
    c = Cloud([vote(uuid4(), DEVICE)])
    before = rm_cloud_skipped_total["rm_cloud_no_evidence_token"]
    no_token = ctx(FakePool())
    no_token.settings.evidence_token = SecretStr("")
    await cloud.run(no_token, http=c.client())
    assert c.baseten == [] and c.ingested == [] and c.choke == []
    assert rm_cloud_skipped_total["rm_cloud_no_evidence_token"] == before + 1


async def test_one_tasks_controld_5xx_skips_that_task_not_the_night(env):
    bad, good = uuid4(), uuid4()
    calls = []

    async def input_for(task_id):
        calls.append(task_id)
        if task_id == bad:
            req = httpx.Request("GET", "http://choke/e")
            raise httpx.HTTPStatusError(
                "502", request=req, response=httpx.Response(502, request=req)
            )
        return INPUT

    c = Cloud([vote(bad, DEVICE), vote(good, DEVICE)])
    before = rm_cloud_skipped_total["rm_cloud_controld_unavailable"]
    await cloud.run(ctx(FakePool()), http=c.client(), input_for=input_for)
    assert calls.count(bad) == 2 and calls.count(good) == 1 and len(c.baseten) == 1
    assert rm_cloud_skipped_total["rm_cloud_controld_unavailable"] == before + 1
    ((event,),) = [b.events for b in c.ingested]
    assert UUID(bytes=event.task_id) == good


async def test_every_task_failing_means_controld_is_down_and_fails_the_run(env):
    async def input_for(task_id):
        raise httpx.ConnectError("refused")

    c = Cloud([vote(uuid4(), DEVICE)])
    with pytest.raises(httpx.ConnectError):
        await cloud.run(ctx(FakePool()), http=c.client(), input_for=input_for)
    assert c.baseten == [] and c.ingested == []
