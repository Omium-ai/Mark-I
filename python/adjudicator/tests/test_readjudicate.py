"""readjudicate (06 §1.2) through fake choke rows, a fake vLLM and a fake E2B: the D18 selection
rule pinned, the RM's zero fusion weight on the escalated verdict, T3 only under consent, the
consistency vote fusing only at escalation=True (FR-VERIFY-017), shadow pairs reaching
run_promotion through promotion.step (FR-LEARN-004), and every failure a counted skip."""

import contextlib
import json
import logging
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, Bundle
from app.certified.runner import CONSISTENCY_ID, execution_hash
from app.jobs import nightly, readjudicate
from app.jobs.readjudicate import (
    MARGIN,
    NO_ATTEMPT,
    bundle_for,
    is_candidate,
    measured_pairs,
    readjudicate_skipped_total,
    registry_by_wire_id,
    votes_by_task,
)
from app.registry.catalog import RegistryEntry
from app.registry.handlers import KIND_CONSISTENCY, KIND_TEST
from app.registry.promotion import Measurement, ShadowPair, youden
from pydantic import SecretStr
from tests.test_certified import ANCHOR, T3_ID, TEMPLATE, FakeE2B
from tests.test_jobs import VOTE_ROW, FakeChoke
from tests.test_rm import GOOD, KEY, RM_ID

TENANT = str(uuid4())
CERT = uuid4()
COSTS = Costs()
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)
E2B_KEY = "sk-e2b-readjudicate-secret"


def row(task: UUID, vid: str, family: str, vote: str, tamper: int = 0, seq: int = 1) -> dict:
    r = {
        **VOTE_ROW,
        "task_id": str(task),
        "vote_id": str(uuid4()),
        "seq": seq,
        "family": family,
        "verifier_id": vid,
        "is_anchor": int(family == "AnchorVote"),
        "vote": vote,
        "abstained": int(vote in ("refused", "error")),
        "tamper": tamper,
    }
    assert r.keys() == VOTE_ROW.keys()
    return r


# Provisional eta under the calibrated defaults: test-accept + judge-reject sits at 0.2726
# (inside the D18 margin of A/R), test-reject at 0.074 (a confident violated), lint-accept
# alone at 0.68 (the middle of the band: refused, but NOT ambiguous by 06 §6.2's rule).
AMBIGUOUS, CONFIDENT, MIDBAND, NO_TEST = uuid4(), uuid4(), uuid4(), uuid4()


def rows() -> list[dict]:
    return [
        row(AMBIGUOUS, ANCHOR, "AnchorVote", "satisfied"),
        row(AMBIGUOUS, "judge:g@1", "JudgeVote", "violated", seq=2),
        row(CONFIDENT, ANCHOR, "AnchorVote", "violated"),
        row(MIDBAND, "ruff@cat-1", "AnchorVote", "satisfied"),
        row(NO_TEST, "ruff@cat-1", "AnchorVote", "violated"),
    ]


def entry(key: str, kind: str, db_kind: str, xh: bytes | None = None) -> dict:
    return {
        "id": uuid4(),
        "verifier_key": key,
        "version": 1,
        "kind": db_kind,
        "definition": json.dumps({"kind": kind}),
        "effective_execution_hash": xh,
        "retired_at": None,
    }


REGISTRY_ROWS = [
    entry(T3_ID, KIND_TEST, "anchor", execution_hash(ANCHOR, TEMPLATE)),
    entry(CONSISTENCY_ID.split("@")[0], KIND_CONSISTENCY, "consistency"),
    entry(RM_ID.split("@")[0], "rm", "reward_model"),
]


class FakePool:
    """The job's PG reads by table, the escalations upsert captured; PG twin in
    tests/test_readjudicate_pg.py."""

    def __init__(self, *, consent=True, cert_status="certified", spectral=None, done=()):
        self.consent, self.cert_status, self.spectral, self.done = (
            consent,
            cert_status,
            spectral,
            done,
        )
        self.upserts: list[tuple] = []
        self.runs: list[tuple] = []

    async def fetch(self, sql, *args):
        if "FROM m1_verifiers" in sql:
            return REGISTRY_ROWS
        if "m1_verifier_promotions" in sql:
            return []
        if "FROM escalations" in sql:
            return [{"task_id": t} for t in self.done]
        raise AssertionError(sql)

    @contextlib.asynccontextmanager
    async def acquire(self):
        pool = self

        class Conn:
            def transaction(self):
                return contextlib.nullcontext()

            async def execute(self, sql, *args):
                assert sql.startswith("SELECT set_config") or "INSERT INTO escalations" in sql, sql
                if "escalations" in sql:
                    pool.upserts.append(args)

            async def fetch(self, sql, *args):
                return await pool.fetch(sql, *args)

            async def fetchrow(self, sql, *args):
                if "FROM noise_certificates" in sql:
                    return None if pool.cert_status is None else _cert_row(pool.cert_status)
                if "FROM spectral_runs" in sql:
                    return pool.spectral
                if "m1_cloud_judge_consents" in sql:
                    if not pool.consent:
                        return None
                    return {"id": uuid4(), "subprocessor": "e2b", "region": "us", "max_tier": "E1"}
                if "INSERT INTO m1_certified_runs" in sql:
                    pool.runs.append(args)
                    return {"id": uuid4(), "tenant_divergence": Decimal("0.5")}
                raise AssertionError(sql)

        yield Conn()


def _cert_row(status: str) -> dict:
    far = datetime(2099, 1, 1, tzinfo=UTC)
    return {
        "id": CERT,
        "status": status,
        "rho_plus": None,
        "rho_minus": None,
        "natarajan_lcb": None,
        "issued_at": WINDOW,
        "expires_at": far,
    }


class FakeCloud:
    """One MockTransport for the choke, vLLM and both E2B hosts."""

    def __init__(self, choke_rows, rm_reply=GOOD, e2b: FakeE2B | None = None):
        self.choke = FakeChoke(choke_rows)
        self.rm_reply, self.e2b = rm_reply, e2b or FakeE2B(stdout=b"FAILED t.py::t\n", exit_code=1)
        self.rm_calls: list[httpx.Request] = []

    async def handler(self, req: httpx.Request) -> httpx.Response:
        host = req.url.host
        if host == "choke":
            return await self.choke.client().send(
                httpx.Request(req.method, req.url, headers=req.headers, content=req.content)
            )
        if host == "rm.test":
            self.rm_calls.append(req)
            return httpx.Response(200, json={"choices": [{"message": {"content": self.rm_reply}}]})
        return self.e2b(req)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _ctx(pool, base_url="http://choke") -> SimpleNamespace:
    return SimpleNamespace(
        pool=pool,
        settings=SimpleNamespace(
            querychoke_base_url=base_url, querychoke_token=SecretStr("svc"), http_timeout_s=1.0
        ),
        tenant_id=TENANT,
        window_start=WINDOW,
        day=date(2026, 9, 15),
    )


async def _evidence(task_id, attempt_id, tier):
    return f"{tier}:typed"


async def _archive(task_id, attempt_id, tier):
    return b"TAR-" + tier.encode()


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ADJ_RM_BASE_URL", "http://rm.test/v1")
    monkeypatch.setenv("ADJ_RM_API_KEY", KEY)
    monkeypatch.setenv("ADJ_E2B_API_KEY", E2B_KEY)
    monkeypatch.setenv("ADJ_E2B_TEMPLATE", TEMPLATE)


async def _run(pool, cloud, *, evidence=_evidence, archive=_archive) -> dict[UUID, dict]:
    await readjudicate.run(
        _ctx(pool), http=cloud.client(), evidence_for=evidence, archive_for=archive
    )
    cols = (
        "tenant_id task_id window_start eta provisional verdict stage posterior provenance "
        "noise_cert_id vote_count consistency_fused consistency_excluded agreement_rate "
        "certified_run_id t3_skipped rm_verifier_id rm_vote rm_skipped"
    ).split()
    out = {}
    for args in pool.upserts:
        rec = dict(zip(cols, args, strict=True))
        assert rec["tenant_id"] == UUID(TENANT) and rec["window_start"] == WINDOW
        out[rec["task_id"]] = rec
    return out


@pytest.mark.parametrize(
    ("eta", "want"),
    [
        (0.0, False),
        (1 / 3 - MARGIN, False),  # exactly the margin is not inside it
        (1 / 3 - MARGIN + 1e-9, True),
        (0.30, True),
        (1 / 3 + MARGIN, False),
        (0.5, False),  # the middle of the band is refused, not ambiguous
        (8 / 9 - 0.05, True),
        (8 / 9 + MARGIN - 1e-9, True),
        (1.0, False),
    ],
)
def test_candidate_rule_is_the_d18_margin_around_the_band_edges(eta, want):
    assert is_candidate(eta, COSTS) is want
    assert is_candidate(0.5, COSTS, margin=0.2)


async def test_run_escalates_only_tasks_inside_the_margin_and_persists_the_row(env):
    pool, cloud = FakePool(), FakeCloud(rows())
    esc = await _run(pool, cloud)
    assert set(esc) == {AMBIGUOUS, NO_TEST}
    assert cloud.choke.requests == [
        (nightly.VOTES_TEMPLATE, {"from": "2026-08-17", "to": "2026-09-15"}, "Bearer svc")
    ]
    rec = esc[AMBIGUOUS]
    assert rec["eta"] == Decimal("0.272582") and rec["provisional"] == "violated"
    assert rec["verdict"] == "violated" and rec["stage"] == "bootstrapping"
    assert len(rec["posterior"]) == 4 and abs(sum(rec["posterior"]) - 1.0) < 1e-9
    assert rec["noise_cert_id"] == CERT and rec["provenance"] == "prior"
    assert (rec["vote_count"], rec["consistency_fused"], rec["consistency_excluded"]) == (3, 1, 0)
    assert rec["agreement_rate"] == Decimal("1.000000")  # T3 violated, provisional violated
    assert rec["certified_run_id"] is not None and rec["t3_skipped"] is None
    assert (rec["rm_verifier_id"], rec["rm_vote"], rec["rm_skipped"]) == (RM_ID, "accept", None)
    assert len(cloud.rm_calls) == 2 and len(pool.runs) == 1
    no_test = esc[NO_TEST]
    assert no_test["t3_skipped"] == "t3_no_test_anchor" and no_test["certified_run_id"] is None
    assert no_test["agreement_rate"] is None and no_test["consistency_fused"] == 0


async def test_rm_shadow_vote_never_changes_the_escalated_verdict(env):
    """A sharp reject from the RM (score 0.02) on a task the ensemble accepts: the escalated
    verdict and posterior are bit-identical to the run without any RM, and the pair is recorded."""
    ambiguous_accept = uuid4()
    accept_rows = [
        row(ambiguous_accept, ANCHOR, "AnchorVote", "satisfied"),
        row(ambiguous_accept, "judge:g@1", "JudgeVote", "satisfied", seq=2),
    ]
    e2b_pass = FakeE2B(stdout=b"3 passed\n", exit_code=0)
    with_rm = await _run(
        FakePool(),
        FakeCloud(
            accept_rows, rm_reply=json.dumps({"score": 0.02, "rationale": "x"}), e2b=e2b_pass
        ),
    )
    pool = FakePool()
    without = await _run(pool, FakeCloud(accept_rows, e2b=FakeE2B(exit_code=0)), evidence=None)
    a, b = with_rm[ambiguous_accept], without[ambiguous_accept]
    assert a["rm_vote"] == "reject" and b["rm_vote"] is None and b["rm_skipped"] == "rm_no_scorer"
    assert (a["verdict"], a["posterior"], a["stage"]) == (b["verdict"], b["posterior"], b["stage"])
    assert a["verdict"] == "satisfied" and a["vote_count"] == b["vote_count"] == 3
    # Positive control: the same reject COUNTED would flip it (the bundle lists rm as a kind).
    bundle = Bundle(calibrated_defaults=True)
    votes = votes_by_task(accept_rows, {})[ambiguous_accept]
    rm = replace(votes[0], verifier_id=RM_ID, kind="rm", vote="reject", tier="T2")
    assert adjudicate([*votes, rm], bundle).posterior != adjudicate(votes, bundle).posterior


async def test_t3_runs_only_under_a_live_t3_consent(env):
    refused, cloud = FakePool(consent=False), FakeCloud(rows())
    esc = await _run(refused, cloud)
    assert cloud.e2b.calls == [] and refused.runs == []
    rec = esc[AMBIGUOUS]
    assert rec["t3_skipped"] == "t3_refused:refused_no_cloud_consent"
    assert rec["certified_run_id"] is None and rec["consistency_fused"] == 0
    assert rec["verdict"] == "violated" and rec["vote_count"] == 2  # ledger votes only
    consented, cloud = FakePool(consent=True), FakeCloud(rows())
    esc = await _run(consented, cloud)
    assert [c.url.path for c in cloud.e2b.calls][0] == "/sandboxes" and len(consented.runs) == 1
    assert esc[AMBIGUOUS]["certified_run_id"] is not None
    # The run row cites the ledger's task and the honest no-attempt id (07 §2).
    run_args = consented.runs[0]
    assert run_args[2] == AMBIGUOUS and run_args[3] == NO_ATTEMPT and run_args[7] == "E1"
    assert run_args[11] == "satisfied" and run_args[12] == "violated"  # edge vote, provisional


async def test_escalation_stage_fuses_the_consistency_vote_as_its_own_clique(env):
    pool = FakePool()
    esc = await _run(pool, FakeCloud(rows()), evidence=None)
    rec = esc[AMBIGUOUS]
    assert (rec["consistency_fused"], rec["consistency_excluded"]) == (1, 0)
    # Rebuild the same fusion input and show the default stage excludes what escalation fused.
    votes = votes_by_task(rows(), registry_by_wire_id([]))[AMBIGUOUS]
    t3 = replace(votes[0], verifier_id=T3_ID, kind=KIND_TEST, vote="reject", tier="T3")
    cv = replace(
        votes[0], verifier_id=CONSISTENCY_ID, kind=KIND_CONSISTENCY, vote="reject", tier="T3"
    )
    bundle = Bundle(calibrated_defaults=True)
    default = adjudicate([*votes, t3, cv], bundle, noise_cert_id=str(CERT))
    escalated = adjudicate([*votes, t3, cv], bundle, noise_cert_id=str(CERT), escalation=True)
    assert default.consistency_excluded == 1 and escalated.consistency_excluded == 0
    assert list(escalated.posterior) == rec["posterior"] != list(default.posterior)
    assert rec["vote_count"] == escalated.vote_count == 3  # never an ensemble member


async def test_bundle_uses_the_windows_spectral_laws_and_stamps_only_a_certified_cert(env):
    laws = {
        ANCHOR: [[0.95, 0.02, 0.03], [0.5, 0.45, 0.05]],
        "judge:g@1": [[0.85, 0.10, 0.05], [0.20, 0.75, 0.05]],
    }
    spectral = {"passed": True, "diagnostics": "{}", "confusion": json.dumps(laws)}
    esc = await _run(FakePool(spectral=spectral), FakeCloud(rows()), evidence=None, archive=None)
    rec = esc[AMBIGUOUS]
    assert rec["eta"] == Decimal("0.294366")  # measured laws moved eta, still in the margin
    assert (rec["provenance"], rec["stage"]) == ("spectral", "CERTIFIED")
    assert rec["t3_skipped"] == "t3_no_archive_reader" and rec["certified_run_id"] is None
    assert esc[NO_TEST]["provenance"] == "prior"  # ruff@cat-1 has no measured law
    votes = votes_by_task(rows(), {})[AMBIGUOUS]
    bundle = bundle_for(votes, {"passed": True, "confusion": laws})
    assert {p.provenance for p in bundle.verifiers.values()} == {"spectral"}
    assert bundle.verifiers[ANCHOR].confusion[:2] == ((0.95, 0.02, 0.03), (0.5, 0.45, 0.05))
    assert bundle.verifiers[ANCHOR].confusion[2:] == CALIBRATED_CONFUSION["test"][2:]
    assert adjudicate(votes, bundle, noise_cert_id=str(CERT)).stage == "CERTIFIED"
    assert bundle_for(votes, {"passed": False, "confusion": {}}).verifiers == {}
    assert bundle_for(votes, None).calibrated_defaults
    for status, want in (("bootstrapping", None), (None, None), ("certified", CERT)):
        esc = await _run(
            FakePool(cert_status=status), FakeCloud(rows()), evidence=None, archive=None
        )
        assert esc[AMBIGUOUS]["noise_cert_id"] == want
        assert esc[AMBIGUOUS]["stage"] == ("bootstrapping" if want else "uncertified")


async def test_every_failure_is_a_counted_skip_never_a_fabricated_vote(env):
    before = dict(readjudicate_skipped_total)
    pool = FakePool()
    esc = await _run(pool, FakeCloud(rows(), rm_reply="not json", e2b=FakeE2B(fail_at="create")))
    rec = esc[AMBIGUOUS]
    assert (rec["rm_vote"], rec["rm_skipped"]) == (None, "rm_refused")
    # A sandbox that never came up is a T3 run whose anchor vote is an infra abstain, so the
    # escalated verdict is the ledger's alone -- never a `violated` invented from the outage.
    assert rec["certified_run_id"] is not None and rec["t3_skipped"] is None
    assert rec["verdict"] == "violated" and rec["consistency_fused"] == 1
    assert pool.runs[0][10] == "error"
    counted = {k: v - before.get(k, 0) for k, v in readjudicate_skipped_total.items()}
    assert counted["rm_refused"] == 2 and counted["t3_no_test_anchor"] == 1
    assert counted["vote_unusable:RmScore"] == 0 if "vote_unusable:RmScore" in counted else True
    with pytest.raises(RuntimeError, match="ADJ_QUERYCHOKE_BASE_URL"):
        await readjudicate.run(_ctx(FakePool(), base_url=""), http=FakeCloud([]).client())


async def test_done_tasks_and_tampered_or_unusable_rows_are_skipped(env):
    pool = FakePool(done=(AMBIGUOUS,))
    esc = await _run(pool, FakeCloud(rows()))
    assert set(esc) == {NO_TEST}
    tampered = [
        row(AMBIGUOUS, ANCHOR, "AnchorVote", "violated", tamper=1),
        row(AMBIGUOUS, "judge:g@1", "JudgeVote", "satisfied", seq=2),
        row(AMBIGUOUS, "rm:x@1", "RmScore", "", seq=3),
    ]
    votes = votes_by_task(tampered, {})[AMBIGUOUS]
    assert [(v.verifier_id, v.integrity.tamper) for v in votes] == [
        (ANCHOR, True),
        ("judge:g@1", False),
    ]
    pool = FakePool()
    esc = await _run(pool, FakeCloud(tampered))
    rec = esc[AMBIGUOUS]  # judge-accept alone: eta 0.8166, inside the margin of 1 - A/D
    assert rec["eta"] == Decimal("0.816594")
    # The tampered edge anchor never entered the likelihood, but it IS re-run certified: the
    # run row's edge_verdict is the tampered vote, so the 10 §11.3 divergence is measured.
    assert rec["vote_count"] == 2 and rec["certified_run_id"] is not None
    assert pool.runs[0][11] == "violated" and pool.runs[0][13] == 0  # edge, divergence


def test_latest_vote_per_verifier_wins_and_kinds_resolve_through_the_registry():
    task = uuid4()
    votes = votes_by_task(
        [
            row(task, ANCHOR, "AnchorVote", "violated", seq=1),
            row(task, ANCHOR, "AnchorVote", "satisfied", seq=2),
            row(task, "ruff@cat-1", "AnchorVote", "error", seq=3),
            row(task, "judge:g@1", "JudgeVote", "refused", seq=4),
            row(task, "consistency", "ConsistencyVote", "violated", seq=5),
        ],
        {},
    )[task]
    got = {v.verifier_id: (v.kind, v.vote, v.integrity.infra_failed, v.tier) for v in votes}
    assert got == {
        ANCHOR: ("test", "accept", False, "T0"),
        "ruff@cat-1": ("lint", "abstain", True, "T0"),
        "judge:g@1": ("judge", "abstain", False, "T1"),
        "consistency": ("consistency", "reject", False, "T3"),
    }
    listed = RegistryEntry(uuid4(), "ruff@cat-1", 1, "anchor", "lint", b"\x01" * 32, False)
    reg = registry_by_wire_id(
        [listed, RegistryEntry(uuid4(), "judge:g", 1, "judge", "judge", None, False)]
    )
    assert set(reg) == {"ruff@cat-1@1", "ruff@cat-1", "judge:g@1"}
    assert (
        votes_by_task([row(task, "ruff@cat-1", "AnchorVote", "satisfied")], reg)[task][0].kind
        == "lint"
    )
    assert all(v.attempt_id == NO_ATTEMPT for v in votes)


class FakeConn:
    def __init__(self, heads, rows):
        self.heads, self.rows = heads, rows

    def transaction(self):
        return contextlib.nullcontext()

    async def execute(self, sql, *args):
        assert sql.startswith("SELECT set_config")

    async def fetch(self, sql, *args):
        return self.heads if "m1_verifier_promotions" in sql else self.rows


def _head(pid, vid, incumbent_kind=None):
    inc = incumbent_kind is not None
    return {
        "id": pid,
        "vid": vid,
        "inc_id": uuid4() if inc else None,
        "inc_key": "judge:incumbent" if inc else None,
        "inc_version": 1 if inc else None,
        "inc_kind": "judge" if inc else None,
        "inc_definition": json.dumps({"kind": incumbent_kind}) if inc else None,
        "inc_hash": None,
        "inc_retired": None,
    }


async def test_measured_pairs_reach_run_promotion_through_promotion_step(monkeypatch):
    rm_pid, judge_pid, idle_pid = uuid4(), uuid4(), uuid4()
    heads = [
        _head(rm_pid, RM_ID),
        _head(judge_pid, "judge:l@1", "judge"),
        _head(idle_pid, "rm:idle@1"),
    ]
    esc_rows = [
        {
            "rm_verifier_id": RM_ID,
            "rm_vote": "reject",
            "verdict": "violated",
            "noise_cert_id": CERT,
        },
        {
            "rm_verifier_id": RM_ID,
            "rm_vote": "accept",
            "verdict": "satisfied",
            "noise_cert_id": None,
        },
        {
            "rm_verifier_id": "judge:l@1",
            "rm_vote": "reject",
            "verdict": "refused",
            "noise_cert_id": CERT,
        },
    ]
    measured = await measured_pairs(FakeConn(heads, esc_rows), TENANT)
    assert set(measured) == {rm_pid, judge_pid}
    assert measured[rm_pid] == Measurement(
        [ShadowPair("reject", "violated", str(CERT)), ShadowPair("accept", "satisfied", "")], 0.0
    )
    assert measured[judge_pid] == Measurement(
        [ShadowPair("reject", "refused", str(CERT))], youden(CALIBRATED_CONFUSION["judge"])
    )

    seen = {}

    async def fake_run_promotion(conn, append, *, tenant_id, measured, now=None):
        seen["measured"], seen["append"] = measured, append
        return SimpleNamespace(receipt_ids=(uuid4(),))

    monkeypatch.setattr("app.registry.promotion.run_promotion", fake_run_promotion)

    class Pool:
        @contextlib.asynccontextmanager
        async def acquire(self):
            yield FakeConn(heads, esc_rows)

    ctx = SimpleNamespace(pool=Pool(), tenant_id=TENANT, settings=_ctx(None).settings)
    assert await nightly.promotion_step(ctx, http=httpx.AsyncClient()) is not None
    assert seen["measured"] == measured
    assert seen["append"].args[1:] == ("http://choke", "svc")  # the controld appender, bearer bound


async def test_no_key_appears_in_logs(env, caplog):
    caplog.set_level(logging.DEBUG)
    await _run(FakePool(), FakeCloud(rows()))
    assert caplog.records
    assert KEY not in caplog.text and E2B_KEY not in caplog.text
    for r in caplog.records:
        assert KEY not in repr(r.args) and E2B_KEY not in repr(r.args)
