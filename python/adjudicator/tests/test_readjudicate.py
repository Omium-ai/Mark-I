"""readjudicate (06 §1.2) through fake choke rows and a fake E2B: the D18 selection rule
pinned, a folded RmScore of an unpromoted RM carrying zero fusion weight, T3 only under consent,
the consistency vote fusing only at escalation=True (FR-VERIFY-017), and every failure a
counted skip. The RM never rides escalation (16 §Independence)."""

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
import zstandard
from app import ledger
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import CALIBRATED_CONFUSION, Bundle
from app.certified.runner import CONSISTENCY_ID, execution_hash
from app.choke import QuerychokeError
from app.jobs import nightly, readjudicate
from app.jobs.readjudicate import (
    MARGIN,
    NO_ATTEMPT,
    RM_NOT_ESCALATION_SCOPED,
    bundle_for,
    is_candidate,
    readjudicate_skipped_total,
    registry_by_wire_id,
    votes_by_task,
)
from app.registry.catalog import RegistryEntry
from app.registry.handlers import KIND_CONSISTENCY, KIND_TEST
from app.rm.scorer import CALIBRATION_VERSION
from m1p.v1 import Batch, CertificationStatus, VerdictStage
from pydantic import SecretStr
from tests.test_certified import ANCHOR, T3_ID, TEMPLATE, FakeE2B
from tests.test_jobs import RM_XH, VOTE_ROW, FakeChoke
from tests.test_rm import KEY, RM_ID

TENANT = str(uuid4())
CERT = uuid4()
COSTS = Costs()
WINDOW = datetime(2026, 9, 15, tzinfo=UTC)
E2B_KEY = "sk-e2b-readjudicate-secret"
SESSION = uuid4()


def row(
    task: UUID, vid: str, family: str, vote: str, tamper: int = 0, seq: int = 1, session=SESSION
) -> dict:
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
    # adjudication_votes.v2 serves session_id; None models a pre-v2 row, which the run counts
    # and never posts.
    if session is None:
        r.pop("session_id", None)
    else:
        r["session_id"] = str(session)
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
    entry(RM_ID.split("@")[0], "rm", "reward_model", RM_XH),
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
        if "RIGHT JOIN m1_verifiers" in sql:  # promotion.fusion_states: the RM has no head
            key, version = RM_ID.split("@")
            return [{"verifier_key": key, "version": int(version), "scope": None, "state": None}]
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
    """One MockTransport for the choke, controld's service ingest and both E2B hosts."""

    def __init__(self, choke_rows, e2b: FakeE2B | None = None, ingest=200):
        self.choke = FakeChoke(choke_rows)
        self.e2b = e2b or FakeE2B(stdout=b"FAILED t.py::t\n", exit_code=1)
        self.ingested: list[httpx.Request] = []
        self.ingest = ingest

    async def handler(self, req: httpx.Request) -> httpx.Response:
        host = req.url.host
        if host == "choke" and req.url.path == ledger.INGEST_PATH:
            self.ingested.append(req)
            if self.ingest != 200:
                return httpx.Response(self.ingest, json={"error": {"code": "M1E-9500"}})
            return httpx.Response(
                200, json={"batch_id": req.headers["M1P-Batch-Id"], "accepted": 1}
            )
        if host == "choke":
            return await self.choke.client().send(
                httpx.Request(req.method, req.url, headers=req.headers, content=req.content)
            )
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
    assert (rec["rm_verifier_id"], rec["rm_vote"]) == (None, None)
    assert rec["rm_skipped"] == RM_NOT_ESCALATION_SCOPED and len(pool.runs) == 1
    no_test = esc[NO_TEST]
    assert no_test["t3_skipped"] == "t3_no_test_anchor" and no_test["certified_run_id"] is None
    assert no_test["agreement_rate"] is None and no_test["consistency_fused"] == 0


def rm_row(task: UUID, score: float, seq: int = 3) -> dict:
    return {
        **row(task, RM_ID, "RmScore", "", seq=seq),
        "score": score,
        "calibration_version": CALIBRATION_VERSION,
    }


async def test_unpromoted_rm_score_folds_but_never_moves_the_escalated_verdict(env):
    """A sharp RmScore reject (0.02 folds to violated) on a task the ensemble accepts: the RM
    has no promotion head, so fusion_states holds it in probation and the escalated verdict and
    posterior are bit-identical to the ledger without it."""
    ambiguous_accept = uuid4()
    accept_rows = [
        row(ambiguous_accept, ANCHOR, "AnchorVote", "satisfied"),
        row(ambiguous_accept, "judge:g@1", "JudgeVote", "satisfied", seq=2),
    ]
    e2b_pass = FakeE2B(stdout=b"3 passed\n", exit_code=0)
    with_rm = await _run(
        FakePool(), FakeCloud([*accept_rows, rm_row(ambiguous_accept, 0.02)], e2b=e2b_pass)
    )
    without = await _run(FakePool(), FakeCloud(accept_rows, e2b=FakeE2B(exit_code=0)))
    a, b = with_rm[ambiguous_accept], without[ambiguous_accept]
    assert (a["verdict"], a["posterior"], a["stage"]) == (b["verdict"], b["posterior"], b["stage"])
    assert a["verdict"] == "satisfied" and a["vote_count"] == b["vote_count"] == 3
    registry = registry_by_wire_id(
        [RegistryEntry(uuid4(), RM_ID.split("@")[0], 1, "reward_model", "rm", RM_XH, False)]
    )
    votes = votes_by_task([*accept_rows, rm_row(ambiguous_accept, 0.02)], registry)
    rm = next(v for v in votes[ambiguous_accept] if v.verifier_id == RM_ID)
    assert (rm.kind, rm.vote, rm.tier) == ("rm", "reject", "T2")
    # Positive control: the same folded reject COUNTED would move it.
    bundle = Bundle(calibrated_defaults=True)
    honest = [v for v in votes[ambiguous_accept] if v.verifier_id != RM_ID]
    assert adjudicate([*honest, rm], bundle).posterior != adjudicate(honest, bundle).posterior


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
    unfit = bundle_for(votes, {"passed": False, "confusion": {}}).verifiers
    assert {p.provenance for p in unfit.values()} == {"prior"}
    assert unfit.keys() == bundle.verifiers.keys()
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
    esc = await _run(pool, FakeCloud(rows(), e2b=FakeE2B(fail_at="create")))
    rec = esc[AMBIGUOUS]
    assert (rec["rm_vote"], rec["rm_skipped"]) == (None, RM_NOT_ESCALATION_SCOPED)
    # A sandbox that never came up is a T3 run whose anchor vote is an infra abstain, so the
    # escalated verdict is the ledger's alone -- never a `violated` invented from the outage.
    assert rec["certified_run_id"] is not None and rec["t3_skipped"] is None
    assert rec["verdict"] == "violated" and rec["consistency_fused"] == 1
    assert pool.runs[0][10] == "error"
    counted = {k: v - before.get(k, 0) for k, v in readjudicate_skipped_total.items()}
    assert counted["t3_no_test_anchor"] == 1
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


async def test_no_key_appears_in_logs(env, caplog):
    caplog.set_level(logging.DEBUG)
    await _run(FakePool(), FakeCloud(rows()))
    assert caplog.records
    assert KEY not in caplog.text and E2B_KEY not in caplog.text
    for r in caplog.records:
        assert KEY not in repr(r.args) and E2B_KEY not in repr(r.args)


def _posted(cloud: FakeCloud) -> dict[UUID, tuple[Batch, object]]:
    """(batch, event) per task across every service-ingest POST, wire-decoded like controld."""
    out = {}
    for req in cloud.ingested:
        assert req.headers[ledger.TENANT_HEADER] == TENANT
        assert req.headers["authorization"] == "Bearer svc"
        batch = Batch().parse(zstandard.decompress(req.content))
        assert UUID(bytes=batch.batch_id) == UUID(req.headers["M1P-Batch-Id"])
        for ev in batch.events:
            out[UUID(bytes=ev.task_id)] = (batch, ev)
    return out


async def test_escalated_verdicts_reenter_the_ledger_as_verify_proto_spells_them(env):
    # A passing T3 run moves AMBIGUOUS from the provisional `violated` into the band: REVISED.
    pool, cloud = FakePool(), FakeCloud(rows(), e2b=FakeE2B(stdout=b"3 passed\n", exit_code=0))
    esc = await _run(pool, cloud)
    posted = _posted(cloud)
    assert len(cloud.ingested) == 1 and set(posted) == set(esc) == {AMBIGUOUS, NO_TEST}
    for task, rec in esc.items():
        batch, ev = posted[task]
        assert batch.advisory_tenant_id == UUID(TENANT).bytes
        assert ev.event_id == ledger.event_id(UUID(TENANT), task, WINDOW)
        assert ev.session_id == SESSION.bytes and ev.task_id == task.bytes
        assert ev.session_epoch == 0xFFFFFFFF and ev.occurred_at == ledger.window_close(WINDOW)
        v = ev.verdict_event
        want_stage = (
            VerdictStage.CERTIFIED if rec["verdict"] == rec["provisional"] else VerdictStage.REVISED
        )
        assert v.stage == want_stage
        assert v.verdict.name.lower() == rec["verdict"]
        assert v.posterior == rec["posterior"] and len(v.posterior) == 4
        assert v.certification == CertificationStatus[rec["stage"].upper()]
        assert v.noise_cert_id == str(rec["noise_cert_id"]) and v.vote_count == rec["vote_count"]
        assert v.bundle_seq == 0  # no spectral run this window: calibrated defaults
    assert (esc[AMBIGUOUS]["provisional"], esc[AMBIGUOUS]["verdict"]) == ("violated", "refused")
    assert posted[AMBIGUOUS][1].verdict_event.stage == VerdictStage.REVISED
    assert esc[NO_TEST]["provisional"] == esc[NO_TEST]["verdict"] == "violated"
    assert posted[NO_TEST][1].verdict_event.stage == VerdictStage.CERTIFIED


async def test_bundle_seq_names_the_windows_spectral_run(env):
    laws = {ANCHOR: [[0.95, 0.02, 0.03], [0.5, 0.45, 0.05]]}
    spectral = {"passed": True, "diagnostics": "{}", "confusion": json.dumps(laws)}
    cloud = FakeCloud(rows())
    await _run(FakePool(spectral=spectral), cloud, evidence=None, archive=None)
    assert {ev.verdict_event.bundle_seq for _, ev in _posted(cloud).values()} == {
        int(WINDOW.timestamp())
    }


async def test_ingest_refusal_fails_the_run_before_any_row_lands(env):
    pool, cloud = FakePool(), FakeCloud(rows(), ingest=503)
    with pytest.raises(QuerychokeError, match="M1E-9500"):
        await _run(pool, cloud)
    assert len(cloud.ingested) == 1 and pool.upserts == []


async def test_rows_without_session_id_are_counted_never_posted(env):
    before = readjudicate_skipped_total["ingest_no_session_id"]
    no_session = [
        row(AMBIGUOUS, ANCHOR, "AnchorVote", "satisfied", session=None),
        row(AMBIGUOUS, "judge:g@1", "JudgeVote", "violated", seq=2, session=None),
        row(NO_TEST, "ruff@cat-1", "AnchorVote", "violated", session=None),
    ]
    pool, cloud = FakePool(), FakeCloud(no_session)
    esc = await _run(pool, cloud)
    assert set(esc) == {AMBIGUOUS, NO_TEST} and cloud.ingested == []
    assert readjudicate_skipped_total["ingest_no_session_id"] - before == 2


async def test_rerun_reposts_the_same_event_ids_under_a_fresh_batch(env):
    first, second = FakeCloud(rows()), FakeCloud(rows())
    await _run(FakePool(), first)
    await _run(FakePool(), second)
    a, b = _posted(first), _posted(second)
    assert {t: ev.event_id for t, (_, ev) in a.items()} == {
        t: ev.event_id for t, (_, ev) in b.items()
    }
    assert a[AMBIGUOUS][0].batch_id != b[AMBIGUOUS][0].batch_id
