"""T3 certified runs (06 §2.5 tier T3, 14 task 6.5) against a fake E2B over
httpx.MockTransport: the consent gate shared with the cloud-judge path, E0/E2 refusals,
the sandbox lifecycle with destroy-on-failure, T3 vote emission through the registry
normalizer, the escalation-only ConsistencyVote through adjudicate() (FR-VERIFY-017),
and the signed anchor-vs-T3 divergence (10 §11.3)."""

import base64
import json
import logging
import struct
from dataclasses import replace
from uuid import uuid4

import httpx
import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.likelihoods import Bundle, VerifierParams
from app.certified.e2b import E2BClient, E2BSettings, RunResult, _frames
from app.certified.runner import (
    ARCHIVE,
    CONSENT_ID,
    CONSISTENCY_ID,
    EXTRACT,
    REPO,
    TEST_ANCHORS,
    CertifiedRunner,
    RunRow,
    divergence,
    execution_hash,
    verdict_of,
)
from app.judges.cloud_path import Consent
from app.judges.specs import JudgeRefused
from app.registry.catalog import RegistryEntry
from app.registry.handlers import KIND_CONSISTENCY, KIND_TEST, NormalizedVote
from app.registry.integrity import IntegrityFlags
from m1p.v1 import Verdict
from pydantic import SecretStr

ANCHOR = "pytest@cat-1"
T3_ID = f"t3:{ANCHOR}"
TEMPLATE = "mark1-py312"
KEY = "sk-e2b-test-secret"
CONSENT = Consent(subprocessor="e2b", region="us", max_tier="E1")
IDS = (uuid4(), uuid4(), uuid4())  # tenant, task, attempt


def _env(payload: dict) -> bytes:
    b = json.dumps(payload).encode()
    return struct.pack(">BI", 0, len(b)) + b


def _stream(stdout: bytes, exit_code: int) -> bytes:
    return (
        _env({"event": {"start": {"pid": 7}}})
        + _env({"event": {"data": {"stdout": base64.b64encode(stdout).decode()}}})
        + _env({"event": {"end": {"exitCode": exit_code, "exited": True}}})
        + struct.pack(">BI", 2, 2)
        + b"{}"
    )


class FakeE2B:
    """The two E2B hosts as one MockTransport handler; `fail_at` makes step N answer 500."""

    def __init__(self, stdout=b"", exit_code=0, fail_at: str | None = None, tar_exit=0):
        self.calls: list[httpx.Request] = []
        self.stdout, self.exit_code, self.fail_at, self.tar_exit = (
            stdout,
            exit_code,
            fail_at,
            tar_exit,
        )

    def starts(self) -> list[dict]:
        return [
            json.loads(c.content[5:])["process"]
            for c in self.calls
            if c.url.path == "/process.Process/Start"
        ]

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        step = {"/sandboxes": "create", "/files": "upload"}.get(req.url.path) or (
            "destroy" if req.method == "DELETE" else "run"
        )
        if step == "run":
            step = "extract" if json.loads(req.content[5:])["process"]["cmd"] == "tar" else "anchor"
        if step == self.fail_at:
            return httpx.Response(500, json={"code": 500, "message": "boom"})
        if step == "create":
            return httpx.Response(201, json={"sandboxID": "sb-1", "envdAccessToken": "envd-tok"})
        if step == "upload":
            return httpx.Response(200, json=[{"path": req.url.params["path"]}])
        if step == "extract":
            return httpx.Response(200, content=_stream(b"", self.tar_exit))
        if step == "anchor":
            return httpx.Response(200, content=_stream(self.stdout, self.exit_code))
        return httpx.Response(204)


def entry(vid: str, kind: str, xh: bytes | None) -> RegistryEntry:
    db_kind = "consistency" if kind == KIND_CONSISTENCY else "anchor"
    return RegistryEntry(uuid4(), vid.split("@")[0], 1, db_kind, kind, xh, False)


REGISTRY = {
    T3_ID: entry(T3_ID, KIND_TEST, execution_hash(ANCHOR, TEMPLATE)),
    CONSISTENCY_ID: entry(CONSISTENCY_ID, KIND_CONSISTENCY, None),
}


class Harness:
    def __init__(self, fake: FakeE2B | None = None, consent=CONSENT, registry=REGISTRY):
        self.fake = fake or FakeE2B()
        self.rows: list[RunRow] = []
        self.consent_calls = 0
        settings = E2BSettings(api_key=SecretStr(KEY), template=TEMPLATE)
        self.client = E2BClient(
            httpx.AsyncClient(transport=httpx.MockTransport(self.fake)), settings
        )

        async def consent_for(tenant_id, key):
            self.consent_calls += 1
            assert key == CONSENT_ID
            return (uuid4(), consent) if consent else None

        async def archive_for(task_id, attempt_id, tier):
            return b"TAR-" + tier.encode()

        async def record(row: RunRow):
            self.rows.append(row)
            return uuid4(), float(sum(r.divergence for r in self.rows)) / len(self.rows)

        self.runner = CertifiedRunner(
            self.client, consent_for, archive_for, record, registry, TEMPLATE, "us"
        )

    async def run(self, anchor=ANCHOR, tier="E1", edge="satisfied", provisional="satisfied"):
        return await self.runner.run(IDS[0], IDS[1], IDS[2], anchor, tier, edge, provisional)


@pytest.mark.parametrize(
    ("consent", "reason"),
    [
        (None, "refused_no_cloud_consent"),
        (replace(CONSENT, subprocessor="anthropic"), "refused_subprocessor_not_listed:e2b"),
        (replace(CONSENT, region="eu"), "refused_region_mismatch:us"),
        (replace(CONSENT, max_tier="E0"), "refused_tier_above_consent:E1"),
    ],
)
async def test_run_without_a_matching_consent_is_refused_before_any_sandbox(consent, reason):
    h = Harness(consent=consent)
    with pytest.raises(JudgeRefused) as e:
        await h.run()
    assert e.value.reason == reason
    assert h.fake.calls == [] and h.rows == []


async def test_e0_has_no_code_and_is_refused_before_consent_is_even_read():
    h = Harness()
    with pytest.raises(JudgeRefused, match="refused_tier_e0_no_code"):
        await h.run(tier="E0")
    assert h.consent_calls == 0 and h.fake.calls == [] and h.rows == []


async def test_e2_never_reaches_a_rented_sandbox():
    h = Harness(consent=replace(CONSENT, max_tier="E1"))
    with pytest.raises(JudgeRefused, match="refused_tier_e2_never_cloud"):
        await h.run(tier="E2")
    assert h.fake.calls == [] and h.rows == []


async def test_unknown_anchor_id_is_refused_never_faked():
    h = Harness()
    with pytest.raises(JudgeRefused, match="refused_unregistered_anchor:ruff@cat-1"):
        await h.run(anchor="ruff@cat-1")
    assert h.consent_calls == 0 and h.fake.calls == []


async def test_sandbox_lifecycle_create_upload_extract_run_destroy():
    h = Harness(FakeE2B(stdout=b"3 passed\n", exit_code=0))
    run = await h.run()
    steps = [(c.method, c.url.host, c.url.path) for c in h.fake.calls]
    assert steps == [
        ("POST", "api.e2b.app", "/sandboxes"),
        ("POST", "sandbox.e2b.app", "/files"),
        ("POST", "sandbox.e2b.app", "/process.Process/Start"),
        ("POST", "sandbox.e2b.app", "/process.Process/Start"),
        ("DELETE", "api.e2b.app", "/sandboxes/sb-1"),
    ]
    create, upload, *_ = h.fake.calls
    assert json.loads(create.content) == {
        "templateID": TEMPLATE,
        "timeout": 600,
        "allow_internet_access": False,
    }
    assert upload.url.params["path"] == ARCHIVE and b"TAR-E1" in upload.content
    assert upload.headers["E2b-Sandbox-Id"] == "sb-1"
    assert upload.headers["X-Access-Token"] == "envd-tok"
    extract, anchor = h.fake.starts()
    assert [extract["cmd"], *extract["args"]] == EXTRACT
    assert [anchor["cmd"], *anchor["args"]] == TEST_ANCHORS[ANCHOR][0]
    assert anchor["cwd"] == REPO
    assert (run.verdict, run.exit_code, run.sandbox_id) == ("satisfied", 0, "sb-1")
    (row,) = h.rows
    assert (row.sandbox_id, row.verdict, row.exit_code, row.evidence_tier) == (
        "sb-1",
        "satisfied",
        0,
        "E1",
    )
    assert row.execution_hash == execution_hash(ANCHOR, TEMPLATE) and len(row.execution_hash) == 32


@pytest.mark.parametrize("fail_at", ["upload", "extract", "anchor", "destroy"])
async def test_sandbox_is_destroyed_even_when_a_step_fails_and_the_result_is_error(fail_at):
    h = Harness(FakeE2B(stdout=b"FAILED t\n", exit_code=1, fail_at=fail_at))
    run = await h.run()
    assert [c.method for c in h.fake.calls][-1] == "DELETE"
    assert (run.verdict, run.exit_code) == ("error", None)
    (row,) = h.rows
    assert (row.verdict, row.exit_code, row.sandbox_id) == ("error", None, "sb-1")
    assert run.divergence == 0  # an infra failure is not a divergence claim
    anchor_vote = next(v for v in run.votes if v.kind == KIND_TEST)
    assert anchor_vote.vote == "abstain" and anchor_vote.integrity.infra_failed


async def test_create_failure_records_a_sandboxless_error_run():
    h = Harness(FakeE2B(fail_at="create"))
    run = await h.run()
    assert [c.url.path for c in h.fake.calls] == ["/sandboxes"]
    assert (run.verdict, run.sandbox_id) == ("error", None)
    assert h.rows[0].sandbox_id is None


async def test_materialisation_failure_is_error_and_the_anchor_never_runs():
    h = Harness(FakeE2B(exit_code=0, tar_exit=2))
    run = await h.run()
    assert len(h.fake.starts()) == 1  # tar only
    assert run.verdict == "error" and run.exit_code is None


CARGO = VerifierParams(
    "cargo-check-warm",
    "compile",
    ((0.98, 0.02, 0.00), (0.60, 0.40, 0.00), (0.50, 0.02, 0.48), (0.50, 0.02, 0.48)),
    "syntactic",
    "prior",
)
T3 = VerifierParams(
    T3_ID,
    KIND_TEST,
    ((0.97, 0.03, 0.00), (0.05, 0.95, 0.00), (0.30, 0.30, 0.40), (0.30, 0.30, 0.40)),
    "certified",
    "prior",
)
CONSISTENCY = VerifierParams(
    CONSISTENCY_ID,
    KIND_CONSISTENCY,
    ((0.60, 0.25, 0.15), (0.40, 0.45, 0.15), (0.30, 0.30, 0.40), (0.30, 0.30, 0.40)),
    "consistency",
    "prior",
)
BUNDLE = Bundle(
    priors=(0.55, 0.30, 0.10, 0.05),
    verifiers={p.verifier_id: p for p in (CARGO, T3, CONSISTENCY)},
)
EDGE = NormalizedVote(
    CARGO.verifier_id, "compile", IDS[1], IDS[2], "accept", b"", IntegrityFlags(), "T0"
)


async def test_t3_votes_normalize_at_tier_t3_and_the_consistency_vote_fuses_only_on_escalation():
    h = Harness(FakeE2B(stdout=b"FAILED tests/test_x.py::t\n", exit_code=1))
    run = await h.run(edge="satisfied", provisional="satisfied")
    assert run.verdict == "violated" and run.refusals == []
    by_kind = {v.kind: v for v in run.votes}
    assert set(by_kind) == {KIND_TEST, KIND_CONSISTENCY}
    assert all(v.tier == "T3" for v in run.votes)
    t3, cv = by_kind[KIND_TEST], by_kind[KIND_CONSISTENCY]
    assert (t3.verifier_id, t3.vote, t3.integrity.tamper, t3.integrity.infra_failed) == (
        T3_ID,
        "reject",
        False,
        False,
    )
    assert (cv.verifier_id, cv.vote) == (CONSISTENCY_ID, "reject")
    assert (run.consistency.vote, run.consistency.sample_count, run.consistency.agreement_rate) == (
        Verdict.VIOLATED,
        1,
        0.0,
    )
    # FR-VERIFY-017 through the production entrypoint: default stage excludes the
    # consistency vote (reported, not dropped); escalation fuses it as its own clique.
    default = adjudicate([EDGE, *run.votes], BUNDLE)
    assert default.consistency_excluded == 1
    assert default.posterior == adjudicate([EDGE, t3], BUNDLE).posterior
    assert default.vote_count == 2
    escalated = adjudicate([EDGE, *run.votes], BUNDLE, escalation=True)
    assert escalated.consistency_excluded == 0
    assert escalated.posterior != default.posterior
    assert escalated.vote_count == 2  # never an ensemble member
    assert escalated.verdict == "violated"


async def test_agreeing_run_reports_full_agreement():
    h = Harness(FakeE2B(exit_code=0))
    run = await h.run(edge="satisfied", provisional="satisfied")
    assert run.consistency.agreement_rate == 1.0 and run.consistency.vote == Verdict.SATISFIED


async def test_registry_hash_mismatch_marks_the_t3_vote_tamper():
    stale = {**REGISTRY, T3_ID: entry(T3_ID, KIND_TEST, b"\x99" * 32)}
    h = Harness(registry=stale)
    run = await h.run()
    assert next(v for v in run.votes if v.kind == KIND_TEST).integrity.tamper


async def test_unregistered_t3_verifier_is_a_refusal_not_a_vote():
    h = Harness(registry={CONSISTENCY_ID: REGISTRY[CONSISTENCY_ID]})
    run = await h.run()
    assert [r.reason for r in run.refusals] == ["refused_unknown_verifier"]
    assert [v.kind for v in run.votes] == [KIND_CONSISTENCY]


@pytest.mark.parametrize(
    ("edge", "certified", "want"),
    [
        ("satisfied", "violated", 1),
        ("violated", "satisfied", -1),
        ("satisfied", "satisfied", 0),
        ("violated", "violated", 0),
        ("satisfied", "error", 0),
        ("error", "violated", 0),
        ("refused", "satisfied", 0),
    ],
)
def test_divergence_is_signed_toward_edge_over_acceptance(edge, certified, want):
    assert divergence(edge, certified) == want


async def test_divergence_rides_on_the_run_row_and_the_tenant_mean():
    h = Harness(FakeE2B(stdout=b"FAILED t\n", exit_code=1))
    run = await h.run(edge="satisfied")
    assert run.divergence == 1 and h.rows[-1].divergence == 1 and run.tenant_divergence == 1.0
    h.fake.stdout, h.fake.exit_code = b"ok", 0
    run = await h.run(edge="violated")
    assert run.divergence == -1 and run.tenant_divergence == 0.0


@pytest.mark.parametrize(
    ("res", "want"),
    [
        (RunResult(0, b"", b""), "satisfied"),
        (RunResult(1, b"FAILED tests/test_a.py::t\n", b""), "violated"),
        (RunResult(1, b"", b"  FAILED tests/test_a.py::t\n"), "violated"),
        (RunResult(1, b"FAILED\n", b""), "error"),
        (RunResult(127, b"", b"pytest: not found"), "error"),
        (None, "error"),
    ],
)
def test_verdict_mapping_matches_the_edge_line_handler(res, want):
    assert verdict_of(res, TEST_ANCHORS[ANCHOR][1]) == want


def test_execution_hash_commits_to_argv_and_template():
    a = execution_hash(ANCHOR, TEMPLATE)
    assert len(a) == 32
    assert a != execution_hash(ANCHOR, "other-template")
    assert a != execution_hash("go-test@cat-1", TEMPLATE)


async def test_api_key_never_appears_in_repr_or_logs(caplog):
    h = Harness()
    with caplog.at_level(logging.DEBUG):
        await h.run()
    assert KEY not in repr(h.client) and KEY not in repr(h.runner)
    assert KEY not in caplog.text
    assert h.fake.calls[0].headers["X-API-Key"] == KEY  # on the wire, nowhere else
    assert "X-API-Key" not in h.fake.calls[1].headers  # envd gets the sandbox token only


def test_connect_frames_round_trip_and_stream_error_is_an_http_error():
    body = _stream(b"hi", 3)
    frames = _frames(body)
    assert frames[-1] == (2, {}) and frames[2][1]["event"]["end"]["exitCode"] == 3


async def test_envd_stream_error_is_an_infra_failure_not_a_verdict():
    class BrokenStream(FakeE2B):
        def __call__(self, req):
            r = super().__call__(req)
            if req.url.path == "/process.Process/Start":
                err = b'{"error":{"code":"unknown"}}'
                clean_end = _stream(b"", 0)[:-7]  # a full exit-0 stream, then the error trailer
                return httpx.Response(
                    200, content=clean_end + struct.pack(">BI", 2, len(err)) + err
                )
            return r

    h = Harness(BrokenStream())
    run = await h.run()
    assert run.verdict == "error" and h.fake.calls[-1].method == "DELETE"
