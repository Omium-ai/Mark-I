"""The cascade registry and its framework twin (the runner is byte-identical to intel's), and
spectral.estimate through a fake choke: planted votes → Diagnostics.passed → CERTIFIED reachable;
a degenerate design keeps the certificate at bootstrapping."""

import contextlib
import hashlib
import hmac
import json
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx
import numpy as np
import pytest
from app.certs.state_machine import BOOTSTRAPPING, CERTIFIED, CertEvidence, next_status
from app.jobs import JOBS, nightly
from app.jobs.registry import order, validate
from pydantic import SecretStr

HERE = Path(__file__).resolve().parents[1] / "app" / "jobs"
INTEL = Path(__file__).resolve().parents[2] / "intel" / "app" / "jobs"


def test_framework_files_are_twins_of_intel():
    for name in ("registry.py", "runner.py", "__main__.py"):
        assert (HERE / name).read_bytes() == (INTEL / name).read_bytes(), name


def test_gold_refresh_and_spectral_run_before_certs_recompute_and_targets_resolve():
    assert [j.name for j in order(JOBS)] == [
        "gold.refresh",
        "spectral.estimate",
        "certs.recompute",
        "readjudicate.run",
        "promotion.step",
    ]
    assert set(validate(JOBS)) == {
        "gold.refresh",
        "spectral.estimate",
        "certs.recompute",
        "readjudicate.run",
        "promotion.step",
    }
    by_name = {j.name: j for j in JOBS}
    assert by_name["readjudicate.run"].runs_after == ("spectral.estimate",)
    assert "readjudicate.run" in by_name["promotion.step"].runs_after


FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "go/controld/internal/querychoke/testdata/intel_template_rows.json"
    ).read_text()
)
VOTE_ROW = FIXTURE["adjudication_votes"][0]
NAMES = ("rubric", "rrm", "anchor")
FAMILY = {"rubric": "JudgeVote", "rrm": "RmScore", "anchor": "AnchorVote"}
WIRE = {0: "satisfied", 1: "violated", 2: "refused"}
PAPER2 = np.array(
    [
        [[0.85, 0.15, 0.0], [0.2, 0.8, 0.0]],
        [[0.75, 0.25, 0.0], [0.25, 0.75, 0.0]],
        [[1.0, 0.0, 0.0], [0.6, 0.4, 0.0]],
    ]
)
TENANT = str(uuid4())


def vote_rows(votes: np.ndarray, names=NAMES, *, tamper_verifier: str | None = None) -> list[dict]:
    """(n, V) codes → `adjudication_votes` wire rows, key set locked to the Go fixture."""
    rows = []
    for n, task in enumerate(votes):
        task_id = str(UUID(int=n + 1))
        for v, code in enumerate(task):
            if code < 0:
                continue
            row = {
                **VOTE_ROW,
                "task_id": task_id,
                "vote_id": str(uuid4()),
                "seq": v + 1,
                "family": FAMILY.get(names[v], "JudgeVote"),
                "verifier_id": names[v],
                "is_anchor": int(names[v] == "anchor"),
                "vote": WIRE[int(code)],
                "abstained": int(code == 2),
                "tamper": int(names[v] == tamper_verifier),
            }
            assert row.keys() == VOTE_ROW.keys()
            rows.append(row)
    return rows


class FakeChoke:
    """controld's exact read wire (module.go handleQuery), rows planted per template."""

    def __init__(self, rows: list[dict], gold: list[dict] | None = None) -> None:
        self.rows, self.gold, self.requests = rows, gold or [], []

    def client(self) -> httpx.AsyncClient:
        def handler(req: httpx.Request) -> httpx.Response:
            body = json.loads(req.content)
            self.requests.append(
                (body["template"], body["params"], req.headers.get("authorization"))
            )
            served = {nightly.VOTES_TEMPLATE: self.rows, nightly.GOLD_TEMPLATE: self.gold}
            if body["template"] not in served:
                return httpx.Response(400, json={"error": {"code": "M1E-2008", "message": "?"}})
            return httpx.Response(
                200,
                json={
                    "rows": served[body["template"]],
                    "template_version": body["template"] + ".v1",
                },
            )

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://choke")


class FakePool:
    """Captures the spectral_runs upsert; the PG twin is tests/test_jobs_pg.py."""

    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple]] = []

    @contextlib.asynccontextmanager
    async def acquire(self):
        pool = self

        class Conn:
            def transaction(self):
                return contextlib.nullcontext()

            async def execute(self, sql, *args):
                pool.executed.append((sql, args))

        yield Conn()


def _ctx(pool, base_url="http://choke", **settings) -> SimpleNamespace:
    return SimpleNamespace(
        pool=pool,
        settings=SimpleNamespace(
            querychoke_base_url=base_url,
            querychoke_token=SecretStr("svc"),
            http_timeout_s=1.0,
            **settings,
        ),
        tenant_id=TENANT,
        window_start=datetime(2026, 9, 15, tzinfo=UTC),
        day=date(2026, 9, 15),
    )


async def _run(rows: list[dict]) -> tuple[dict, FakeChoke]:
    choke, pool = FakeChoke(rows), FakePool()
    await nightly.spectral_estimate(_ctx(pool), http=choke.client())
    (sql, args), *rest = [e for e in pool.executed if "spectral_runs" in e[0]]
    assert not rest and "ON CONFLICT (tenant_id, window_start)" in sql
    assert args[0] == UUID(TENANT) and args[2] == nightly.SPECTRAL_WINDOW_DAYS
    return {
        "n_tasks": args[3],
        "passed": args[4],
        "diagnostics": json.loads(args[5]),
        "confusion": json.loads(args[6]),
        "prior": json.loads(args[7]),
    }, choke


def _evidence(passed: bool) -> CertEvidence:
    return CertEvidence(
        gold_n=250,
        fresh_frac=0.9,
        estimator_ran=True,
        identifiability_passed=passed,
        natarajan_ok=True,
    )


async def test_spectral_estimate_reaches_certified_on_planted_votes(simulate):
    votes, _ = simulate(np.random.default_rng(1), [0.4, 0.6], PAPER2, 5000)
    run, choke = await _run(vote_rows(votes))
    assert choke.requests == [
        (nightly.VOTES_TEMPLATE, {"from": "2026-08-17", "to": "2026-09-15"}, "Bearer svc")
    ]
    assert run["passed"] and run["n_tasks"] == 5000 and run["diagnostics"]["failed"] == []
    assert set(run["confusion"]) == set(NAMES) and len(run["prior"]) == 2
    assert abs(np.array(run["confusion"]["anchor"]) - PAPER2[2]).max() < 0.03
    assert run["diagnostics"]["anchor_separation"] > 10 and run["diagnostics"]["triple"]
    assert next_status(BOOTSTRAPPING, _evidence(run["passed"])) == CERTIFIED


async def test_degenerate_design_keeps_cert_bootstrapping(simulate):
    votes, _ = simulate(np.random.default_rng(3), [0.4, 0.6], PAPER2[:2], 5000)
    run, _ = await _run(vote_rows(votes, NAMES[:2]))  # two cliques: Thm 4.1 needs three (G1)
    assert not run["passed"] and "G1" in run["diagnostics"]["failed"]
    assert run["confusion"] == {} and run["prior"] is None
    assert run["diagnostics"]["sigma_min"] is None  # NaN lands as null, never as invalid jsonb
    assert next_status(BOOTSTRAPPING, _evidence(run["passed"])) == BOOTSTRAPPING


async def test_tampered_votes_quarantined_and_empty_window_is_honest(simulate):
    votes, _ = simulate(np.random.default_rng(1), [0.4, 0.6], PAPER2, 5000)
    run, _ = await _run(vote_rows(votes, tamper_verifier="anchor"))  # 06 §2.4
    assert not run["passed"] and "G1" in run["diagnostics"]["failed"]  # no anchor ⇒ two cliques
    run, _ = await _run([])
    assert run == {
        "n_tasks": 0,
        "passed": False,
        "diagnostics": {"n_tasks": 0, "failed": ["G1", "G3"]},
        "confusion": {},
        "prior": None,
    }


async def test_spectral_estimate_refuses_without_a_choke_url():
    with pytest.raises(RuntimeError, match="ADJ_QUERYCHOKE_BASE_URL"):
        await nightly.spectral_estimate(_ctx(FakePool(), base_url=""), http=FakeChoke([]).client())


def test_vote_matrix_codes_the_wire_vocabulary():
    rows = [
        {
            **VOTE_ROW,
            "verifier_id": "ruff@1",
            "family": "AnchorVote",
            "is_anchor": 1,
            "vote": "satisfied",
        },
        {
            **VOTE_ROW,
            "verifier_id": "judge:x@1",
            "family": "JudgeVote",
            "is_anchor": 0,
            "vote": "error",
        },
        {**VOTE_ROW, "verifier_id": "rm:x@1", "family": "RmScore", "is_anchor": 0, "vote": ""},
    ]
    votes, groups, anchors, verifiers = nightly.vote_matrix(rows)
    assert verifiers == ["judge:x@1", "rm:x@1", "ruff@1"]
    assert votes.tolist() == [[2, -1, 0]] and anchors == [False, False, True]
    assert groups == ["judges", "rms", "syntactic"]


GOLD_ROW = FIXTURE["gold_vs_verdict"][0]
PEPPER = bytes(range(32))


def _digest(session_id: str, task_id: str) -> bytes:
    """intel corpus/export.py tenant_root + task_digest verbatim (the one m1_021 definition),
    via cryptography's HKDF — the oracle nightly.py's stdlib derivation must equal."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    info = f"mark1-tenant-root-v1:{UUID(TENANT)}".encode()
    root = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(PEPPER)
    return hmac.new(root, UUID(session_id).bytes + UUID(task_id).bytes, hashlib.sha256).digest()


async def test_ledger_pairs_joins_gold_labels_to_stage_final_verdicts_by_task_digest():
    """The Natarajan input (06 §5.2): controld's `gold_vs_verdict` fixture rows (aliases locked
    on the Go side) joined to gold members on m1_021's task_digest — a certified ledger row pairs
    with its label, a provisional-only task and an unlabeled task pair with nothing."""
    now = datetime(2026, 9, 15, tzinfo=UTC)
    provisional = {
        **GOLD_ROW,
        "task_id": str(UUID(int=9)),
        "fused_verdict": "violated",
        "verdict_stage": "provisional",
    }
    unlabeled = {**GOLD_ROW, "task_id": str(UUID(int=10))}
    assert provisional.keys() == GOLD_ROW.keys() == unlabeled.keys()
    members = [
        nightly.GoldLabel(_digest(GOLD_ROW["session_id"], GOLD_ROW["task_id"]), "violated", now),
        nightly.GoldLabel(
            _digest(GOLD_ROW["session_id"], provisional["task_id"]), "satisfied", now
        ),
        nightly.GoldLabel(bytes(32), "satisfied", now),  # labeled, not in the ledger window
    ]
    choke = FakeChoke([], gold=[GOLD_ROW, provisional, unlabeled])
    ctx = _ctx(FakePool(), tenant_hmac_pepper=PEPPER.hex())
    pairs = await nightly._ledger_pairs(ctx, members, http=choke.client())
    assert pairs == [("violated", "satisfied")]
    assert choke.requests == [
        (nightly.GOLD_TEMPLATE, {"from": "2026-03-19", "to": "2026-09-15"}, "Bearer svc")
    ]
    # Wrong pepper ⇒ no digest matches ⇒ nothing measured, never a false pairing.
    ctx = _ctx(FakePool(), tenant_hmac_pepper=bytes(32).hex())
    assert await nightly._ledger_pairs(ctx, members, http=choke.client()) == []


async def test_ledger_pairs_without_a_pepper_or_members_is_unmeasured():
    choke = FakeChoke([], gold=[GOLD_ROW])
    member = nightly.GoldLabel(bytes(32), "satisfied", datetime(2026, 9, 15, tzinfo=UTC))
    assert await nightly._ledger_pairs(_ctx(FakePool()), [member], http=choke.client()) == []
    ctx = _ctx(FakePool(), tenant_hmac_pepper=PEPPER.hex())
    assert await nightly._ledger_pairs(ctx, [], http=choke.client()) == []
    assert choke.requests == []
