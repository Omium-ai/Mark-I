"""T3 certified runs (06 §2.5 tier T3; 14 task 6.5). An escalated task's E1 evidence is
materialised into a rented microVM, the repo's declared test anchor is run there by
catalog id (argv from the table below, never from a bundle — CON-009), and the result
comes back as a T3 anchor-class vote plus the ConsistencyVote FR-VERIFY-017 scopes to
escalation. A rented sandbox is a cloud subprocessor: the run is admitted through the
judges' consent gate (06 §6.5 preconditions 1-4) and refused without it."""

import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from uuid import UUID

import asyncpg
import httpx
from m1p.v1 import ConsistencyVote, Verdict
from mark1_receipts import canonical_json

from app.certified.e2b import E2BClient, RunResult
from app.db import set_local_tenant
from app.judges.cloud_path import Consent, admit
from app.judges.specs import Tier, refuse
from app.registry.catalog import RegistryEntry
from app.registry.handlers import (
    KIND_CONSISTENCY,
    KIND_TEST,
    NormalizedVote,
    RawVoteEvent,
    Refusal,
    normalize_votes,
)

PROVIDER = "e2b"
CONSENT_ID = f"t3:{PROVIDER}@1"  # the m1_065 register key (m1_074 admits the t3: prefix)
CONSISTENCY_ID = "consistency:t3-rerun@1"
HOME = "/home/user"
REPO = f"{HOME}/repo"
ARCHIVE = f"{HOME}/repo.tar"
EXTRACT = ["tar", "-xf", ARCHIVE, f"--one-top-level={REPO}"]

# The edge's four test-class catalog rows (mark1d anchors/catalog.go), argv + fail line verbatim.
TEST_ANCHORS: dict[str, tuple[list[str], re.Pattern[str]]] = {
    "pytest@cat-1": (["pytest", "-q", "-p", "no:cacheprovider"], re.compile(r"^FAILED \S")),
    "go-test@cat-1": (["go", "test", "./..."], re.compile(r"^--- FAIL: ")),
    "cargo-test@cat-1": (
        ["cargo", "test", "--quiet", "--no-fail-fast"],
        re.compile(r"^test \S+ \.\.\. FAILED$"),
    ),
    "npm-test@cat-1": (["npm", "test", "--silent"], re.compile(r"^(not ok \d+|[✕✗×] )")),
}


@dataclass(frozen=True)
class SandboxSpec:
    """The four fields admit() reads, for a cloud path that is not a judge."""

    judge_id: str
    evidence_tier: Tier
    subprocessor: str
    region: str


def definition(anchor_id: str, template: str) -> dict:
    """The m1_verifiers definition of `t3:<anchor_id>`; its hash is the run's envelope."""
    return {
        "kind": KIND_TEST,
        "locus": PROVIDER,
        "template": template,
        "argv": TEST_ANCHORS[anchor_id][0],
    }


def execution_hash(anchor_id: str, template: str) -> bytes:
    return hashlib.sha256(canonical_json(definition(anchor_id, template)).encode()).digest()


def verdict_of(res: RunResult | None, fail_line: re.Pattern[str]) -> str:
    """The edge's lineHandler mapping: clean exit ⇒ satisfied; a parsed failure ⇒
    violated; anything else is the tool (or the sandbox) failing ⇒ error, never violated."""
    if res is None:
        return "error"
    if res.exit_code == 0:
        return "satisfied"
    text = (res.stdout + b"\n" + res.stderr).decode(errors="replace")
    return "violated" if any(fail_line.match(ln.strip()) for ln in text.split("\n")) else "error"


def divergence(edge_verdict: str, certified: str) -> int:
    """Signed anchor-vs-T3 (10 §11.3): +1 = the edge accepted what the certified
    environment rejects (the reward-hacking direction), -1 = the reverse, 0 otherwise —
    an infra failure on either side is not a divergence claim."""
    if edge_verdict == "satisfied" and certified == "violated":
        return 1
    if edge_verdict == "violated" and certified == "satisfied":
        return -1
    return 0


@dataclass(frozen=True)
class RunRow:
    tenant_id: UUID
    consent_id: UUID
    task_id: UUID
    attempt_id: UUID
    anchor_id: str
    sandbox_id: str | None
    evidence_tier: str
    execution_hash: bytes
    exit_code: int | None
    verdict: str
    edge_verdict: str
    provisional: str
    divergence: int
    started_at: datetime


@dataclass(frozen=True)
class CertifiedRun:
    run_id: UUID
    sandbox_id: str | None
    verdict: str
    exit_code: int | None
    divergence: int
    tenant_divergence: float
    votes: list[NormalizedVote]  # the T3 anchor-class vote + the consistency vote
    refusals: list[Refusal]
    consistency: ConsistencyVote


T3ConsentReader = Callable[[UUID, str], Awaitable[tuple[UUID, Consent] | None]]
ArchiveReader = Callable[[UUID, UUID, str], Awaitable[bytes]]
RunRecorder = Callable[[RunRow], Awaitable[tuple[UUID, float]]]


def pg_t3_consent_reader(pool: asyncpg.Pool) -> T3ConsentReader:
    """cloud_path.pg_consent_reader plus the row id the run row cites (m1_074 FK)."""

    async def read(tenant_id: UUID, key: str) -> tuple[UUID, Consent] | None:
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(tenant_id))
            row = await conn.fetchrow(
                """
                SELECT id, subprocessor, region, max_tier FROM m1_cloud_judge_consents
                WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL
                """,
                tenant_id,
                key,
            )
        if row is None:
            return None
        return row["id"], Consent(row["subprocessor"], row["region"], row["max_tier"])

    return read


def pg_run_recorder(pool: asyncpg.Pool) -> RunRecorder:
    async def record(r: RunRow) -> tuple[UUID, float]:
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(r.tenant_id))
            row = await conn.fetchrow(
                """
                INSERT INTO m1_certified_runs
                  (tenant_id, consent_id, task_id, attempt_id, anchor_id, provider, sandbox_id,
                   evidence_tier, execution_hash, exit_code, verdict, edge_verdict, provisional,
                   divergence, tenant_divergence, started_at)
                SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::smallint,
                       (COALESCE(SUM(divergence), 0) + $14::smallint)::numeric / (COUNT(*) + 1), $15
                FROM m1_certified_runs WHERE tenant_id = $1
                RETURNING id, tenant_divergence
                """,
                r.tenant_id,
                r.consent_id,
                r.task_id,
                r.attempt_id,
                r.anchor_id,
                PROVIDER,
                r.sandbox_id,
                r.evidence_tier,
                r.execution_hash,
                r.exit_code,
                r.verdict,
                r.edge_verdict,
                r.provisional,
                r.divergence,
                r.started_at,
            )
        return row["id"], float(row["tenant_divergence"])

    return record


class CertifiedRunner:
    """`consent_for` reads m1_065 by the t3 key; `archive_for` assembles the tier-bounded
    tar of the worktree — injected because the ledger read lives behind controld's query
    choke (as cloud_path's evidence_for is); `record` writes m1_074; `registry` is the
    m1_verifiers view normalize_votes keys on."""

    def __init__(
        self,
        sandbox: E2BClient,
        consent_for: T3ConsentReader,
        archive_for: ArchiveReader,
        record: RunRecorder,
        registry: dict[str, RegistryEntry],
        template: str,
        region: str,
    ) -> None:
        self._sandbox = sandbox
        self._consent_for = consent_for
        self._archive_for = archive_for
        self._record = record
        self._registry = registry
        self._template = template
        self._region = region

    async def run(
        self,
        tenant_id: UUID,
        task_id: UUID,
        attempt_id: UUID,
        anchor_id: str,
        tier: Tier,
        edge_verdict: str,
        provisional: str,
    ) -> CertifiedRun:
        if tier == "E0":
            raise refuse("refused_tier_e0_no_code", "E0 is typed diagnostics; nothing to run")
        anchor = TEST_ANCHORS.get(anchor_id)
        if anchor is None:
            raise refuse(f"refused_unregistered_anchor:{anchor_id}", "not a test-class catalog id")
        found = await self._consent_for(tenant_id, CONSENT_ID)
        admit(SandboxSpec(CONSENT_ID, tier, PROVIDER, self._region), found[1] if found else None)
        consent_id = found[0]  # type: ignore[index]
        archive = await self._archive_for(task_id, attempt_id, tier)
        started = datetime.now(UTC)
        sandbox_id, res = None, None
        try:
            sb = await self._sandbox.create()
            sandbox_id = sb.id
            try:
                await self._sandbox.upload(sb, ARCHIVE, archive)
                if (await self._sandbox.run(sb, EXTRACT, cwd=HOME)).exit_code == 0:
                    res = await self._sandbox.run(sb, anchor[0], cwd=REPO)
            finally:
                await self._sandbox.destroy(sb)
        except httpx.HTTPError:
            res = None  # Thm 5.2: an unobservable outcome is `error`, never `violated`
        verdict = verdict_of(res, anchor[1])
        d = divergence(edge_verdict, verdict)
        xh = execution_hash(anchor_id, self._template)
        run_id, tenant_div = await self._record(
            RunRow(
                tenant_id=tenant_id,
                consent_id=consent_id,
                task_id=task_id,
                attempt_id=attempt_id,
                anchor_id=anchor_id,
                sandbox_id=sandbox_id,
                evidence_tier=tier,
                execution_hash=xh,
                exit_code=res.exit_code if res else None,
                verdict=verdict,
                edge_verdict=edge_verdict,
                provisional=provisional,
                divergence=d,
                started_at=started,
            )
        )
        # ponytail: sha256 not HMAC_tenant; no Python resolver for m1_001's hmac salt exists yet
        digest = hashlib.sha256(res.stdout + res.stderr if res else b"").digest()
        raws = [
            RawVoteEvent(f"t3:{anchor_id}", KIND_TEST, task_id, attempt_id, verdict, digest, xh),
            RawVoteEvent(CONSISTENCY_ID, KIND_CONSISTENCY, task_id, attempt_id, verdict, digest),
        ]
        votes, refusals = await normalize_votes(raws, self._registry)
        return CertifiedRun(
            run_id=run_id,
            sandbox_id=sandbox_id,
            verdict=verdict,
            exit_code=res.exit_code if res else None,
            divergence=d,
            tenant_divergence=tenant_div,
            votes=[replace(v, tier="T3") for v in votes],
            refusals=refusals,
            consistency=ConsistencyVote(
                vote=Verdict[verdict.upper()],
                sample_count=1,
                agreement_rate=1.0 if verdict == provisional else 0.0,
            ),
        )
