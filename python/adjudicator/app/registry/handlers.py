"""The code-side half of the registry (06 §2.1): per-kind vote normalizers — raw
AnchorVote/JudgeVote/RmScore ledger events → the canonical NormalizedVote ADJUDICATE
consumes. The registry table and the handled set are the same fact stated twice, kept
in lockstep the probes.py way: asserts at import, refusal for everything else.

06 §2.2, imported whole: a vote whose kind has no handler produces NO synthetic vote
and NO silent drop — it is recorded as a refusal ({refusal: true, reason:
"refused_unimplemented_kind:<kind>"}), excluded from the ensemble, and counted. A
refusal is a statement about Mark 1; a `reject` vote is a statement about the
customer's code; the two must never be confusable in the record."""

from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from app.registry.catalog import RegistryEntry
from app.registry.integrity import IntegrityFlags, anchor_integrity

KIND_LINT = "lint"
KIND_TYPECHECK = "typecheck"
KIND_COMPILE = "compile"
KIND_TEST = "test"
KIND_JUDGE = "judge"
KIND_RM = "rm"  # T2 reward model (Phase 6; registered, gated)
KIND_CONSISTENCY = "consistency"  # escalation-scoped only (C1.16)

_HANDLED_KINDS = frozenset(
    {KIND_LINT, KIND_TYPECHECK, KIND_COMPILE, KIND_TEST, KIND_JUDGE, KIND_RM, KIND_CONSISTENCY}
)
# Kinds this build knows OF but refuses to interpret. Empty in Phase 2 — kept (with its
# assert below) because the refusal discipline is structural, not situational.
_REFUSED_KINDS: frozenset[str] = frozenset()

# Wire Verdict (proto m1p.v1, artifacts.proto) → ensemble vote. A raw `error` verdict
# is the anchor run itself failing — Paper II's observable event E: it normalizes to an
# uninformative abstain carrying infra_failed, never to a statement about the code.
_WIRE_VOTE = {
    "satisfied": "accept",
    "violated": "reject",
    "refused": "abstain",
    "error": "abstain",
}

_KIND_TIER = {
    KIND_LINT: "T0",
    KIND_TYPECHECK: "T0",
    KIND_COMPILE: "T0",
    KIND_TEST: "T0",
    KIND_JUDGE: "T1",
    KIND_RM: "T2",
    KIND_CONSISTENCY: "T3",
}


@dataclass(frozen=True)
class RawVoteEvent:
    """One vote row as read from the ledger (wire truth: proto/m1p/v1/verify.proto;
    identity fields ride on m1p.v1.Event and are joined in by the reader)."""

    verifier_id: str  # "ruff@1", "judge:rubric-a1f3@2" — the registry key
    kind: str  # catalog kind, hopefully one of _HANDLED_KINDS
    task_id: UUID
    attempt_id: UUID
    verdict: str  # wire Verdict name: satisfied|violated|refused|error
    evidence_digest: bytes  # HMAC-salted; joins to EvidenceRecord.output_hmac
    # Anchor envelope (AnchorIntegrity) — None/defaults for judge/rm/consistency.
    execution_hash: bytes | None = None
    env_scrub_ok: bool = True
    merkle_root_present: bool = True
    suppression_delta: int = 0
    envelope_tamper: bool = False


@dataclass(frozen=True)
class NormalizedVote:
    """06 §2.1's canonical shape, verbatim fields."""

    verifier_id: str
    kind: str
    task_id: UUID
    attempt_id: UUID
    vote: Literal["accept", "reject", "abstain"]
    evidence_digest: bytes
    integrity: IntegrityFlags
    tier: Literal["T0", "T1", "T2", "T3"]
    column: str = ""  # 16 §L7 law key, votes.column_of (`<id>/E0`: E0 fallback); "" = verifier_id
    group: str = ""  # that column's correlation group, votes.groups_of; "" = the kind's

    @property
    def law_id(self) -> str:
        return self.column or self.verifier_id


@dataclass(frozen=True)
class Refusal:
    """06 §2.2's refusal record — about Mark 1, never about the customer's code."""

    verifier_id: str
    kind: str
    reason: str
    detail: str
    refusal: bool = True


# The `verifier_votes_refused_total` metric (06 §2.2), scraped by whatever metrics
# surface lands later; a Counter so tests can assert the discipline held.
votes_refused_total: Counter[str] = Counter()


def _vote_and_infra(raw: RawVoteEvent) -> tuple[str, bool]:
    vote = _WIRE_VOTE[raw.verdict]  # KeyError on a non-wire verdict is a caller bug
    return vote, raw.verdict == "error"


async def _normalize_anchor(raw: RawVoteEvent, entry: RegistryEntry) -> NormalizedVote:
    vote, infra = _vote_and_infra(raw)
    flags = anchor_integrity(
        envelope_hash=raw.execution_hash,
        registry_hash=entry.effective_execution_hash,
        env_scrub_ok=raw.env_scrub_ok,
        merkle_root_present=raw.merkle_root_present,
        suppression_delta=raw.suppression_delta,
        envelope_tamper=raw.envelope_tamper,
        run_errored=infra,
    )
    return NormalizedVote(
        verifier_id=raw.verifier_id,
        kind=raw.kind,
        task_id=raw.task_id,
        attempt_id=raw.attempt_id,
        vote=vote,  # type: ignore[arg-type]
        evidence_digest=raw.evidence_digest,
        integrity=flags,
        tier="T0",
    )


async def _normalize_plain(raw: RawVoteEvent, entry: RegistryEntry) -> NormalizedVote:
    """Judges/RMs/consistency: no execution envelope — their identity is their
    definition (m1_020's anchor-hash equivalence CHECK), so there is no hash to check."""
    vote, infra = _vote_and_infra(raw)
    return NormalizedVote(
        verifier_id=raw.verifier_id,
        kind=raw.kind,
        task_id=raw.task_id,
        attempt_id=raw.attempt_id,
        vote=vote,  # type: ignore[arg-type]
        evidence_digest=raw.evidence_digest,
        integrity=IntegrityFlags(infra_failed=infra),
        tier=_KIND_TIER[raw.kind],  # type: ignore[arg-type]
    )


VoteHandler = Callable[[RawVoteEvent, RegistryEntry], Awaitable[NormalizedVote]]

VOTE_HANDLERS: dict[str, VoteHandler] = {
    KIND_LINT: _normalize_anchor,  # ruff, eslint-class
    KIND_TYPECHECK: _normalize_anchor,  # incremental tsc, mypy-class
    KIND_COMPILE: _normalize_anchor,  # warm cargo check, go build
    KIND_TEST: _normalize_anchor,  # opt-in test anchors
    KIND_JUDGE: _normalize_plain,  # 06 §6
    KIND_RM: _normalize_plain,  # T2 reward model (Phase 6; registered, gated)
    KIND_CONSISTENCY: _normalize_plain,  # escalation-scoped only (C1.16)
}

# The registry and the handled set are the same fact stated twice (probes.py rule).
assert set(VOTE_HANDLERS) == set(_HANDLED_KINDS)
assert not (set(VOTE_HANDLERS) & _REFUSED_KINDS)


async def normalize_votes(
    raws: list[RawVoteEvent],
    registry: dict[str, RegistryEntry],
) -> tuple[list[NormalizedVote], list[Refusal]]:
    """Every raw event becomes exactly one NormalizedVote or one Refusal — never
    a synthetic vote, never a silent drop (06 §2.2)."""
    votes: list[NormalizedVote] = []
    refusals: list[Refusal] = []
    for raw in raws:
        entry = registry.get(raw.verifier_id)
        if entry is None:
            refusals.append(
                Refusal(
                    verifier_id=raw.verifier_id,
                    kind=raw.kind,
                    reason="refused_unknown_verifier",
                    detail=f"{raw.verifier_id!r} has no m1_verifiers row",
                )
            )
            votes_refused_total[raw.kind] += 1
            continue
        handler = VOTE_HANDLERS.get(raw.kind)
        if handler is None or raw.kind in _REFUSED_KINDS:
            refusals.append(
                Refusal(
                    verifier_id=raw.verifier_id,
                    kind=raw.kind,
                    reason=f"refused_unimplemented_kind:{raw.kind}",
                    detail="a handler that never reads anything is a refusal wearing "
                    "a handler's registration (06 §2.2)",
                )
            )
            votes_refused_total[raw.kind] += 1
            continue
        votes.append(await handler(raw, entry))
    return votes, refusals
