"""The registry's code-side half (06 §2.1–§2.4): normalization, the refusal
discipline, and the anti-tamper envelope fold."""

from uuid import uuid4

from app.registry.catalog import RegistryEntry
from app.registry.handlers import (
    _HANDLED_KINDS,
    VOTE_HANDLERS,
    RawVoteEvent,
    normalize_votes,
    votes_refused_total,
)

HASH = b"\x11" * 32


def entry(kind: str | None = "compile", exec_hash: bytes | None = HASH) -> RegistryEntry:
    return RegistryEntry(
        id=uuid4(),
        verifier_key="cargo-check-warm",
        version=1,
        db_kind="anchor",
        kind=kind,
        effective_execution_hash=exec_hash,
        retired=False,
    )


def raw(**kw) -> RawVoteEvent:
    defaults = dict(
        verifier_id="cargo-check-warm@1",
        kind="compile",
        task_id=uuid4(),
        attempt_id=uuid4(),
        verdict="satisfied",
        evidence_digest=b"\x22" * 32,
        execution_hash=HASH,
    )
    defaults.update(kw)
    return RawVoteEvent(**defaults)


def test_handlers_and_handled_kinds_are_the_same_fact():
    # probes.py rule — restated as a test so a drive-by edit cannot desync them.
    assert set(VOTE_HANDLERS) == set(_HANDLED_KINDS)


async def test_clean_anchor_vote_normalizes():
    votes, refusals = await normalize_votes([raw()], {"cargo-check-warm@1": entry()})
    assert not refusals
    (v,) = votes
    assert v.vote == "accept"
    assert v.tier == "T0"
    assert not v.integrity.tamper
    assert not v.integrity.infra_failed


async def test_hash_mismatch_is_tamper():
    votes, _ = await normalize_votes(
        [raw(execution_hash=b"\x99" * 32)], {"cargo-check-warm@1": entry()}
    )
    assert votes[0].integrity.tamper


async def test_missing_envelope_hash_is_tamper():
    # An anchor with nothing to compare is not a verified execution (06 §2.4).
    votes, _ = await normalize_votes([raw(execution_hash=None)], {"cargo-check-warm@1": entry()})
    assert votes[0].integrity.tamper


async def test_failed_env_scrub_is_tamper():
    votes, _ = await normalize_votes([raw(env_scrub_ok=False)], {"cargo-check-warm@1": entry()})
    assert votes[0].integrity.tamper


async def test_absent_merkle_root_is_infra_not_tamper():
    # Tamper-UNKNOWN semantics (proto AnchorIntegrity): never feeds certification,
    # but is not an accusation — it rides as event E, not as tamper.
    votes, _ = await normalize_votes(
        [raw(merkle_root_present=False)], {"cargo-check-warm@1": entry()}
    )
    assert not votes[0].integrity.tamper
    assert votes[0].integrity.infra_failed


async def test_suppression_delta_vote_stands_annotated():
    votes, _ = await normalize_votes([raw(suppression_delta=2)], {"cargo-check-warm@1": entry()})
    assert votes[0].integrity.suppression_delta == 2
    assert not votes[0].integrity.tamper  # stands — suppressions can be legitimate


async def test_wire_error_verdict_is_uninformative_abstain():
    votes, _ = await normalize_votes([raw(verdict="error")], {"cargo-check-warm@1": entry()})
    assert votes[0].vote == "abstain"
    assert votes[0].integrity.infra_failed


async def test_unimplemented_kind_is_refused_never_faked():
    before = votes_refused_total["quantum-vibes"]
    votes, refusals = await normalize_votes(
        [raw(kind="quantum-vibes")],
        {"cargo-check-warm@1": entry(kind="quantum-vibes")},
    )
    assert votes == []  # no synthetic vote
    (r,) = refusals  # no silent drop
    assert r.refusal is True
    assert r.reason == "refused_unimplemented_kind:quantum-vibes"
    assert votes_refused_total["quantum-vibes"] == before + 1


async def test_unknown_verifier_is_refused():
    votes, refusals = await normalize_votes([raw()], {})
    assert votes == []
    assert refusals[0].reason == "refused_unknown_verifier"


async def test_judge_vote_has_no_envelope_and_t1_tier():
    e = RegistryEntry(
        id=uuid4(),
        verifier_key="judge:rubric-a1f3",
        version=2,
        db_kind="judge",
        kind="judge",
        effective_execution_hash=None,
        retired=False,
    )
    votes, refusals = await normalize_votes(
        [raw(verifier_id="judge:rubric-a1f3@2", kind="judge", verdict="violated")],
        {"judge:rubric-a1f3@2": e},
    )
    assert not refusals
    assert votes[0].vote == "reject"
    assert votes[0].tier == "T1"
    assert not votes[0].integrity.tamper
