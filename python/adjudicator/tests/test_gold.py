"""Gold-set mechanics (06 §5.1): stratified selection with the D14 repo cap, the
D16/D17 freshness arithmetic, and quota-preserving rotation."""

import random
from datetime import UTC, datetime, timedelta

import pytest
from app.gold.rotate import GoldLabel, fresh_fraction, rotate_oldest_out, scoring_window
from app.gold.select import REPO_CAP_FRAC, CandidateTask, select_gold_candidates

NOW = datetime(2026, 8, 30, tzinfo=UTC)


def cand(i: int, verdict="satisfied", agent="claudecode", repo=b"\x01" * 32) -> CandidateTask:
    return CandidateTask(
        task_digest=i.to_bytes(32, "big"),
        verdict_class=verdict,
        agent=agent,
        repo_digest=repo,
        completed_at=NOW - timedelta(hours=i),
    )


def test_repo_cap_d14_bounds_any_single_repo():
    mono = [cand(i) for i in range(100)]  # 100 candidates, ONE repo digest
    picked = select_gold_candidates(mono, target_n=10, rng=random.Random(7))
    # ≤ 30% of the set from any one repo digest — the set comes back SHORT rather
    # than over-concentrated.
    assert len(picked) == int(REPO_CAP_FRAC * 10)


def test_stratified_across_classes_and_repos():
    # 3 verdict classes × 4 repos per class = enough diversity to fill target under D14.
    candidates = (
        [cand(i, verdict="satisfied", repo=bytes([i % 4]) * 32) for i in range(40)]
        + [cand(100 + i, verdict="violated", repo=bytes([4 + i % 4]) * 32) for i in range(40)]
        + [cand(200 + i, verdict="refused", repo=bytes([8 + i % 4]) * 32) for i in range(40)]
    )
    picked = select_gold_candidates(candidates, target_n=9, rng=random.Random(7))
    assert len(picked) == 9
    classes = {c.verdict_class for c in picked}
    assert classes == {"satisfied", "violated", "refused"}
    repo_counts: dict[bytes, int] = {}
    for c in picked:
        repo_counts[c.repo_digest] = repo_counts.get(c.repo_digest, 0) + 1
    assert max(repo_counts.values()) <= max(1, int(0.30 * 9))


def test_selection_is_deterministic_under_a_seed():
    candidates = [cand(i, repo=bytes([i % 7]) * 32) for i in range(50)]
    a = select_gold_candidates(candidates, 12, random.Random(42))
    b = select_gold_candidates(candidates, 12, random.Random(42))
    assert [c.task_digest for c in a] == [c.task_digest for c in b]


def test_target_n_must_be_positive():
    with pytest.raises(ValueError):
        select_gold_candidates([], 0, random.Random(1))


def label(days_old: float, cls="satisfied", i=0) -> GoldLabel:
    return GoldLabel(
        task_digest=(i + int(days_old * 100)).to_bytes(32, "big"),
        true_label=cls,
        labeled_at=NOW - timedelta(days=days_old),
    )


def test_scoring_window_drops_labels_older_than_90_days():
    members = [label(10), label(89), label(91), label(365)]
    kept = scoring_window(members, NOW)
    assert len(kept) == 2  # D17: >90d leaves the window ENTIRELY


def test_fresh_fraction_is_the_d16_numerator():
    members = [label(5), label(10), label(45), label(60)]
    assert fresh_fraction(members, NOW) == pytest.approx(0.5)
    # >90d labels don't dilute the fraction — they are not in the window at all.
    members.append(label(120))
    assert fresh_fraction(members, NOW) == pytest.approx(0.5)


def test_fresh_fraction_of_empty_window_is_zero():
    assert fresh_fraction([], NOW) == 0.0
    assert fresh_fraction([label(120)], NOW) == 0.0


def test_rotation_is_oldest_out_preserving_class_quotas():
    members = [label(d, cls="satisfied", i=1) for d in range(1, 61)] + [
        label(d, cls="violated", i=2) for d in range(1, 31)
    ]
    kept = rotate_oldest_out(members, max_size=30)
    assert len(kept) == 30
    by_class = {"satisfied": 0, "violated": 0}
    for m in kept:
        by_class[m.true_label] += 1
    # 2:1 mix preserved (largest remainder): 20 satisfied, 10 violated.
    assert by_class == {"satisfied": 20, "violated": 10}
    # Oldest-out: everything kept is newer than everything dropped, per class.
    for cls, quota_newest_days in (("satisfied", 20), ("violated", 10)):
        ages = sorted((NOW - m.labeled_at).days for m in kept if m.true_label == cls)
        assert ages == list(range(1, quota_newest_days + 1))


def test_rotation_noop_under_capacity():
    members = [label(d) for d in range(1, 11)]
    assert rotate_oldest_out(members, 30) == members
