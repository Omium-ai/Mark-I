"""Registry + runner unit tests (06 §7.2/§7.3): ordering, loud validation, window arithmetic."""

from datetime import UTC, date, datetime

import pytest
from app.jobs import JOBS
from app.jobs.registry import Job, RegistryError, order, validate
from app.jobs.runner import window_for


def _pos(names: list[str], name: str) -> int:
    return names.index(name)


def test_registry_orders_extract_before_admit_before_compile():
    names = [j.name for j in order(JOBS)]
    assert _pos(names, "memory.extract") < _pos(names, "memory.admit")
    assert _pos(names, "memory.admit") < _pos(names, "policy_compiler.compile")
    assert set(names) == {j.name for j in JOBS}


def test_export_is_independent_of_compile():
    by_name = {j.name: j for j in JOBS}
    assert "policy_compiler.compile" not in by_name["corpus.export"].runs_after
    # Declared before compile with no edge, export stays before it: independence is real.
    jobs = (
        Job("corpus.export", "x:y", "nightly"),
        Job("memory.admit", "x:y", "nightly"),
        Job("policy_compiler.compile", "x:y", "nightly", ("memory.admit",)),
    )
    names = [j.name for j in order(jobs)]
    assert _pos(names, "corpus.export") < _pos(names, "policy_compiler.compile")


def test_registry_cadences_and_edges_are_well_formed():
    assert {j.cadence for j in JOBS} == {"nightly", "hourly"}
    assert {j.name for j in JOBS if j.cadence == "hourly"} == {"tvo.rollup_verify"}
    order(JOBS)  # no cycle, every runs_after resolves to a registered name


def test_missing_module_fails_at_validation():
    with pytest.raises(RegistryError, match=r"ghost: target 'app\.no_such_lane:run'"):
        validate([Job("ghost", "app.no_such_lane:run", "nightly")])


def test_missing_attr_fails_at_validation():
    with pytest.raises(RegistryError, match="ghost.*nope"):
        validate([Job("ghost", "app.jobs.registry:nope", "nightly")])


def test_validation_rejects_bad_graphs():
    with pytest.raises(RegistryError, match="unregistered"):
        validate([Job("a", "app.jobs.registry:order", "nightly", ("zzz",))])
    with pytest.raises(RegistryError, match="cycle"):
        validate(
            [
                Job("a", "app.jobs.registry:order", "nightly", ("b",)),
                Job("b", "app.jobs.registry:order", "nightly", ("a",)),
            ]
        )
    with pytest.raises(RegistryError, match="duplicate"):
        validate([Job("a", "app.jobs.registry:order", "nightly")] * 2)
    with pytest.raises(RegistryError, match="cadence"):
        validate([Job("a", "app.jobs.registry:order", "weekly")])
    assert validate([Job("a", "app.jobs.registry:order", "nightly")])["a"] is order


def test_window_for():
    now = datetime(2026, 9, 16, 3, 17, tzinfo=UTC)
    assert window_for("nightly", now) == datetime(2026, 9, 15, tzinfo=UTC)
    assert window_for("nightly", now, date(2026, 9, 1)) == datetime(2026, 9, 1, tzinfo=UTC)
    assert window_for("hourly", now) == datetime(2026, 9, 16, 2, tzinfo=UTC)
