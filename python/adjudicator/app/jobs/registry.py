"""Job registry (06 §7.2): name → dotted target, cadence, runs_after; resolved at validate()."""

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter

CADENCES = frozenset({"nightly", "hourly"})


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class Job:
    name: str
    target: str  # "pkg.module:attr" — an async callable (ctx) -> receipt_id | None
    cadence: str
    runs_after: tuple[str, ...] = ()


def resolve(job: Job) -> Callable:
    module, _, attr = job.target.partition(":")
    try:
        fn = getattr(importlib.import_module(module), attr)
    except (ImportError, AttributeError) as exc:
        raise RegistryError(f"{job.name}: target {job.target!r} does not resolve: {exc}") from exc
    if not callable(fn):
        raise RegistryError(f"{job.name}: target {job.target!r} is not callable")
    return fn


def order(jobs: Iterable[Job]) -> list[Job]:
    """runs_after-respecting order, stable in declaration order among independents."""
    by_name = {j.name: j for j in jobs}
    try:
        names = list(
            TopologicalSorter({j.name: j.runs_after for j in by_name.values()}).static_order()
        )
    except CycleError as exc:
        raise RegistryError(f"runs_after cycle: {exc.args[1]}") from exc
    return [by_name[n] for n in names if n in by_name]


def validate(jobs: Iterable[Job]) -> dict[str, Callable]:
    """Everything that can fail at deploy time instead of at 3 am, including target imports."""
    jobs = list(jobs)
    names = [j.name for j in jobs]
    if len(set(names)) != len(names):
        raise RegistryError(
            f"duplicate job names: {sorted(n for n in names if names.count(n) > 1)}"
        )
    for j in jobs:
        if j.cadence not in CADENCES:
            raise RegistryError(f"{j.name}: unknown cadence {j.cadence!r}")
        for dep in j.runs_after:
            if dep not in names:
                raise RegistryError(f"{j.name}: runs_after unregistered job {dep!r}")
    order(jobs)
    targets, errors = {}, []
    for j in jobs:
        try:
            targets[j.name] = resolve(j)
        except RegistryError as exc:
            errors.append(str(exc))
    if errors:
        raise RegistryError("; ".join(errors))
    return targets
