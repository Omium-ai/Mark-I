"""conformance/tenancy — tenant-isolation negative tests (12 §4).

This file has two jobs, and the second is why it exists at all.

1. Hand every test in this directory a Postgres connection.
2. Make "passed" impossible to earn by not running.

Job 2 is the whole point. The estate's idiom is ``pytest.mark.skipif(no DSN)``,
which turns an absent store into a green run — and this repo's required suites
are the ones where green-because-skipped is indistinguishable from
green-because-verified. Under ``M1_REQUIRE_STORES=1`` (the justfile default,
and what CI exports) that idiom is **inverted**:

* a missing or unreachable ``M1_TEST_PG_DSN`` is a collection-time hard error,
* every skip in the session is fatal at session end,
* and collecting zero tests is fatal too.

That last one is not paranoia. ``conformance/tenancy/`` was an empty directory
while the justfile, ``12 §4`` and ``m1_060_roles_and_grants.sql``'s postcondition
comment all cited it as the thing that enforces SEC-04. Three citations, no
enforcement. An empty directory must be as loud as a failing test, or the next
deletion is silent in exactly the same way.

Set ``M1_REQUIRE_STORES=0`` to develop without stores. CI never does.
"""

from __future__ import annotations

import os

import asyncpg
import pytest

# ---------------------------------------------------------------------------
# Store contract (12 §11.4). The names come from the justfile, which is the one
# definition; nothing here invents a fallback DSN, because a fallback is how a
# suite ends up silently testing a different database than the one CI migrated.
# ---------------------------------------------------------------------------

REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "1") == "1"
PG_DSN = os.environ.get("M1_TEST_PG_DSN", "")

_skipped: list[str] = []


@pytest.fixture(scope="session")
def pg_dsn() -> str:
    if PG_DSN:
        return PG_DSN
    msg = (
        "M1_TEST_PG_DSN is unset. Run `just stores-up` (or export the DSN at a "
        "Postgres 15 you already have) — see the store contract at the top of "
        "the justfile."
    )
    if REQUIRE_STORES:
        pytest.fail(msg, pytrace=False)
    pytest.skip(msg)


@pytest.fixture
async def pg(pg_dsn: str):
    """A connection as whatever role the DSN names.

    Deliberately NOT an ``*_app`` role: the tests here read ``pg_roles`` and
    ``pg_policies`` cluster-wide, which is a question about the cluster, not a
    question asked from inside one tenant's session. Tests that need a tenant
    session open their own connection and set the GUC themselves, so the two
    postures can never be confused for one another.
    """
    try:
        conn = await asyncpg.connect(pg_dsn)
    except Exception as exc:  # unreachable store, wrong port, wrong credentials
        if REQUIRE_STORES:
            pytest.fail(
                f"M1_REQUIRE_STORES=1 and {pg_dsn!r} is unreachable: {exc!r}. "
                "A store that is down is a failing test, not a skipped one.",
                pytrace=False,
            )
        pytest.skip(f"Postgres unreachable: {exc!r}")
    try:
        yield conn
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# The zero-skip assertion the justfile promises: "its conftest asserts zero
# skips under M1_REQUIRE_STORES=1, so 'passed' cannot mean 'did not run'."
# ---------------------------------------------------------------------------


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped:
        reason = ""
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
            reason = report.longrepr[2]
        _skipped.append(f"{report.nodeid}: {reason}")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not REQUIRE_STORES:
        return

    # `pytest.ExitCode.NO_TESTS_COLLECTED` is already non-zero, so the run is
    # red either way — but a bare "no tests ran" reads like a path typo. Name
    # what it actually means here, because this directory's emptiness is a
    # security regression and it has happened once already.
    if exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
        print(
            "\nconformance/tenancy collected ZERO tests. This directory is cited as the "
            "enforcement point by the justfile (`test-isolation`), 12 §4, and the "
            "postcondition comment in m1_060_roles_and_grants.sql (SEC-04). If the tests "
            "are gone, those citations are false and must be deleted in the same commit."
        )
        return

    if _skipped:
        print(
            "\nM1_REQUIRE_STORES=1 forbids skips in conformance/tenancy — "
            f"{len(_skipped)} test(s) skipped:"
        )
        for entry in _skipped:
            print(f"  - {entry}")
        print(
            "A skipped isolation test is indistinguishable from a passing one in a CI "
            "summary, which is the entire failure this suite exists to prevent."
        )
        session.exitstatus = 1
