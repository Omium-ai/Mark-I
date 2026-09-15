"""conformance/e2e — the Phase-1 replay path, spanning real processes and real stores.

12 §1.1's `end-to-end` row: "agent fixture → edge → ingest → ledger → receipt → offline
verifier", the Phase-1 gate's first bullet (12 §12: golden hook fixtures + recorded
transcripts replayed through `mark1d` → `controld` → ClickHouse). The rig (rig.py) builds
the shipping binaries, boots `controld` against the store contract, enrolls a device with
the real `mark1 enroll` (fake tenant IdP), enables a workspace with the real `mark1 enable`,
runs the real `mark1-hookshim` per registered hook, lays the pinned transcripts where the
tailer looks, and waits for the uplink. Every test here reads the CLOUD side back.

Same inversion as conformance/tenancy: under ``M1_REQUIRE_STORES=1`` (the justfile default,
what CI exports) a missing or unreachable store is a hard failure, every skip is fatal at
session end, and zero collected tests is fatal. A leg the shipped binaries cannot complete
is a named ``pytest.fail`` carrying the seam — never a skip, never a pass by omission.
"""

from __future__ import annotations

import os

import pytest
from rig import REQUIRE_STORES, Rig

_skipped: list[str] = []


@pytest.fixture(scope="session")
def rig() -> Rig:
    """The one end-to-end drive; every test asserts against what it left in the stores."""
    for var in ("M1_TEST_PG_DSN", "M1_MIGRATE_PG_DSN", "M1_TEST_CH_DSN", "M1_TEST_S3_ENDPOINT"):
        if not os.environ.get(var):
            msg = f"{var} is unset — run `just test-e2e` (the justfile exports the store contract)"
            if REQUIRE_STORES:
                pytest.fail(msg, pytrace=False)
            pytest.skip(msg)
    r = Rig()
    try:
        r.drive()
    except BaseException:
        r.teardown()
        raise
    yield r
    r.teardown()


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped:
        reason = ""
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
            reason = report.longrepr[2]
        _skipped.append(f"{report.nodeid}: {reason}")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not REQUIRE_STORES:
        return
    if exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
        print(
            "\nconformance/e2e collected ZERO tests. The justfile's `test-e2e` and 12 §12 "
            "(Phase-1 gate, item 1) cite this directory as the mark1d→controld→ClickHouse "
            "replay evidence; an empty directory is that evidence gone."
        )
        return
    if _skipped:
        print(f"\nM1_REQUIRE_STORES=1 forbids skips in conformance/e2e — {len(_skipped)} skipped:")
        for entry in _skipped:
            print(f"  - {entry}")
        session.exitstatus = 1
