"""SEC-04 — no login role reaches BYPASSRLS or SUPERUSER outside a hard-coded list.

`m1_060_roles_and_grants.sql`'s postcondition names this file:

    Deliberately NOT enforced here: that current_user (the migration role) is
    unprivileged. On RDS the bootstrap apply legitimately runs as the master.
    conformance/tenancy/ owns the allow-list assertion over the whole cluster
    (RECONCILIATION SEC-04: `SELECT rolname FROM pg_roles WHERE rolcanlogin
    AND (rolbypassrls OR rolsuper)` must equal a hard-coded list) -- an
    allow-list, not the `*_app` naming convention, which is a habit and not a
    predicate.

WHY AN ALLOW-LIST AND NOT A PATTERN. The estate's RLS was decorative for 61
FORCE-RLS tables because the connecting role inherited `rds_superuser`, and
BYPASSRLS came with it. Nothing about that role's *name* was wrong; a predicate
over names would have passed. Only an enumeration of who is allowed to be
privileged catches a new privileged role, because a new privileged role is
precisely the thing that has no name you thought of in advance.

WHY TWO PRIVILEGES, LISTED SEPARATELY. SEC-04's one-line query ORs them, but
they are not one property. `mark1_federation_worker` is BYPASSRLS **by design**
(m1_060 §62: "THE one bypass" — the (k,m) `count(DISTINCT tenant_id)` a
per-tenant GUC loop cannot compute), and m1_060 §7(b) separately asserts it must
never hold or inherit SUPERUSER. One merged list would waive both for it and
silently accept the escalation that migration explicitly refuses.

WHY TWO QUERIES. The literal SEC-04 text is an **attribute** query. The incident
was **membership** — privilege arriving through `GRANT rds_superuser TO ...`,
where the role's own attributes stay clean and `ALTER ROLE ... NOBYPASSRLS`
repairs nothing. A test running only the literal query would reproduce the exact
blind spot m1_060's comment spends a paragraph warning about, so this file runs
the attribute query for traceability to SEC-04 *and* the resolution query that
is the real control. `pg_has_role(member, grantee, 'USAGE')` is true when
privileges are actually inherited and true for a role against itself, so one
predicate spans both cases — the same predicate m1_060 §7(a) uses.
"""

from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# THE ALLOW-LISTS. Editing these is the point: a newly privileged login role
# must arrive as a reviewed diff in a security test, not as a silent fact about
# a cluster.
#
# Profile is explicit, never sniffed. Sniffing means an unrecognised cluster
# picks a list on its own, which is fail-open inside a fail-closed control.
# ---------------------------------------------------------------------------

# `local` covers both ways this repo's clusters get built: `just stores-up` runs
# `initdb -U mark1` (so `mark1` is the bootstrap superuser and no `postgres`
# role exists), while a container image ships `postgres`. Both names are listed
# because both are legitimately the migration runner; neither is required to
# exist. A name that is allowed but absent costs nothing — the assertions below
# are subset checks, so an unused entry can never turn a red run green.
SUPERUSER_ALLOWED: dict[str, frozenset[str]] = {
    "local": frozenset({"postgres", "mark1"}),
    # RDS PG15: `rdsadmin` is AWS's own and cannot be dropped; the master user
    # holds rds_superuser and runs the Argo migration Job.
    "rds": frozenset({"rdsadmin", "omium_master"}),
}

# BYPASSRLS is the wider list: it is everything above (a superuser bypasses RLS
# whether or not the attribute is set) plus the one role designed to have it.
BYPASSRLS_EXTRA: frozenset[str] = frozenset({"mark1_federation_worker"})

# The request-path roles. None may appear in any result, ever — asserted
# separately from the allow-lists so that adding one to a list does not waive it.
APP_ROLES = frozenset({"controld_app", "adjudicator_app", "intel_app"})

PROFILE = os.environ.get("M1_PG_PROFILE", "local")

Q_SUPER_ATTR = "SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolsuper"
Q_BYPASS_ATTR = "SELECT rolname FROM pg_roles WHERE rolcanlogin AND (rolbypassrls OR rolsuper)"

# The same questions asked as privilege RESOLVES, which is how the estate's
# failure actually arrived. `{attr}` is substituted from the two constants
# below, never from anything reaching this module from outside it.
Q_RESOLVED = """
SELECT r.rolname
  FROM pg_roles r
 WHERE r.rolcanlogin
   AND EXISTS (SELECT 1 FROM pg_roles g
                WHERE {attr}
                  AND pg_has_role(r.rolname, g.oid, 'USAGE'))
"""
ATTR_SUPER = "g.rolsuper"
ATTR_BYPASS = "(g.rolbypassrls OR g.rolsuper)"


def _superusers() -> frozenset[str]:
    try:
        return SUPERUSER_ALLOWED[PROFILE]
    except KeyError:
        pytest.fail(
            f"M1_PG_PROFILE={PROFILE!r} has no allow-list. Add one to SUPERUSER_ALLOWED in "
            f"this file (known: {sorted(SUPERUSER_ALLOWED)}). An unknown cluster does not "
            "get a default — that would make a fail-closed control fail open.",
            pytrace=False,
        )


def _bypassers() -> frozenset[str]:
    return _superusers() | BYPASSRLS_EXTRA


def _fail_message(kind: str, unexpected: set[str], via: str) -> str:
    return (
        f"login role(s) {via} {kind} outside the {PROFILE!r} allow-list: {sorted(unexpected)}. "
        "Either the privilege should not exist, or this file's allow-list should be edited "
        "as a reviewed change. Do not widen it to make a run green."
    )


async def test_sec04_superuser_attribute(pg) -> None:
    found = {r["rolname"] for r in await pg.fetch(Q_SUPER_ATTR)}
    unexpected = found - _superusers()
    assert not unexpected, _fail_message("SUPERUSER", unexpected, "hold")


async def test_sec04_bypassrls_attribute(pg) -> None:
    """SEC-04 as literally written, for traceability to the reconciliation item."""
    found = {r["rolname"] for r in await pg.fetch(Q_BYPASS_ATTR)}
    unexpected = found - _bypassers()
    assert not unexpected, _fail_message("BYPASSRLS", unexpected, "hold")


async def test_sec04_superuser_membership(pg) -> None:
    """The escalation m1_060 §7(b) refuses, checked cluster-wide.

    `mark1_federation_worker` is exempt from the BYPASSRLS list below but NOT
    from this one: it may bypass RLS and may never be, or inherit, a superuser.
    """
    found = {r["rolname"] for r in await pg.fetch(Q_RESOLVED.format(attr=ATTR_SUPER))}
    unexpected = found - _superusers()
    assert not unexpected, _fail_message("SUPERUSER", unexpected, "REACH")


async def test_sec04_bypassrls_membership(pg) -> None:
    """The control that would have caught the estate's actual incident.

    Privilege inherited through role membership leaves the member's own
    attributes clean, so this is a strict superset of the attribute query and
    the only one of the two that sees `GRANT rds_superuser TO some_app`.
    """
    found = {r["rolname"] for r in await pg.fetch(Q_RESOLVED.format(attr=ATTR_BYPASS))}
    unexpected = found - _bypassers()
    assert not unexpected, _fail_message("BYPASSRLS", unexpected, "REACH")


async def test_app_roles_never_privileged(pg) -> None:
    """Independent of the allow-lists, by design.

    If someone adds `intel_app` to an allow-list to make the tests above go
    green, this one still fails. The allow-lists name roles that are permitted
    to be privileged; a request-path role is never one of those, so it does not
    get to be waived by editing a set.
    """
    reachable = {r["rolname"] for r in await pg.fetch(Q_RESOLVED.format(attr=ATTR_BYPASS))}
    offenders = reachable & APP_ROLES
    assert not offenders, (
        f"request-path role(s) can bypass RLS: {sorted(offenders)}. Every FORCE ROW LEVEL "
        "SECURITY policy in this database is decorative for these roles — which is the "
        "estate incident this entire suite exists to make unrepeatable."
    )
