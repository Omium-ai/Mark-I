"""`python -m app.jobs validate | run (--job NAME | --all --nightly) --tenant ID|all`.

Exit 1 = fail."""

from app.logging import configure_logging

configure_logging()

import argparse  # noqa: E402
import asyncio  # noqa: E402
import logging  # noqa: E402
from datetime import UTC, date, datetime  # noqa: E402

from app.config import load_settings  # noqa: E402
from app.db import create_pool  # noqa: E402
from app.jobs import JOBS  # noqa: E402
from app.jobs.registry import RegistryError, validate  # noqa: E402
from app.jobs.runner import run_many  # noqa: E402

log = logging.getLogger("jobs")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.jobs")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser(
        "validate", help="resolve every registered target; fails loudly on a missing one"
    )
    run = sub.add_parser("run")
    which = run.add_mutually_exclusive_group(required=True)
    which.add_argument("--job", help="one registered job name")
    which.add_argument(
        "--all", action="store_true", help="every registered job (of the cadence given)"
    )
    run.add_argument("--nightly", action="store_true")
    run.add_argument("--hourly", action="store_true")
    run.add_argument(
        "--tenant",
        action="append",
        required=True,
        help="repeatable; `all` = every active tenant in m1_tenant_directory (m1_084)",
    )
    run.add_argument(
        "--day",
        type=date.fromisoformat,
        help="closed UTC day for nightly jobs (default: yesterday)",
    )
    args = parser.parse_args(argv)

    try:
        targets = validate(JOBS)
    except RegistryError as exc:
        log.error("registry refused: %s", exc)
        return 2
    if args.cmd == "validate":
        log.info("registry ok: %s", ", ".join(j.name for j in JOBS))
        return 0
    cadences = {c for c, on in (("nightly", args.nightly), ("hourly", args.hourly)) if on} or {
        "nightly",
        "hourly",
    }
    jobs = [j for j in JOBS if (j.name == args.job if args.job else j.cadence in cadences)]
    if not jobs:
        parser.error(f"no such job {args.job!r}" if args.job else "no jobs for that cadence")

    async def _run() -> dict[str, dict[str, str]]:
        settings = load_settings()
        pool = await create_pool(settings)
        try:
            now = datetime.now(UTC)
            tenants = list(args.tenant)
            if "all" in tenants:
                # the directory is global (no RLS) so this enumeration can exist:
                # FORCE RLS on m1_tenants admits one id per GUC
                rows = await pool.fetch(
                    "SELECT tenant_id FROM m1_tenant_directory"
                    " WHERE status = 'active' ORDER BY tenant_id"
                )
                tenants = [t for t in tenants if t != "all"] + [str(r["tenant_id"]) for r in rows]
                tenants = list(dict.fromkeys(tenants))
                log.info("tenant directory: %d active tenant(s)", len(rows))
            return {
                t: await run_many(pool, settings, jobs, targets, tenant_id=t, now=now, day=args.day)
                for t in tenants
            }
        finally:
            await pool.close()

    results = asyncio.run(_run())
    for tenant, outcomes in results.items():
        log.info("tenant %s: %s", tenant, outcomes)
    return 1 if any(o in ("failed", "parked") for r in results.values() for o in r.values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())
