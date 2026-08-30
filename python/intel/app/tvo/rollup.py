"""ADR-0010 driver: `tvo.rollup_tenant_day` — intel DRIVES, querychoke EXECUTES.

*** ADR-0010 IS UNSIGNED (Status: Proposed — founder sign-off required BEFORE the first
`tvo_tenant_day` write). Until it is signed, every write this module drives is TEST/DEV
LANE ONLY: the driver runs solely behind the explicit `allow_unsigned_write=True` /
`--i-understand-adr-0010-is-unsigned` flag, is invoked by CLI/cron seam, and is NEVER a
default-on loop. Same guard class as ADR-0001's "first production write" gate. ***

The mechanics, verbatim from ADR-0010 and the choke's write carve-out
(go/controld/internal/querychoke/templates.go `tvo_rollup_tenant_day`):
- one job per (tenant, day, series), firing after the UTC day closes plus the 2 h grace
  lag (D20); a mid-day task_seg cutover is two series ⇒ two jobs, two rows, never blended;
- intel never holds a ClickHouse credential — the write goes through the write-shaped
  querychoke template, with intel's SERVICE credential naming the job's tenant
  (querychoke service.go FromServiceJob — the one sanctioned tenant-parameter path);
- idempotency layer 2 (physical): the insert carries insert_deduplication_token = job_key,
  job_key = ('tvo.rollup_tenant_day', day, day+1, params_hash) with
  params = {tenant_id, series, watermark} (ADR-0010 §3) — a re-run with the same key is a
  dedup-dropped no-op the choke acks with the SAME 200 (module.go: the no-op signal
  belongs to the driving job's ledger, layer 1, not the write seam);
- layer 3 (structural): one (tenant, day, series) = one row = one insert block = one
  run_write call;
- restatement is a NEW series label (new params_hash → new job_key → new row), never a
  re-run (ADR-0010 §6); history is never restated in place.

ponytail: idempotency layer 1 (the intel_jobs UNIQUE job_key ledger, 06 §7.3) arrives with
the §7 scheduler wave — this driver ships layers 2–3 end to end and leaves the ledger seam
to the job-runner row."""

import argparse
import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import httpx

from app.tvo.reader import CoverageInputs, LedgerWindow, QuerychokeReader
from app.tvo.waste import retry_loop_tokens

ROLLUP_KIND = "tvo.rollup_tenant_day"
GRACE_LAG = timedelta(hours=2)  # D20 (06 §7.3): windows close 2 h after the UTC day ends.

_CERTIFIED_STAGES = frozenset({"certified", "revised"})

log = logging.getLogger("intel.tvo.rollup")


def window_close(day: date) -> datetime:
    """The instant [day, day+1) becomes readable: UTC day end + D20 grace (ADR-0010 §1)."""
    return datetime.combine(day + timedelta(days=1), time(0, 0), tzinfo=UTC) + GRACE_LAG


def watermark_for(day: date) -> str:
    """The explicit read watermark recorded in the job identity (06 §7.3.2). Deterministic
    per day — the window-close instant — so a re-run reads the same input set and hashes
    to the SAME job_key; late events belong to the next window, never a silent top-up."""
    return window_close(day).isoformat()


def job_key(day: date, tenant_id: str, series: str, watermark: str) -> str:
    """ADR-0010 §3: job_key = (kind, window_start, window_end, params_hash),
    params = {tenant_id, series, watermark}. Canonical-JSON hashed so the key is
    deterministic across processes — identity pinned to the JOB, never to what the job
    happened to read (the ADR's row-2 lesson). The result stays inside the choke's
    jobKeyClass ([A-Za-z0-9._:|-]{1,255}, builder.go)."""
    params = json.dumps(
        {"series": series, "tenant_id": tenant_id, "watermark": watermark},
        sort_keys=True,
        separators=(",", ":"),
    )
    params_hash = hashlib.sha256(params.encode()).hexdigest()
    return f"{ROLLUP_KIND}:{day.isoformat()}:{(day + timedelta(days=1)).isoformat()}:{params_hash}"


@dataclass(frozen=True)
class RollupOutcome:
    job_key: str
    series: str
    # The choke's ack, verbatim ("written"). Deliberately NOT a written/deduplicated
    # pair: the write seam acks a dedup-dropped re-run identically (module.go
    # handleRollupWrite — idempotent by design), and the no-op signal belongs to the
    # intel_jobs ledger (ADR-0010 layer 1), which is not this driver's row to fake.
    status: str


def compute_rollup_rows(
    day: date, ledger: LedgerWindow, cov: CoverageInputs, *, series: str = ""
) -> list[dict[str, Any]]:
    """One param dict per (day, series) — the EXACT flat parameter schema of the choke's
    `tvo_rollup_tenant_day` template (templates.go): tasks_verified/tasks_unresolved are
    UUID arrays (the template arrayReduces them into uniqExactState), everything else a
    plain scalar. `series` names a restatement label (ADR-0010 §6) and is only
    unambiguous when the day has a single task_seg_version."""
    by_version: dict[str, list[str]] = {}
    for task, version in ledger.seg_version_by_task.items():
        by_version.setdefault(version, []).append(task)
    if series and len(by_version) > 1:
        # A restatement names ONE series label; a cutover day has two rows and needs two
        # restatements — refuse the ambiguity rather than blend series (ADR-0002/-0010).
        raise ValueError(
            f"series={series!r} names one restated row but day {day} has "
            f"{sorted(by_version)} — restate each version separately"
        )

    terminal: dict[str, tuple[str, str]] = {}
    by_task: dict[str, list] = {}
    for a in ledger.attempts:
        by_task.setdefault(a.task_id, []).append(a)
    for task, rows in by_task.items():
        last = max(rows, key=lambda a: a.attempt_n)
        terminal[task] = (last.fused_verdict, last.verdict_stage)

    versions = list(by_version)
    rows_out: list[dict[str, Any]] = []
    for version, tasks in by_version.items():
        task_set = set(tasks)
        attempts = [a for a in ledger.attempts if a.task_id in task_set]
        verified = sorted(
            t
            for t in tasks
            if terminal[t][0] == "satisfied" and terminal[t][1] in _CERTIFIED_STAGES
        )
        unresolved = sorted(
            t
            for t in tasks
            if not (
                terminal[t][0] in ("satisfied", "violated") and terminal[t][1] in _CERTIFIED_STAGES
            )
        )
        # ponytail: coverage durations are surface-time, not version-attributable — they
        # ride the LATEST version's row (zeros elsewhere) so a cutover day sums correctly
        # across its rows; per-version attribution would be an invented split.
        is_latest = version == versions[-1]
        rows_out.append(
            {
                "day": day.isoformat(),
                "series": series or version,
                "tokens_total": sum(a.gen_tokens + a.verifier_tokens for a in attempts),
                "cost_usd": round(sum(ledger.cost_usd_by_task[t] for t in tasks), 8),
                "tasks_verified": verified,
                "tasks_unresolved": unresolved,
                "retry_loop_tokens": retry_loop_tokens(attempts),
                # Witness-free channels claim zero (06 §8.3, counterfactual-free): no
                # served-set / rung-signal read template exists in the v1 registry.
                "reexploration_tokens": 0,
                "over_model_tokens": 0,
                "observed_ms": cov.observed_ms if is_latest else 0,
                "bypass_ms": cov.bypass_ms if is_latest else 0,
                "disabled_ms": cov.disabled_ms if is_latest else 0,
                "dropped_billing": cov.dropped_billing if is_latest else 0,
            }
        )
    return rows_out


async def run_rollup(
    reader: QuerychokeReader,
    *,
    tenant_id: str,
    day: date,
    bearer: str,
    series: str = "",
    now: datetime | None = None,
    allow_unsigned_write: bool = False,
) -> list[RollupOutcome]:
    """One (tenant, day) invocation ⇒ one job per series present. `tenant_id` enters the
    job identity (ADR-0010 §3) AND the write call (the FromServiceJob path — `bearer`
    here is intel's service credential; the tenant predicate on the rendered INSERT is
    still Build-bound by the choke, never trusted from us). Re-run with the same
    (tenant, day, series) ⇒ same job_key ⇒ the choke's dedupe reports a no-op.
    Restatement = new `series` ⇒ new key, new row beside the original."""
    if not allow_unsigned_write:
        # PRODUCTION-WRITE GUARD: ADR-0010 is unsigned; the first tvo_tenant_day write is
        # founder-gated. No code path may default past this.
        raise RuntimeError(
            "ADR-0010 is UNSIGNED — tvo_tenant_day writes are test/dev-lane only; "
            "pass allow_unsigned_write=True (CLI: --i-understand-adr-0010-is-unsigned)"
        )
    now = now or datetime.now(UTC)
    close = window_close(day)
    if now < close:
        # D20: events whose ingested_at trails occurred_at land in the window they belong
        # to; writing early would mint a permanently-short row instead of a late one.
        raise ValueError(f"window for {day} closes at {close.isoformat()} — not yet closed")

    wm = watermark_for(day)
    ledger = await reader.attempt_window(day, day + timedelta(days=1), bearer=bearer)
    if not ledger.attempts:
        # No activity ⇒ no row (a zero-task day has no TVO terms). The report side's
        # missing-day refusal (ADR-0010 §7) is the honest surface for this, not a zero row.
        log.info("rollup %s %s: empty day, nothing to write", tenant_id, day)
        return []
    cov = await reader.coverage_inputs(day, day + timedelta(days=1), bearer=bearer)

    outcomes: list[RollupOutcome] = []
    for row in compute_rollup_rows(day, ledger, cov, series=series):
        key = job_key(day, tenant_id, row["series"], wm)
        # Layer 3: one (tenant, day, series) = one row = one insert block = this call.
        ack = await reader.run_write(row, job_key=key, tenant_id=tenant_id, bearer=bearer)
        if ack.job_key != key:
            # The seam echoes the dedup token; a mismatch is a wiring bug, not a retry.
            raise ValueError(f"rollup ack echoed job_key {ack.job_key!r}, sent {key!r}")
        log.info("rollup %s: status=%s", key, ack.status)
        outcomes.append(RollupOutcome(job_key=key, series=row["series"], status=ack.status))
    return outcomes


def main(argv: list[str] | None = None) -> int:
    """Cron/CLI seam (deliberately NOT a scheduler loop): `python -m app.tvo.rollup`.
    The service credential comes from INTEL_QUERYCHOKE_TOKEN."""
    parser = argparse.ArgumentParser(description=ROLLUP_KIND)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--day", required=True, type=date.fromisoformat)
    parser.add_argument("--base-url", required=True, help="querychoke base URL")
    parser.add_argument("--series", default="", help="restatement series label (ADR-0010 §6)")
    parser.add_argument(
        "--i-understand-adr-0010-is-unsigned",
        action="store_true",
        dest="allow_unsigned",
        help="required: ADR-0010 is unsigned; writes are test/dev-lane only",
    )
    args = parser.parse_args(argv)
    bearer = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not bearer:
        parser.error("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")

    async def _run() -> list[RollupOutcome]:
        async with httpx.AsyncClient(timeout=30.0) as http:
            reader = QuerychokeReader(http, args.base_url)
            return await run_rollup(
                reader,
                tenant_id=args.tenant_id,
                day=args.day,
                bearer=bearer,
                series=args.series,
                allow_unsigned_write=args.allow_unsigned,
            )

    for outcome in asyncio.run(_run()):
        log.info(
            "done: job_key=%s series=%s status=%s",
            outcome.job_key,
            outcome.series,
            outcome.status,
        )
    return 0


if __name__ == "__main__":
    from app.logging import configure_logging

    configure_logging()
    raise SystemExit(main())
