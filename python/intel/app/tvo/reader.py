"""The querychoke HTTP client — intel's ONLY ledger read path (08 §3.3; 06 §8 seam note).

WHY this module exists at all: 05 §6 makes `controld.querychoke` the only ClickHouse
principal; `mark1-intel` never holds a ClickHouse credential or driver (asserted by
tests/test_no_clickhouse_dep.py, which walks intel's uv.lock dependency closure). Every
read here is `POST /api/v1/query` with a NAMED template — the chokepoint refuses unknown
templates (M1E-2008), it does not improvise (08 §3.3).

Tenancy: for READS the choke binds the tenant predicate from the caller's verified token
claims (05 §6.2 — "the caller has no parameter slot for it"); this client NEVER puts a
tenant_id in read-template params. The ONE sanctioned exception is the ADR-0010 write
path (querychoke service.go FromServiceJob): the verified thing is the calling SERVICE,
which names the job's tenant beside the job_key — run_write() carries both as top-level
body fields on controld's INTERNAL rollup route (never /api/v1/query, which 403s
write-shaped templates by design; module.go handleQuery)."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

import httpx

from app.tvo.engine import AttemptRow

QUERY_PATH = "/api/v1/query"

# The ADR-0010 §2.2 write seam — controld's INTERNAL route (module.go
# RegisterRoutes), service-credential authenticated, with its own request and
# response shapes. It is NOT a template execution of /api/v1/query: that
# surface refuses write-shaped templates outright (403 M1E-1001, 05 §6.3).
ROLLUP_WRITE_PATH = "/internal/v1/rollup/tvo_tenant_day"

# 08 §9 (normative taxonomy): the only codes the §2.5 automaton may retry without a human.
_RETRYABLE_CODES = frozenset({"M1E-9001", "M1E-9500"})


class QuerychokeError(Exception):
    """A choke response carrying its M1E code — one taxonomy, every surface (08 §9).
    `retryable` mirrors the taxonomy's Retryable column so callers inherit the frozen
    posture matrix instead of inventing their own."""

    def __init__(self, code: str, message: str, http_status: int) -> None:
        self.code = code
        self.message = message
        self.http_status = http_status
        super().__init__(f"{code} (HTTP {http_status}): {message}")

    @property
    def retryable(self) -> bool:
        return self.code in _RETRYABLE_CODES or self.http_status >= 500


@dataclass(frozen=True)
class QueryResult:
    """The 08 §3.3 response body of POST /api/v1/query, verbatim keys."""

    rows: tuple[Mapping[str, Any], ...]
    template_version: str


@dataclass(frozen=True)
class RollupAck:
    """POST /internal/v1/rollup/tvo_tenant_day's exact 200 body (module.go
    handleRollupWrite): {"status": "written", "job_key": …}. A dedup-dropped re-run
    answers the SAME 200 — idempotent by design; the no-op signal belongs to the
    driving job's ledger (idempotency layer 1), never this seam."""

    status: str
    job_key: str


@dataclass(frozen=True)
class LedgerWindow:
    """One coherent read of the `tvo_task_window` template: attempt-grain rows mapped into
    engine.py's AttemptRow seam, plus the task-grain facts the rollup driver needs
    (task_seg_version is stamped at TaskOpen — task grain, never attempt grain, which
    is why it rides beside AttemptRow rather than inside it)."""

    attempts: tuple[AttemptRow, ...]
    seg_version_by_task: Mapping[str, str]
    cost_usd_by_task: Mapping[str, float]

    @property
    def task_seg_versions(self) -> tuple[str, ...]:
        """Distinct versions in first-appearance order — report.py's boundary-refusal input."""
        seen: dict[str, None] = {}
        for a in self.attempts:
            seen.setdefault(self.seg_version_by_task[a.task_id], None)
        return tuple(seen)


@dataclass(frozen=True)
class CoverageInputs:
    """The five terms of the coverage band (07, normative; 06 §8.2): surface durations
    from the `coverage_band` template, shed accounting from `dropped_by_tenant_day`."""

    observed_ms: int
    bypass_ms: int
    disabled_ms: int
    dropped_billing: int
    events_billing_ingested: int


def _require(row: Mapping[str, Any], key: str, template: str) -> Any:
    # A missing column is a broken template contract, not user error — fail loudly with
    # the template name so the drift is attributable to the choke-side registry entry.
    if key not in row:
        raise ValueError(f"querychoke template {template!r} row missing {key!r}: {dict(row)!r}")
    return row[key]


class QuerychokeReader:
    """Consumer of the 08 §3.3 query contract. The write-shaped ADR-0010 template is
    driven through run_write() by app/tvo/rollup.py — this class stays
    template-name-agnostic so the closed registry (05 §6.3) remains the single list."""

    def __init__(self, http: httpx.AsyncClient, base_url: str) -> None:
        self._http = http
        self._base_url = base_url.rstrip("/")

    async def run_template(
        self, template: str, params: Mapping[str, Any], *, bearer: str
    ) -> QueryResult:
        """POST /api/v1/query {"template", "params"} → {"rows", "template_version"}
        (08 §3.3, exact). Non-2xx bodies carry {"error": {"code", "message"}} (08 §9)
        and surface as typed QuerychokeError — the M1E code crosses intact."""
        resp = await self._http.post(
            f"{self._base_url}{QUERY_PATH}",
            json={"template": template, "params": dict(params)},
            headers={"Authorization": f"Bearer {bearer}"},
        )
        return self._decode(resp)

    @staticmethod
    def _raise_for_error(resp: httpx.Response) -> None:
        if resp.status_code == 200:
            return
        try:
            err = resp.json()["error"]
            code, message = err["code"], err.get("message", "")
        except Exception:
            # 08 §9: M1E-9500 is the generic 5xx wrapper; an unparseable error body
            # gets the generic code rather than a guessed specific one.
            code, message = "M1E-9500", resp.text[:200]
        raise QuerychokeError(code, message, resp.status_code)

    @staticmethod
    def _decode(resp: httpx.Response) -> QueryResult:
        QuerychokeReader._raise_for_error(resp)
        body = resp.json()
        if "rows" not in body or "template_version" not in body:
            raise ValueError(f"querychoke response missing rows/template_version: {body!r}")
        return QueryResult(rows=tuple(body["rows"]), template_version=body["template_version"])

    async def run_write(
        self,
        fields: Mapping[str, Any],
        *,
        job_key: str,
        tenant_id: str,
        bearer: str,
    ) -> RollupAck:
        """The ADR-0010 §2.2 write call: POST controld's INTERNAL rollup route with the
        FLAT body module.go's rollupRequest declares — the 13 row fields beside
        `job_key` (the mandatory insert_deduplication_token, idempotency layer 2) and
        `tenant_id` (FromServiceJob: the verified SERVICE names the job's tenant; the
        bearer is intel's service credential). There is no `template` field — the route
        IS the template. WHY the previous shape was wrong (wave-5 lesson,
        RECONCILIATION.md: stub-tested halves of one contract drift unless one side's
        tests speak the other side's exact wire bytes): this method POSTed the write
        template to /api/v1/query, which controld deliberately 403s for write-shaped
        templates — the mock alone accepted it. The lock is now two-way:
        tests/choke_mock.py speaks controld's exact route/body/response, and controld's
        Go test replays THIS body verbatim (querychoke testdata/rollup_write_body.json)."""
        resp = await self._http.post(
            f"{self._base_url}{ROLLUP_WRITE_PATH}",
            json={**dict(fields), "job_key": job_key, "tenant_id": tenant_id},
            headers={"Authorization": f"Bearer {bearer}"},
        )
        self._raise_for_error(resp)
        body = resp.json()
        if "status" not in body or "job_key" not in body:
            raise ValueError(f"rollup write response missing status/job_key: {body!r}")
        return RollupAck(status=body["status"], job_key=body["job_key"])

    async def attempt_window(
        self, window_start: date, window_end: date, *, bearer: str
    ) -> LedgerWindow:
        """`tvo_task_window` template over [window_start, window_end): attempt-grain rows
        from mark1.tvo_task (06 §8.1 sources c, v, p from attempt grain — the day-grain
        `tvo_report` rollup read cannot supply them). This name is NOT yet in the choke's
        v1 registry: adding a read template is a registry PR (05 §6.3), and until it
        lands a live call refuses loudly with M1E-2008 — a refusal, never a wrong shape."""
        result = await self.run_template(
            "tvo_task_window",
            {"from": window_start.isoformat(), "to": window_end.isoformat()},
            bearer=bearer,
        )
        attempts: list[AttemptRow] = []
        seg_by_task: dict[str, str] = {}
        cost_by_task: dict[str, float] = {}
        for row in result.rows:
            task_id = str(_require(row, "task_id", "tvo_task_window"))
            attempts.append(
                AttemptRow(
                    task_id=task_id,
                    attempt_n=int(_require(row, "attempt_n", "tvo_task_window")),
                    gen_tokens=int(_require(row, "gen_tokens", "tvo_task_window")),
                    verifier_tokens=int(_require(row, "verifier_tokens", "tvo_task_window")),
                    fused_verdict=str(_require(row, "fused_verdict", "tvo_task_window")),
                    verdict_stage=str(_require(row, "verdict_stage", "tvo_task_window")),
                )
            )
            seg_by_task[task_id] = str(_require(row, "task_seg_version", "tvo_task_window"))
            cost_by_task[task_id] = cost_by_task.get(task_id, 0.0) + float(row.get("cost_usd", 0))
        return LedgerWindow(
            attempts=tuple(attempts),
            seg_version_by_task=seg_by_task,
            cost_usd_by_task=cost_by_task,
        )

    async def coverage_inputs(
        self, window_start: date, window_end: date, *, bearer: str
    ) -> CoverageInputs:
        """The two templates 11 §4.4 names intel evaluating: `coverage_band` (surface
        durations, day-grain rows summed here) + `dropped_by_tenant_day` (shed
        accounting, summed across days). Zero rows sum to zero coverage — 'never
        enabled' is band `insufficient` downstream, never an assumed pass (07)."""
        window = {"from": window_start.isoformat(), "to": window_end.isoformat()}
        band = await self.run_template("coverage_band", window, bearer=bearer)
        dropped = await self.run_template("dropped_by_tenant_day", window, bearer=bearer)
        return CoverageInputs(
            observed_ms=sum(int(_require(r, "observed_ms", "coverage_band")) for r in band.rows),
            bypass_ms=sum(int(_require(r, "bypass_ms", "coverage_band")) for r in band.rows),
            disabled_ms=sum(int(_require(r, "disabled_ms", "coverage_band")) for r in band.rows),
            dropped_billing=sum(
                int(_require(r, "dropped_billing", "dropped_by_tenant_day")) for r in dropped.rows
            ),
            events_billing_ingested=sum(
                int(_require(r, "events_billing_ingested", "dropped_by_tenant_day"))
                for r in dropped.rows
            ),
        )
