"""The cloud RM path (16 §L6): for a tenant holding a live E1 consent row under the rm: register
key (m1_073), every task in the window this model has not scored, from a device whose latest
consent chose Cloud (m1_097 cloud_rm) and E1, goes to the Baseten endpoint as the rm-input/v1
prefix of task text + E1 sanitized hunks ONLY, never anchor output, EvidenceRecords, the
trajectory or a judge's output (16 §Independence rules). The score re-enters the ledger as
RmScore{locus: CLOUD, execution_hash} through the service ingest route (app/ledger.py)."""

import contextlib
import logging
import math
import re
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from functools import partial
from typing import Any
from uuid import UUID

import httpx
from m1p.v1 import RmScore
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from app import ledger
from app.choke import run_template
from app.db import set_local_tenant
from app.judges.cloud_path import Consent, pg_consent_reader
from app.llm import reserve_today
from app.rm import render

log = logging.getLogger("adjudicator.rm_cloud")

SUBPROCESSOR = "baseten"
MODEL_ID = "rm:mark1-rm-a@1"
MAX_SEQ_LEN = 4096  # objective.encode's cut; the deployment never scores more ids
WINDOW_DAYS = 2  # tonight's closed day plus the one before: a late-closing task still scores

rm_cloud_skipped_total: Counter[str] = Counter()


class RmCloudSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADJ_RM_", frozen=True)

    endpoint_url: str = ""  # Baseten predict URL; empty ⇒ the job is a counted skip
    api_key: SecretStr = SecretStr("")  # ExternalSecret mark1-baseten-rm, never logged
    model_id: str = Field(MODEL_ID, pattern=r"^rm:[a-z0-9-]+@[1-9][0-9]*$")
    region: str = "us"  # the Baseten deployment's region; the consent row must name it
    deadline_s: float = (
        180.0  # the edge's scoreTimeout: a 4096-token CPU pass scores, never abstains
    )
    max_tasks_per_day: int = 200  # per tenant per UTC day, ledgered (m1_101)
    max_tasks_per_run: int = 200  # the one-run bound on top of it


@dataclass(frozen=True)
class RmInput:
    """Everything the RM may read (16 §Independence rules): the task and the final diff."""

    task: str
    hunks: str


InputReader = Callable[[UUID], Awaitable[RmInput | None]]


def prompt(inp: RmInput) -> render.Rendered:
    """rm-input/v1 over the task and E1 hunks, byte for byte what training and the edge render."""
    return render.render(inp.task, inp.hunks)


def admit(settings: RmCloudSettings, consent: Consent | None) -> str | None:
    """06 §6.5 preconditions for the rm: key: consent, Baseten named, region pinned, exactly E1."""
    if consent is None:
        return "refused_no_cloud_consent"
    if consent.subprocessor != SUBPROCESSOR:
        return f"refused_subprocessor_not_listed:{SUBPROCESSOR}"
    if consent.region != settings.region:
        return f"refused_region_mismatch:{settings.region}"
    if consent.max_tier != "E1":
        return "refused_tier_not_e1"
    return None


def cloud_score(
    model_id: str, score: float, calibration_version: str, execution_hash: bytes = b""
) -> RmScore:
    msg = RmScore(
        model_id=model_id,
        score=score,
        calibration_version=calibration_version,
        execution_hash=execution_hash,
    )
    if "locus" in RmScore.__dataclass_fields__:  # 16 §L6a's field; CLOUD is this path's
        msg.locus = msg._type_hint("locus")["CLOUD"]
    return msg


class CloudRm:
    """One POST per task under a hard deadline; any failure is a counted skip, never a score."""

    def __init__(self, settings: RmCloudSettings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._client = client

    async def score(self, inp: RmInput) -> RmScore | None:
        s = self._settings
        r = prompt(inp)
        if r.abstain is not None:
            return _skip(f"rm_cloud_abstain:{r.abstain}")
        try:
            resp = await self._client.post(
                s.endpoint_url,
                json={"model_id": s.model_id, "prefix": r.prefix},
                headers={"Authorization": f"Api-Key {s.api_key.get_secret_value()}"},
                timeout=s.deadline_s,
            )
            resp.raise_for_status()
            body = resp.json()
        except httpx.TimeoutException:
            return _skip("rm_cloud_timeout")
        except (httpx.HTTPError, ValueError) as exc:
            return _skip(f"rm_cloud_unavailable:{type(exc).__name__}")
        return parse(body, s.model_id)


REPLY = {"model_id", "logit", "calibration_version", "execution_hash", "n_tokens"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def parse(body: Any, model_id: str) -> RmScore | None:
    """The pinned model's deploy/baseten/mark1-rm reply as RmScore{σ(logit), hash}, or nothing."""
    if not isinstance(body, dict) or set(body) != REPLY:
        return _skip("rm_cloud_malformed")
    if body["model_id"] != model_id:
        return _skip("rm_cloud_off_model")
    logit, cal, xh, n = (
        body[k] for k in ("logit", "calibration_version", "execution_hash", "n_tokens")
    )
    if isinstance(logit, bool) or not isinstance(logit, int | float) or not math.isfinite(logit):
        return _skip("rm_cloud_malformed")
    if not isinstance(cal, str) or not cal or not isinstance(xh, str) or not _HEX64.match(xh):
        return _skip("rm_cloud_malformed")
    if isinstance(n, bool) or not isinstance(n, int) or not 0 < n <= MAX_SEQ_LEN:
        return _skip("rm_cloud_malformed")
    score = 0.5 * (1.0 + math.tanh(logit / 2.0))  # σ(logit) without exp overflow
    return cloud_score(model_id, score, cal, bytes.fromhex(xh))


def _skip(reason: str) -> None:
    rm_cloud_skipped_total[reason.split(":", 1)[0]] += 1
    log.info("rm cloud skipped: %s", reason)
    return None


def unscored(
    rows: list[dict[str, Any]], model_id: str, cloud_devices: set[UUID]
) -> dict[UUID, UUID]:
    """task → session for every task in the window with no RmScore from this model yet, whose
    device chose Cloud; a task no device consent covers never leaves."""
    sessions: dict[UUID, UUID] = {}
    scored: set[UUID] = set()
    for r in rows:
        task = UUID(str(r["task_id"]))
        if r["family"] == "RmScore" and r["verifier_id"] == model_id:
            scored.add(task)
        if (
            r.get("session_id")
            and r.get("device_id")
            and UUID(str(r["device_id"])) in cloud_devices
        ):
            sessions.setdefault(task, UUID(str(r["session_id"])))
    return {t: s for t, s in sessions.items() if t not in scored}


async def cloud_devices(pool: Any, tenant_id: UUID) -> set[UUID]:
    """Devices whose LATEST consent record says E1 and Cloud RM (m1_082 is append-only)."""
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, str(tenant_id))
        rows = await conn.fetch(
            "SELECT DISTINCT ON (device_id) device_id, e1, cloud_rm FROM m1_device_consents "
            "WHERE tenant_id = $1 ORDER BY device_id, row_seq DESC",
            tenant_id,
        )
    return {r["device_id"] for r in rows if r["e1"] and r["cloud_rm"]}


async def run(
    ctx: Any,
    *,
    http: httpx.AsyncClient | None = None,
    input_for: InputReader | None = None,
) -> None:
    """Scheduler target `app.rm.cloud:run`. `input_for` defaults to controld's E1 read (the
    task intent + sanitized hunks, app/judges/evidence.py); a task with none is a counted skip."""
    from app.jobs.nightly import VOTES_TEMPLATE
    from app.judges.evidence import PerTask, rm_input_reader

    settings, rm = ctx.settings, RmCloudSettings()
    tenant = UUID(ctx.tenant_id)
    consent = await pg_consent_reader(ctx.pool)(tenant, rm.model_id)
    if consent is None:
        return None  # the tenant chose Local or Off: nothing leaves, nothing to count
    if reason := admit(rm, consent):
        return _skip(reason)
    if not rm.endpoint_url or not rm.api_key.get_secret_value():
        return _skip("rm_cloud_no_endpoint")
    window = {
        "from": (ctx.day - timedelta(days=WINDOW_DAYS - 1)).isoformat(),
        "to": ctx.day.isoformat(),
    }
    bearer = settings.querychoke_token.get_secret_value()
    own = (
        contextlib.nullcontext(http) if http else httpx.AsyncClient(timeout=settings.http_timeout_s)
    )
    e1_token = settings.evidence_token.get_secret_value()
    if input_for is None and not e1_token:
        return _skip("rm_cloud_no_evidence_token")
    async with own as client:
        read = input_for or rm_input_reader(client, settings.querychoke_base_url, e1_token, tenant)
        rows = await run_template(
            client,
            settings.querychoke_base_url,
            VOTES_TEMPLATE,
            window,
            bearer=bearer,
            tenant_id=ctx.tenant_id,
        )
        todo = unscored(rows, rm.model_id, await cloud_devices(ctx.pool, tenant))
        if len(todo) > rm.max_tasks_per_run:
            rm_cloud_skipped_total["rm_cloud_run_cap"] += len(todo) - rm.max_tasks_per_run
        ready, guard = [], PerTask(rm_cloud_skipped_total, "rm_cloud_controld_unavailable")
        for task_id, session_id in sorted(todo.items())[: rm.max_tasks_per_run]:
            inp, ok = await guard(partial(read, task_id))
            if not ok:
                continue
            if inp is None or not inp.hunks:
                _skip("rm_cloud_no_e1_hunks")
                continue
            ready.append((task_id, session_id, inp))
        guard.check()
        async with ctx.pool.acquire() as conn:
            granted = await reserve_today(
                conn, ctx.tenant_id, rm.model_id, len(ready), rm.max_tasks_per_day
            )
        rm_cloud_skipped_total["rm_cloud_daily_cap"] += len(ready) - granted
        scorer, events = CloudRm(rm, client), []
        for task_id, session_id, inp in ready[:granted]:
            score = await scorer.score(inp)
            if score is not None:
                events.append(
                    ledger.rm_score_wire(
                        score,
                        tenant_id=tenant,
                        task_id=task_id,
                        session_id=session_id,
                        window_start=ctx.window_start,
                    )
                )
        if events:
            await ledger.post_verdicts(client, settings.querychoke_base_url, bearer, tenant, events)
    log.info(
        "rm_cloud %s %s: %d unscored, %d posted, skips=%s",
        ctx.tenant_id,
        ctx.day,
        len(todo),
        len(events),
        dict(rm_cloud_skipped_total),
    )
    return None
