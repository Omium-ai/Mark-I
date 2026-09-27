"""The E1 read (16 §L6/§L7): controld's internal evidence route, for the cloud judge and RM.
Every read names its purpose, so controld can hold it to the device consent that purpose needs
(judge → cloud_judge, rm → cloud_rm); a refusal (403) or nothing held (404) is no evidence."""

import logging
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

import httpx

from app.judges.cloud_path import EvidenceReader
from app.judges.specs import JudgeRefused, refuse
from app.rm.cloud import InputReader, RmInput

EVIDENCE_PATH = "/internal/v1/evidence/"
TENANT_HEADER = "M1P-Tenant-Id"
Purpose = Literal["judge", "rm"]
PURPOSE_CONSENT: dict[str, str] = {"judge": "cloud_judge", "rm": "cloud_rm"}

log = logging.getLogger("adjudicator.evidence")


def transient(exc: BaseException) -> bool:
    """A controld 5xx or a transport failure: worth one retry, then the task waits a night."""
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    if isinstance(exc, JudgeRefused):
        return exc.reason.startswith("refused_dispatch_failed:5")
    return isinstance(exc, httpx.TransportError)


class PerTask:
    """Per-task controld calls in a nightly: one retry on a transient failure, then a counted
    skip. A night on which every call failed (controld down) re-raises the last failure."""

    def __init__(self, skipped: Counter[str], key: str) -> None:
        self.skipped, self.key, self.ok, self.last = skipped, key, False, None

    async def __call__(self, call: Callable[[], Awaitable[Any]]) -> tuple[Any, bool]:
        for _ in range(2):
            try:
                value = await call()
            except Exception as exc:
                if not transient(exc):
                    raise
                self.last = exc
                continue
            self.ok = True
            return value, True
        self.skipped[self.key] += 1
        log.warning("%s: %s", self.key, self.last)
        return None, False

    def check(self) -> None:
        if self.last is not None and not self.ok:
            raise self.last


@dataclass(frozen=True)
class E1Evidence:
    task_id: UUID
    intent: str
    hunks: str
    receipt_id: str


async def fetch_e1(
    http: httpx.AsyncClient,
    base_url: str,
    bearer: str,
    tenant_id: UUID,
    task_id: UUID,
    purpose: Purpose,
) -> E1Evidence | None:
    """The task's E1 part for `purpose`, or None when controld refuses it (403: the device's
    consent for that purpose is off, or this credential may not read it) or holds none (404);
    any other failure propagates."""
    if purpose not in PURPOSE_CONSENT:
        raise ValueError(f"unknown E1 purpose {purpose!r}")
    resp = await http.get(
        f"{base_url.rstrip('/')}{EVIDENCE_PATH}{task_id}",
        params={"purpose": purpose},
        headers={"Authorization": f"Bearer {bearer}", TENANT_HEADER: str(tenant_id)},
    )
    if resp.status_code == 403:
        log.warning("E1 %s read of %s refused by controld", purpose, task_id)
        return None
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    body = resp.json()
    if body.get("tier") != "E1" or body.get("task_id") != str(task_id) or not body.get("hunks"):
        return None
    return E1Evidence(
        task_id, str(body.get("intent") or ""), str(body["hunks"]), body["receipt_id"]
    )


def render(e: E1Evidence) -> str:
    """The edge diff judge's user message shape: the task, then the hunks, nothing else."""
    task = e.intent.strip() or "(the task text is not available; judge the diff alone)"
    return f"<task>\n{task}\n</task>\n<diff>\n{e.hunks}\n</diff>"


def e1_reader(
    http: httpx.AsyncClient, base_url: str, bearer: str, tenant_id: UUID
) -> EvidenceReader:
    """judge_batch's evidence_for: absent E1 is a JudgeRefused, which falls back to E0."""

    async def read(task_id: UUID, attempt_id: UUID, tier: str) -> str:
        if tier != "E1":
            raise refuse(f"refused_tier_no_archive:{tier}", "only E1 is receipted and served")
        e = await fetch_e1(http, base_url, bearer, tenant_id, task_id, "judge")
        if e is None:
            raise refuse("refused_no_receipted_excerpts", f"task {task_id}")
        return render(e)

    return read


def rm_input_reader(
    http: httpx.AsyncClient, base_url: str, bearer: str, tenant_id: UUID
) -> InputReader:
    """app.rm.cloud.run's input_for: task text + E1 hunks only (16 §Independence rules)."""

    async def read(task_id: UUID) -> RmInput | None:
        e = await fetch_e1(http, base_url, bearer, tenant_id, task_id, "rm")
        return RmInput(task=e.intent, hunks=e.hunks) if e else None

    return read
