"""06 §9.1 Batch-API extraction cascade over certified sessions (FR-REMEMBER-001/002/006)."""

import asyncio
import json
import logging
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Protocol

import asyncpg
from anthropic import AsyncAnthropic
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

from app.db import set_local_tenant
from app.tvo.reader import QuerychokeReader

KINDS = frozenset({"pitfall", "fix_pattern", "preference", "invariant"})
CANDIDATE_MODEL = "claude-haiku-4-5"
VALIDATE_MODEL = "claude-opus-5"
SESSION_TEMPLATE = "memory_certified_sessions"
MAX_CANDIDATES = 3
_CERTIFIED_STAGES = frozenset({"certified", "revised"})
_NAMESPACE = uuid.UUID("6f1c2a4e-9b3d-4c1e-8a7f-2d5e6b9c0a11")

log = logging.getLogger("intel.memory.extract")

_CANDIDATE_SYSTEM = (
    "You distill reusable memory artifacts from one verified coding-agent session. "
    f"Reply with ONLY a JSON array of 0-{MAX_CANDIDATES} objects, each exactly "
    '{"kind": one of ' + "|".join(sorted(KINDS)) + ', "trigger": string, "guidance": string, '
    '"evidence": [event digests copied verbatim from the session]}. '
    "Abstract identifiers to roles; never quote code spans longer than 40 tokens; "
    "an artifact with no evidence digests is worthless."
)
_VALIDATE_SYSTEM = (
    "You audit a proposed memory artifact against the session events it cites. "
    'Reply with ONLY {"valid": true|false, "reason": string}. valid is true only when the '
    "guidance is non-trivial, actionable without any source identifier, and each cited event "
    "actually supports it."
)


@dataclass(frozen=True)
class Session:
    session_id: str
    task_id: str
    device_id: str
    verdict: str
    stage: str
    noise_cert_id: str
    tamper: bool
    events: tuple[Mapping[str, Any], ...]

    @property
    def digests(self) -> frozenset[str]:
        return frozenset(str(e["digest"]) for e in self.events)


@dataclass(frozen=True)
class Artifact:
    id: uuid.UUID
    tenant_id: str
    kind: str
    body: Mapping[str, Any]
    cert_id: str

    @property
    def abstraction(self) -> str:
        return "invariant" if self.kind == "invariant" else "instance"


@dataclass(frozen=True)
class ExtractReport:
    sessions_seen: int
    sessions_certified: int
    candidates: int
    grounded: int
    validated: int
    inserted: int


class BatchRunner(Protocol):
    async def run(self, requests: Sequence[Request]) -> dict[str, str]: ...


class AnthropicBatchRunner:
    def __init__(self, client: AsyncAnthropic, *, poll_s: float = 60.0) -> None:
        self._client = client
        self._poll_s = poll_s

    async def run(self, requests: Sequence[Request]) -> dict[str, str]:
        batch = await self._client.messages.batches.create(requests=list(requests))
        while batch.processing_status != "ended":
            await asyncio.sleep(self._poll_s)
            batch = await self._client.messages.batches.retrieve(batch.id)
        out: dict[str, str] = {}
        async for r in await self._client.messages.batches.results(batch.id):
            if r.result.type == "succeeded":
                msg = r.result.message
                out[r.custom_id] = next((b.text for b in msg.content if b.type == "text"), "")
            else:
                log.warning("batch %s: %s %s", batch.id, r.custom_id, r.result.type)
        return out


def ledger_certified(rows: Sequence[Mapping[str, Any]]) -> list[Session]:
    """FR-REMEMBER-002 at the ledger grain: CERTIFIED stage, a stamped cert, no tamper."""
    kept: list[Session] = []
    for r in rows:
        s = Session(
            session_id=str(r["session_id"]),
            task_id=str(r["task_id"]),
            device_id=str(r["device_id"]),
            verdict=str(r["verdict"]),
            stage=str(r["verdict_stage"]),
            noise_cert_id=str(r.get("noise_cert_id") or ""),
            tamper=bool(r.get("tamper", False)),
            events=tuple(r.get("events") or ()),
        )
        if (
            s.stage in _CERTIFIED_STAGES
            and s.noise_cert_id
            and not s.tamper
            and s.verdict in ("satisfied", "violated")
        ):
            kept.append(s)
    return kept


async def live_certs(conn: asyncpg.Connection, tenant_id: str, cert_ids: set[str]) -> set[str]:
    """The §5.4 read-time gate: mark1_assert_certified()'s predicate, over one tenant's certs."""
    if not cert_ids:
        return set()
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id FROM noise_certificates WHERE id = ANY($1::uuid[]) "
            "AND status = 'certified' AND expires_at > now()",
            [uuid.UUID(c) for c in cert_ids],
        )
    return {str(r["id"]) for r in rows}


async def certified_sessions(
    reader: QuerychokeReader,
    conn: asyncpg.Connection,
    *,
    tenant_id: str,
    window_start: date,
    window_end: date,
    bearer: str,
) -> tuple[int, list[Session]]:
    result = await reader.run_template(
        SESSION_TEMPLATE,
        {"from": window_start.isoformat(), "to": window_end.isoformat()},
        bearer=bearer,
    )
    stamped = ledger_certified(result.rows)
    live = await live_certs(conn, tenant_id, {s.noise_cert_id for s in stamped})
    return len(result.rows), [s for s in stamped if s.noise_cert_id in live]


def _request(custom_id: str, model: str, system: str, user: str) -> Request:
    return Request(
        custom_id=custom_id,
        params=MessageCreateParamsNonStreaming(
            model=model,
            max_tokens=4096,
            system=system,
            messages=[{"role": "user", "content": user}],
        ),
    )


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text.strip().removeprefix("```json").removesuffix("```"))
    except ValueError:
        return None


def grounded(candidate: Any, session: Session) -> bool:
    """§9.1 step 2 mechanics: kind is the enum, every evidence digest is ledger-witnessed."""
    if not isinstance(candidate, Mapping) or candidate.get("kind") not in KINDS:
        return False
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence or not str(candidate.get("guidance", "")):
        return False
    return all(isinstance(d, str) and d in session.digests for d in evidence)


def artifact_id(tenant_id: str, kind: str, trigger: str, guidance: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, json.dumps([tenant_id, kind, trigger, guidance]))


async def cascade(
    batch: BatchRunner, tenant_id: str, sessions: Sequence[Session]
) -> tuple[list[Artifact], int, int]:
    """Cheap rung proposes, mechanics ground, the strong rung validates only what survived."""
    by_id = {s.task_id: s for s in sessions}
    proposals = await batch.run(
        [
            _request(
                s.task_id,
                CANDIDATE_MODEL,
                _CANDIDATE_SYSTEM,
                json.dumps({"verdict": s.verdict, "events": list(s.events)}),
            )
            for s in sessions
        ]
    )
    candidates: list[tuple[Session, Mapping[str, Any]]] = []
    n_candidates = 0
    for task_id, text in proposals.items():
        parsed = _parse_json(text)
        for c in parsed[:MAX_CANDIDATES] if isinstance(parsed, list) else []:
            n_candidates += 1
            if grounded(c, by_id[task_id]):
                candidates.append((by_id[task_id], c))
    if not candidates:
        return [], n_candidates, 0
    verdicts = await batch.run(
        [
            _request(
                f"{s.task_id}:{i}",
                VALIDATE_MODEL,
                _VALIDATE_SYSTEM,
                json.dumps(
                    {
                        "artifact": c,
                        "events": [e for e in s.events if e["digest"] in c["evidence"]],
                    }
                ),
            )
            for i, (s, c) in enumerate(candidates)
        ]
    )
    artifacts: list[Artifact] = []
    for i, (s, c) in enumerate(candidates):
        v = _parse_json(verdicts.get(f"{s.task_id}:{i}", ""))
        if not (isinstance(v, Mapping) and v.get("valid") is True):
            continue
        kind, trigger, guidance = str(c["kind"]), str(c.get("trigger", "")), str(c["guidance"])
        artifacts.append(
            Artifact(
                id=artifact_id(tenant_id, kind, trigger, guidance),
                tenant_id=tenant_id,
                kind=kind,
                body={
                    "trigger": trigger,
                    "guidance": guidance,
                    "evidence": list(c["evidence"]),
                    "provenance": {
                        "session_id": s.session_id,
                        "task_id": s.task_id,
                        "device_id": s.device_id,
                        "verdict": s.verdict,
                    },
                    "support_n": 1,
                },
                cert_id=s.noise_cert_id,
            )
        )
    return artifacts, n_candidates, len(candidates)


async def insert_artifacts(
    conn: asyncpg.Connection, tenant_id: str, artifacts: Sequence[Artifact]
) -> int:
    """Idempotent by deterministic id (06 §7.3.3): a re-run re-inserts nothing."""
    inserted = 0
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        for a in artifacts:
            row = await conn.fetchrow(
                "INSERT INTO memory_artifacts (id, tenant_id, abstraction, kind, body, cert_id) "
                "VALUES ($1, $2, $3::artifact_abstraction, $4::artifact_kind, $5::jsonb, $6) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                a.id,
                uuid.UUID(tenant_id),
                a.abstraction,
                a.kind,
                json.dumps(a.body, sort_keys=True),
                uuid.UUID(a.cert_id),
            )
            inserted += row is not None
    return inserted


async def run_extract(
    reader: QuerychokeReader,
    conn: asyncpg.Connection,
    batch: BatchRunner,
    *,
    tenant_id: str,
    day: date,
    bearer: str,
) -> ExtractReport:
    seen, sessions = await certified_sessions(
        reader,
        conn,
        tenant_id=tenant_id,
        window_start=day,
        window_end=day + timedelta(days=1),
        bearer=bearer,
    )
    if not sessions:
        return ExtractReport(seen, 0, 0, 0, 0, 0)
    artifacts, n_candidates, n_grounded = await cascade(batch, tenant_id, sessions)
    inserted = await insert_artifacts(conn, tenant_id, artifacts)
    log.info("extract %s: %d/%d sessions -> %d artifacts", tenant_id, len(sessions), seen, inserted)
    return ExtractReport(seen, len(sessions), n_candidates, n_grounded, len(artifacts), inserted)
