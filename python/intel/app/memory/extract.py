"""06 §9.1 extraction cascade over certified sessions (FR-REMEMBER-001/002/006), through the
platform llm-router (16 §L1) and only for a tenant whose mem:extract@1 consent admits it.
What reaches the router is E0 by construction: each ledger event is cut to TYPED_FIELDS."""

import asyncio
import json
import logging
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date, timedelta
from typing import Any, Protocol

import asyncpg

from app.db import set_local_tenant
from app.llm import RouterClient, RouterRefused, reserve_today
from app.tvo.reader import QuerychokeReader

KINDS = frozenset({"pitfall", "fix_pattern", "preference", "invariant"})
CANDIDATE_MODEL = "Qwen/Qwen3-30B-A3B-Instruct-2507"
VALIDATE_MODEL = "zai-org/GLM-5.2"
CONSENT_ID = "mem:extract@1"  # the m1_065 register key, written by controld's Settings switch
SUBPROCESSOR, REGION = "nebius", "global"
MAX_SESSIONS_PER_DAY = 30
MAX_INPUT_TOKENS = 20_000
CHARS_PER_TOKEN = 4  # ponytail: char estimate, no tokenizer; a real count if the cap binds wrongly
SESSION_TEMPLATE = "memory_certified_sessions"
MAX_CANDIDATES = 3
_CERTIFIED_STAGES = frozenset({"certified", "revised"})
_NAMESPACE = uuid.UUID("6f1c2a4e-9b3d-4c1e-8a7f-2d5e6b9c0a11")

log = logging.getLogger("intel.memory.extract")

extract_skipped_total: Counter[str] = Counter()

_CANDIDATE_SYSTEM = (
    "You distill reusable memory artifacts from one verified coding-agent session. "
    f"Reply with ONLY a JSON array of 0-{MAX_CANDIDATES} objects, each exactly "
    '{"kind": one of ' + "|".join(sorted(KINDS)) + ', "trigger": string, "guidance": string, '
    '"evidence": [event digests copied verbatim from the session]}. '
    "The events are typed records (event kinds, tool and model names, diagnostic codes, counts, "
    "verdicts), never code or text. Abstract identifiers to roles; "
    "an artifact with no evidence digests is worthless."
)
_VALIDATE_SYSTEM = (
    "You audit a proposed memory artifact against the session events it cites. "
    'Reply with ONLY {"valid": true|false, "reason": string}. valid is true only when the '
    "guidance is non-trivial, actionable without any source identifier, and each cited event "
    "actually supports it."
)


# The only payload fields sent to the router (10 §10.4 E0); an unlisted kind or field never leaves.
TYPED_FIELDS: dict[str, frozenset[str]] = {
    "SessionStart": frozenset({"agent", "agent_version", "capture_paths"}),
    "SessionEnd": frozenset({"reason", "duration_ms", "drained"}),
    "TaskOpen": frozenset({"task_seg_version", "task_class"}),
    "TaskClose": frozenset({"resolution", "turn_count"}),
    "Turn": frozenset({"turn_index", "initiator"}),
    "ToolUse": frozenset({"tool_name", "duration_ms", "status"}),
    "ModelRequest": frozenset({"model", "served_model", "stream", "request_bytes"}),
    "ModelResponse": frozenset(
        {"status_code", "ttfb_ms", "duration_ms", "response_bytes", "stop_reason"}
    ),
    "Usage": frozenset(
        {
            "model",
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
            "service_tier",
            "source",
        }
    ),
    "GuardDecision": frozenset(
        {
            "outcome",
            "reason_code",
            "tokens_saved_estimate",
            "attempt",
            "evidence",
            "knee_basis",
            "cost_basis",
        }
    ),
    "AnchorVote": frozenset(
        {
            "anchor_id",
            "vote",
            "evidence.tool",
            "evidence.diagnostic_code",
            "evidence.category",
            "evidence.counts.errors",
            "evidence.counts.warnings",
            "evidence.counts.files_affected",
            "evidence.path_role",
            "integrity.diff_classification",
            "integrity.suppression_directive_delta",
            "integrity.tamper",
        }
    ),
    "JudgeVote": frozenset({"judge_id", "vote", "tier_used", "locus", "trigger"}),
    "RmScore": frozenset({"model_id", "score", "locus"}),
    "ConsistencyVote": frozenset({"vote", "sample_count", "agreement_rate"}),
    "VerdictEvent": frozenset({"stage", "verdict", "posterior", "vote_count", "certification"}),
    "MemoryInjection": frozenset({"channel", "tokens_used"}),
    "CortexInjection": frozenset({"channel", "token_budget", "tokens_used"}),
    "ArtifactOutcome": frozenset({"task_verdict", "artifact_followed"}),
    "RouteDecision": frozenset({"action", "candidates", "propensity", "fidelity"}),
    "CoverageTransition": frozenset({"kind", "duration_ms", "reason_code", "agent"}),
    "EvidenceExcerpt": frozenset({"tier"}),
    "OutcomeContribution": frozenset(
        {
            "labels.survival_30d",
            "labels.reverted",
            "labels.tests_pass",
            "labels.human",
            "label_age_days",
        }
    ),
}
_SCALAR = (str, int, float, bool)


def _field(payload: Any, path: str) -> Any:
    for part in path.split("."):
        if not isinstance(payload, Mapping):
            return None
        payload = payload.get(part)
    if isinstance(payload, _SCALAR):
        return payload
    if isinstance(payload, list) and all(isinstance(v, _SCALAR) for v in payload):
        return payload
    return None


def typed_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """One ledger event as E0: digest, kind and only its TYPED_FIELDS, flattened."""
    kind, raw = str(event["kind"]), event.get("payload")
    try:
        payload = json.loads(raw) if isinstance(raw, str) and raw else raw
    except ValueError:
        payload = None
    fields = {p: _field(payload, p) for p in sorted(TYPED_FIELDS.get(kind, ()))}
    return {
        "digest": str(event["digest"]),
        "kind": kind,
        "payload": {p: v for p, v in fields.items() if v is not None},
    }


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
    owner_subject: str | None = None

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


Request = Mapping[
    str, Any
]  # {"custom_id", "params": {"model", "max_tokens", "system", "messages"}}


class BatchRunner(Protocol):
    async def run(self, requests: Sequence[Request]) -> dict[str, str]: ...


class RouterRunner:
    """One router call per request; a refused, blocked or off-model reply is a counted omission,
    exactly as an errored batch result was."""

    def __init__(self, router: RouterClient) -> None:
        self._router = router

    async def run(self, requests: Sequence[Request]) -> dict[str, str]:
        replies = await asyncio.gather(
            *(
                self._router.complete(
                    r["params"]["model"],
                    r["params"]["system"],
                    r["params"]["messages"][0]["content"],
                    r["params"]["max_tokens"],
                )
                for r in requests
            ),
            return_exceptions=True,
        )
        out: dict[str, str] = {}
        for r, reply in zip(requests, replies, strict=True):
            if isinstance(reply, RouterRefused):
                extract_skipped_total[reply.reason.split(":", 1)[0]] += 1
                log.warning("extract %s: %s", r["custom_id"], reply)
            elif isinstance(reply, BaseException):
                raise reply
            else:
                out[r["custom_id"]] = reply.text.rsplit("</think>", 1)[-1]
        return out


async def extraction_consented(conn: asyncpg.Connection, tenant_id: str) -> bool:
    """16 §L1: a live mem:extract@1 row naming the subprocessor and region the router uses."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        row = await conn.fetchrow(
            "SELECT subprocessor, region FROM m1_cloud_judge_consents "
            "WHERE tenant_id = $1 AND judge_id = $2 AND revoked_at IS NULL",
            uuid.UUID(tenant_id),
            CONSENT_ID,
        )
    return row is not None and (row["subprocessor"], row["region"]) == (SUBPROCESSOR, REGION)


def fit_events(session: Session, max_input_tokens: int) -> Session:
    """The newest events whose JSON fits the input cap; grounding then checks only what was sent."""
    budget, kept = max_input_tokens * CHARS_PER_TOKEN, []
    for e in reversed(session.events):
        budget -= len(json.dumps(e)) + 2
        if budget < 0:
            break
        kept.append(e)
    if len(kept) < len(session.events):
        extract_skipped_total["events_over_input_cap"] += len(session.events) - len(kept)
    return replace(session, events=tuple(reversed(kept)))


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
            events=tuple(typed_event(e) for e in r.get("events") or ()),
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


async def device_owners(
    conn: asyncpg.Connection, tenant_id: str
) -> tuple[dict[str, str], str | None]:
    """Doc 15 ownership: device -> the subject of its latest approved (or since revoked)
    enrollment in this tenant, and the tenant's owner_subject."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT DISTINCT ON (device_id) device_id, oidc_subject FROM m1_device_enrollments "
            "WHERE tenant_id = $1 AND device_id IS NOT NULL AND oidc_subject IS NOT NULL "
            "AND status IN ('approved', 'revoked') ORDER BY device_id, row_seq DESC",
            uuid.UUID(tenant_id),
        )
        owner = await conn.fetchval(
            "SELECT owner_subject FROM m1_tenants WHERE id = $1", uuid.UUID(tenant_id)
        )
    return {str(r["device_id"]): r["oidc_subject"] for r in rows}, owner


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
    return {
        "custom_id": custom_id,
        "params": {
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
    }


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


def artifact_id(
    tenant_id: str, kind: str, trigger: str, guidance: str, owner: str | None = None
) -> uuid.UUID:
    key = [tenant_id, kind, trigger, guidance]
    return uuid.uuid5(_NAMESPACE, json.dumps(key if owner is None else [*key, owner]))


def owner_key(owner: str | None, tenant_owner: str | None) -> str | None:
    """The merge key's owner part: None for the tenant owner (so personal and org tenants keep
    today's ids), the subject for a teammate, so two owners never fold into one artifact."""
    return owner if owner and tenant_owner and owner != tenant_owner else None


async def cascade(
    batch: BatchRunner,
    tenant_id: str,
    sessions: Sequence[Session],
    owners: Mapping[str, str] | None = None,
    tenant_owner: str | None = None,
    max_input_tokens: int = MAX_INPUT_TOKENS,
) -> tuple[list[Artifact], int, int]:
    """Cheap rung proposes, mechanics ground, the strong rung validates only what survived."""
    owners = owners or {}
    sessions = [fit_events(s, max_input_tokens) for s in sessions]
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
        owner = owners.get(s.device_id)
        artifacts.append(
            Artifact(
                id=artifact_id(tenant_id, kind, trigger, guidance, owner_key(owner, tenant_owner)),
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
                owner_subject=owner,
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
                "INSERT INTO memory_artifacts (id, tenant_id, abstraction, kind, body, cert_id, "
                "owner_subject) VALUES ($1, $2, $3::artifact_abstraction, $4::artifact_kind, "
                "$5::jsonb, $6, $7) ON CONFLICT (id) DO NOTHING RETURNING id",
                a.id,
                uuid.UUID(tenant_id),
                a.abstraction,
                a.kind,
                json.dumps(a.body, sort_keys=True),
                uuid.UUID(a.cert_id),
                a.owner_subject,
            )
            inserted += row is not None
    return inserted


async def run_extract(
    reader: QuerychokeReader,
    conn: asyncpg.Connection,
    batch: BatchRunner | None,
    *,
    tenant_id: str,
    day: date,
    bearer: str,
    max_sessions: int = MAX_SESSIONS_PER_DAY,
    max_input_tokens: int = MAX_INPUT_TOKENS,
    max_sessions_per_day: int = MAX_SESSIONS_PER_DAY,
) -> ExtractReport:
    """`max_sessions` bounds this run; `max_sessions_per_day` is the tenant's UTC-day ledger."""
    if not await extraction_consented(conn, tenant_id):
        return ExtractReport(0, 0, 0, 0, 0, 0)  # the default: no session leaves for the router
    if batch is None:
        extract_skipped_total["no_router"] += 1
        log.warning("extract %s: LLM_ROUTER_URL unset; consented tenant skipped", tenant_id)
        return ExtractReport(0, 0, 0, 0, 0, 0)
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
    if len(sessions) > max_sessions:
        extract_skipped_total["sessions_over_run_cap"] += len(sessions) - max_sessions
        sessions = sessions[:max_sessions]
    granted = await reserve_today(conn, tenant_id, CONSENT_ID, len(sessions), max_sessions_per_day)
    extract_skipped_total["sessions_over_daily_cap"] += len(sessions) - granted
    sessions = sessions[:granted]
    if not sessions:
        return ExtractReport(seen, 0, 0, 0, 0, 0)
    owners, tenant_owner = await device_owners(conn, tenant_id)
    artifacts, n_candidates, n_grounded = await cascade(
        batch, tenant_id, sessions, owners, tenant_owner, max_input_tokens
    )
    inserted = await insert_artifacts(conn, tenant_id, artifacts)
    log.info("extract %s: %d/%d sessions -> %d artifacts", tenant_id, len(sessions), seen, inserted)
    return ExtractReport(seen, len(sessions), n_candidates, n_grounded, len(artifacts), inserted)
