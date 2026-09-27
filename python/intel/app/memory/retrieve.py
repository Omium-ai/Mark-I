"""06 §9.4/§9.5 retrieval: the admitted pack source and the one halfvec fuzzy match
(FR-REMEMBER-004/008). Delivery and the per-task decision live at the edge (mark1d/memory)."""

import hashlib
import json
import math
import re
import uuid
from collections.abc import Sequence
from typing import Any

import asyncpg

from app.db import set_local_tenant

DIM = 1024
FUZZ_DISTANCE = 0.15
M_INJECT = 3
SIGNATURE_LINES = 2
SIGNATURE_MAX_CHARS = 240
# Allowlist: the DB enum's 'preference' is 06 §9.2's routing_hint class, bundles only, never served.
INJECTABLE_KINDS = frozenset({"pitfall", "fix_pattern", "invariant"})
# Doc 15 fragments over memory_artifacts: $1 is the tenant, $2 the viewer (NULL = unfiltered).
# Once a tenant has had a member it stays per-person: a leaver's last token never reads tenant-wide.
IS_TEAM = "EXISTS (SELECT 1 FROM m1_team_members WHERE tenant_id = $1 AND role = 'member')"
# Team consent is per device: TRUE only when every approved device's latest row says team.
LATEST_TEAM_CONSENT = (
    "(SELECT bool_and(l.team) FROM (SELECT DISTINCT ON (c.device_id) c.team "
    "FROM m1_device_consents c JOIN m1_device_enrollments e "
    "ON e.device_id = c.device_id AND e.tenant_id = c.tenant_id AND e.status = 'approved' "
    "WHERE c.tenant_id = $1 AND e.oidc_subject = {subject} "
    "ORDER BY c.device_id, c.row_seq DESC) l)"
)
# NULL owner = the tenant owner's.
OWNS = (
    "($2::text IS NULL OR owner_subject = $2 OR (owner_subject IS NULL "
    "AND $2 = (SELECT owner_subject FROM m1_tenants WHERE id = $1)))"
)
# The viewer is still on the team (owner or active member): a leaver never reads shared memory.
PARTICIPANT = (
    "($2 = (SELECT owner_subject FROM m1_tenants WHERE id = $1) OR EXISTS (SELECT 1 "
    "FROM m1_team_members WHERE tenant_id = $1 AND subject = $2 AND role = 'member' "
    "AND left_at IS NULL))"
)
VISIBLE = (
    f"({OWNS} OR (scope = 'team' AND (SELECT shared_memory FROM m1_tenants WHERE id = $1) "  # noqa: S608 — literal fragments
    f"AND {PARTICIPANT} "
    f"AND {LATEST_TEAM_CONSENT.format(subject='memory_artifacts.owner_subject')} IS TRUE))"
)


async def team_viewer(conn: asyncpg.Connection, tenant_id: str, viewer: str | None) -> str | None:
    """The viewer to filter by, or None: no viewer given, or the tenant is not a team (then every
    artifact is the viewer's own, today's behaviour). Call under the tenant GUC."""
    if viewer is None:
        return None
    return viewer if await conn.fetchval(f"SELECT {IS_TEAM}", uuid.UUID(tenant_id)) else None


_LINE = re.compile(r"\r\n|\r|\n")
_PATH = re.compile(r"(?:[A-Za-z]:)?(?:[\\/][A-Za-z0-9_.\-]+){2,}")
_TOKEN = re.compile(r"[a-z0-9]+")
_NUM = re.compile(r"[0-9]+")
_WS = re.compile(r"[ \t\r\n]+")
_STRIP = " \t\r\n\f\v"


def normalize_signature(text: str) -> str:
    """The Go twin is memory.NormalizeSignature (go/mark1d/internal/memory/signature.go);
    test_signature_digest_agrees_with_go pins them to one vector."""
    lines = [ln.strip(_STRIP) for ln in _LINE.split(text)]
    s = " ".join([ln for ln in lines if ln][:SIGNATURE_LINES])[:SIGNATURE_MAX_CHARS].lower()
    s = _PATH.sub("<path>", s)
    s = _TOKEN.sub(_hex_token, s)
    s = _NUM.sub("0", s)
    return _WS.sub(" ", s).strip(_STRIP)


def _hex_token(m: re.Match[str]) -> str:
    t = m.group(0)
    if len(t) >= 6 and any(c.isdigit() for c in t) and all(c in "0123456789abcdef" for c in t):
        return "<hex>"
    return t


def signature_digest(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def embed(normalized: str) -> list[float] | None:
    """ponytail: feature-hashed char 3-5-grams (sha256 bucket + sign), unit-normalized; 06 fixes no
    embedder, so this is deterministic and model-free. Swap the model behind this one function and
    re-run embed_missing."""
    if not normalized:
        return None
    v = [0.0] * DIM
    s = f" {normalized} "
    for n in (3, 4, 5):
        for i in range(len(s) - n + 1):
            h = hashlib.sha256(s[i : i + n].encode("utf-8")).digest()
            v[int.from_bytes(h[:4], "little") % DIM] += 1.0 if h[4] & 1 else -1.0
    scale = math.sqrt(sum(x * x for x in v))
    if scale == 0.0:
        return None
    return [x / scale for x in v]


def vector_literal(v: Sequence[float]) -> str:
    return "[" + ",".join(f"{x:.6g}" for x in v) + "]"


def _row(r: asyncpg.Record) -> dict[str, Any]:
    body = json.loads(r["body"]) if isinstance(r["body"], str) else dict(r["body"])
    out = {
        "artifact_id": str(r["id"]),
        "kind": str(r["kind"]),
        "trigger": str(body.get("trigger", "")),
        "guidance": str(body.get("guidance", "")),
        "utility_lcb": float(r["lcb"]) if r["lcb"] is not None else 0.0,
    }
    if out["kind"] == "pitfall":
        out["error_sig_digest"] = signature_digest(normalize_signature(out["trigger"]))
    return out


async def admitted(
    conn: asyncpg.Connection, tenant_id: str, viewer: str | None = None
) -> list[dict[str, Any]]:
    """The edge cache's sync source: every admitted injectable artifact, LCB-ranked (06 §9.4 with
    d̂ = 0 — no unlabeled repo features reach this service yet, so λ·d̂ is the owed term)."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id, kind, body, lcb, state::text AS state, scope, pinned, n_obs, "  # noqa: S608 — literal fragments, values bound
            f"{OWNS} AS mine FROM memory_artifacts WHERE tenant_id = $1 "
            f"AND state = 'admitted' AND kind::text = ANY($3::text[]) AND {VISIBLE} "
            "ORDER BY lcb DESC NULLS LAST, id",
            uuid.UUID(tenant_id),
            await team_viewer(conn, tenant_id, viewer),
            sorted(INJECTABLE_KINDS),
        )
    # state/scope/pinned/n/mine are the app's action fields (spec §5.5); the edge ignores them.
    return [
        {
            **_row(r),
            "state": str(r["state"]),
            "scope": str(r["scope"]),
            "pinned": bool(r["pinned"]),
            "n": int(r["n_obs"]),
            "mine": bool(r["mine"]),
        }
        for r in rows
    ]


async def outcomes(
    conn: asyncpg.Connection, tenant_id: str, viewer: str | None = None
) -> list[dict[str, Any]]:
    """Per-artifact ADMIT-LCB evidence for the app (spec §5.5): the stored lcb and the certified
    sample count it was computed from; verified_outcomes is that same count (the samples are
    certified tasks), not a satisfied-only subset, which no column holds."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id, lcb, n_obs FROM memory_artifacts WHERE tenant_id = $1 AND n_obs > 0 "  # noqa: S608 — literal fragments, values bound
            f"AND {VISIBLE} ORDER BY lcb DESC NULLS LAST, id",
            uuid.UUID(tenant_id),
            await team_viewer(conn, tenant_id, viewer),
        )
    return [
        {
            "artifact_id": str(r["id"]),
            "verified_outcomes": int(r["n_obs"]),
            "uplift_lcb": float(r["lcb"]) if r["lcb"] is not None else 0.0,
            "n": int(r["n_obs"]),
        }
        for r in rows
    ]


async def fuzzy_match(
    conn: asyncpg.Connection,
    tenant_id: str,
    normalized: str,
    *,
    limit: int = M_INJECT,
    max_distance: float = FUZZ_DISTANCE,
    viewer: str | None = None,
) -> list[dict[str, Any]]:
    """06 §9.5 D29: admitted pitfalls within cosine 0.15 over ix_artifacts_error_signature."""
    v = embed(normalized)
    if v is None:
        return []
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id, kind, body, lcb, error_signature <=> $3::text::halfvec AS distance "  # noqa: S608 — literal fragments, values bound
            "FROM memory_artifacts WHERE tenant_id = $1 AND state = 'admitted' "
            "AND kind = 'pitfall' AND error_signature IS NOT NULL "
            f"AND {VISIBLE} ORDER BY error_signature <=> $3::text::halfvec LIMIT $4",
            uuid.UUID(tenant_id),
            await team_viewer(conn, tenant_id, viewer),
            vector_literal(v),
            limit,
        )
    out = []
    for r in rows:
        if r["distance"] <= max_distance:
            out.append({**_row(r), "distance": float(r["distance"])})
    return out


async def embed_missing(conn: asyncpg.Connection, tenant_id: str) -> int:
    """Stamp error_signature on pitfall rows that lack one, from body.trigger (the extractor
    inserts none). Idempotent: a stamped row is never rewritten."""
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        rows = await conn.fetch(
            "SELECT id, body FROM memory_artifacts WHERE tenant_id = $1 AND kind = 'pitfall' "
            "AND error_signature IS NULL",
            uuid.UUID(tenant_id),
        )
        n = 0
        for r in rows:
            body = json.loads(r["body"]) if isinstance(r["body"], str) else dict(r["body"])
            v = embed(normalize_signature(str(body.get("trigger", ""))))
            if v is None:
                continue
            await conn.execute(
                "UPDATE memory_artifacts SET error_signature = $2::text::halfvec, "
                "updated_at = now() WHERE id = $1 AND error_signature IS NULL",
                r["id"],
                vector_literal(v),
            )
            n += 1
    return n
