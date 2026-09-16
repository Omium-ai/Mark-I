"""The hand-off (05 §4.1; 06 §10.4): a compiled draft becomes one `bundle_drafts` row (m1_070).

The compiler holds zero keys and no publish verb. It INSERTs canonical section bytes, the map
hash and the knee gate's verdict; controld's draft publisher (policydist/drafts.go) re-decodes
under the strict reference decoder, signs, logs, commits the catalog row and attaches the canary
plan. A draft the knee gate rejects is written `refused` with the reason (06 §10.3: a violated
gate blocks publication and pages) so the refusal is on record, not just in a log.

Identity is the job's (06 §7.3): (tenant, channel, window_start). ON CONFLICT DO NOTHING is the
whole idempotency story — intel_app holds INSERT and no UPDATE.
"""

from datetime import datetime, timedelta

import asyncpg

from app.policy_compiler.compile import SECTION_NAMES, Compiled

# ponytail: fail-static horizon (07 max_age). Nightly cadence × D21's five retries is ~2 days;
# a week leaves room for a parked compile before edges fall to built-ins. Tenant-tunable later.
MAX_AGE = timedelta(days=7)


class KneeGateViolation(RuntimeError):
    """06 §10.3: the table's implied knee is not within ±1 of k*(ρ̂, γ̂) — fit or ledger is wrong."""


async def previous_sections(
    conn: asyncpg.Connection, tenant_id: str, channel: str
) -> dict[str, bytes] | None:
    """Per-section bytes of the tenant's last published draft on the channel, if any."""
    row = await conn.fetchrow(
        "SELECT verify_cbor, route_cbor, memory_cbor, cortex_cbor, gates_cbor, agent_maps_cbor "
        "FROM bundle_drafts WHERE tenant_id = $1 AND channel = $2 AND state = 'published' "
        "ORDER BY published_seq DESC LIMIT 1",
        tenant_id,
        channel,
    )
    return None if row is None else {n: bytes(row[f"{n}_cbor"]) for n in SECTION_NAMES}


async def write_draft(
    conn: asyncpg.Connection,
    tenant_id: str,
    channel: str,
    window_start: datetime,
    compiled: Compiled,
    max_age: timedelta = MAX_AGE,
) -> bool:
    """True when this call created the row; False when the window's draft already existed."""
    state = "pending" if compiled.knee_gate_ok else "refused"
    reason = None if compiled.knee_gate_ok else f"knee sanity gate (06 §10.3): {compiled.note}"
    tag = await conn.execute(
        "INSERT INTO bundle_drafts (tenant_id, channel, window_start, verify_cbor, route_cbor, "
        "memory_cbor, cortex_cbor, gates_cbor, agent_maps_cbor, draft_hash, max_age, "
        "knee_gate_ok, knee_note, state, refusal_reason) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) "
        "ON CONFLICT (tenant_id, channel, window_start) DO NOTHING",
        tenant_id,
        channel,
        window_start,
        *(compiled.sections[n] for n in SECTION_NAMES),
        compiled.draft_hash,
        max_age,
        compiled.knee_gate_ok,
        compiled.note,
        state,
        reason,
    )
    return tag == "INSERT 0 1"
