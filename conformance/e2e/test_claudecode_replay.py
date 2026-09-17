"""The Phase-1 replay path, asserted from the cloud side (12 §12 Phase 1, item 1).

Every assertion reads what the rig left in the REAL stores after the REAL binaries ran:
ClickHouse through the m1p_query principal, Postgres' receipt chain, the MinIO landing
prefix, controld's querychoke, and the verifier's verdict over a local export. The oracle
for what a correct tailer emits is the corpus' own `expectations.json`; nothing here is
authored from memory.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
from rig import SESSION_ID, Rig, usage_idem_key

# What the nine pinned hook bodies become on the wire (rust/mark1-hookshim/maps/claudecode.json →
# m1p.v1 bodies): SessionStart, UserPromptSubmit→Turn, 3×ToolUse, Stop→Turn, SubagentStop→Turn,
# PreCompact→nothing, SessionEnd. Counted per event family as the ledger names them.
HOOK_EVENTS_ON_LEDGER = {"SessionStart": 1, "Turn": 3, "ToolUse": 3, "SessionEnd": 1}


def _expected_usage(rig: Rig) -> dict[str, dict]:
    """idem_key hex → the exact Usage numbers expectations.json names, both streams."""
    out = {}
    for stream in rig.expectations()["streams"]:
        for ev in stream["usage_events"]:
            k = ev["idem_key_inputs"]
            key = usage_idem_key(
                rig.tenant_root, uuid.UUID(k["session_id"]), k["message_id"], k["request_id"]
            )
            out[key.hex().upper()] = {**ev["usage"], "model": ev["model"], **k}
    return out


def _usage_rows(rig: Rig) -> list[dict]:
    return rig.ch_query(f"""
        SELECT hex(idem_key) AS idem_key, uniqExact(event_id) AS event_ids, count() AS rows,
               anyLast(input_tokens) AS input_tokens, anyLast(output_tokens) AS output_tokens,
               anyLast(cache_creation_input_tokens) AS cache_creation_input_tokens,
               anyLast(cache_read_input_tokens) AS cache_read_input_tokens,
               anyLast(model) AS model, anyLast(session_id) AS session_id,
               anyLast(JSONExtractString(payload, 'message_id')) AS message_id
        FROM mark1.m1p_events
        WHERE tenant_id = toUUID('{rig.tenant_id}') AND event_type = 'Usage'
        GROUP BY idem_key ORDER BY idem_key""")


def test_e2e_hook_bodies_land_on_ledger_via_shim(rig: Rig) -> None:
    """Each pinned hook body → the command settings.json registered → fabric → spool →
    ingest → m1p_events, under the fixture's session. The shim's contract is exit 0 always."""
    assert [h.returncode for h in rig.hook_runs] == [0] * 9, rig.hook_runs
    stop = next(h for h in rig.hook_runs if h.event == "Stop")
    assert '"block"' not in stop.stdout, (
        f"the stop gate blocked with no verdict on file: {stop.stdout}"
    )
    rows = rig.ch_query(f"""
        SELECT event_type, uniqExact(event_id) AS n FROM mark1.m1p_events
        WHERE tenant_id = toUUID('{rig.tenant_id}') AND session_id = toUUID('{SESSION_ID}')
        GROUP BY event_type""")
    got = {r["event_type"]: int(r["n"]) for r in rows}
    for event_type, n in HOOK_EVENTS_ON_LEDGER.items():
        assert got.get(event_type) == n, (
            f"{event_type}: ledger has {got.get(event_type)}, want {n}; all={got}"
        )
    # Every row on the ledger names the enrolled identity — stamped from the token, never
    # the envelope.
    ids = rig.ch_query(f"""SELECT uniqExact(device_id) AS d FROM mark1.m1p_events
                           WHERE tenant_id = toUUID('{rig.tenant_id}')
                             AND device_id = toUUID('{rig.device_id}')""")
    assert int(ids[0]["d"]) == 1


def test_e2e_transcript_usage_matches_expectations(rig: Rig) -> None:
    """FR-AGENT-010's end-to-end clause: the pinned transcripts, tailed by the real daemon,
    reach ClickHouse as exactly the Usage events expectations.json names — idem_key
    (HMAC under the tenant root), every token field, model, and the parent session id
    on the subagent stream too (04 §2.1)."""
    want = _expected_usage(rig)
    got = {r["idem_key"]: r for r in _usage_rows(rig)}
    assert set(got) == set(want), (
        f"idem_key sets differ.\n missing: {[want[k]['message_id'] for k in set(want) - set(got)]}"
        f"\n unexpected: {[got[k]['message_id'] for k in set(got) - set(want)]}"
    )
    for key, exp in want.items():
        row = got[key]
        for f in (
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
        ):
            assert int(row[f]) == exp[f], f"{exp['message_id']}.{f}: ledger {row[f]}, want {exp[f]}"
        assert row["model"] == exp["model"], (exp["message_id"], row["model"])
        assert row["message_id"] == exp["message_id"]
        assert uuid.UUID(row["session_id"]) == SESSION_ID, row
    assert len(got) == 7  # 5 parent + 2 subagent, per the corpus README


def test_e2e_usage_deduped_per_idem_key_no_overcount(rig: Rig) -> None:
    """FR-SPINE-003 / NFR-CORRECTNESS-001 on the wire: one Usage per (message.id, requestId)
    after the whole path. The corpus' 4-line streaming rewrite must land as ONE event carrying
    the last line's cumulative count — never the naive per-line sum (the verified ~2.5×)."""
    exp = rig.expectations()["overcount_case"]
    rows = {r["message_id"]: r for r in _usage_rows(rig)}
    over = rows[exp["message_id"]]
    assert int(over["event_ids"]) == 1 and int(over["rows"]) == 1, over
    assert int(over["output_tokens"]) == exp["correct_output_tokens"] == 1042, over
    assert int(over["output_tokens"]) != exp["naive_per_line_output_token_sum"]
    # Summed over the corpus, the ledger must not carry the overcount either.
    total_out = sum(int(r["output_tokens"]) for r in rows.values())
    hand = sum(
        ev["usage"]["output_tokens"]
        for s in rig.expectations()["streams"]
        for ev in s["usage_events"]
    )
    assert total_out == hand == 2302
    # Every idem_key: exactly one event_id, exactly one row (no duplicate delivery survived).
    dup = [r for r in rows.values() if int(r["event_ids"]) != 1 or int(r["rows"]) != 1]
    assert not dup, dup


def test_e2e_sidechain_and_foreign_streams_never_land(rig: Rig) -> None:
    """The sidechain rule (08 §5.1) and invariant 3 (04 §0.3), observed at the ledger: the
    parent's sidechain replay owns no key of its own (its key is the subagent's, landed once),
    and the munge-colliding foreign session — same vendor directory, cwd outside the enabled
    root — contributes nothing."""
    exp = rig.expectations()
    rows = {r["message_id"]: r for r in _usage_rows(rig)}
    for never in exp["streams"][0]["never_emit"]:
        # Same (message.id, requestId) as the subagent's own line ⇒ same idem_key ⇒ one event.
        assert int(rows[never["message_id"]]["event_ids"]) == 1, rows[never["message_id"]]
    for foreign in exp["out_of_workspace_streams"]:
        assert foreign["never_emit_message_id"] not in rows, rows.keys()
    hits = rig.ch_query(f"""SELECT count() AS n FROM mark1.m1p_events
                            WHERE tenant_id = toUUID('{rig.tenant_id}')
                              AND positionCaseInsensitive(payload, 'SynthForeign') > 0""")
    assert int(hits[0]["n"]) == 0


def test_e2e_landing_objects_under_tenant_prefix(rig: Rig) -> None:
    """05 §2.2: land in S3 first, then ack. Every object in the per-run bucket sits under
    t/<tenant>/ingest/v1/ — the prefix the bucket policy scopes."""
    keys = [
        o["Key"]
        for page in rig.s3().get_paginator("list_objects_v2").paginate(Bucket=rig.bucket)
        for o in page.get("Contents", [])
    ]
    assert keys, "no landing object at all — nothing was acked"
    prefix = f"t/{rig.tenant_id}/ingest/v1/dt="
    assert all(k.startswith(prefix) and k.endswith(".m1p.zst") for k in keys), keys
    quarantined = [k for k in keys if "/quarantine/" in k]
    assert not quarantined, quarantined


def _chain(rig: Rig) -> list[dict]:
    return rig.pg(
        """SELECT seq, checkpoint_seq, event_count, device_key_id, server_key_id
                     FROM m1_receipts WHERE tenant_id = $1 AND record_type = 'checkpoint'
                     ORDER BY seq""",
        rig.tenant_id,
    )


def _emitted_checkpoints(rig: Rig) -> list[dict]:
    """The ReceiptCheckpoint events the device uploaded, as the ledger holds them."""
    return rig.ch_query(f"""
        SELECT event_id, JSONExtractUInt(payload, 'checkpoint_seq') AS checkpoint_seq,
               JSONExtractUInt(payload, 'leaf_count') AS leaf_count
        FROM mark1.m1p_events
        WHERE tenant_id = toUUID('{rig.tenant_id}') AND event_type = 'ReceiptCheckpoint'
        ORDER BY event_id""")


def test_e2e_receipt_chain_first_batch_sealed_by_enrolled_key(rig: Rig) -> None:
    """07's checkpoint model on the first acked batch: sealed by the key `mark1 enroll`
    registered, countersigned by the server chain key, one Merkle root over the batch."""
    chain = _chain(rig)
    assert chain, "no checkpoint on the chain at all"
    first = chain[0]
    # seq 1 is the tenant's bundle_publication receipt (05 §4.1): enrollment publishes the
    # bootstrap bundle before any batch can seal, so the first checkpoint follows it.
    publication = rig.pg(
        "SELECT seq FROM m1_receipts WHERE tenant_id = $1 AND record_type = 'bundle_publication'",
        rig.tenant_id,
    )
    assert [r["seq"] for r in publication] == [1], publication
    assert (first["seq"], first["checkpoint_seq"]) == (2, 1), first
    assert first["device_key_id"] == rig.device_key_id, first
    assert first["server_key_id"], first
    emitted = {int(c["checkpoint_seq"]): int(c["leaf_count"]) for c in _emitted_checkpoints(rig)}
    assert emitted.get(1) == first["event_count"] >= 1, (emitted, first)
    assert rig.mark1d_exit == 0, f"mark1d exited {rig.mark1d_exit} on SIGTERM"


def test_e2e_receipt_chain_seals_every_landed_event(rig: Rig) -> None:
    """The clause the Phase-1 gate actually states — "certified usage events": every event
    the ledger holds sits under an ACCEPTED checkpoint, and every checkpoint the device
    emitted was appended to the chain. RED TODAY, deterministically, and the seam is a
    contract split between the two shipped binaries (nothing in-process could see it):

      * mark1d seals the ReceiptCheckpoint record it uploads as a leaf of the NEXT tree
        (go/mark1d/internal/uplink/batch.go batchLeaves; receipt/sealer.go allMine's doc:
        "a batch with even one other event still seals, and covers the checkpoints riding
        beside it"), while controld never queues a checkpoint as a leaf
        (go/controld/internal/ingest/sidefx/sidefx.go Apply: "deliberately not a leaf of
        any tree"). The second batch of every session is [checkpoint, …] ⇒ leaf_count
        disagrees ⇒ refused ("N leaf(s) pending, seal claims N+1").
      * mark1d reads the chain head right after the ack (sealer.go head) while controld
        appends the checkpoint that rode in that very batch asynchronously post-ack
        (sidefx worker) ⇒ the stale head re-claims checkpoint_seq ⇒ broken_link.
      * the orphaned leaf then heads controld's pending queue, so every later honest seal
        is a merkle_mismatch — paged as a SECURITY event (GuardDecision M1E-8003) — and
        the last Usage events of the session are outside any accepted checkpoint.
    """
    chain = _chain(rig)
    emitted = _emitted_checkpoints(rig)
    landed = rig.landed()
    non_ckpt = sum(
        n for t, n in landed.items() if t not in ("ReceiptCheckpoint", "Dropped", "GuardDecision")
    )
    accepted_leaves = sum(c["event_count"] for c in chain)
    security = rig.ch_query(f"""SELECT count() AS n FROM mark1.m1p_events
                                WHERE tenant_id = toUUID('{rig.tenant_id}')
                                  AND event_type = 'GuardDecision'
                                  AND positionCaseInsensitive(payload, 'merkle_mismatch') > 0""")
    problems = []
    if len(chain) != len(emitted):
        problems.append(f"device emitted {len(emitted)} checkpoints, chain appended {len(chain)}")
    if accepted_leaves < non_ckpt:
        problems.append(
            f"accepted checkpoints cover {accepted_leaves} leaves, ledger holds {non_ckpt} events"
        )
    if int(security[0]["n"]):
        problems.append(
            f"{security[0]['n']} merkle_mismatch security event(s) raised against an honest device"
        )
    if problems:
        pytest.fail(
            "receipt chain does not certify the session's events end to end:\n  - "
            + "\n  - ".join(problems)
            + "\nSeam: reconcile whether a ReceiptCheckpoint is a leaf of the next tree "
            "(mark1d uplink/batch.go batchLeaves + receipt/sealer.go allMine say yes; controld "
            "ingest/sidefx/sidefx.go Apply says no) and make the head the sealer reads "
            "(sealer.go head) reflect the checkpoint riding in the batch just acked "
            "(sidefx appends it asynchronously post-ack).",
            pytrace=False,
        )


def test_e2e_verifier_offline_accepts_chain(rig: Rig) -> None:
    """FR-SPINE-020 / FR-CLI-007 on the chain this run produced: the real `mark1
    verify-receipts --offline` over the real mark1-verifier, fed only local files."""
    assert rig.verify is not None
    assert rig.verify.returncode == 0, (
        f"verify-receipts exit {rig.verify.returncode}\n{rig.verify.stdout.decode()}\n"
        f"{rig.verify.stderr.decode()}"
    )
    report = json.loads(rig.verify.stdout.decode())
    assert report.get("ok") is True, report
    lines = [ln for ln in rig.export_path.read_text().splitlines() if ln.strip()]
    ckpts = rig.pg("SELECT count(*) AS n FROM m1_receipts WHERE tenant_id = $1", rig.tenant_id)
    assert len(lines) == int(ckpts[0]["n"]) >= 1


def test_e2e_tvo_session_rollup_matches_hand_computation(rig: Rig) -> None:
    """TVO at session grain: the m1_ch_002 session rollup read through controld's querychoke
    (`usage_by_session`, the 08 §3.3 surface, device token) equals the field-by-field hand
    sum of expectations.json. Task grain — ADR-0002's denominator — is the next test."""
    exp = rig.expectations()
    hand = {"tokens_in": 0, "tokens_out": 0, "tokens_cache_read": 0, "tokens_cache_create": 0}
    for s in exp["streams"]:
        for ev in s["usage_events"]:
            u = ev["usage"]
            hand["tokens_in"] += u["input_tokens"]
            hand["tokens_out"] += u["output_tokens"]
            hand["tokens_cache_read"] += u["cache_read_input_tokens"]
            hand["tokens_cache_create"] += u["cache_creation_input_tokens"]
    assert hand == {
        "tokens_in": 46,
        "tokens_out": 2302,
        "tokens_cache_read": 11008,
        "tokens_cache_create": 3904,
    }

    rows = rig.choke("usage_by_session", {"from": "2026-08-29", "to": "2026-08-29"})
    mine = [r for r in rows if uuid.UUID(r["session_id"]) == SESSION_ID]
    assert len(mine) == 1, rows
    row = mine[0]
    assert str(row["day"]).startswith("2026-08-29"), row  # the choke renders Date as RFC 3339
    assert row["agent"] == "claudecode"
    got = {k: int(row[k]) for k in hand}
    assert got == hand, (got, hand)
    # Tenancy is bound from the token's claims: a tenant with no session sees none.
    assert {uuid.UUID(r["session_id"]) for r in rows} == {SESSION_ID}


def test_e2e_tvo_task_rollup_matches_hand_computation(rig: Rig) -> None:
    """TVO at task grain — the ADR-0002 denominator — read through the `tvo_task_window`
    template reader.py's attempt_window consumes (the rollup driver's only ledger read).

    Hand-derived from the corpus, rule by rule: the nine hook bodies carry ONE UserPromptSubmit
    ⇒ R1 opens exactly one task (task_seg.v1); no second prompt ⇒ R2/R3 never fire; the rig
    consents no anchor ⇒ no stage-final verdict ⇒ ONE attempt with fused_verdict '' ; SessionEnd
    ⇒ R4 closes it UNRESOLVED_SESSION_END. Every one of the 7 Usage events is admitted while
    that task is open, so the attempt's gen_tokens is expectations.json's four-field sum
    (46 + 2302 + 3904 + 11008 = 17260); verifier_tokens is 0 because no ledger row carries
    judge or anchor tokens; cost_usd is 0 because chproj projects none. The window runs from
    the vendor-stamped Usage day (2026-08-29) past today: TaskOpen carries the daemon's clock."""
    exp = rig.expectations()
    hand_gen = sum(
        ev["usage"][f]
        for s in exp["streams"]
        for ev in s["usage_events"]
        for f in (
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
        )
    )
    assert hand_gen == 17260
    scope = f"tenant_id = toUUID('{rig.tenant_id}') AND session_id = toUUID('{SESSION_ID}')"
    opens = rig.ch_query(f"""
        SELECT DISTINCT task_id, JSONExtractString(payload, 'task_seg_version') AS v
        FROM mark1.m1p_events WHERE {scope} AND event_type = 'TaskOpen'""")
    assert len(opens) == 1 and opens[0]["v"] == "task_seg.v1", opens  # R1, once
    task = opens[0]["task_id"]
    closes = rig.ch_query(f"""
        SELECT DISTINCT task_id, JSONExtractString(payload, 'resolution') AS r
        FROM mark1.m1p_events WHERE {scope} AND event_type = 'TaskClose'""")
    assert closes == [{"task_id": task, "r": "RESOLUTION_UNRESOLVED_SESSION_END"}], closes  # R4
    stamped = rig.ch_query(f"""
        SELECT uniqExact(task_id) AS tasks, uniqExact(event_id) AS n
        FROM mark1.m1p_events WHERE {scope} AND event_type = 'Usage'
          AND task_id = toUUID('{task}')""")
    if int(stamped[0]["n"]) != 7:
        pytest.fail(
            f"{stamped[0]['n']}/7 transcript Usage rows carry the open task's task_id. Seam: "
            "cmd/main.go tailWorkspaces builds claudecode.TailConfig without Observe — set "
            "Observe to func(ev) { seg.Observe(ev, nil) } (tailers.Config.Observe runs before "
            "Emit, so route.Decision inherits the id) and pass seg into tailWorkspaces.",
            pytrace=False,
        )

    to = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=2)).isoformat()
    rows = rig.choke("tvo_task_window", {"from": "2026-08-29", "to": to})
    assert len(rows) == 1, rows  # one task, one attempt — the tenant is this run's alone
    row = rows[0]
    got = {
        "task_id": row["task_id"],
        "attempt_n": int(row["attempt_n"]),
        "gen_tokens": int(row["gen_tokens"]),
        "verifier_tokens": int(row["verifier_tokens"]),
        "fused_verdict": str(row["fused_verdict"]),
        "verdict_stage": str(row["verdict_stage"]),
        "task_seg_version": row["task_seg_version"],
        "cost_usd": float(row["cost_usd"]),
    }
    assert got == {
        "task_id": task,
        "attempt_n": 1,
        "gen_tokens": hand_gen,
        "verifier_tokens": 0,
        "fused_verdict": "",
        "verdict_stage": "",
        "task_seg_version": "task_seg.v1",
        "cost_usd": 0.0,
    }, got
    # The same rows through reader.py's own mapping: the AttemptRow seam the tenant-day rollup
    # (rollup.py) reads — one attempt, terminal verdict blank ⇒ the `unresolved` class (R5).
    assert {k for k in row} >= {
        "task_id",
        "attempt_n",
        "gen_tokens",
        "verifier_tokens",
        "fused_verdict",
        "verdict_stage",
        "task_seg_version",
        "cost_usd",
    }


def test_e2e_run_shape(rig: Rig) -> None:
    """The run's own shape, so a regression that keeps the numbers right but changes the
    path (a shim that spilled everything, an IdP never consulted) is still visible."""
    assert rig.idp is not None and rig.idp.grants == 1 and rig.idp.polls >= 1
    assert all(h.wall_ms < 40_000 for h in rig.hook_runs)
    print(f"\nrig timings (s): { {k: round(v, 1) for k, v in rig.timings.items()} }")
    if rig.timings.get("total", 0) > 600:
        pytest.fail("the e2e drive exceeded 10 minutes; move this suite behind the nightly gate")
