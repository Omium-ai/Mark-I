# ADR-0015 — Arrest modes: ACT enforces, RECOMMEND reports to the host's loop

- **Status:** Accepted — directed by Anurag Upadhyay (founder) 2026-10-03 as Part 4 of the host-agnostic integration
- **Date:** 2026-10-03
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap. One additive event family, one additive `GateVerdict` field, one additive `FabricFrame` arm, one sink selected from a profile field that is `Act` for every session that declared nothing. Removing RECOMMEND is deleting one branch; the ACT path is the code that existed before.
- **Blocks:** Part 6's receipt fields (acted and recommended arrest counts) read the two event families this ADR separates.

## Context

A knee arrest (04 §2.3, 06 §3) is Mark 1 deciding that a retry loop has stopped being worth its cost. For an agent whose execution Mark 1 gates through the hookshim, the arrest **acts**: the gate answers `BLOCK` and the human is told. A host that owns its execution loop (ADR-0013 `owns_execution`, `arrest_mode: RECOMMEND`) wants the same judgement without the enforcement — told what Mark 1 would have stopped, and why, so its own loop can decide. Two consequences fall out of taking that seriously:

- A recommendation is **not** an arrest. The savings guarantee (08 §3.3 reports, the desktop app's figures) counts tokens an arrest actually saved; a recommendation the host may ignore saved nothing it can claim. The two must be counted apart, and the guarantee must count ACT only.
- The host must be able to receive the recommendation however it is attached: over its own fabric connection, from a file if it is a file-tail host, from the control API if it is the desktop app watching, and in the ledger for the record.

## Decision

1. **Detection is untouched.** `fabric.Gate.Answer` still resolves the task, reads the cached verdict and the knee state (`internal/verdict`: ladder, fuse, `KneeState`), and still computes the block, the cap and the knee stop exactly as before. The profile's `ArrestMode` selects only what happens **after** the judgement.

2. **ACT is today's code.** `hostprofile.Default` carries `Act`, so every hookshim, cortexd, transcript-tailer and loopback session — and every `ext:` session that declared nothing or `ARREST_MODE_ACT` — takes the pre-existing path: `BLOCK`, `GuardDecision{BLOCKED|ARRESTED}` in the ledger, `Hub.Arrest` to the control API, the `systemMessage` to the human. The existing gate golden tests pin it.

3. **RECOMMEND never returns BLOCK.** Where ACT would set `GATE_DECISION_BLOCK` (below the knee, at the consecutive-block cap) or arrest at the knee, RECOMMEND leaves the decision `ALLOW` and produces one `m1p.v1.ArrestRecommendation` (events.proto): `kind` (`stop_gate_block` | `knee_arrest` | `block_cap`), `reason` (the same text ACT prints), `k_star_estimate` (the attempt index the governor evaluated at), `projected_cost` (the tokens the daemon estimates the next attempt would spend — what an acted arrest would have saved), `task_id`, `turn`, `session_id`, `evidence_ref`. It reaches the host on **four paths**, all driven from one `Gate.OnRecommend` hook the daemon wires:
   - the `GateVerdict` reply itself (`recommendation`, field 7) — a host that asks the gate gets its answer in the answer;
   - the bound `ext:` fabric connection, as a daemon→writer `FabricFrame{arrest_recommendation}` (arm 11) — the only unsolicited frame the daemon ever writes, and only to an `ext:` connection in RECOMMEND mode;
   - `<state>/run/recommendations/<session-hex>.jsonl`, one protojson `Event` per line, for file-tail hosts, which have no connection to push to;
   - the control API's SSE stream (`event: recommendation`) and verify ring, through the same `Hub.Publish` every admitted event takes;
   and it is **recorded as a ledger `Event`** (`Event.body.arrest_recommendation`, field 24, diagnostic class).

4. **Counted apart, by construction.** A recommendation produces **no `GuardDecision`**. The arrest and block counts and the `tokens_saved` sum that feed receipts, 08 §3.3 reports and the desktop app read `GuardDecision` rows (`reason_code IN (knee_arrest, block_cap)`, `stop_gate_block`, `tokens_saved_estimate`); they therefore count ACT only without a single template changing. Recommendations are counted from their own event family: at the edge in the verify ring (`type: recommendation`), in the cloud through the additive ClickHouse projection below. The receipt payload does not change in this ADR (Part 6).

5. **controld: one additive projection, one migration.** `ArrestRecommendation` rows enter `mark1.m1p_events` through the existing reflection-driven projector (`event_type = "ArrestRecommendation"`, class `diagnostic`, payload in proto field names) with no code change. `migrations/m1_ch_003_arrest_recommendations.sql` adds a materialized view, `mark1.mv_arrest_recommendations` → `mark1.arrest_recommendations`, keyed `(tenant_id, day, session_id, event_id)` with `kind`, `k_star_estimate`, `projected_cost`, `task_id`, so recommendations can be counted and joined without scanning payloads. No existing migration is edited; no other controld contract moves.

6. **Hosts may ask the gate.** 08 §4.6.1's "not available to `ext:` writers" row narrows: `GateQuery` is available to an `ext:` session in RECOMMEND mode, and its `GateVerdict` carries the recommendation. The hookshim's own gate contract (08 §5.1) is unchanged because a hookshim session is never in RECOMMEND mode.

## Consequences

- `m1p.v1` gains `ArrestRecommendation`, `Event.arrest_recommendation = 24`, `GateVerdict.recommendation = 7`, `FabricFrame.arrest_recommendation = 11`; `buf breaking` at `WIRE_JSON` is clean. Rust writers gain `recommendation: None` in their `GateVerdict` literals and ignore the new frame arm as they ignore any arm they do not match.
- The fabric `Server` keeps each connection's session so `Push(session, frame)` can find the bound `ext:` connection; a per-connection write mutex keeps the push from interleaving with a reply.
- 02 §9 FR-SPINE-043..046; 08 §4.2 (control table), §4.6.1, new §4.7; 07 §3 (the family); traceability.

## Not decided here

- What a host that received a recommendation reports back (acted on it, ignored it). A later `ArtifactOutcome` or a new event; not this ADR.
- Whether the desktop app shows recommendations as a distinct column. It can — the verify ring and the ClickHouse view carry them — but the app contract is out of scope.
