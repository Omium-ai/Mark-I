# ADR-0016 — Memory modes: STORE_AND_INJECT is today, PROPOSE hands the host a candidate and touches nothing

- **Status:** Accepted — directed by Anurag Upadhyay (founder) 2026-10-03 as Part 5 of the host-agnostic integration
- **Date:** 2026-10-03
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap. One additive event family, one additive `FabricFrame` arm, one sink selected from `Profile.OwnsMemory` which is `true`-for-Mark-1 (today's behaviour) for every session that declared nothing. Removing PROPOSE deletes one branch.
- **Blocks:** nothing downstream; Part 6 reads no memory field.

## Context

Mark 1's memory plane (06 §9) retrieves admitted artifacts for the task at hand and **injects** them into the agent — a packed context block at hook time, a reactive pitfall remedy on a tool failure — and records each delivery as a `MemoryInjection` so outcomes can be attributed and fed back to admission (`ArtifactOutcome` at task close, 06 §9.5). That is right when Mark 1 owns the memory the agent sees. A host that holds its own memory (ADR-0013 `owns_memory`) wants the detection — "this looks like a pitfall you have hit before, here is what helped" — without Mark 1 writing into a store it does not own or injecting text into a loop it does not run.

## Decision

1. **Detection is untouched.** `internal/memory` still syncs the admitted set, still matches a tool failure against the cached signature digests, still packs the LCB-ordered candidates under the token budget. The profile selects only what happens with the result.

2. **STORE_AND_INJECT is today's code.** `hostprofile.Default.OwnsMemory` is `true` and reads, as every Default field does, "the owner — Mark 1 — owns it": `pack` and `pitfall` record a `MemoryInjection`, return the text, and `OnClose` emits the `ArtifactOutcome`s. Every hookshim, cortexd, tailer and loopback session, and any `ext:` session that declared nothing, takes this path; the existing memory tests pin it.

3. **PROPOSE, for a declared host that owns memory.** `HostID != "" && OwnsMemory` (the same declared-host reading as ADR-0014 §4):
   - **never writes the store** — no `MemoryInjection` is recorded, the task's injected set stays empty, `OnClose` emits no `ArtifactOutcome`;
   - **never injects** — `Context` returns no text on either channel;
   - **never calls the intel memory admission path for that session** — the reactive tier's server hop (`POST /api/v1/memory/match`, 08 §3.7) is not made, and nothing that feeds `ADMIT-LCB` (06 §9.3) is emitted; the guard is in `Cache.Context` before any channel is served;
   - instead emits one `m1p.v1.MemoryProposal` (intelligence.proto) per candidate it would have injected: `candidate` (the artifact's trigger and guidance), `category` (`CONVENTION` for an invariant, `PITFALL` for a pitfall, `TOOL_GUIDANCE` for a fix pattern, `DECISION` reserved), `evidence` (the error signature or the pack context that selected it), `artifact_id`, `channel`. The proposal is delivered on two paths and recorded: a `FabricFrame{memory_proposal}` pushed to the bound `ext:` connection (the second daemon→writer arm after ADR-0015's), one protojson `Event` line in `<state>/run/proposals/<session-hex>.jsonl`, and the ledger `Event` (`Event.body.memory_proposal`, field 40, diagnostic class), which the control API republishes as SSE family `proposal`.

4. **Counting stays honest.** A proposal is not an injection: `MemoryInjection` counts, `tokens_used` numerators and `ArtifactOutcome` attribution read their own families and see nothing from a PROPOSE session.

## Consequences

- `m1p.v1` gains `MemoryProposal`, `ProposalCategory`, `Event.memory_proposal = 40`, `FabricFrame.memory_proposal = 12`; `buf breaking` clean.
- `memory.Cache` gains `SetOnPropose` (the sink seam; `propose.go` is PROPOSE mode's `Context`, selected by `ProposeMode(ProfileFor(session))`); the daemon's `cmd/propose.go` `proposeSink` fans out exactly as `cmd/recommend.go` does (fabric push, `<state>/run/proposals/<session-hex>.jsonl`, the ledger → SSE family `proposal`).
- 02 §9 FR-SPINE-047..049; 08 §3.7 (edge-side note), §4.2 (the arm); 06 §9.5 (the mode); 07 §4; traceability.

## Not decided here

- Whether a host reports back which proposals it adopted. A later event.
- Whether Mark 1 should learn from a host's own memory. No: ownership is the point.
