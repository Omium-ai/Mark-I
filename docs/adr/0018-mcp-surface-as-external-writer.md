# ADR-0018 — The MCP surface as an external writer

- **Status:** accepted
- **Date:** 2026-10-03
- **Scope:** `cortexd`'s MCP server (08 §6): three `mark1.*` tools; `cortexd`'s fabric client.
- **Reversibility:** cheap. Three tools and one shared handshake; the daemon side is untouched — an MCP client is an `ext:` writer like any other (ADR-0012/0013), and removing the tools removes nothing the daemon depends on.

## Context

A host that owns its agent loop reaches Mark 1 today over the fabric socket or the JSONL file-tail (ADR-0012), declares itself with a manifest (ADR-0013), and receives recommendations (ADR-0015) and proposals (ADR-0016) on its connection or in the daemon's files. Many such hosts already speak MCP to `cortexd` for the index tools. Making them also implement M1PL framing and a Unix-socket / named-pipe client to send five event kinds is friction with no information in it: the bytes they would produce are exactly what `cortexd` already knows how to frame and deliver.

## Decision

1. **Three tools, transport only.** `mark1.send_manifest`, `mark1.emit_event`, `mark1.get_recommendations` (08 §6.7–6.9). They do not read the index, spend no budget, emit no `CortexInjection`, and bypass the index-state gates (`M1E-6401`/`6404`) that guard the query tools — `handle` routes on the `mark1.` prefix before `call_tool`. A refusal is a success result with `refused: true` (08 §6's envelope), never an MCP error, and never a retry.
2. **The client is the writer.** A call names a `client` (`^[A-Za-z0-9._-]{1,64}$`); the fabric component is `ext:mcp/<client>`. The first Hello for a client carries no session id, so the daemon mints one (ADR-0012) and `cortexd` keeps it, with the manifest and correlation id, for the life of its process; every later Hello for that client presents the same id, manifest and correlation id, so the daemon binds the same session and its echo check holds. One session per client per `cortexd` process; a second `send_manifest` for the same client opens a new session (a new manifest is a new declaration).
3. **One handshake.** `fabric::exchange` is the Hello → HelloAck → frames sequence both paths share: `deliver` (cortexd's own first-party push, unchanged bytes) and `ext_exchange` (the tools). EOF before an ack is the daemon's refusal (`M1E-4003`, or `M1E-4007` when a manifest was sent) and is reported as such; a daemon that cannot be reached is `M1E-4008`, a new fabric code for "unreachable from the MCP surface".
4. **Events are protojson.** `mark1.emit_event` takes one `m1p.v1.Event` as the object 08 §4.6.2's file-tail line format already defines: optional `task_id` (base64, or hex for a 16-byte id) and `occurred_at` (RFC 3339; now when absent), and exactly one of `task_open`, `task_close`, `turn`, `usage`, `artifact_outcome` — proto or lowerCamelCase field names, enum names or numbers. `event_id`, `seq` and `session_id` are ignored: the daemon stamps them (ADR-0012), and `idem_key` on `Usage` is the daemon's too. Nothing else is accepted — a host wanting another family writes the socket or the file.
5. **Recommendations and proposals come from the daemon's files.** `mark1.get_recommendations` reads `<state>/run/recommendations/<session-hex>.jsonl` and `<state>/run/proposals/<session-hex>.jsonl` (08 §4.7, §3.7) — the file-tail host's path, which needs no connection to be open at the moment the gate decides. `<state>` is `MARK1_STATE_DIR`, else `$HOME/.omium/mark1` (the socket's own directory). Malformed lines are counted, not fatal.

## Consequences

- An MCP client gets the whole external-writer lane — manifest, events, recommendations, proposals, host-bound receipts (ADR-0017: transport `fabric`, `host_id` from its manifest) — without implementing M1PL.
- The daemon learns nothing new: `ext:mcp/<client>` is an `ext:` component, validated, bound, admitted and judged exactly as a socket host. The golden hookshim, cortexd first-party push and transcript-tailer paths are untouched (`deliver` produces the same Hello and frames; its tests pass unchanged).
- Not done: a fabric push of recommendations to the MCP client (the daemon pushes to the bound `ext:` connection, which `cortexd` opens per call and closes); the files are the stable path. Not done: any event family beyond the five.
