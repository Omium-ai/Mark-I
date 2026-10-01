# ADR-0012 — External writers: how a third-party host binds to a Mark 1 session

- **Status:** Accepted — decisions directed by Anurag Upadhyay (founder) 2026-10-02 in review of the external-writer plan (session minting in `HelloAck`, `idem_key` stamped by the daemon, equality check scoped to `ext:` connections only, host correlation id carried not adopted)
- **Date:** 2026-10-02
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap. Every change is additive within `m1p.v1` (two new fields, one new `HelloAck` behaviour gated on a `component` prefix) and no first-party writer's bytes or path change. Retiring it is deleting the `ext:` branch.
- **Blocks:** the external-writer contract (08 §4, 2026-10 wave), the partner JSONL file-tail source, `mark1 validate-events`, the reference emitter, `docs/integrating-a-host.md`

## Context

The local fabric (07 §5, 08 §4) was built for writers Mark 1 ships: `mark1-hookshim`, `mark1-proxy`, `cortexd`, the transcript tailers. D-AT made `Hello.session_id` mandatory — a 16-byte non-zero UUIDv7, the attribution key for everything the connection sends — and D-AV struck cortexd's exemption by having the daemon publish the workspace's live session to a file cortexd reads first. Every first-party writer therefore knows its session before it connects: the hookshim takes it from the vendor's hook payload, cortexd from the daemon's session file.

A third-party agent runtime that owns its own execution loop (the CEM888 case) has neither. It has its own run ids, and it has no way to learn a Mark 1 session id because no Mark 1 process observed its session start. Under D-AT as written it cannot pass the handshake at all, and the only alternative — inventing a UUID client-side — is the "synthetic id attributes events to a session that does not exist" lie D-AT exists to end.

Two further facts shaped the decision:

- `capture` is already the sole authority for `seq`, `session_epoch`, and (when the writer omits it) `event_id`. The daemon stamping identity at admission is the existing pattern, not a new one.
- `Usage.idem_key` is an HMAC under the tenant's usage-idem key (events.proto), derived from the tenant HMAC root that arrives with enrollment and lives in daemon custody. An external host cannot compute it and must not hold the key.

## Decision

1. **Session minting, `ext:` writers only.** A `Hello` whose `component` starts with `ext:` (convention: `ext:<vendor>/<product>@<version>`) MAY carry an empty `session_id`. The daemon mints a UUIDv7, binds the connection to it, and returns it in the new `HelloAck.session_id` (field 4). The writer echoes it in `Event.session_id` on every frame. An `ext:` writer that sends a 16-byte id is bound to that id and nothing is minted. A wrong-length or all-zero id remains the D-AT refusal (`M1E-4003`): minting is for an empty field, never a repair. First-party writers are unchanged — their `Hello` without a session is still refused.

2. **Session echo check, `ext:` connections only.** On an `ext:` connection every decodable `Event` must carry `session_id` equal to the bound session; any other value closes the connection (`M1E-4003`) before admission. An undecodable payload passes to capture, which quarantines and accounts it as on every other connection. **This rule is not applied to hookshim, proxy, cortexd or the §4.5 loopback door.** The goal of this wave is zero behaviour change on the existing path, and "safe by inspection" is not the same as tested; widening the rule is a separate decision (see "Not decided here"). `TestFirstPartyEventSessionIsNotCheckedAgainstHello` pins the scope.

3. **Host correlation id, carried not adopted.** `Hello.host_correlation_id` (field 6, string, ≤ 256 bytes, [P1]) is the host's own reference for the session. The daemon stores it beside the Mark 1 session (surfaced through `Server.OnExtHello`) for later echo on receipts; it is never used as the Mark 1 session id and never an admission criterion. Over 256 bytes ⇒ `M1E-4003`. First-party writers leave it empty.

4. **`Usage.idem_key` is stamped by the daemon for `ext:` writers.** The tenant usage-idem key never leaves the daemon. For every `Usage` admitted from an `ext:`-bound session the daemon computes `idem_key` per the events.proto recipe over `(session_id, message_id, request_id)`. If the writer sent a non-empty `idem_key` it is **overwritten**, and the overwrite is logged once per session at debug. `Usage` therefore stays in the minimum event set an external host emits (08 §4). This lands with the shared admission path for ext writers (the JSONL file-tail source and the socket both route through it), not in the fabric layer, which stays transport.

5. **The file-tail transport binds the same way.** A partner JSONL file's sidecar manifest (`<basename>.manifest.json`: component, host correlation id, schema version) is the `Hello` of that transport; the daemon mints the session on first read exactly as for an `ext:` `Hello`. The two transports are symmetric by construction, and downstream code cannot tell them apart.

## Consequences

- `m1p.v1` gains two additive fields (`Hello.host_correlation_id = 6`, `HelloAck.session_id = 4`). `buf breaking` at `WIRE_JSON` is clean against `main`.
- The fabric's handshake grows one branch, gated on a string prefix. Every existing writer's bytes, replies and admission path are byte-identical (`TestSessionedCortexHelloIsAdmitted`, `TestHelloWithoutASessionIsRejected` unchanged and green).
- An external host gets its session from the daemon, which is the one party that can guarantee it is unique on this device and will be attributed.
- 08 §4.2 (control table), §4.3 (steps 2a and 4a) and §9 (`M1E-4003` row) are updated in the same commit.

## Not decided here

- **Whether the session echo check should become global.** It would be safe for hookshim (same id in Hello and every Event, from the vendor payload) and cortexd (stamps the id it Hello'd with), and the loopback door has no Hello to check against. That is an inspection, not a test, and it is a behaviour change on the path this wave promised not to touch. If it is to happen it is its own ADR with its own tests.
- **Echoing `host_correlation_id` on receipts.** The receipt payload (`go/mark1d/internal/identity/receipt.go`) does not change in this wave. The id is stored; the echo is a later feature.
- **Transport in the receipt payload.** Likewise deferred.
