# Integrating a host with Mark 1

For a third-party agent runtime that owns its own execution loop and wants Mark 1 to
receive its events. This page is sufficient on its own; the normative contract behind
it is `docs/design/08-api-contracts.md` §4.6 and the decision record is
`docs/adr/0012-external-writer-session-binding.md`. Everything here is **public and
versioned**: additive-only within `m1p.v1`, so what you build today keeps working.

Two transports, one contract. Start with the file (no socket client to write), move
to the socket when you want events to land as they happen.

## 1. The endpoint

| Platform | Fabric endpoint |
|---|---|
| Linux | `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock`, else `~/.omium/mark1/m1p.sock` |
| macOS | `~/.omium/mark1/m1p.sock` |
| Windows | `\\.\pipe\omium-mark1-<user-SID>` — the SID of the user running `mark1d` |

Owner-only. Your host runs as the same OS user as `mark1d`, or it cannot connect, by
design. There is no network listener and no token: the operating system's user
boundary is the authentication.

## 2. Framing (socket only)

Nine bytes, then one serialized `m1p.v1.FabricFrame` (`proto/m1p/v1/fabric.proto`):

```
offset  size  field
0       4     "M1PL"
4       1     0x01
5       4     len, u32 little-endian, 0 < len ≤ 4_194_304
9       len   FabricFrame bytes
```

A frame outside the bound closes the connection. `conformance/emitter/emitter.go`
carries a complete writer in ~40 lines (`writeFrame`/`readFrame`); copy it.

## 3. Hello and session binding

Your first frame is `Hello`. Set `component` to `ext:<vendor>/<product>@<version>`
(the `ext:` prefix is what makes you an external writer), leave `session_id` empty,
and optionally set `host_correlation_id` to your own run or thread id (≤ 256 bytes).
`mark1d` answers `HelloAck{accepted: true, session_id: <16 bytes>}`: a session it
minted for you. Put those 16 bytes in `Event.session_id` on **every** frame you
send on that connection; a frame naming any other session closes the connection
(`M1E-4003`).

```
→ Hello{component: "ext:acme/runner@1.2.3", host_correlation_id: "run-7781"}
← HelloAck{accepted: true, max_frame: 4194304, session_id: 0x0199…}
→ Event{session_id: 0x0199…, …}      (repeat)
→ Flush{}
← FlushAck{drained: N}                 N = events admitted on this connection
```

Send `Flush` after your `SessionEnd` and wait for the ack before exiting. If you
already hold a 16-byte session id (because Mark 1 gave you one earlier), you may send
it in `Hello` and are bound to it; nothing is minted. Your correlation id is stored
beside the session and never used as a Mark 1 identity.

## 4. Phase one without a key: the JSONL file-tail mode

Write two files with one basename, the sidecar first:

```
~/.omium/mark1/partner/<name>.manifest.json
  {"component":"ext:acme/runner@1.2.3","host_correlation_id":"run-7781","schema_version":"m1p.v1"}

~/.omium/mark1/partner/<name>.jsonl
  one m1p.v1.Event per line, protojson, appended as they happen
```

The sidecar is the file's `Hello`: `mark1d` binds the file to a session it mints once
(persisted, so a daemon restart continues the same session) and tails the file through
the same admission path the socket uses. Leave `session_id` out of every line; the
daemon stamps it. Files elsewhere are tailed with `mark1d --partner-events <path>`.

Rules that matter: only complete `\n`-terminated lines are read, so an append that is
cut mid-line is picked up when you finish it; rotate by renaming the file and creating
a new one (the daemon drains the old one first); set `event_id` on every line (a
UUIDv7) so that if the daemon ever re-scans the file, the server deduplicates at
ingest rather than double-counting. A line that will not decode, or that names a
session other than the file's, is quarantined and counted; the tail continues.

## 5. The events

Rules for every `Event` (`proto/m1p/v1/envelope.proto`): `event_id` 16 bytes
(UUIDv7, recommended); `seq` and `session_epoch` **zero** — the daemon assigns them;
`task_id` empty — the daemon segments; `occurred_at` your wall clock, **non-decreasing**
within a session, and lines/frames in causal order; `tenant_id`, `device_id`,
`received_at`, `clock_skew_ms` unset.

Emit, in this order:

| Event | When | Minimal protojson example |
|---|---|---|
| `SessionStart` | once, first | `{"eventId":"…","occurredAt":"2026-10-02T12:00:00Z","sessionStart":{"agent":"acme-runner","agentVersion":"1.2.3"}}` |
| `TaskOpen` | your loop opens a unit of work | `{"eventId":"…","occurredAt":"…","taskOpen":{"taskSegVersion":"ext:acme/runner.v1","taskClass":"*"}}` |
| `Turn{HUMAN}` | each new user intent — **this opens a Mark 1 task** | `{"eventId":"…","occurredAt":"…","turn":{"initiator":"INITIATOR_HUMAN"}}` |
| `Turn{AGENT}` | each attempt your loop makes | `{"eventId":"…","occurredAt":"…","turn":{"turnIndex":1,"initiator":"INITIATOR_AGENT"}}` |
| `ToolUse` | each tool call | `{"eventId":"…","occurredAt":"…","toolUse":{"toolName":"Bash","toolUseId":"toolu_01","durationMs":"42","status":"TOOL_STATUS_OK"}}` |
| `Usage` | each model response | `{"eventId":"…","occurredAt":"…","usage":{"messageId":"msg_01","requestId":"req_01","model":"claude-fable-5-1","inputTokens":"120","outputTokens":"30"}}` |
| `ArtifactOutcome` | you claim an outcome | `{"eventId":"…","occurredAt":"…","artifactOutcome":{"artifactId":"<16 bytes b64>","taskVerdict":"VERDICT_SATISFIED","artifactFollowed":true}}` |
| `TaskClose` | your loop closes the unit of work | `{"eventId":"…","occurredAt":"…","taskClose":{"resolution":"RESOLUTION_VERDICT","turnCount":2}}` |
| `SessionEnd` | once, last | `{"eventId":"…","occurredAt":"…","sessionEnd":{"reason":"END_REASON_EXIT","durationMs":"8000","drained":true}}` |

The five-event floor is `TaskOpen`, `TaskClose`, `Turn`, `Usage`, `ArtifactOutcome`.
Two things the daemon owns on your behalf: `Usage.idem_key` (the billing dedupe key)
is computed and stamped by the daemon — send `message_id` and `request_id` and leave
`idem_key` empty — and the receipted task boundary is the `task_seg.v1` task the daemon
opens at your `Turn{HUMAN}`; your `TaskOpen`/`TaskClose` are recorded as your declared
boundaries. Unknown fields you add are ignored, never refused.

`conformance/vectors/ext/sample.jsonl` is a complete, valid session you can diff
against.

## 6. `mark1 validate-events`

Before you connect:

```
mark1 validate-events <name>.jsonl            # or "-" for stdin; --json for machines
```

It checks every rule in §5 — decoding, required fields, the daemon-owned fields left
zero, timestamps non-decreasing, and the causal order (`TaskClose` only after its
`TaskOpen`, `Turn` only inside an open task, `Usage` and `ArtifactOutcome` only after a
`Turn`). Unknown fields are warnings. Exit 0 is valid; exit 5 with `M1E-4006` lists
every error, first one first.

## 7. Conformance checklist

1. **Run the emitter.** `go run ./conformance/emitter/cmd/mark1-emitter -out /tmp/ext`
   or `python conformance/emitter/emit.py /tmp/ext`. Both write the same
   `sample.jsonl` + `sample.manifest.json`, byte for byte.
2. **Validate.** `mark1 validate-events /tmp/ext/sample.jsonl` → exit 0, zero errors.
   Then validate your own file the same way.
3. **Tail.** Copy both files into `~/.omium/mark1/partner/` (or point
   `mark1d --partner-events` at the `.jsonl`). `mark1d`'s log shows `partner: file bound`
   with your component and a session; `mark1 status` shows the session's usage.
4. **Push.** `mark1-emitter -socket <endpoint>` (unix) pushes the same session over the
   socket; `HelloAck` carries your minted session.
5. **Compare.** The repository's `TestConfVectorsExtTransportsAgree` is exactly this
   check automated: the two transports must yield identical internal streams. Run
   `cd go/mark1d && go test ./cmd -run ConfVectorsExt` to prove it on your machine.

What is not for you: the loopback HTTP door (`08` §4.5) has no `Hello` and so no
identity or session binding; `GateQuery`/`ContextQuery` exist for first-party shims
whose execution Mark 1 gates — a host that owns its loop has nothing to gate.
