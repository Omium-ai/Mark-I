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

## 8. Declare what you own

A host that owns more than its loop says so once, at the handshake, with a
`HostManifest` (`proto/m1p/v1/fabric.proto`, ADR-0013). On the socket it rides
`Hello.host_manifest`; in the file-tail mode it is the sidecar's `host_manifest`
block, in protojson. Same message, same validation, same result.

| Field | Meaning | cem888 |
|---|---|---|
| `host_id` | your stable identifier; non-empty | `cem888` |
| `host_version` | your version string; non-empty | `2.0.1` |
| `owns_execution` | you run the agent loop — must be `true` for an `ext:` writer | `true` |
| `owns_config_surface` | you write the agent's config; Mark 1's provisioning must not | `true` |
| `owns_memory` | you hold the memory the agent sees; Mark 1 must not inject | `true` |
| `arrest_mode` | `ARREST_MODE_ACT`: Mark 1 enforces an arrest; `ARREST_MODE_RECOMMEND`: Mark 1 reports it and your loop decides | `ARREST_MODE_RECOMMEND` |
| `supplies_identity` | your `host_correlation_id` is authoritative for the session's identity | `true` |
| `schema_version` | the manifest's revision; must be `m1p.v1` | `m1p.v1` |

The sidecar form, exactly as `conformance/vectors/extmanifest/sample.manifest.json`:

```json
{"component":"ext:omium/reference-emitter@0.1.0","host_correlation_id":"sample-run-0001","schema_version":"m1p.v1",
 "host_manifest":{"hostId":"cem888","hostVersion":"2.0.1","ownsExecution":true,"ownsConfigSurface":true,
                  "ownsMemory":true,"arrestMode":"ARREST_MODE_RECOMMEND","suppliesIdentity":true,"schemaVersion":"m1p.v1"}}
```

`mark1-emitter -manifest …` and `python emit.py --manifest …` produce it.

**If you omit it**, your session is Mark 1's default posture: Mark 1 provisions the
agent's config, injects memory, and acts on an arrest. Nothing you send is treated
differently; the daemon simply has nothing to yield on.

**If it is invalid** — an empty `host_id` or `host_version`, `arrest_mode` left
unspecified, `owns_execution` false, a `schema_version` other than `m1p.v1` — the
connection closes (or the file is not tailed) with `M1E-4007`, logged once. A manifest
on a connection whose `component` does not start with `ext:` is refused with the same
code.

What the daemon does with it today: validates it, stores it per session, exposes it to
provisioning, the gate and memory, and logs whether `host_id` is a known host. Known
hosts are listed in `go/mark1d/internal/hostprofile/hosts.json` (cem888 is the first);
being unlisted refuses nothing. The decisions those consumers take on your declaration
— not writing your config, recommending instead of blocking, not injecting — arrive as
their own features and are described in the sections that follow when they land.

### 8.1 If you own the config surface

Declare `owns_config_surface: true` and Mark 1's provisioning never writes into your
agent's configuration: `mark1 enable`, the control API and `mark1 off` refuse every
adapter for your session with `M1E-7105` ("host owns config surface", naming your
`host_id`), write nothing, and say so in one line — the active host owns its own
configuration; Mark 1 is attached through the fabric. Nothing of Mark 1's is in your
files, so there is nothing to detach either. The fence you would otherwise get
(08 §8.1) is yours to install, or not, by your own means.

For everyone else, detach is drift-aware (ADR-0014): if your file is exactly what
Mark 1 wrote, or merely reformatted, the original bytes come back verbatim; if a
second writer added entries before or after Mark 1's, exactly Mark 1's entries are
removed and theirs survive; an edit inside Mark 1's entries is left alone and
reported, never silently overwritten.

## 9. If you already speak MCP: the `mark1.*` tools

A host that talks to `cortexd` over MCP for the index tools can do everything in §§3–5 and §8 through three more tools, with `cortexd` as the transport and no M1PL client of its own (08 §6.7–6.9, ADR-0018):

1. `mark1.send_manifest { client, host_manifest, host_correlation_id? }` — the §8 manifest, as JSON. The daemon validates it (M1E-4007 on refusal) and mints your session; the result carries the session id. Your fabric component is `ext:mcp/<client>`.
2. `mark1.emit_event { client, event }` — one Event per call, the §5 vocabulary in the §4 line format (protojson): `task_open`, `task_close`, `turn`, `usage`, `artifact_outcome`. Leave `event_id`, `seq`, `session_id` and `idem_key` out; the daemon stamps them.
3. `mark1.get_recommendations { client }` — the gate's recommendations (§8, `arrest_mode: recommend`) and memory's proposals (`owns_memory: true`) for your session so far, read from the daemon's run files.

What you get is the whole lane: your sessions are bound and validated like a socket host's, your arrests are recommended instead of acted when you asked for that, your memory is proposed instead of injected, and the receipts the daemon seals name your host (ADR-0017: transport `fabric`, your `host_id`, your correlation id). The daemon learns nothing new about you — `ext:mcp/<client>` is an `ext:` writer, full stop. One session per client per `cortexd` process; a refusal from the daemon comes back in the tool result (`refused: true`, `reason_code` M1E-4003 / M1E-4007 / M1E-4008) and is never retried for you.
