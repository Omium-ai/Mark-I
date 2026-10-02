# `ext` conformance vectors — the external-writer sample session

The golden output of the reference external writer (`conformance/emitter`, Go and
Python copies): one realistic session in the partner JSONL file-tail format of
08 §4.6.2 with its sidecar. It is what a third-party host integrates against, and
what pins the two transports to one stream (FR-SPINE-031).

```
sample.jsonl            nine protojson m1p.v1.Events, one per line, 08 §4.6.3 order:
                        SessionStart, TaskOpen, Turn{HUMAN}, Turn{AGENT}, ToolUse, Usage,
                        ArtifactOutcome, TaskClose, SessionEnd — the five-event minimum,
                        the lifecycle pair and one tool call
sample.manifest.json    the file's Hello: component, host_correlation_id, schema_version
```

**Frozen.** `go run ./conformance/emitter/cmd/mark1-emitter -out <dir>` and
`python conformance/emitter/emit.py <dir>` must both reproduce these bytes exactly;
a regeneration that changes a byte is a finding against an emitter, never a license
to update the vector. Deterministic by construction: fixed UUIDv7-shaped
`event_id`s, timestamps one second apart from 2026-10-02T12:00:00Z, protojson
re-serialised with sorted keys and compact separators.

## What locks on it

| Lane | Test | Claim |
|---|---|---|
| Go, `go/mark1d/cmd` | `TestConfVectorsExtEmitterIsPinned` | the Go emitter's JSONL and sidecar equal these files |
| Go, `go/mark1d/cmd` | `TestConfVectorsExtTransportsAgree` | the same session pushed over the socket into one daemon and tailed from this file by another yields identical internal streams (spool records with the daemon-minted fields masked) and identical receipt leaves (the writer-stamped `event_id`s in order) |
| Go, `go/mark1/internal/validateevents` | `TestConfVectorsExtGoldenValidates` | `mark1 validate-events sample.jsonl` is OK with zero errors |
| Python, `python/shared/mark1_receipts/tests` | `test_conf_vectors_ext_emitter_matches_golden` | `emit.py` reproduces both files byte for byte |

No Rust twin: no Rust component produces or consumes an external writer's stream;
the M1PL framing the socket push uses is already locked by the `m1pl` family.

Receipts are sealed at upload (07 "The receipt chain") against a control-plane head,
so the in-process comparison pins the receipt **leaves** — the `event_id` sequence
a checkpoint's Merkle root is computed over — rather than a signed checkpoint. The
receipt payload carries no transport field (deliberately: a later feature).
