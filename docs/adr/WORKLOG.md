# WORKLOG — host-agnostic integration (branch Fazil)

Not an ADR: a running log of the master-prompt job (Parts 0–8). Appended after every
commit. Decisions live in the ADRs it cites; this file says what happened, in order.

## Orientation (2026-10-03)

HEAD at the start of this log: `20d7cb5` (Part 1 steps 1–6 committed; step 7's re-tag in
the working tree). Earlier on the branch: `abb539c` ADR-0012 session binding (Part 1.1),
`5d8326e` admit refactor (1.2), `c3f5813` contract docs (1.3), `7123e91` JSONL tailer (1.4),
`ed48be6` validate-events (1.5), `640c709` emitter + ext vectors (1.6), `20d7cb5` partner
doc (1.7).

What already existed on `main` before this job: the fabric (UDS + Windows named pipe,
M1PL framing, Hello/HelloAck, gate, context, flush), the loopback door (08 §4.5), the
transcript tailers (Usage-only, vendor formats as Go adapters), capture as the sole
seq/epoch/event_id authority, the segmenter (task_seg.v1), the receipt sealer, the
control API, cortexd with its session-file binding (D-AV), the verifiers, the m1pl /
redact / receipt / bundle / fusion / coverage vector families.

Toolchain on this Windows machine: Go 1.26.5, cargo, uv, buf 1.72.0 and just 1.42.4
(installed into ~/.local/bin by this job), golangci-lint 2.1.6, and a `python` shim in
~/.local/bin that runs the uv-managed interpreter. `just` must be invoked with
`--shell <git-bash> --shell-arg -c` here. Known environment-only failures (all confirmed
on a clean worktree or by dependency direction, none caused by this job): mark1
doctor/enable agent detection, control's settings-file tests, the otel docs allowlist
gate, the D-AP Go/Python posterior diff (24 content-identical lines reordered), the
python intel cp1252 read, and — because this disk sits at 97 % used, past the 95 % hard
stop — every test that counts diagnostic-class spool records without stubbing the disk
sampler (obs, cmd agentversion/contamination). trace-check reports 100 "no such test"
rows for unix-tagged suites it cannot list on Windows; the key-set check passes.

## Part 1 — external writer lane: file plan (done)

- 1.1 `proto/m1p/v1/fabric.proto` (Hello.host_correlation_id=6, HelloAck.session_id=4),
  `go/mark1d/internal/fabric/{session,server}.go`, Rust literal updates, ADR-0012, 08 §4.2–4.3, §9.
- 1.2 `go/mark1d/cmd/admit.go` (admitPath), `cmd/admitpath_golden_test.go` +
  `testdata/socket_stream.golden`, `cmd/dial_{unix,windows}_test.go`.
- 1.3 08 §1.1/§1.2/§4.6, 07 §5 + "Partner event files", 02 §9.2 FR-SPINE-027..032, traceability.
- 1.4 `go/mark1d/internal/tailers/{partner.go,partner_test.go,cursor.go,tailer.go,stream.go}`,
  `cmd/main.go` (--partner-events, Partner wiring, bindExt, idem_key stamp),
  `cmd/{partner_golden,ext_socket}_test.go`.
- 1.5 `go/mark1/internal/validateevents/`, `go/mark1/cmd/main.go`, 08 §7.8, §9 M1E-4006.
- 1.6 `conformance/emitter/` (Go module + emit.py), `conformance/vectors/ext/`, EXPECTED,
  `tools/ci/conformance_crosslang.sh` (PY_REQUIRED), `cmd/ext_conformance_test.go`,
  `validateevents/conf_vectors_ext_test.go`, `python/shared/mark1_receipts/tests/test_conf_vectors_ext.py`.
- 1.7 `docs/integrating-a-host.md`, docs/README.md row.
- 1.8 02 §9.2 rows re-tagged Phase 1.

Deviation recorded: the master prompt's 1.2 wants the admit function "in its own package
with a session context argument". It landed in package main (cmd/admit.go) with an
ext-session map; Part 2.4 moves it to `go/mark1d/internal/admit` with an explicit
session context (id, component, correlation id, profile), under the same golden test.

## Part 2 — host profile manifest: file plan

- 2.1 `docs/adr/0013-host-profile-manifest.md`; 02 §9.2 FR-SPINE-033..038 (Phase 2);
  08 §4.3 step 2b + §9 M1E-4007; 07 "Partner event files" host_manifest block; traceability.
- 2.2 `fabric.proto`: ArrestMode, HostManifest, Hello.host_manifest=7; `just gen`.
- 2.3 `go/mark1d/internal/hostprofile/{profile.go,profile_test.go}` (+ golden canonical).
- 2.4 `go/mark1d/internal/admit/` (lifted from cmd/admit.go, with Session context),
  `fabric/session.go` (manifest read, M1E-4007), `tailers/partner.go` (sidecar host_manifest),
  `hostprofile.Registry`; tests in fabric, tailers, cmd.
- 2.5 `adapters/provision/provision.go` (Options.Profile), `fabric/gate.go` (Profiles),
  `internal/memory` (Profiles); one test each.
- 2.6 `hostprofile/hosts.json` (embedded), `Lookup`, handshake known/unknown log; tests.
- 2.7 emitter `-manifest` flag + emit.py; `conformance/vectors/ext-manifest/`; EXPECTED;
  Python copy; cmd conformance test; integrating-a-host.md "Declare what you own"; re-tag.

## Parts 3–8: file plans are appended when each part starts.

## Commit log

- `abb539c` … `20d7cb5` — Part 1 steps 1–7 (see the orientation entry).
- Part 1.8: 02 §9.2 FR-SPINE-027..032 re-tagged Phase 1; trace-check reports them fully
  proven (its only failures are the 100 unix-only listings this Windows box cannot see).
  Final Go suites: only the known environment failures, plus one flaky run of
  TestSocketStreamGolden inside the full cmd package (passed standalone, passed on the
  next full run; an eight-run hunt is logged under Part 2). WORKLOG.md starts here.
