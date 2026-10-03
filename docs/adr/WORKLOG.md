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

### Part 2 (host profile manifest) — what landed, in commit order

- 2.1 docs: ADR-0013; 02 §9.2 FR-SPINE-033..038 (Phase 2 in flight); 08 §4.3 step 2b and
  §9 M1E-4007; 07 sidecar `host_manifest`; traceability rows.
- 2.2 proto: `ArrestMode`, `HostManifest`, `Hello.host_manifest = 7`; `just gen`; every Rust
  `Hello` literal gains `host_manifest: None`; the proxy `deliver` sink fingerprint re-pinned.
- 2.3 `go/mark1d/internal/hostprofile`: `Profile`, `FromManifest`, `Default` (once),
  `Canonical` (golden-pinned), `Registry`, and — folded in from 2.6 because the handshake
  of 2.4 logs known/unknown through it — the embedded `hosts.json` with `Lookup`.
- 2.4 handshake + sidecar + admit package: `fabric/session.go` reads the manifest after
  binding (absent ⇒ Default, invalid or non-ext ⇒ M1E-4007), stores it on the session
  (`HostProfile()`), hands it to `Server.OnExtHello`, logs known/unknown host with the
  canonical profile; `tailers/partner.go` reads the sidecar block through the same
  `FromManifest`; the admit path moved from `cmd/admit.go` to `internal/admit` with an
  explicit `Session` context (id, component, correlation id, profile, ext) and a
  `Registry`; `TestSocketStreamGolden` unchanged and green across the move.
- 2.5 plumbing: `provision.Apply` (Options.Profile → Result.Profile, debug log),
  `fabric.Gate.ProfileFor` called from `Answer`, `memory.Cache.ProfileFor` called from
  `record`; one reachability test per package; no decision changes.
- 2.6 registry: see 2.3; the handshake's known/unknown line is 2.4's.
- 2.7 conformance: emitter `-manifest` (Go) / `--manifest` (Python), the `extmanifest`
  family (events identical to `ext`, sidecar with the cem888 block) in EXPECTED and
  PY_REQUIRED, `TestConfVectorsExtmanifestTransportsAgree` comparing the canonical
  profile each daemon logged at bind; `integrating-a-host.md` §8 "Declare what you own".
  Rows re-tagged Phase 1 once the suite ran.

Environment note for Part 2's runs: the Rust proxy test
`rewritten_request_streams_the_response_untouched` failed once and passed on re-run
(port/timing); recorded as flaky, not as a regression.

### Part 3 (collision-safe config writing) — what landed

- 3.1 The four fenced states as the tree defines them (`claudecode.State`, mirrored in
  codex/gemini/cursor): `OK` (post-image hash matches), `USER-EDITED` (our entries intact,
  the rest changed), `FRAGMENT-DAMAGED` (edit inside our entries — "edited inside the
  fence" is this one), `MISSING`. Every fence in the tree is strict JSON with `_mark1`
  tags (claudecode also `_mark1_managed`); copilot and opencode are mechanism A. There is
  no comment-style fence anywhere, so the CRLF/newline cases are JSON reformat cases.
- 3.2 ADR-0014; 02 §9.2 FR-SPINE-039..042; 08 §8.2 (`post_image`), §8.3 step 0
  (M1E-7105), §8.4 rewritten drift-aware, §9 row; traceability.
- 3.3 `go/mark1d/adapters/fence`: `Classify(pre, post, cur)` → `DriftNone |
  DriftOutsideFence | DriftInsideFence | FenceMissing`, structural for strict JSON with
  `Split` (ours = tagged array elements + the managed object), sorted-key traversal so the
  verdict is deterministic; table tests incl. CRLF, trailing newline, reindent, a second
  writer before/after, inside edits, removal, unparseable.
- 3.4 Each JSON-fence adapter's manifest gains `post_image` (`postimage.go`:
  `encodeImage`, `RestorePostImage`, `ErrNoPostImage`); each `Revert`'s default branch
  classifies first — `DriftNone` restores the pre-image verbatim, everything else takes
  exactly the path it took before; a legacy manifest without `post_image` skips the
  classifier. Generated per-adapter `drift_test.go` (one template, four seeds):
  none → verbatim, reformat → verbatim (new), neighbour after/before → surgical with
  theirs surviving, legacy manifest → old rule. `consent_test.go` unchanged.
- 3.5 `provision.Apply` refuses every walked adapter with M1E-7105 when a DECLARED host
  owns the surface (`HostOwnsSurface`: `HostID != "" && OwnsConfigSurface` — `Default`
  describes Mark 1's own posture and never refuses; recorded in ADR-0014 §4);
  `RevertUnless` is the matching no-op. The CLI module cannot import
  `mark1d/internal/hostprofile`, so `provision.Profile`/`DefaultProfile` re-export the
  type; `enable`, `off` and `doctor` take `Options.Profile` (nil = Default, the
  daemon-down CLI has no session) and render the one line (`NOT PROVISIONED … M1E-7105 …`
  in enable's existing style, `host          M1E-7105 …` in off and doctor; `host_owned`
  in their --json). Tests per verb.
- 3.6 integrating-a-host.md §8.1. Rows re-tagged Phase 1 after the suite.

### Part 4 (arrest modes) — what landed

- 4.1 ADR-0015; 02 §9.2 FR-SPINE-043..046; 08 §4.2 (GateVerdict.recommendation, the
  daemon→writer ArrestRecommendation arm), §4.6.1 (GateQuery available to RECOMMEND hosts),
  new §4.7; 07 §3 note; traceability.
- 4.2 proto: `ArrestRecommendation` (events.proto), `Event.arrest_recommendation = 24`,
  `GateVerdict.recommendation = 7`, `FabricFrame.arrest_recommendation = 11`;
  fabric.proto imports events.proto; `just gen`; Rust GateVerdict literals gain
  `recommendation: None`.
- 4.3 gate.go: detection untouched; `recommend := ProfileFor(session).ArrestMode ==
  Recommend` selects the sink at the three sites (below-the-knee block, consecutive-block
  cap, knee stop): RECOMMEND leaves ALLOW, records an allow instead of a block, sets
  `GateVerdict.recommendation` and calls `OnRecommend`; `ProjectedCost(session, task,
  attempts, kind)` is the daemon's estimate. fabric.Server keeps each connection's
  session (`conns map[net.Conn]*session`) and `Push(sid, frame)` writes to the bound ext:
  connection(s) under a per-session write mutex. cmd/recommend.go `recommendSink` fans out:
  fabric push, `<state>/run/recommendations/<session-hex>.jsonl`, the ledger Event (which
  the hub republishes as SSE family `recommendation` and files as a verify-ring row).
- 4.4 controld: no code change — the reflection-driven projector already emits
  `event_type = "ArrestRecommendation"`, class diagnostic, payload in proto field names;
  `migrations/m1_ch_003_arrest_recommendations.sql` adds `mark1.arrest_recommendations` +
  `mv_arrest_recommendations`. `TestArrestRecommendationProjects` pins the row shape.
- 4.5 Count separation by construction: a recommendation records no GuardDecision, so the
  querychoke session row's arrests/blocks/tokens_saved (reason-code and GuardDecision
  filters, untouched) count ACT only; recommendations have their own family, verify-ring
  row and ClickHouse view. The receipt payload is untouched (Part 6).
- 4.6 Tests: `TestActModeIsUnchangedByTheRegistry` + the existing gate suite (ACT identical),
  `TestRecommendModeNeverBlocks`, `TestRecommendModeAtTheKnee`,
  `TestPushReachesTheBoundExtConnection`, `TestRecommendSinkFansOutOnEveryPath`,
  `TestRecommendationReachesTheControlAPI`, `TestArrestRecommendationProjects`;
  `TestSocketStreamGolden` unchanged.

Environment note (Part 4 runs): `controld/internal/querychoke TestTVOReportContract` fails
identically on the pre-Part-4 commit b7ee1fc in a scratch worktree (calendar-sensitive:
its 7-day window has moved past the fixture's rollup days) — listed with the other
pre-existing failures, not a regression.

## Part 5 — memory modes (ADR-0016)

- 5.1 Docs: ADR-0016; 02 §9 FR-SPINE-047..049; 06 §9.5 "Memory modes" (the rules
  below it are STORE_AND_INJECT; PROPOSE for a declared host that owns memory); 08 §3.7
  edge-side note (no `/memory/match` hop for a PROPOSE session) and §4.2 `MemoryProposal`
  row; 07 §3 family note; traceability.
- 5.2 Proto (additive, buf breaking clean): `enum ProposalCategory`, `message
  MemoryProposal{artifact_id, category, candidate_trigger, candidate_guidance, evidence,
  channel, session_id, task_id}` (intelligence.proto); `Event.memory_proposal = 40`;
  `FabricFrame.memory_proposal = 12`; `just gen`; Rust needs no literal patch (a new oneof
  arm only).
- 5.3 memory/propose.go: `ProposeMode(p)` = declared host (`HostID != ""`) that owns
  memory — `hostprofile.Default`'s `OwnsMemory` reads "Mark 1 owns it", the ADR-0014
  declared-host reading; `Cache.Context` branches to `propose` right after task
  resolution, before either tier, so the fuzz hop (`c.fuzz`) is never reached for the
  session. `propose` walks the same candidates `pack`/`pitfall` would have chosen (same
  kind allowlist, LCB order, MInject room, per-task `seen`) and hands each to the
  `SetOnPropose` sink; it never calls `record`, so no `MemoryInjection` and, with no
  `st.ids`, no `ArtifactOutcome` at close. cmd/propose.go `proposeSink` mirrors
  `recommendSink` (shared `appendSessionLine`): fabric push, `<state>/run/proposals/
  <session-hex>.jsonl`, the ledger → hub family `proposal` + verify-ring row.
- 5.4 Tests: `TestProposeModeIsADeclaredHostThatOwnsMemory`,
  `TestProposeInjectsNothingAndRecordsNothing` (pack and reactive propose, no text, no
  injection/outcome, zero `/memory/match` calls, and the same cache injects for a Default
  session), `TestProposeSinkFansOutOnEveryPath`, `TestProposalReachesTheControlAPI`; the
  existing memory suite unchanged; `TestSocketStreamGolden` unchanged.
- Decision recorded in ADR-0016: proposals are bounded per call by MInject and
  de-duplicated per task by `seen`, but do not consume the task's injection budget —
  nothing was injected, the budget is the host's to spend.
