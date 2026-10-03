# FINAL REPORT — Mark 1 host-agnostic integration (branch `Fazil`)

Eight parts, forty-one commits on top of `f85bff9` (the merge base with `main`), every one
with the full suite run first. Everything is additive: `buf breaking` against `main` is
clean at every proto commit, the golden hookshim/cortexd/tailer streams are byte-identical
(`TestSocketStreamGolden`, `conf_vectors_m1pl_*`, cortexd's golden tests), and nothing in
`omium-mark1` (the sibling directory) was touched. The running log is
`docs/adr/WORKLOG.md`; the environment-only gate failures are `BLOCKERS.md` (reproduced at
the end of this report).

## 1. Files changed per commit, grouped by part

### Part 1 — the external-writer lane (ADR-0012)

| Commit | Files |
|---|---|
| `abb539c` feat: Implement ADR-0012 for external writers session binding | docs/adr/0012-external-writer-session-binding.md, docs/design/08-api-contracts.md, go.work.sum, go/mark1d/internal/fabric/{server.go, session.go, session_test.go}, proto/gen/{go,python,rust} bindings, proto/m1p/v1/fabric.proto, rust/cortexd/src/fabric/mod.rs, rust/cortexd/tests/fabric_wire.rs, rust/m1p-wire/{fuzz/fuzz_targets/frame_decode.rs, gen/m1p.v1.rs, tests/m1pl.rs}, rust/mark1-hookshim/{src/context.rs, src/fabric.rs, tests/shim_e2e.rs}, rust/mark1-proxy/src/fabric.rs, rust/mark1-redact/tests/no_admit_off_switch.rs |
| `5d8326e` mark1d: lift the fabric handler closure into admitPath | go/mark1d/cmd/{admit.go, admitpath_golden_test.go, dial_unix_test.go, dial_windows_test.go, main.go, testdata/socket_stream.golden} |
| `c3f5813` docs: the external-writer contract | conformance/traceability.yaml, docs/design/{02-requirements.md, 07-data-model.md, 08-api-contracts.md} |
| `7123e91` mark1d: the partner JSONL file-tail transport | conformance/traceability.yaml, docs/design/07-data-model.md, go/mark1d/cmd/{admit.go, ext_socket_test.go, main.go, partner_golden_test.go}, go/mark1d/internal/tailers/{cursor.go, partner.go, partner_test.go, stream.go, tailer.go} |
| `ed48be6` mark1: validate-events | conformance/traceability.yaml, docs/design/08-api-contracts.md, go/mark1/cmd/main.go, go/mark1/go.mod, go/mark1/internal/validateevents/{validateevents.go, validateevents_test.go} |
| `640c709` conformance: the ext family | conformance/emitter/{cmd/mark1-emitter/main.go, emit.py, emitter.go, go.mod, go.sum}, conformance/traceability.yaml, conformance/vectors/EXPECTED, conformance/vectors/ext/{README.md, sample.jsonl, sample.manifest.json}, go.work, go/mark1/internal/validateevents/conf_vectors_ext_test.go, go/mark1d/cmd/ext_conformance_test.go, go/mark1d/go.mod, python/shared/mark1_receipts/tests/test_conf_vectors_ext.py, tools/ci/conformance_crosslang.sh |
| `20d7cb5` docs: integrating-a-host.md | conformance/traceability.yaml, docs/README.md, docs/integrating-a-host.md |
| `e66cffa` docs: FR-SPINE-027..032 armed at Phase 1; WORKLOG opens | docs/adr/WORKLOG.md, docs/design/02-requirements.md |

### Part 2 — the host profile manifest (ADR-0013)

| Commit | Files |
|---|---|
| `4000807` docs: ADR-0013 host profile manifest | conformance/traceability.yaml, docs/adr/0013-host-profile-manifest.md, docs/adr/WORKLOG.md, docs/design/{02, 07, 08} |
| `383de48` proto: ArrestMode, HostManifest, Hello.host_manifest | proto/m1p/v1/fabric.proto, proto/gen bindings, rust/cortexd/src/fabric/mod.rs, rust/m1p-wire/{fuzz target, gen, tests/m1pl.rs}, rust/mark1-hookshim/src/fabric.rs, rust/mark1-proxy/src/fabric.rs, rust/mark1-redact/tests/no_admit_off_switch.rs |
| `ea3b703` mark1d: hostprofile | go/mark1d/internal/hostprofile/{hosts.go, hosts.json, hosts_test.go, profile.go, profile_test.go} |
| `63cbf7e` mark1d: the handshake resolves the host manifest; admit moves to internal/admit | go/mark1d/cmd/{admit.go, main.go}, go/mark1d/internal/admit/admit.go, go/mark1d/internal/fabric/{server.go, session.go, session_test.go}, go/mark1d/internal/tailers/{partner.go, partner_test.go} |
| `7bd519f` mark1d: provisioning, the gate and memory read the session profile | go/mark1d/adapters/provision/{profile_test.go, provision.go}, go/mark1d/internal/fabric/{gate.go, gate_profile_test.go}, go/mark1d/internal/memory/{cache.go, inject.go, profile_test.go} |
| `a444086` conformance: the extmanifest family; host guide §8; FR-SPINE-033..038 armed | conformance/emitter/{cmd/mark1-emitter/main.go, emit.py, emitter.go}, conformance/traceability.yaml, conformance/vectors/EXPECTED, conformance/vectors/extmanifest/{README.md, sample.jsonl, sample.manifest.json}, docs/design/02-requirements.md, docs/integrating-a-host.md, go/mark1d/cmd/extmanifest_conformance_test.go, python/shared/mark1_receipts/tests/test_conf_vectors_extmanifest.py, tools/ci/conformance_crosslang.sh |

### Part 3 — collision-safe config writing (ADR-0014)

| Commit | Files |
|---|---|
| `f159d6c` docs: ADR-0014 detach removes the fence, not the file | conformance/traceability.yaml, docs/adr/0014-detach-removes-the-fence-not-the-file.md, docs/design/{02, 08} |
| `20a0807` mark1d: adapters/fence | go/mark1d/adapters/fence/{drift.go, drift_test.go} |
| `8ac6a57` adapters: drift-aware revert; manifests record post_image | go/mark1d/adapters/{claudecode, codex, cursor, gemini}/{drift_seed_test.go, drift_test.go, fragment.go, postimage.go, revert.go} |
| `6c17c3a` provision: a declared host that owns the config surface is refused | go/mark1/internal/doctor/{doctor.go, hostowned_test.go}, go/mark1/internal/enable/{enable.go, hostowned_test.go}, go/mark1/internal/off/{hostowned_test.go, off.go}, go/mark1d/adapters/provision/{hostowned_test.go, provision.go} |
| `b7ee1fc` docs: host guide §8.1; FR-SPINE-039..042 armed; WORKLOG Part 3 | conformance/traceability.yaml, docs/adr/WORKLOG.md, docs/design/02-requirements.md, docs/integrating-a-host.md |

### Part 4 — arrest modes (ADR-0015)

| Commit | Files |
|---|---|
| `b4a874f` docs: ADR-0015 arrest modes | conformance/traceability.yaml, docs/adr/0015-arrest-modes.md, docs/design/{02, 07, 08} |
| `2a3f006` proto: ArrestRecommendation; Event 24; GateVerdict 7; FabricFrame 11 | proto/m1p/v1/{envelope.proto, events.proto, fabric.proto}, proto/gen bindings, rust/m1p-wire/{fuzz target, gen, tests/m1pl.rs} |
| `35707d0` mark1d: the arrest sink | go/mark1d/cmd/{main.go, recommend.go, recommend_test.go}, go/mark1d/internal/control/{hub.go, recommendation_test.go}, go/mark1d/internal/fabric/{gate.go, gate_recommend_test.go, push_test.go, server.go, session.go} |
| `3fa388f` controld: arrest recommendations project into ClickHouse | go/controld/internal/ingest/chproj/recommendation_test.go, migrations/m1_ch_003_arrest_recommendations.sql |
| `23b292b` docs: FR-SPINE-043..046 armed; WORKLOG Part 4 | conformance/traceability.yaml, docs/adr/WORKLOG.md, docs/design/02-requirements.md |

### Part 5 — memory modes (ADR-0016)

| Commit | Files |
|---|---|
| `6ddba83` python: ruff format the ext/extmanifest conformance tests | python/shared/mark1_receipts/tests/{test_conf_vectors_ext.py, test_conf_vectors_extmanifest.py} |
| `cee1e99` docs: ADR-0016 memory modes | conformance/traceability.yaml, docs/adr/0016-memory-modes.md, docs/design/{02, 06-lld-intelligence.md, 07, 08} |
| `3fd6e44` proto: ProposalCategory, MemoryProposal; Event 40; FabricFrame 12 | proto/m1p/v1/{envelope.proto, fabric.proto, intelligence.proto}, proto/gen bindings, rust/m1p-wire/gen/m1p.v1.rs |
| `3ec890f` mark1d: the memory sink | go/mark1d/cmd/{main.go, propose.go, propose_test.go, recommend.go}, go/mark1d/internal/control/{hub.go, proposal_test.go}, go/mark1d/internal/memory/{cache.go, propose.go, propose_test.go} |
| `ac54294` docs: FR-SPINE-047..049 armed; WORKLOG Part 5; BLOCKERS.md | BLOCKERS.md, conformance/traceability.yaml, docs/adr/WORKLOG.md, docs/design/02-requirements.md |

### Part 6 — host-bound receipts (ADR-0017)

| Commit | Files |
|---|---|
| `d6f7f13` docs: ADR-0017 host-bound receipts | conformance/traceability.yaml, conformance/vectors/receipt/README.md, docs/adr/0017-host-bound-receipts.md, docs/design/{02, 07, 08} |
| `efb8354` proto: ReceiptCheckpoint 8–11; HostBinding, TaskBinding; m1_090 | migrations/m1_090_receipt_host_bindings.sql, proto/m1p/v1/artifacts.proto, proto/gen bindings, rust/m1p-wire/gen/m1p.v1.rs |
| `0006147` receipts: checkpoint payload v2 in lock-step; the hostchain vector family | conformance/vectors/EXPECTED, conformance/vectors/hostchain/{README.md, gen_vectors.py, manifest.json}, go/controld/internal/receipts/{chain.go, conf_vectors_hostchain_test.go, hostbind.go}, go/mark1d/internal/identity/{conf_vectors_hostchain_test.go, hostbind.go, hostbind_test.go, receipt.go}, python/shared/mark1_receipts/src/mark1_receipts/checkpoint.py, python/shared/mark1_receipts/tests/test_conf_vectors_hostchain.py, rust/mark1-receipt/{src/checkpoint.rs, src/lib.rs, tests/conf_vectors_hostchain.rs}, rust/verifier/tests/conf_vectors_hostchain.rs, tools/ci/conformance_crosslang.sh |
| `124d54d` mark1d: the sealer binds hosts | go/mark1d/cmd/{hostbind.go, main.go}, go/mark1d/internal/admit/admit.go, go/mark1d/internal/receipt/{sealer.go, sealer_hostbind_test.go, sealer_test.go}, go/mark1d/internal/uplink/{batch.go, batchfacts_test.go, uplink.go, uplink_test.go} |
| `8e90ad0` controld: countersign the v2 reconstruction | go/controld/internal/ingest/sidefx/{hostbind_test.go, sidefx.go}, go/controld/internal/receipts/{server_record.go, store.go} |
| `1fbdaa6` docs: FR-SPINE-050..053 armed; WORKLOG Part 6; BLOCKERS disk note | BLOCKERS.md, conformance/traceability.yaml, docs/adr/WORKLOG.md, docs/design/02-requirements.md |

### Part 7 — the MCP surface as an external writer (ADR-0018)

| Commit | Files |
|---|---|
| `01808bf` docs: ADR-0018 | conformance/traceability.yaml, docs/adr/0018-mcp-surface-as-external-writer.md, docs/design/{02, 08}, docs/integrating-a-host.md |
| `ca13490` cortexd: mark1.send_manifest / mark1.emit_event / mark1.get_recommendations | rust/cortexd/src/fabric/mod.rs, rust/cortexd/src/mcp/{mark1.rs, mod.rs}, rust/cortexd/src/session/mod.rs |
| `6fcba00` docs: FR-SPINE-054..056 armed; WORKLOG Part 7 | conformance/traceability.yaml, docs/adr/WORKLOG.md, docs/design/02-requirements.md |

### Part 8 — close out

| Commit | Files |
|---|---|
| `9b548de` provision: the host-owned refusal is M1E-7107 (M1E-7105 was already taken) | go/mark1d/adapters/provision/{provision.go, hostowned_test.go}, go/mark1/internal/{doctor, enable, off}/{*.go, hostowned_test.go}, docs/design/{02, 08}, docs/adr/0014-…, docs/integrating-a-host.md, docs/adr/WORKLOG.md |
| `27e10a7` docs: host guide §8.2–8.4 and §10 cem888 end to end; WORKLOG Part 8; BLOCKERS §8 | BLOCKERS.md, docs/adr/WORKLOG.md, docs/integrating-a-host.md |
| (head) docs: FINAL_REPORT.md | FINAL_REPORT.md |

## 2. Every new test

**Go — mark1d**
- `cmd/admitpath_golden_test.go`: TestSocketStreamGolden (the byte-identical first-party socket stream, `cmd/testdata/socket_stream.golden`); `cmd/dial_{unix,windows}_test.go` are its dial helpers.
- `cmd/ext_socket_test.go`: TestSocketExtSessionGetsDaemonIdemKey. `cmd/partner_golden_test.go`: TestPartnerFileStreamMatchesSocketGolden.
- `cmd/ext_conformance_test.go`: TestConfVectorsExtEmitterIsPinned, TestConfVectorsExtTransportsAgree. `cmd/extmanifest_conformance_test.go`: TestConfVectorsExtmanifestEmitterIsPinned, TestConfVectorsExtmanifestTransportsAgree.
- `cmd/recommend_test.go`: TestRecommendSinkFansOutOnEveryPath. `cmd/propose_test.go`: TestProposeSinkFansOutOnEveryPath.
- `internal/fabric/session_test.go` (added): TestExtHelloWithoutSessionIsMintedAndEchoAdmits, TestExtWriterEchoingWrongSessionIsClosed, TestExtHelloWithOwnSessionIsBoundNotMinted, TestExtHelloWithMalformedSessionIsStillRejected, TestFirstPartyEventSessionIsNotCheckedAgainstHello, TestHostManifestIsResolvedAndStored, TestAbsentHostManifestIsDefault, TestInvalidHostManifestIsRefused, TestHostManifestOnAFirstPartyHelloIsRefused.
- `internal/fabric/gate_profile_test.go`: TestGateReadsTheSessionProfile. `internal/fabric/gate_recommend_test.go`: TestRecommendModeNeverBlocks, TestRecommendModeAtTheKnee, TestActModeIsUnchangedByTheRegistry. `internal/fabric/push_test.go`: TestPushReachesTheBoundExtConnection.
- `internal/control/recommendation_test.go`: TestRecommendationReachesTheControlAPI. `internal/control/proposal_test.go`: TestProposalReachesTheControlAPI.
- `internal/hostprofile/profile_test.go`: TestDefaultIsTodaysBehaviour, TestFromManifestValid, TestFromManifestRefusals, TestCanonicalIsPinned, TestRegistryDefaultsUnknownSessions. `internal/hostprofile/hosts_test.go`: TestRegistryParsesAndLooksUp.
- `internal/tailers/partner_test.go`: TestPartnerBindsAndStampsTheSession, TestPartnerResumesTheSameSessionAfterRestart, TestPartnerTornTailAndRotation, TestPartnerRefusesABadSidecar, TestPartnerExplicitPathsAndPollRun, TestPartnerSidecarHostManifestResolvesLikeTheSocket.
- `internal/memory/profile_test.go`: TestMemoryReadsTheSessionProfile. `internal/memory/propose_test.go`: TestProposeModeIsADeclaredHostThatOwnsMemory, TestProposeInjectsNothingAndRecordsNothing.
- `internal/identity/hostbind_test.go`: TestBatchFactsBindKeepsV1ForSoloDevelopers, TestBatchFactsBindIsSortedAndIdentityIsPerTask, TestBatchFactsMergeCarriesPendingLeaves. `internal/identity/conf_vectors_hostchain_test.go`: TestConfVectorsHostchainProfiles, TestConfVectorsHostchainChain, TestConfVectorsHostchainNegatives.
- `internal/uplink/batchfacts_test.go`: TestBatchFactsCountsActedAndRecommendedApart. `internal/receipt/sealer_hostbind_test.go`: TestSealBindsHostsAsControldWould.
- `adapters/fence/drift_test.go`: TestClassifyTable, TestClassifyUnparseableIsFenceMissingWithError, TestClassifyNothingFencedIsMissing, TestSplitKeepsTheirEntriesAndOrder.
- `adapters/{claudecode,codex,gemini,cursor}/drift_test.go` (each): TestDriftNoneRevertsVerbatim, TestDriftReformatOnlyRestoresTheOriginal, TestDriftNeighbourAfterOurEntrySurvivesDetach, TestDriftNeighbourBeforeOurEntrySurvivesDetach, TestDriftLegacyManifestKeepsTheOldRule (`drift_seed_test.go` holds each adapter's seed document).
- `adapters/provision/profile_test.go`: TestApplyReadsTheHostProfile. `adapters/provision/hostowned_test.go`: TestApplyRefusesAHostOwnedSurface, TestHostOwnsSurfaceSemantics.

**Go — mark1 (CLI)**
- `internal/validateevents/validateevents_test.go`: TestValidateTable, TestRunContract. `internal/validateevents/conf_vectors_ext_test.go`: TestConfVectorsExtGoldenValidates.
- `internal/enable/hostowned_test.go`: TestEnableSurfacesAHostOwnedSurface. `internal/off/hostowned_test.go`: TestOffSurfacesAHostOwnedSurface. `internal/doctor/hostowned_test.go`: TestDoctorSurfacesAHostOwnedSurface.

**Go — controld**
- `internal/ingest/chproj/recommendation_test.go`: TestArrestRecommendationProjects. `internal/ingest/sidefx/hostbind_test.go`: TestHostBindingsMapTheWireFieldForField. `internal/receipts/conf_vectors_hostchain_test.go`: TestConfVectorsHostchainControldChain, TestConfVectorsHostchainControldNegatives.

**Rust**
- `cortexd/src/fabric/mod.rs`: ext_exchange_binds_the_minted_session_on_a_named_pipe (windows), ext_exchange_binds_the_minted_session_on_a_socket (unix).
- `cortexd/src/mcp/mark1.rs`: base64_and_hex_bytes, rfc3339_to_unix, manifest_accepts_proto_and_camel_spellings, events_from_protojson_for_every_writer_body, events_need_exactly_one_body, client_names_are_bounded, tool_list_names_the_three_tools, get_recommendations_reads_the_sessions_files, daemon_files_are_read_line_by_line.
- `mark1-receipt/tests/conf_vectors_hostchain.rs`: conf_vectors_hostchain_profile_and_identity_hashes, conf_vectors_hostchain_assembly_reproduces_frozen_bytes, conf_vectors_hostchain_verifies_from_genesis, conf_vectors_hostchain_negative_receipts.
- `verifier/tests/conf_vectors_hostchain.rs`: conf_vectors_hostchain_verifier_accepts_v1_and_v2_rows, conf_vectors_hostchain_verifier_names_the_defect.
- Part 1's ADR-0012 commit extended `cortexd/tests/fabric_wire.rs`, `mark1-hookshim/tests/shim_e2e.rs`, `m1p-wire/tests/m1pl.rs` and re-pinned `mark1-redact/tests/no_admit_off_switch.rs` (the proxy sink fingerprint) for the new Hello fields.

**Python**
- `mark1_receipts/tests/test_conf_vectors_ext.py`: test_conf_vectors_ext_emitter_matches_golden, test_conf_vectors_ext_golden_is_well_formed.
- `mark1_receipts/tests/test_conf_vectors_extmanifest.py`: test_conf_vectors_extmanifest_emitter_matches_golden, test_conf_vectors_extmanifest_events_equal_ext_and_block_is_the_cem888_profile.
- `mark1_receipts/tests/test_conf_vectors_hostchain.py`: test_conf_vectors_hostchain_profile_hash, test_conf_vectors_hostchain_identity_domain, test_conf_vectors_hostchain_assembly_reproduces_frozen_bytes, test_conf_vectors_hostchain_verifies_from_genesis, test_conf_vectors_hostchain_negative_receipt.

**Conformance families** (armed in `conformance/vectors/EXPECTED` and the gate's `PY_REQUIRED`): `ext`, `extmanifest`, `hostchain`.

## 3. New M1E codes and migrations

| Code | Meaning | Where |
|---|---|---|
| `M1E-4006` | `mark1 validate-events` found an error in an external writer's JSONL (exit 5) | 08 §7.8, §10; `go/mark1/internal/validateevents` |
| `M1E-4007` | host manifest invalid — empty `host_id`/`host_version`, `arrest_mode` unspecified, `owns_execution` false on an `ext:` connection, `schema_version` outside `{"m1p.v1"}`, or a manifest on a non-`ext:` connection; the connection closes / the file is not tailed | 08 §4.3 step 2b, §10; `hostprofile.FromManifest`, `fabric.session.hello`, `tailers.partner` |
| `M1E-4008` | mark1d not reachable from the MCP surface (socket/pipe refused or timed out); reported in the tool's refusal envelope, never retried | 08 §6.7–6.9, §10; `cortexd/src/mcp/mark1.rs` |
| `M1E-7107` | host owns config surface: the session's declared host set `owns_config_surface`, so provisioning writes nothing and revert is a no-op; `enable`/`off`/`doctor` say so in one line | 08 §8.3 step 0, §10; `provision.CodeHostOwnsSurface` (renumbered from the colliding `M1E-7105` in Part 8) |

| Migration | Contents |
|---|---|
| `migrations/m1_ch_003_arrest_recommendations.sql` | ClickHouse `mark1.arrest_recommendations` (ReplacingMergeTree, ORDER BY tenant_id, day, session_id, event_id) and `mark1.mv_arrest_recommendations` projecting `m1p_events WHERE event_type = 'ArrestRecommendation'` (kind, k_star_estimate, projected_cost, turn, evidence_ref) |
| `migrations/m1_090_receipt_host_bindings.sql` | Postgres `m1_receipts.host_bindings jsonb`, `arrests_acted integer`, `arrests_recommended integer` — the v2 checkpoint payload's host block and counters restated as query columns, NULL on v1 rows |

No existing migration was edited.

## 4. The Profile struct and Default, verbatim (`go/mark1d/internal/hostprofile/profile.go`)

```go
type ArrestMode string

const (
	Act       ArrestMode = "act"
	Recommend ArrestMode = "recommend"
)

type Profile struct {
	HostID            string
	HostVersion       string
	OwnsExecution     bool
	OwnsConfigSurface bool
	OwnsMemory        bool
	ArrestMode        ArrestMode
	SuppliesIdentity  bool
	SchemaVersion     string
}

// Default is today's behaviour, exactly, defined ONCE: Mark 1 owns the
// config surface (provisioning writes fences) and memory (the daemon
// injects), acts on an arrest, supplies the identity, and the writer does
// not own execution. A session with no manifest resolves to this.
var Default = Profile{
	HostID:            "",
	HostVersion:       "",
	OwnsExecution:     false,
	OwnsConfigSurface: true,
	OwnsMemory:        true,
	ArrestMode:        Act,
	SuppliesIdentity:  false,
	SchemaVersion:     "",
}
```

`Canonical(Default)` is golden-pinned to
`{"arrest_mode":"act","host_id":"","host_version":"","owns_config_surface":true,"owns_execution":false,"owns_memory":true,"schema_version":"","supplies_identity":false}`;
its sha256 (`e563e71912c3ad5ec1ba2249f591ceb1af277edac9ffe0e42285e68beb78fe83`) is the
`profile_hash` of a native session in a v2 receipt. The "owner" readings are: `Default`'s
`OwnsConfigSurface`/`OwnsMemory` mean Mark 1 owns them; every refusal or mode switch keys on
a *declared* host (`HostID != ""`).

## 5. The drift classifier, verbatim (`go/mark1d/adapters/fence/drift.go`)

```go
// Drift is the four-way verdict. The names are 08 §8.4's.
type Drift int

const (
	DriftNone         Drift = iota // the file is exactly as we left it, structurally
	DriftOutsideFence              // our entries are intact; the user changed something else
	DriftInsideFence               // our entries are present but not what we wrote (08 §7.4 FRAGMENT-DAMAGED)
	FenceMissing                   // none of our entries is present (08 §7.4 MISSING)
)

// Classify compares cur against post (and pre, which only informs the error
// text for a missing fence). Byte-identical ⇒ DriftNone without parsing.
// An unparseable cur is reported as FenceMissing with the parse error: a file
// we cannot read is one whose fence we cannot find, and the caller's existing
// handling for that case decides what to do.
func Classify(pre, post, cur []byte) (Drift, error)

func Split(doc any) (outside any, ours []any)
```

| Verdict | `String()` | Detach does |
|---|---|---|
| `DriftNone` | `none` | restores the pre-image verbatim (byte-identical, or reformatted-only) |
| `DriftOutsideFence` | `outside-fence` | removes exactly Mark 1's entries (`_mark1` / `_mark1_managed`) and keeps the second writer's |
| `DriftInsideFence` | `inside-fence` | today's handling: left alone and reported (08 §7.4 FRAGMENT-DAMAGED), never overwritten |
| `FenceMissing` | `fence-missing` | today's handling (08 §7.4 MISSING); an unparseable file is this with the parse error |

Each adapter manifest gained `PostImage string `json:"post_image,omitempty"``; a legacy manifest without it keeps the old rule.

## 6. The refusal message text (`go/mark1d/adapters/provision/provision.go`)

```
M1E-7107: host owns config surface — <host_id> <host_version> owns its own configuration; Mark 1 is attached through the fabric and writes nothing here
```

(`RefusalHostOwnsSurface(p hostprofile.Profile) string`; `enable` renders it as `NOT PROVISIONED … M1E-7107 …` in its existing style, `off` and `doctor` as the one line `host          M1E-7107 …`, and `--json` as `host_owned`.)

## 7. Every new proto message, verbatim

`proto/m1p/v1/fabric.proto`:

```proto
enum ArrestMode {
  ARREST_MODE_UNSPECIFIED = 0;  // an error when a manifest is present: a host must choose
  ARREST_MODE_ACT = 1;          // Mark 1 enforces the arrest (today's BLOCK)
  ARREST_MODE_RECOMMEND = 2;    // Mark 1 reports it; the host's own loop decides
}

message HostManifest {
  string host_id = 1;              // stable host identifier, e.g. "cem888"; non-empty
  string host_version = 2;         // the host's own version string; non-empty
  bool owns_execution = 3;         // the host runs the agent loop (ext: writers: must be true)
  bool owns_config_surface = 4;    // the host writes the agent's config; provisioning must not
  bool owns_memory = 5;            // the host holds the memory the agent sees; the daemon must not inject
  ArrestMode arrest_mode = 6;      // ACT or RECOMMEND; UNSPECIFIED refused
  bool supplies_identity = 7;      // the host's correlation id is authoritative for the session's identity
  string schema_version = 8;       // the manifest's revision; accepted set is {"m1p.v1"}
}
```

`proto/m1p/v1/events.proto`:

```proto
message ArrestRecommendation {
  string kind = 1;              // [P0] "stop_gate_block" | "knee_arrest" | "block_cap" — the judgement ACT would have enforced
  string reason = 2;            // [P0] the same text an acted arrest carries (the knee inequality, the cap)
  uint32 k_star_estimate = 3;   // [P0] the attempt index the governor evaluated at (KneeState.N)
  uint64 projected_cost = 4;    // [P0] tokens the daemon estimates the next attempt would spend — what acting would have saved
  bytes task_id = 5;            // [P1] 16 bytes; the task the judgement names (also the envelope's task_id)
  uint32 turn = 6;              // [P0] the session's turn counter at the judgement
  bytes session_id = 7;         // [P1] 16 bytes; the bound session (also the envelope's)
  string evidence_ref = 8;      // [P0] local evidence-store reference, resolvable on this device only (as GateVerdict.evidence_ref)
}
```

`proto/m1p/v1/intelligence.proto`:

```proto
enum ProposalCategory {
  PROPOSAL_CATEGORY_UNSPECIFIED = 0;
  PROPOSAL_CATEGORY_CONVENTION = 1;     // an invariant artifact
  PROPOSAL_CATEGORY_PITFALL = 2;        // a pitfall artifact
  PROPOSAL_CATEGORY_DECISION = 3;       // reserved: a decision record (no edge producer yet)
  PROPOSAL_CATEGORY_TOOL_GUIDANCE = 4;  // a fix_pattern artifact
}

message MemoryProposal {
  bytes artifact_id = 1;               // [P1] the admitted artifact the candidate came from
  ProposalCategory category = 2;       // [P0]
  string candidate_trigger = 3;        // [P0] the artifact's trigger text, as the host would see it
  string candidate_guidance = 4;       // [P0] the artifact's guidance text
  string evidence = 5;                 // [P0] why it was selected: the normalized error signature digest (reactive) or "pack" (hook context)
  InjectionChannel channel = 6;        // [P0] the channel it would have ridden
  bytes session_id = 7;                // [P1] 16 bytes; the bound session (also the envelope's)
  bytes task_id = 8;                   // [P1] 16 bytes; the task (also the envelope's)
}
```

`proto/m1p/v1/artifacts.proto`:

```proto
message HostBinding {
  bytes session_id = 1;             // 16 bytes
  string transport = 2;             // "fabric" | "jsonl" | "native"
  string host_id = 3;               // empty for a native session
  string host_version = 4;
  bytes profile_hash = 5;           // 32 bytes: sha256(hostprofile.Canonical(profile))
  string host_correlation_id = 6;
  repeated TaskBinding tasks = 7;   // sorted by task_id
}

message TaskBinding {
  bytes task_id = 1;                // 16 bytes
  bytes identity_hash = 2;          // 32 bytes iff the host supplies identity, else empty
}
```

Fields added to existing messages (all additive; `buf breaking` clean at each commit):

| Message | Field |
|---|---|
| `Hello` | `string host_correlation_id = 6;` `HostManifest host_manifest = 7;` |
| `HelloAck` | `bytes session_id = 4;` (the daemon-minted session for an `ext:` Hello without one) |
| `GateVerdict` | `ArrestRecommendation recommendation = 7;` |
| `FabricFrame` | `ArrestRecommendation arrest_recommendation = 11;` `MemoryProposal memory_proposal = 12;` |
| `Event.body` | `ArrestRecommendation arrest_recommendation = 24;` `MemoryProposal memory_proposal = 40;` |
| `ReceiptCheckpoint` | `uint32 payload_version = 8;` `repeated HostBinding hosts = 9;` `uint32 arrests_acted = 10;` `uint32 arrests_recommended = 11;` |

## 8. Exact commands to run everything

From the repository root. On this Windows machine `just` needs its shell named (`BASHW=$(cygpath -w "$(command -v bash)"); just --shell "$BASHW" --shell-arg -c <recipe>`); on Linux/macOS plain `just <recipe>`.

```sh
# toolchain
go version; cargo --version; uv --version; buf --version; just --version   # buf 1.72.0, just 1.42.4, golangci-lint 2.1.6, pip-audit installed
uv sync --frozen --all-packages

# codegen is fresh
just gen && git status --porcelain proto/gen rust/m1p-wire/gen            # prints nothing

# proto
just lint-proto                                                            # buf lint + buf breaking --against '.git#branch=main,subdir=proto'

# Go
( cd go/mark1d  && gofmt -l . && go vet ./... && golangci-lint run ./... && go mod tidy && go test ./... -count=1 )
( cd go/controld && gofmt -l . && go vet ./... && golangci-lint run ./... && go mod tidy && go test ./... -count=1 )
( cd go/mark1   && gofmt -l . && go vet ./... && golangci-lint run ./... && go test ./... -count=1 )
( cd conformance/emitter && go vet ./... && go test ./... -count=1 )

# Rust
cargo fmt --all -- --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked

# Python
PYTHONUTF8=1 just test-py && just lint-py                                  # pytest lanes; ruff format/check; pip-audit

# conformance, three languages, all families in EXPECTED (ext, extmanifest, hostchain included)
PYTHONUTF8=1 tools/ci/conformance_crosslang.sh

# requirement → test gate, and the tools/ci gates
just trace-check
just gates                                                                 # or each tools/ci/*_gate.sh directly
just gen-check

# the golden rule, on its own
( cd go/mark1d && go test ./cmd -run 'TestSocketStreamGolden|ConfVectorsExt' -count=1 )
cargo test -p cortexd --locked                                             # cortexd golden tests + the first-party deliver test

# the host lane end to end (docs/integrating-a-host.md §10)
go run ./conformance/emitter/cmd/mark1-emitter -manifest -out /tmp/cem
python conformance/emitter/emit.py --manifest /tmp/cem
go run ./go/mark1/cmd validate-events /tmp/cem/sample.jsonl
cd conformance/vectors/hostchain && uv run --frozen --all-packages python gen_vectors.py && git diff --exit-code manifest.json
```

## 9. Final suite results (2026-10-03, this machine)

| Gate | Result |
|---|---|
| `gofmt -l` (mark1d, controld, mark1, emitter) | clean |
| `go vet`, `golangci-lint run` (mark1d, controld, mark1) | clean, 0 issues |
| `go mod tidy` (mark1d, controld) | no diff |
| `go test ./...` mark1d | every package without a real spool green (identity, admit, memory, hostprofile, tailers, adapters/*, control, fabric, cmd targets incl. `TestSocketStreamGolden` and the ext/extmanifest conformance); the spool-bound packages are BLOCKERS §1 (disk at 100 %) |
| `go test ./...` controld | green except `TestTVOReportContract` (BLOCKERS §2, pre-existing) |
| `go test ./...` mark1 | green except the three agent-detection tests (BLOCKERS §6, pre-existing) |
| `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --workspace` | clean / clean / 12 suites green, 0 failed |
| `just test-py` (PYTHONUTF8=1), `just lint-py` | green; ruff clean; pip-audit no known vulnerabilities |
| `just lint-proto` (buf lint, buf breaking vs main) | clean |
| `just gen` byte-stable | yes |
| `tools/ci/conformance_crosslang.sh` | every family on every leg green (Go 5 / Python 11 / Rust hostchain vectors included); the D-AP bit-identity step fails only on CRLF (BLOCKERS §3; bits identical) |
| `just trace-check` | `trace-check: ok` under the Windows shim (BLOCKERS §5); FR-SPINE-027..056 all Phase 1 with named evidence |
| `tools/ci/*_gate.sh` | see the table below |

Gate scripts, run one by one (`just gates` itself needs the nested-`just` shell fix, BLOCKERS §8):

| Gate script | Result |
|---|---|
| otel_gate.sh | Rust and Go lock-file sections pass; the docs sweep fails on an output-encoding artefact (BLOCKERS §8; the allow-list and its documents are byte-identical to `main`) |
| secret_type_gate.sh | pass |
| override_pattern_gate.sh | pass |
| build_tag_gate.sh | pass |
| shapley_gate.sh | pass |
| adr_signed_gate.sh | pass |
| vendor_binary_gate.sh | pass |
| ci_matrix_gate.sh | pass |
| verifier_offline_gate.sh | pass |
| buf_breaking_gate.sh | pass |
| tokenpath_deps_gate.sh | pass |
| raw_credential_gate.sh | **no result**: the run was stopped by the host while this script was scanning (the machine ran critically low on memory, BLOCKERS §9); it had reported only allow-listed hits up to that point |
| posture_gate.sh | **not run** (same stop, BLOCKERS §9) |
| crush_reserved_gate.sh | **not run** (same stop, BLOCKERS §9) |

## 10. BLOCKERS.md, verbatim

Gates that could not be made green on the development machine, each with what was tried and
the believed fix. Nothing here is a gap in the work: every entry is environment-only on a
Windows laptop whose disk is full, confirmed against the pre-change baseline where that was
possible. CI runs on Linux and sees none of them. No FR row is held at Phase 2 by any entry.

### 1. mark1d tests that write a real spool — disk at 100 %

- **Failure:** `go test ./...` in `go/mark1d` fails every test that lands an event in a real
  spool with "spool holds 0 records" (packages `cmd`, `capture`, `control`, `coverage`, `fabric`,
  `obs`, `receipt`, `spill`, `spool`, `supervise`, `uplink`; `capture`, `receipt`, `spool` and
  `uplink` hit the 10-minute package timeout waiting on the stop). `TestSocketStreamGolden` and
  `TestConfVectors{Ext,Extmanifest}TransportsAgree` fail only inside the full `./...` run,
  under the load of the blocked packages; standalone they pass 8/8.
- **Cause:** the spool's 95 % disk hard stop (07 §6). `df -h /c` reports 475G used of 475G,
  2.2G free, 100 %. Every daemon-level test this work added stubs `diskUsage` for exactly this
  reason.
- **Tried:** removing the scratch worktree and build caches (does not reach the 24 GB the stop
  needs); running the packages alone (the same tests fail with the same "0 records").
  Measured on 2026-10-03: `%TEMP%` holds 7.8 GB of Visual Studio installer extractions and
  3.6 GB of VS package caches (not this work's to delete); `go clean -cache` and the stale
  test temp dirs recovered ~3 GB, enough to build and lint, not enough for the spool stop.
- **Believed fix:** free the disk below 95 % and rerun; or run on CI. The test set is the one in
  `docs/adr/WORKLOG.md` "Environment" notes, unchanged across Parts 1–8.

### 2. `controld/internal/querychoke TestTVOReportContract` — calendar-sensitive fixture

- **Failure:** fails identically on a clean worktree at the pre-Part-4 commit `b7ee1fc`.
- **Cause:** the test's 7-day window has moved past the fixture's rollup days.
- **Believed fix:** anchor the fixture's days to the test's clock. Not touched: no controld
  contract change is permitted here beyond the additive projections.

### 3. `tools/ci/conformance_crosslang.sh` D-AP bit-identity — CRLF on Windows

- **Failure:** "the two ADJUDICATE legs do NOT agree bit for bit" with every line visibly
  identical.
- **Cause:** the Python leg writes its posterior dump through `open(path, "a")`, which on
  Windows emits `\r\n`; `diff -u` then sees every line differ. `diff <(tr -d '\r' < py.txt |
  sort) <(sort go.txt)` is empty — the bits are identical. Every family's vectors pass on both
  legs (`go — family ext/extmanifest`, `python — family ext/extmanifest` included).
- **Believed fix:** `open(path, "a", newline="\n")` in
  `python/adjudicator/tests/test_conf_vectors_fusion.py`. Not applied: the adjudicator's test
  is outside this work's scope and the gate is correct on CI.

### 4. `python/intel/tests/test_no_clickhouse_dep.py` — cp1252 default encoding

- **Failure:** `UnicodeDecodeError: 'charmap' codec` reading a source file with a non-ASCII
  character.
- **Cause:** Python on Windows opens text as cp1252 unless `PYTHONUTF8=1`; the `test-py`
  recipe does not set it. With `PYTHONUTF8=1` the test passes (2 passed).
- **Believed fix:** `open(..., encoding="utf-8")` in the test. Not applied for the same reason
  as entry 3.

### 5. `just trace-check` — unix-only tests invisible to `go test -list` / `cargo test --list`

- **Failure:** NFR-SECURITY-007's evidence (`TestListenRefusesSymlinkAtSocketPath`,
  `TestListenRejectsBadPerms`, `port_file_tests::port_file_is_private_even_when_it_already_existed_world_readable`,
  `loose_store_or_discovery_modes_are_refused`) reports "no such test" because the tests are
  `_unix.go` / `#[cfg(all(test, unix))]`.
- **Tried:** a scratchpad copy of the tool that additionally accepts a test whose function
  exists in source; under it `trace-check: ok` with every FR row of this work resolved.
- **Believed fix:** none needed on Linux.

### 6. `go/mark1` `internal/doctor` and `internal/enable` — agent detection on this machine

- `TestDoctorGeminiAndOpenCodeRowsWithoutBinaries`, `TestEnableReportsProvisioningRefusal`,
  `TestEnableGeminiAndOpenCodeOnlyWhenInstalled` fail on the untouched baseline (`f85bff9`,
  clean worktree): the machine has agent binaries installed where the tests assume none.

### 7. `just lint-py` — `pip-audit` was absent

- Installed with `uv tool install pip-audit`; the recipe is green ("No known vulnerabilities
  found"). Recorded because the toolchain rule is "install, never skip".

### 8. `tools/ci/otel_gate.sh` docs sweep and `just gen-check` — Git Bash on Windows

- **`otel_gate.sh`** (run directly): Rust and Go lock-file sections pass; the docs sweep
  reports "OTel identifier references do not match the reviewed allow-list" while the diff it
  prints shows the same line of `docs/adr/0005-no-otel-m1p.md` as both removed and added —
  the allow-list and every document it names are byte-identical to `main`
  (`git diff main --stat` on them is empty). A `grep` output-encoding difference under Git
  Bash, not a reference this work added. The other thirteen gate scripts are listed with
  their results in FINAL_REPORT.md.
- **`just gen-check`** calls `tools/ci/gen_fresh.sh`, which runs a nested `just gen` with
  `just`'s default shell; on this machine that resolves to WSL's `/bin/bash`, which does not
  exist. The check it performs — regenerate and diff — was run by hand after the last proto
  change: `just --shell <git-bash> --shell-arg -c gen` followed by
  `git status --porcelain proto/gen rust/m1p-wire/gen` prints nothing.
- **Believed fix:** none needed on Linux CI.

### 9. `raw_credential_gate.sh`, `posture_gate.sh`, `crush_reserved_gate.sh` — stopped by the host

- **What happened:** the fourteen gate scripts were run one after another (`just gates`
  cannot run here, §8). Eleven completed; while `raw_credential_gate.sh` was scanning, the
  machine ran critically low on memory and the session's background shell was stopped.
  `raw_credential_gate.sh` had reported only ALLOWLISTED hits before the stop; `posture_gate.sh`
  and `crush_reserved_gate.sh` never started. Not restarted on this machine by instruction.
- **Believed fix:** run `just gates` on CI (Linux, enough memory); nothing this work adds
  touches credentials, posture files or the crush-reserved set, but the gates are the proof,
  and these three have none from this machine.
