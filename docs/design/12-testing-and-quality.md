# 12 — Testing, Conformance and Quality Gates

**Status:** Authored 2026-08-28 against the frozen execution plan (`docs/spec/execution-plan-v2.md`), the architecture spec, and documents 02/04/05/06. Where this document and the frozen plan disagree, the plan wins. This document **owns the test definitions**; 04 §10, 05 §7.5/§9, and 06 §13 named their tests and this document adopts every one of those names verbatim as contract.
**Audience:** anyone writing, reviewing, or gating code in `omium-mark1`.
**Function:** turns `02`'s 181 acceptance criteria (15 CON, 120 FR, 46 NFR) into named, scheduled, CI-enforced tests, and fills `02` §11's `TBD-12` slots (section 10 below is the authoritative replacement text for those slots at reconciliation).

---

## 0. Philosophy and the pyramid

### 0.1 The one rule

**A claim without a test is a defect in the document that makes the claim.** Not a nice-to-have, not backlog: if 02 states an acceptance criterion, or 04/05/06 states a failure posture, or 10 states a control, and no test in this document can fail when that statement is false, the *document set* is buggy and reconciliation must fail. This is the same discipline 02 applies to requirements ("a requirement whose criterion cannot fail is not a requirement"), extended one level: the criterion must also have an implementation with a name, a home, and a schedule.

### 0.2 The shape of the pyramid

```
        canary (weekly, scheduled)          ← proves the guards still guard
       chaos + e2e (nightly + phase gates)  ← proves the postures under real faults
      performance benchmarks (PR, pinned)   ← proves the budgets
     conformance suites (PR)                ← proves the wire, the fixtures, the vectors
    negative / isolation (PR, required)     ← proves what MUST NOT happen, cannot
   property + fuzz (PR regression, nightly exploration)
  unit (PR, colocated, fast)                ← the wide base
```

Two things about this shape are deliberate and unusual:

1. **The conformance layer is fat.** Mark 1's core risk is not internal logic bugs — it is drift against seven external agent surfaces, five wire dialects, and three language decoders that must agree byte-for-byte. Golden fixtures and shared vectors are the only test style that catches that class, so they get PR-blocking status normally reserved for unit tests.
2. **Negative tests are a first-class category, not a flavor of unit test.** The product's legal and privacy posture is a set of *must-never* statements (CON-001…CON-015). A must-never is only testable as an attempted violation that fails. These run on every PR without exception (NFR-SECURITY-003).

### 0.3 The anti-pattern being avoided, and the mechanism that prevents it

The estate's measured state: **~1% test coverage, and `tests/integration/` excluded from CI** — the tests existed and the pipeline was configured not to run them, which is worse than having none, because it manufactures false confidence. A coverage floor alone does not prevent recurrence (the estate *had* tests; they were simply not wired). Four structural mechanisms prevent it here, none of which is a number:

| # | Mechanism | What it makes impossible |
|---|---|---|
| 1 | **One entrypoint per language, no exclusions.** CI invokes exactly `cargo test --workspace --no-fail-fast`, `go test ./...`, and `python -m pytest tests -o asyncio_mode=auto` per service. There is no `--ignore`, no exclusion glob, no second test tree. Excluding anything requires editing a CODEOWNERS-protected workflow file, which is a reviewed security change, not a config drift. | A test directory silently not running |
| 2 | **Skip accounting.** In required suites (isolation, conformance, chaos-on-PR), `pytest` runs with a conftest hook and Go/Rust with a wrapper that **fails the job if the skip count is nonzero**. The estate's `pytest.mark.skipif(no DSN)` pattern degrades to "green because skipped"; here a missing DSN turns the job red, because CI provisions the DSN (§11.4) and the suite asserts it ran. | A gated suite passing by not executing |
| 3 | **The traceability gate.** `tools/trace-check` (§10.3) parses `conformance/traceability.yaml` and fails CI when any requirement ID in 02 §9 has no mapped test, or any mapped test name does not exist in the collected test set of the three toolchains. A new requirement without a test is a red PR. | A claim entering 02 without a test entering the repo |
| 4 | **Gates are test lists.** Each assembly phase's Gate (§12) is a checklist of named tests, per 02 §10. "The phase is done" is a CI query, not a judgment call. | Shipping a phase on demo evidence |

Coverage percentages are still measured (§13) — as a smoke alarm, not as the fire code.

### 0.4 Posture discipline in tests

Every chaos and negative test asserts a **posture**, not just an outcome, per CON-007's normative matrix: fail-open for availability, fail-static for policy, fail-closed for legality and secrets. A test that proves "the request failed" without proving "it failed in the declared direction" is incomplete. The reading rule from 04 §10 is normative for every suite here: no fail-open path may lose billing-grade data (it parks, blocks, or spills), and every gap must surface as `Dropped{}` or a `CoverageTransition` — the difference between a failure and a lie.

---

## 1. Test taxonomy and naming

### 1.1 The ten categories

| Category | Proves | Lives in | Runs on |
|---|---|---|---|
| **unit** | one function/module behaves per its LLD contract | colocated: Rust `#[cfg(test)]`, Go `_test.go`, Python flat `tests/` per service (estate convention) | every PR, all 3 OSes |
| **property** | an invariant holds over generated inputs | same homes; `proptest` (Rust), `pgregory.net/rapid` (Go), `hypothesis` (Python) | every PR (fixed seed + 256 cases); nightly (fresh seeds, 10⁴ cases) |
| **conformance** | byte/vector agreement with a recorded external truth or between languages | `conformance/{frames,hooks,canary,vectors}/` — the four §3 suites, in 13 §1's names | every PR |
| **integration** | two or more Mark 1 components against real stores (PG, CH, MinIO) | `conformance/integration/` + per-service `tests/` (env-DSN'd, §11.4 — never skipped in CI) | every PR (Linux) |
| **negative / isolation** | a must-never cannot happen; cross-tenant access fails | `conformance/tenancy/` (cross-tenant) + colocated negative tests (everything else) | **every PR, required check** |
| **fuzz** | decoders never panic and never accept the forbidden | `fuzz/` per Rust crate (cargo-fuzz), Go native `FuzzXxx` | PR: 60 s regression over corpus; nightly: 1 h/target with ASAN |
| **chaos** | failure postures under injected faults | `chaos/` (Go harness, `//go:build chaos`; cloud suite runs against the compose profile) | fast set (kill -9, spool-full, gate-timeout) on PR; full set nightly + phase gates |
| **performance** | the numbered budgets | `bench/` (criterion, `go test -bench`, hyperfine scripts) | every PR on the pinned runner (§7) |
| **end-to-end** | a full flow: agent fixture → edge → ingest → ledger → receipt → offline verifier | `conformance/e2e/` | nightly + phase gates; the Phase-1 replay path also on PR (it is fast: fixtures, not live agents) |
| **canary** | the guards still classify correctly against fresh reality | `.github/workflows/canary-*.yml` + `conformance/canary/` | weekly, scheduled; failure pages and blocks release |

### 1.2 Naming

- **Adopted slugs are contract.** 04 §10, 05 §7.5, 05 §9, and 06 §13 named their tests (`12/chaos-daemon-kill9`, `test_rls_cross_tenant_denied`, `chaos_s3_outage_no_false_ack`, `test_corpus_refuses_uncertified_labels`, …). Those names are adopted **verbatim** — the `12/` prefix drops, dashes become underscores in the implementing language (`12/chaos-daemon-kill9` → `chaos_daemon_kill9`), and the original slug string appears in `traceability.yaml` so the LLD → test link is greppable. One adopted slug carries a typo (`12/spool-kill9-taillos-accounted`, 04 F-20); it is adopted as-is — the slug is an identifier, not prose — with the typo noted for reconciliation.
- **New tests** follow `<category>_<component>_<behavior>`: `prop_spool_record_roundtrip`, `neg_proxy_forwards_only_provisioned`, `conf_frames_anthropic_golden`. Negative tests end in a refusal verb: `_denied`, `_refused`, `_rejected`, `_blocks`.
- Test names never encode requirement IDs (IDs churn slower than tests but the mapping is many-to-many); the mapping lives only in `traceability.yaml`.

### 1.3 Schedule summary

| Lane | Contents | Budget | Red means |
|---|---|---|---|
| PR (blocking) | unit, property (fixed-seed), conformance, integration, isolation, fuzz regression, chaos-fast, benchmarks, supply-chain gates | ≤ 20 min wall clock (§11.6) | merge blocked |
| Nightly | full chaos, fuzz exploration, e2e soak, mutation testing, property with fresh seeds, 7-day fail-static soak (rolling) | ≤ 4 h | next morning's first task; release blocked while red |
| Weekly | OAuth token-shape canary, hook-fixture refresh recording, dependency re-audit | — | CI red repo-wide for the canary (by design, §3.3); refresh lane files a PR |
| Release | everything above green + SBOM/SLSA emission + `cargo-deny`/`govulncheck` full audit | — | no artifact published |

---

## 2. Per-component unit and property tests

Unit tests follow each component's LLD contract and are not enumerated exhaustively here (the LLDs name them; the traceability matrix binds them). What this section fixes is the **property-based layer** — the invariants strong enough to be stated over *all* inputs, per component. Every property below runs with 256 fixed-seed cases on PR and 10⁴ fresh-seed cases nightly; a nightly counterexample is auto-shrunk and committed as a permanent regression case.

### 2.1 `m1p-wire` (Rust) + Go framing twin

| Test | Invariant asserted |
|---|---|
| `prop_m1pl_frame_roundtrip` | `decode(encode(payload)) == payload` for arbitrary payloads up to the bound; encode of an over-bound payload is `Err`, never a wrapped frame |
| `prop_m1pl_decode_total` | arbitrary bytes never panic the decoder: result is `Ok(frame)` or a typed error; `len` field is bounds-checked before any allocation (NFR-CORRECTNESS-004) |
| `prop_m1pl_incremental_feed` | feeding a valid stream 1 byte at a time yields the same frames as feeding it whole (no buffer-boundary bugs) |
| `unit_m1pl_magic_version` | wrong magic and unknown version each yield their distinct typed error (F-41's `M1E-4002/3`) |

### 2.2 `mark1d/internal/spool` (Go)

| Test | Invariant asserted |
|---|---|
| `prop_spool_record_roundtrip` | for any sequence of records: write → seal → read yields identical bytes and identical `event_id` leading-16-bytes; crc32c verifies on every record |
| `prop_spool_crash_prefix` | for any append sequence with a simulated crash at any byte offset (torn write), recovery yields exactly a **prefix** of the written records — never a gap, never a corrupted record surfaced as valid, and the truncated remainder is accounted as `Dropped{CRC_LOSS}` |
| `prop_spool_class_policy` | under any interleaving of writers at spool-full: billing-grade appends block, diagnostic appends return `ErrFull`, and shed count == emitted `Dropped{}` quantity (FR-SPINE-007) |
| `unit_spool_ack_then_delete` | a segment with ≥1 unacked record survives GC (NFR-DURABILITY-005); a fully acked segment is deleted whole-file |
| `unit_spool_cursor_is_event_id` | the spool cursor equals the wire idempotency key byte-for-byte (FR-SPINE-006's leading-16-bytes rule) |

### 2.3 `mark1-receipt` (Rust) + `python/shared/mark1_receipts` + Go verifier

| Test | Invariant asserted |
|---|---|
| `prop_canonical_json_stability` | for any JSON value: serializing after arbitrary key-order permutation and re-parse yields byte-identical canonical output (`sort_keys, separators=(",",":"), ensure_ascii`); canonical bytes are a fixed point (`canon(canon(x)) == canon(x)`) |
| `prop_receipt_chain_tamper_evident` | for any generated chain of N receipts, flipping any single bit in any receipt, payload, or link causes `verify_chain` to report a defect, and `intact_prefix_seq` equals exactly the last unmodified receipt (the vendored verifier's five defect kinds each reachable) |
| `prop_merkle_inclusion_sound` | every event in a generated checkpoint batch verifies against the root via its `inclusion_path`; any event **not** in the batch fails verification (FR-SPINE-015) |
| `unit_receipt_cross_language_hash` | golden receipts hash identically in Rust, Go, and Python under domain prefix `mark1-label-v1\0` (NFR-CORRECTNESS-006) |
| `unit_receipt_dual_sig` | missing either signature, or a forged device signature, is rejected; rotation cross-sign chain validates (FR-SPINE-018) |

### 2.4 `mark1-redact` (Rust; linked by proxy and shim)

| Test | Invariant asserted |
|---|---|
| `prop_redact_no_secret_survives` | for any document with planted secrets from every rule class at arbitrary offsets/encodings the ruleset claims: output contains zero planted secrets, each replaced by `⟨redacted:class:hash⟩` (CON-008) |
| `prop_redact_idempotent` | `redact(redact(x)) == redact(x)` — already-redacted spans are stable |
| `prop_redact_admit_axis_total` | the admit-to-upload axis returns Admit/Redact/Quarantine for all inputs; an internal scanner error maps to Quarantine, never Admit (F-35) |
| `bench_redact_throughput` | see §7 — throughput is a budget, not a property |

### 2.5 `mark1-policy` (Rust) + `mark1d/internal/policy` (Go)

| Test | Invariant asserted |
|---|---|
| `prop_bundle_cbor_roundtrip` | canonical CBOR encode/decode round-trips for arbitrary valid bundles; non-canonical encodings of the same value are rejected (FR-POLICY-001) |
| `prop_bundle_no_command_decodes` | for any bundle where any anchor-adjacent string matches the command grammar (shell metacharacters, path-to-executable shapes, arbitrary generated command strings): decode is `Err` in **both** languages (CON-009; the assertion is embedded in the fuzz harness too, §5.4) |
| `prop_bundle_seq_monotonic` | any bundle with `seq` ≤ current is rejected; rejection never disturbs last-known-good (F-27) |
| `unit_policy_eval_allocation_free` | evaluation on pre-decoded typed structs performs zero allocations (asserted via counting allocator; NFR-LATENCY-004's correctness half) |

### 2.6 `mark1d/internal/verdict` — fusion and the knee (Go)

| Test | Invariant asserted |
|---|---|
| `prop_fusion_logspace_equals_direct` | log-space naive Bayes posterior equals the direct-probability computation within 1e-12 for random confusion matrices, priors, and vote sets — including underflow regimes where direct computation would denormalize (FR-VERIFY-006) |
| `prop_fusion_posterior_valid` | output is always a 4-vector over exactly `satisfied\|violated\|refused\|error`, summing to 1 ± 1e-9 (FR-VERIFY-020) |
| `prop_fusion_permutation_invariant` | vote order never changes the posterior; abstentions and correlation-group collapse (syntactic ∪ {tests}) are honored per C3's shipped matrices |
| `prop_knee_decision_matches_inequality` | for random `(p̂_LCB, V, c(n))` triples under both `usd` and `quota` bases: governor decision equals `p̂_LCB(n)·V(task) ≤ c(n)` exactly (FR-VERIFY-009); golden triple table pinned as unit cases |
| `prop_knee_caps_clamp_bundles` | no generated bundle can produce >3 consecutive blocks per task or exceed the hourly ceiling; the `MARK1_DISABLE`/off check is evaluated before any gate math (order asserted by instrumented call sequence — FR-VERIFY-010, CON-013) |

### 2.7 Remaining components (unit-dominant; properties where an invariant exists)

| Component | Property / load-bearing unit tests |
|---|---|
| `mark1-frames` | `prop_frames_passthrough_identity`: for any recorded or generated SSE byte stream, the tee-side parse **never alters the forwarded bytes** (output == input, byte-for-byte); `prop_frames_parse_total`: arbitrary input never panics — failure degrades to `ParseDegraded` (F-09) |
| `mark1-hookshim` | `prop_shim_fieldmap_total`: any JSON payload under any bundle-supplied field map yields either a typed event or a typed drop — never a panic, never a partially-mapped event; `unit_shim_stamps_uuidv7_seq` (FR-SPINE-001) |
| `cortexd` | `prop_l0_merkle_content_sensitivity`: root changes iff some file content/path changed; `prop_ppr_ranks_normalized`: PageRank vector sums to 1, deterministic under fixed seed; `unit_cache_key_5part_invalidation` (FR-CORTEX-007) |
| `mark1-proxy` | `unit_guard_state_machine`: every transition of 04 §9.6's machine reachable and no transition from `FP_CHECK`-fail leads to `FORWARDING` (the no-override property is §4/§5's negative + fuzz job); `unit_secret_type_no_debug`: compile-fail tests (`trybuild`) proving `Secret<T>` rejects Debug/Display/Serialize derivation (NFR-SECURITY-001) |
| `controld.querychoke` | `prop_choke_predicate_always_present`: for all template × parameter combinations (generated), the built SQL contains the tenant predicate bound to the `TenantID` newtype — asserted by parsing the generated SQL, not by string search (CON-010) |
| `controld.ingest` | `prop_ingest_idempotent_upsert`: replaying any accepted batch yields `accepted:0, duplicates:n` and zero new rows; `unit_zstd_bomb_bounds` (3 bounds from 05 §10.2) |
| `adjudicator-svc` | `unit_registry_completeness_assert`: `set(HANDLERS) == set(HANDLED_KINDS)` (the probes.py discipline); `prop_ds_posterior_valid`; the correctness battery is §8 |
| `mark1-intel.tvo` | `prop_waste_taxonomy_partitions`: taxonomy categories sum exactly to total attributed tokens — no token counted twice, none dropped (FR-SPINE-022); `unit_no_shapley_symbol` — `tools/ci/shapley_gate.sh`, a `just gates` step, asserting no Shapley **identifier** exists pre-ADR-0003. Deliberately **not** a grep: the only Python occurrence is the docstring *declaring* the ban (`tvo/waste.py:7`), so a literal search self-fails on the sentence promising the property, and the obvious fix — excluding that one file — would blind the gate to the file most likely to grow the first Shapley function. It strips comments and docstrings, scans what remains for symbols, and — because a stripper that silently stopped working reports the same green as a clean tree — downgrades its own result to `PARTIAL` (still exit 0) when **no** file mentions Shapley at all, on the grounds that such a run never exercised the prose-vs-symbol distinction that is the gate's whole mechanism |
| `mark1` CLI | `unit_cli_exit_codes_exhaustive`: table test over every failure path asserting nonzero exit + taxonomy code (FR-CLI-008) |

---

## 3. Conformance suites

The four suites the plan's repo layout fixes under `conformance/`. Each is specified to be buildable without further decisions.

### 3.1 Golden SSE transcripts — `conformance/frames/<dialect>/`

- **Contents:** per dialect (`anthropic-sse`, `openai-responses`, `openai-chat`, `gemini`, `bedrock-eventstream` — the `mark1-frames` module list), a set of recorded upstream response byte streams: normal completion, tool-use, multi-block, mid-stream `error` event, chunk boundaries splitting UTF-8 and splitting SSE field names, zero-length data lines, and the vendor's keepalive/ping frames. Recordings are raw bytes with chunk-boundary annotations (`.bytes` + `.chunks` sidecar), sanitized of credentials at record time by `mark1-redact`.
- **Tests:** `conf_frames_<dialect>_golden` — replay each transcript through the full proxy (not the parser in isolation) and assert:
  1. **Byte-exactness:** client-received bytes `==` upstream bytes, including chunk timing category (streamed, not buffered — asserted by max inter-chunk holdback < 5 ms) (NFR-CORRECTNESS-003).
  2. **Parse yield:** the tee-side parse produces the expected typed events (`Usage`, `ModelResponse`, …) recorded in the fixture's `.expected.json`.
  3. **Degradation:** a deliberately corrupted variant of each transcript still passes assertion 1 while the parse degrades to `ParseDegraded` + transport counters (F-08/F-09 posture: parsing may fail; forwarding may not).
- **Arming:** `conformance/frames/EXPECTED` lists the dialects the gate REQUIRES, on the same reasoning as §3.4's manifest — a listed dialect with zero `.bytes` fixtures is a failed run. Only `anthropic_sse` is armed: it is the Phase 3 dialect and the only one with a parser. The other four degrade by design, so a transcript for them would assert nothing about parsing; each is listed in the same change that lands both its parser and its fixtures.
- **Slug adoption:** this suite is 04 F-09's `frames-golden-per-dialect`.

### 3.2 Hook fixtures per pinned agent version — `conformance/hooks/<agent>/<version>/`

- **Pinning:** the directory name is the exact agent version (`claudecode/v1.0.83/`), and the fixture set includes every hook event the adapter consumes plus transcript samples (`.jsonl` with `requestId`, `message.id`, full `usage` blocks — the verified on-disk shape) and the sidechain/overcount corpus (the recorded ~2.5× streaming overcount session used by `conf_tailer_overcount_defeated`, NFR-CORRECTNESS-001).
- **Tests:** `conf_hooks_<agent>_<version>_replay` — replay every fixture through hookshim field maps + the adapter and assert the exact `m1p.v1` event sequence; `conf_adapter_fieldmap_bundle_push` — apply a renamed-field fixture under a new `agent_maps` bundle and assert it parses with **no binary change** (FR-AGENT-001); `adapter_version_sniff_drop` (F-12) — an unpinned version yields `Dropped{UNSUPPORTED_AGENT_VERSION}` and zero parsed events.
- **Refresh policy:** a weekly scheduled job checks each pinned agent's release channel; a new release triggers a **recording PR**: run the recorder against the new version in a sandbox, commit fixtures under the new version directory, and run the replay suite against them. The old pin's fixtures are never deleted (they document the supported window). An adapter supports exactly the pinned versions with green fixtures; everything else is a typed drop (FR-AGENT-002). Fixture drift on a pinned version (vendor hot-patched a shipped version) fails `conf_hooks_*_replay` on the refresh lane and is handled as §3.5.

### 3.3 The OAuth token-shape canary — `conformance/canary/token-shapes/`

The control this proves is CON-001's tripwire: the classifier that distinguishes OAuth/subscription credentials from API keys. NFR-SECURITY-005: **the canary must fail CI when the classifier misses.**

- **Corpus:** (a) sanitized recorded credential *shapes* (prefix, length, alphabet, structural markers — never live values) for every known Anthropic API-key and OAuth token format, refreshed by the weekly recording lane from a live enrollment fixture account; (b) synthetic near-misses: API-key shapes mutated one character toward OAuth shapes and vice versa; (c) upstream **response** subscription markers for the secondary tripwire (F-38's marker scan).
- **Test:** `canary_oauth_shape_classifier` (weekly, and on any PR touching guard/classifier code) — every OAuth-shaped item must classify OAuth (⇒ refusal path), every API-key shape must classify apikey, every response marker must trigger the contamination path. **One miss = job red = repo-wide CI red** — deliberately louder than a normal failure, because a classifier miss is a latent legal event, not a bug.
- **Proving the canary works (the deliberate miss):** the suite carries a **meta-test**, `canary_selftest_detects_planted_miss`: it runs the canary harness against a classifier instance with one rule disabled through a test-only seam (`#[cfg(test)] fn with_rule_disabled(...)` — the seam does not exist in release builds, asserted by `neg_no_classifier_override_in_binary`). The harness **must** report the miss and exit nonzero; if the harness exits zero, the meta-test fails. This runs on every PR, so a refactor that silently lobotomizes the canary is caught the day it happens — a canary that cannot fail is decoration, which is the estate's RLS lesson applied to a test.

### 3.4 Cross-language wire conformance vectors — `conformance/vectors/{m1pl,redact,receipt,bundle,fusion}/`

- **Contents:** canonical byte vectors, each a triple: input bytes, expected decode (canonical JSON), expected re-encode bytes. Generated once by the Rust reference implementation, then **frozen** — regeneration requires a schema-version bump. `fusion/` is the exception by construction: it has no Rust twin, so its manifest is generated by `gen_fusion_vectors.py` and frozen the same way.
- **The family set is closed at five**, and `conformance/vectors/EXPECTED` is the manifest that arms the gate per family: a family listed there with zero files on disk is a **failed** run, not a quiet pass. Git does not track empty directories, so "we have no vectors yet" and "our vectors vanished" are indistinguishable to a directory scan and only one of them may pass.
- **Arming a family is not the whole gate.** `conformance_crosslang.sh` also requires each armed family to run its *own* tests per language, because a single global pass count lets one family green-light every other — the receipt tests alone once satisfied it while `bundle/` had zero Go coverage. A family with no twin due yet must be named in the script's `GO_PENDING` and is printed loudly; an undeclared zero is a failure. Python is demanded only for families that actually have a Python implementation (`PY_REQUIRED = receipt fusion`), since requiring it of `m1pl`/`redact`/`bundle` would be theatre.

| Family | Implementations that must agree | What one vector pins |
|---|---|---|
| `m1pl/` | Rust `m1p-wire` · Go `mark1d` frame reader · Python payload decode (betterproto) | One M1PL frame's bytes → the decoded `m1p.v1` payload → the re-encoded bytes |
| `redact/` | Rust `mark1-redact` · Go `controld` ingest scanner | Input document → substituted output (`⟨redacted:class:hash⟩`) + admit-axis decision |
| `receipt/` | Rust `mark1-receipt` · Go `mark1d.identity` origin-sign mirror · Python `mark1_receipts` | Payload → canonical bytes → hash → verifiable dual signature (NFR-CORRECTNESS-006) |
| `bundle/` | Rust `mark1-policy` · Go `controld` policy distribution | Canonical-CBOR bundle → decoded sections, plus the command-string and non-canonical-CBOR refusals (FR-POLICY-010) |
| `fusion/` | Go `mark1d` verdict fusion · Python `adjudicator` | One ADJUDICATE input → the posterior **and the derived verdict**. 06 §3 runs one algorithm at two deployment points, so this family pins them to each other rather than each to itself |

- **Tests:** `conf_vectors_m1pl_{rust,go,python}`, `conf_vectors_redact_{rust,go}`, `conf_vectors_receipt_{rust,go,python}`, `conf_vectors_bundle_{rust,go}`, `conf_vectors_fusion_{go,python}`. Divergence in any pair fails CI (NFR-CORRECTNESS-005).
- **`fusion` is checked for agreement, not for self-consistency.** Each leg asserting its own posterior against the manifest within a tolerance is not the claim 06 §3 makes: a 1e-12 tolerance is four orders of magnitude wider than the gap between Go's pure-Go `log`/`exp` and CPython's libm, and the Chow rule compares against exactly A/R = 1/3 — so that gap flips `refused` to `violated` (the edge blocks a developer the cloud does not) while both suites still pass. Both legs therefore assert `verdict` **exactly, with no tolerance**, and the gate additionally requires the set of vectors decided-and-passed by Go to equal the manifest and to equal Python's. A vector only one language drives is a failure. The names are load-bearing rather than descriptive: once a family is listed in `EXPECTED`, `conformance_crosslang.sh` selects by `conf_vectors_` (Rust), `ConfVectors` (Go test functions) and `-k conf_vectors` (pytest), and a Rust or Go filter that matched nothing is a **failure**, not an empty pass — a renamed test is a red build. Python's filter is allowed to collect nothing until `receipt/` has vectors on disk, which is the commit that puts the third language under the same rule.
- **Rejection vectors** are part of every family: inputs each decoder must refuse (command-string bundles, out-of-bound frames, non-canonical CBOR), so "agrees" covers refusals, not just accepts.

**The `m1pl` refusal set, normative and minimal.** The frame codec lands in Rust (`m1p-wire`) and Go (`mark1d`) in one commit; neither may ship without refusing all six. Each is an accept-shaped input with exactly one thing wrong, because a vector that is wrong in two ways proves only that *something* was caught:

| Rejection vector | The input | Every decoder must |
|---|---|---|
| bad magic | bytes 0–3 ≠ `M1PL`, rest well-formed | close (`M1E-4002`); **never** scan forward looking for a valid magic — resynchronizing on attacker-chosen bytes is how a framing bug becomes a parsing primitive |
| unknown `ver` | byte 4 outside the shipped set | close; no partial-parse fallback, no "try v1 anyway" |
| `len == 0` | header well-formed, zero-length payload | close. A zero-length frame is a desynchronized stream, not an empty `Event` — and this is the half a decoder written as `if len > MAX { reject }` silently omits |
| `len == bound + 1` | `len` = `M1PL_MAX_FRAME` + 1, the constant read from 08 §4.2 and **not** re-typed here — a second copy of a bound is how the two implementations end up disagreeing about it | reject **before allocating**, asserted against an allocation counter or a bounded reader, not merely by observing an error |
| truncated payload | `len` promises N bytes, the stream ends at N−1 | never surface a partial `Event`. Incremental decoders answer "need more"; EOF in that state is an error, not a flush |
| trailing garbage | one valid frame followed by 3 undecodable bytes | accept frame 1, then error — never silently discard an unparseable tail, which would make loss invisible to `Dropped{}` accounting |

Each rejection triple's middle slot carries the **expected refusal identity** (the error the decoder must reach), not a message string, so Rust and Go can agree on a refusal without agreeing on error formatting. Accept and reject vectors must be distinguishable without executing them, and a vector must be runnable from either language without a language-specific loader. **The on-disk layout under `conformance/vectors/m1pl/` is fixed by the commit that implements the codec, not by this document** — this section fixes what the vectors must prove; that commit fixes where they sit, and once landed they are frozen with the rest.

- The training-seam vector from 06 §13 lives here too: `test_mark1_row_roundtrip_preserves_completion` — Mark 1 `rows.jsonl` → data-refinery decode → re-emit → byte-compare `completion`.

### 3.5 When a vendor ships a format change

| Change | First test to go red | Where it goes red | Response |
|---|---|---|---|
| Wire dialect change (SSE framing, new event type) | `conf_frames_<dialect>_golden` — new-recording variant | Weekly refresh lane (prod meanwhile: F-09 opaque passthrough, wire `Usage` lost, transcript fallback covers billing) | `DIALECT_REV` bump in `mark1-frames`, new golden fixtures, release. Until released: capture degrades, **never** the client stream |
| Hook payload / transcript schema change | `conf_hooks_<agent>_<newversion>_replay` on the recording PR | Weekly refresh lane (prod: F-12 typed drop + coverage bypass) | New field map shipped as an `agent_maps` **bundle push, not a release** (FR-AGENT-001); fixture PR lands the new pin |
| Credential shape change | `canary_oauth_shape_classifier` | Weekly canary | Classifier rule update, released same week; guard meanwhile fails **closed** (unknown shape ⇒ refuse, CON-001 — a new shape can produce false refusals, never false forwards) |

The asymmetry in the last row is the design: format drift may cost availability or capture coverage; it may never cost legality.

### 3.6 Closed-field-set assertions — `conf_schema_closed_field_set`

Three documents and two proto comments assert that a message's field set is **closed** — `EdgeHealth` and its ten sub-messages (`11` §2.3, the single source of truth for that tree), and the `Dropped{}` loss ledger. A closed set is a privacy control, not a style rule: `EdgeHealth` is the one event family that reports on the developer's *machine* rather than on their consented capture, so a field added to it quietly widens what Omium can see about a laptop it is forbidden to scrape. Widening by accretion is exactly how that boundary erodes — no single field looks like a policy change.

Until this test exists those assertions are **comments claiming an enforcement that is not there**, which is the failure class this document's §0.3 is written against. The test is what converts them into facts.

- **Subject:** the file-descriptor set `buf build` already produces in the `contracts` CI stage (§11.1) — the same artifact `buf breaking` consumes, so no new toolchain and no reflection tricks in three languages.
- **Mechanism:** a committed golden, `conformance/schema/closed_field_sets.txt`, listing one line per field of every message declared closed — `<fq_message>.<field_name> = <number> : <type>` — including `reserved` ranges and names, sorted. The test rebuilds the descriptor and diffs. Any added, removed, renamed or retyped field is a red build.
- **Why a golden and not a hand-written assertion list:** the fix for a red build is to update the golden *in the same PR that changes the proto*, which puts the widening on a reviewer's screen as a diff line with a privacy question attached to it. An assertion list drifts silently the moment someone adds a field and the list is somewhere else.
- **`reserved` is part of the set.** `Dropped` reserves `2`/`"category"` and `GateHealth` reserves `5`/`"read_p50_us"`; a PR that quietly un-reserves either — the precise way a deleted field comes back wearing a decoder's memory of the old one — must be as red as adding a field.
- **Scope, declared explicitly:** `m1p.v1.EdgeHealth`, `ProcessHealth`, `SpoolHealth`, `UplinkHealth`, `BundleHealth`, `GateHealth`, `ProxyLatency`, `ShimHealth`, `CortexHealth`, `DialectRev`, and `m1p.v1.Dropped`. Messages **not** on this list are free to grow additively — the closure is a deliberate exception for the two trees whose growth is a privacy event, not a blanket freeze on `m1p.v1`.
- **Ships:** Phase 1, in the commit that lands the `EdgeHealth` emitter. Until it does, `11` §2.3's privacy rule is enforced by review only, and `11` §12's G-5 stays open — which is where that gap is tracked, rather than being invisible.

This test is what `11` §2.3, `11` §12 G-5, `events.proto`'s `EdgeHealth` and `GateHealth` comments, and `envelope.proto`'s `Dropped` comment all cite. If it is deleted, those five citations must be deleted in the same commit.

---

## 4. Tenant-isolation negative tests

The centerpiece of the security testing, and the direct answer to the estate's decorative-RLS incident (61 FORCE-RLS tables inert because the master user inherited BYPASSRLS). **The whole suite is one required PR check** (`isolation`, NFR-SECURITY-003, CON-010) running against real stores (§11.4) — a skipped run is a failed run (§0.3 mechanism 2). Every test seeds two tenants (A, B), attempts the cross-tenant access as the *production* principal, and asserts denial **plus** the absence of side effects.

### 4.1 Postgres — 05 §7.5's seven tests, adopted verbatim

| Test (name is contract) | Setup | Attempt | Assertion |
|---|---|---|---|
| `test_rls_cross_tenant_denied` | Connect as `controld_app`; seed every FORCE-RLS table with A and B rows; set GUC to A | `SELECT` every RLS table | Zero B rows. Table list is **driven from `pg_policies` at runtime**, so a new tenant-scoped table without a policy fails the test by omission — coverage cannot rot silently |
| `test_rls_unset_guc_matches_nothing` | Same connection, GUC unset | `SELECT` every RLS table | Zero rows from every table — the `NULLIF(current_setting('app.tenant_id', true), '')` form doing its job: forgotten context returns nothing, never everything |
| `test_rls_forced_for_owner_paths` | — | Inspect `pg_class` | Every tenant-scoped table has `relforcerowsecurity = true` — plain ENABLE without FORCE is the decorative mode |
| `test_app_role_nobypassrls` | — | Inspect `pg_roles` | `rolbypassrls = false AND rolsuper = false` for `controld_app` (and every `*_app` role in the migration set) — **the direct regression test for the `rds_superuser` incident** |
| `test_write_rls_denied` | As `controld_app` under tenant A | `INSERT`/`UPDATE` rows stamped tenant B | Policy violation error — `WITH CHECK` holds for writes, not just reads |
| `test_worker_role_confinement` | — | Import-graph analysis + DSN grep | `pgWorker` reachable only from 05 §7.3's enumerated packages; no handler package references the worker role's env vars. A new consumer must extend the enumeration and this test in the same PR |
| `test_append_only_receipts` | Seed receipt-chain and ε-ledger rows | `UPDATE`/`DELETE`/`TRUNCATE` **as every role including `controld_worker` and the migration owner** | All fail by trigger, regardless of role (the `ro_012` discipline) |

### 4.2 Extensions that close the BYPASSRLS class structurally

| Test | Setup | Attempt | Assertion |
|---|---|---|---|
| `neg_bypassrls_role_connection_refused` | Create a scratch role **with** `BYPASSRLS`; hand its DSN to the controld pool constructor | Open a connection | `AfterConnect` returns `errBypassRLSRole`; the pool refuses the connection. This is the runtime enforcement of what `test_app_role_nobypassrls` checks statically — a BYPASSRLS-inheriting role (the exact estate failure: privilege arriving via role *inheritance*, not via the role's own attribute) cannot even connect, because the check queries `rolbypassrls OR rolsuper` for `current_user` **on the live connection**, where inheritance has already resolved |
| `neg_bypassrls_inherited_membership` | Grant the scratch app role membership in a BYPASSRLS role (`GRANT worker TO app_test`) | Run `test_rls_cross_tenant_denied`'s read as that role | Zero B rows still (RLS bypass does not flow through membership for `rolbypassrls` — asserted, not assumed) **and** the boot check `SELECT pg_has_role(...)` audit flags the grant; either failing turns the test red |
| `neg_migration_cannot_weaken_rls` | — | Static scan of `migrations/*.sql` | No `ALTER ROLE ... BYPASSRLS`, no `DISABLE ROW LEVEL SECURITY`, no `DROP POLICY` without a `CREATE POLICY` in the same file, outside an allow-listed, reviewed exception file |

### 4.3 ClickHouse — the chokepoint

| Test | Setup | Attempt | Assertion |
|---|---|---|---|
| `prop_choke_predicate_always_present` | Boot-validated template registry | Fuzz all templates × generated params (this is 05 §6.4's per-PR predicate fuzz) | Every generated query, **parsed** (not string-matched), carries the tenant predicate bound from the `TenantID` newtype |
| `neg_ch_cross_tenant_zero_rows` | Ledger seeded with A and B events | Every registered template executed as tenant A | Zero B rows in every result; unknown template ⇒ `M1E-2008` refusal |
| `neg_ch_no_second_principal` | — | Enumerate CH users/grants in the deployed DDL | Exactly one query principal (`chconn`'s), readonly/insert-only profiles as declared; any other grant fails the test |

### 4.4 Memory API

| Test | Setup | Attempt | Assertion |
|---|---|---|---|
| `neg_memory_api_cross_tenant_denied` | Artifacts admitted for A and B | Retrieve/list/deliver B's artifacts with A's token; retry with a forged tenant claim | 404/403; zero B artifact IDs in any response body; forged claim ⇒ security event row |
| `neg_memory_vector_search_scoped` | Error-signature vectors for A and B in the pgvector column | Fuzzy-match query as A crafted to be nearest-neighbor to B's vectors | Result set contains only A's rows (the HNSW index does not bypass RLS — this is exactly the query shape most likely to be routed around the policy, so it gets its own test) |

### 4.5 S3 and ingest

| Test | Setup | Attempt | Assertion |
|---|---|---|---|
| `neg_s3_cross_prefix_denied` | Per-tenant prefixes + per-tenant KMS keys per NFR-PRIVACY-004 | Read/write `t/<B>/…` with A's IAM role; decrypt B's object with A's key grant | `AccessDenied` on both the object op and the KMS decrypt — two independent denials asserted separately |
| `neg_s3_kms_stamping_backstop` | — | PUT to A's prefix specifying B's KMS key (the stamping-bug simulation) | Bucket policy denies the write (05 B3: a stamping bug is a write failure, not a leak) |
| `negative_envelope_tenant_spoof_rejected` | Valid device token for A | Upload a batch whose envelope claims tenant B | 403 `M1E-8003` + security event + batch quarantined edge-side (05 §9's ingest arm, adopted verbatim) |

### 4.6 Federation arm (Phase 5 onward, then permanent)

`neg_km_direct_sql_bypass` (CON-011/FR-FED-003: direct SQL insert trips the `HAVING`/trigger), `neg_span_below_m_never_publishes` (FR-FED-002 reconstruction test), `negative_epsilon_exhaustion_refuses` (05 §9, adopted). These join the required `isolation` check when their tables exist; the traceability gate (§10.3) enforces that they exist before the Phase 5 gate can pass.

---

## 5. Fuzz targets

Every decoder and parser that touches bytes it did not produce gets a fuzz target. "Never panics" is the floor; each target also carries a **semantic** assertion — the property that must hold even for inputs that decode successfully.

| Target | Harness | Semantic assertion beyond no-panic |
|---|---|---|
| `fuzz_m1pl_frame` — Rust target `m1p-wire/fuzz/frame_decode`, Go twin `FuzzM1plFrameRead` in `mark1d/internal/fabric` (the two names `just fuzz` actually invokes; `fuzz_m1pl_frame` is the traceability slug) | arbitrary bytes → framer | `len` bounds-checked before allocation, both halves of 08 §4.2's bound; a successful decode re-encodes to identical bytes; both languages agree on accept/reject for every corpus entry (F-41), the `conformance/vectors/m1pl/` rejection set included as seed corpus (§3.4) |
| `FuzzSpoolRecord` + `FuzzSegmentRecovery` (Go, `mark1d/internal/spool`) | arbitrary segment bytes → recovery scan | recovery returns a valid record prefix; no record with a bad crc32c is ever surfaced; truncation point is a record boundary |
| `fuzz_m1p_decode` (Rust/prost) + `FuzzIngestDecode` (Go, ingest stage 4–5) | arbitrary bytes → protobuf decode with ingest bounds | ingest bounds hold (≤10k events, ≤1 MiB/event, depth cap); zstd bomb guard trips before decompression spend; a decoded `Usage` without `idem_key` is rejected |
| `fuzz_bundle_decode` (Rust, `mark1-policy/fuzz/`) + `FuzzBundleDecode` (Go) | arbitrary bytes → CBOR bundle decode | **any input whose decode succeeds contains no command string**: the harness re-scans every string field of the decoded struct against the command grammar and panics on a hit — so the fuzzer is actively searching for a bundle that smuggles a command past the decoder (CON-009). Seed corpus includes hand-built command-bearing bundles that must all reject |
| `fuzz_sse_<dialect>` (Rust, `mark1-frames/fuzz/`, one per dialect) | arbitrary bytes + arbitrary chunk splits → parser | forwarded bytes always equal input bytes (the tee cannot corrupt the stream even on garbage); parser ends in a typed state (`Parsed` or `ParseDegraded`), never a hang |
| `FuzzTranscriptLine` (Go, tailers) | arbitrary JSONL lines → tailer | never emits a `Usage` lacking the `(message.id, request_id)` dedupe inputs; sidechain rule applied before emission; arbitrary rotation/truncation mid-line never double-emits (uses `prop_spool_crash_prefix`'s torn-write generator) |
| `fuzz_redact_scanner` (Rust, `mark1-redact/fuzz/`) | arbitrary bytes → both scanner axes | admit axis returns a decision for all inputs; quarantine on internal error (F-35); no catastrophic-backtracking pattern (per-input time budget asserted — rust/regex's guarantee, verified not assumed) |
| `prop_choke_predicate_always_present` (Go fuzz mode) | template params → SQL builder | doubles as §4.3's fuzz arm — the tenant predicate survives every parameter shape |

**Corpus management.** Per-target corpora live in `conformance/fuzz-corpus/<target>/`, checked in. Seeds: every golden fixture (§3), every conformance rejection vector, and every past finding. A finding's minimized reproducer is committed to the corpus in the fixing PR — findings become permanent regression tests by construction.

**Schedule.** PR: 60 s/target in regression mode (corpus replay + brief exploration) — cheap, and it makes every past crash a merge blocker. Nightly: 1 h/target on Linux with ASAN (Rust) and `-race` (Go), fresh exploration.

**Triage.** A nightly finding auto-files a P1 with the minimized input attached; the reproducer is committed immediately (turning PR regression mode red for everyone touching that crate) and the fix follows. Findings in `mark1-redact`'s admit axis, `mark1-policy`'s command gate, or the querychoke are treated as security incidents (they attack fail-closed controls), not bugs: same-day fix or the affected release channel freezes.

---

## 6. Chaos suites

Every test names the exact injected fault and the exact assertion. Slugs from 04 §10 and 05 §9 are adopted verbatim. The fast subset (marked ⚡) runs on PR; everything runs nightly and at phase gates.

### 6.1 Proxy chaos — `chaos_proxy_stream_suite` (04 F-07; Phase 3 gate)

The suite-wide assertion is **zero client-visible regression**: every scenario runs twice — once direct-to-vendor (control), once through the proxy — against the same scripted upstream, and the client-observed byte stream, error class, and timing envelope must match the control run. "The client sees exactly what the vendor would have shown" is the assertion, not "the proxy handled it."

| Test | Injected fault | Assertion |
|---|---|---|
| `chaos_proxy_upstream_stall` | scripted upstream freezes mid-SSE for 60 s, then resumes | client sees the identical stall and resume as control; no proxy-injected timeout, no buffering (bytes delivered ≤5 ms after upstream sends); tee falls behind independently, `Dropped{}` accounted |
| `chaos_proxy_midstream_reset` | upstream sends RST mid-body | client observes the same error class at the same byte offset as control; connection state cleaned; next request unaffected |
| `chaos_proxy_slow_client` | client reads at 1 B/s while upstream streams a large body | proxy RSS stays ≤ 35 MB (flow control propagates; nothing buffers unboundedly); upstream backpressured exactly as in control; tee sheds via `try_send`, never blocks the client write (F-08) |
| `chaos_proxy_tls_fail_midbody` | upstream TLS session killed mid-body (close_notify absent) | client sees the identical truncation error as control; no partial-frame corruption; `GuardDecision`/transport counters still emitted |
| `chaos_proxy_kill_midstream` ⚡ (F-05) | `kill -9` the proxy during an active stream | exactly one failed client request (agent retries); base-URL fragment reverted; traffic flows direct-to-vendor; `CoverageTransition{BYPASS,"proxy_failed"}` receipted; capture continues via transcripts (NFR-AVAILABILITY-002) |
| `proxy_tee_saturation` ⚡ (F-08) | tee channel artificially saturated under load | forwarded bytes unaffected (byte-diff vs control empty); parse degrades; `Dropped{}` counts equal shed events |

### 6.2 Edge chaos — the billing-grade zero-loss suite (Phase 1 gate)

| Test | Injected fault | Assertion |
|---|---|---|
| `chaos_daemon_kill9` ⚡ (F-01, FR-SPINE-024) | `kill -9` `mark1d` in a loop at random points during active spool writes + in-flight uploads, ≥100 iterations | after recovery and drain, the ledger contains **every acknowledged billing-grade event exactly once** — zero loss, zero duplicates (dedupe absorbs replays). Precision note, reconciling the plan's "loses nothing" with 04 F-20: *acknowledged* means acked to the writer after group-commit fsync; a torn tail record that was never acked may be truncated, is bounded by the 250–500 ms fsync window, and **must** appear as `Dropped{CRC_LOSS}` in the first post-recovery batch (`spool-kill9-taillos-accounted`, slug adopted as-is, typo noted). Silent loss of even one unacked record fails the test |
| `spool_billing_blocks_on_full` ⚡ (F-17) | fill spool to cap with uplink paused | billing-grade writers block (goroutine parked, asserted), diagnostics shed-newest with `Dropped{SPOOL_SHED}`; resume uplink ⇒ writers unblock, nothing lost |
| `spool_disk_hardstop` (F-19) | fill the volume to >95% via a ballast file | pre-append statfs halts writes; `CoverageTransition{BYPASS,"disk_hard_stop"}` receipted; deleting ballast resumes capture; no partial segment corruption |
| `chaos_sleep_wake` (F-43) | suspend the VM 10 min mid-session (or clock-freeze harness where suspend is unavailable) | on wake: tailer cursors re-stat, parked uploads re-queue on the network-change signal, slow anchors deferred; no duplicate `Usage` (idem_key), no billing loss |
| `skew_ordering_invariance` (F-44, 05's `conformance_skewed_device_ordering`) | replay fixtures with the edge clock set ±26 h, **and a second fixture with a mid-session `session_epoch` bump** | per-session ordering rides the pair `(session_epoch, seq)` and is unaffected by either — the epoch fixture is the one that fails if a consumer regresses to `seq` alone, which the clock fixture alone cannot catch; server computes and stores skew; TVO joins still resolve; device flagged in doctor at >24 h |
| `uplink_park_requeue` (F-22) | blackhole the ingest endpoint mid-upload for 45 min | retry automaton observes jittered backoff (base 6 s, cap 30 min, ~10 attempts) then PARKED; heal ⇒ re-queue and complete drain; 4xx variant (`uplink_4xx_quarantine`, F-23) quarantines without retry |
| `gate_timeout_allows` ⚡ (F-11) | daemon paused (SIGSTOP) during a gate query | shim returns within the gate deadline, decision = allow (fail-open observer / declared posture for gates, NFR-LATENCY-003); agent never hangs; `Dropped{gate_timeout}` |
| `chaos_no_spof_for_coding` (NFR-AVAILABILITY-001) | kill each Mark 1 process (daemon, proxy, cortexd, shim path) in turn mid-session | the agent completes its task unmodified every time — Mark 1's absence is a coverage event, never an outage |

### 6.3 Cloud chaos — 05 §9's suite, adopted verbatim (Phase 1/3 gates + nightly)

| Test | Injected fault | Assertion |
|---|---|---|
| `chaos_s3_outage_no_false_ack` | deny S3 access mid-load | **zero acks without landed objects** (the S3-first promise kept by withholding); edges back off; billing classes accumulate in blocking spools; after heal: zero billing-grade loss end-to-end |
| `chaos_ch_outage_ingest_unaffected` | stop ClickHouse under load | ack SLI holds (CH is not in ingest readiness); reports 503; post-heal projection replay ⇒ ledger equals landed objects exactly |
| `chaos_pg_failover_bounded_window` | trigger RDS-style failover (or restart PG primary in the compose profile) | recovery < 120 s; revocation-cache staleness never exceeds 60 s (past it, token verification fails **closed**); acks continue through the window; singleton loops re-elect via advisory locks |
| `chaos_kms_throttle_tenant_isolated` | throttle one tenant's KMS key | that tenant's ingest 503s; **other tenants' acks unaffected** (per-tenant blast radius proven, not assumed); bundle publication queues without draining the shared sign budget |
| `chaos_tlog_outage_publication_halts` | take the transparency log down | no bundle becomes servable without a servable inclusion proof (log-before-serve ordering); edges stay on last-known-good; publication resumes with witness continuity verifiable across the gap |
| `negative_poison_batch_parks_not_loops` | inject a payload that decodes but crashes projection | 3 retries then dead-letter park; no projector crashloop; the hole is visible (never hidden by accounting); replay-after-fix restores completeness |
| `negative_duplicate_flood_no_double_count` | replay a full day of traffic twice | ledger counts and TVO outputs byte-identical to the single-run baseline; `accepted:0, duplicates:n` responses; category rate limits trip as designed |
| `negative_revoked_token_60s_cutoff` | revoke a device under sustained load | no request from it succeeds past the 60 s cache ceiling; `OnRevoked()` purge verified on the edge (F-26) |
| `bundle_maxage_builtins` (F-29) + 7-day fail-static soak (NFR-AVAILABILITY-003, rolling nightly) | control-plane blackhole; clock advanced past `max_age` | last-known-good runs indefinitely; past `max_age` ⇒ documented conservative built-ins (knee=1, gates open, `stale_cert` flags) — observed, not inferred |

Remaining 04 §10 rows not tabulated above (`chaos_daemon_crashloop`, `chaos_cortexd_kill`, `cortex_shard_corrupt`, `tailer_rotation`, `tailer_truncation_replay`, `tailer_cursor_loss`, `tailer_retention_gap`, `spool_midfile_crc`, `uplink_409_divergence`, `identity_refresh_outage`, `identity_revoked_purge`, `bundle_invalid_keeps_lkg`, `bundle_command_string_rejects`, `bundle_skip_and_retain`, `anchor_error_not_violated`, `antitamper_path_shim`, `antitamper_worktree_suppression`, `anchor_integrity_incomplete`, `redact_fails_closed`, `redact_substitution_pre_spool`, `guard_no_forward_path`, `guard_contamination_killpath`, `loopback_host_origin`, `fabric_symlink_refusal`, `custody_floor`, `fragment_user_edit_refusal`, `off_byte_equality`, `shim_spill_replay`, `adapter_version_sniff_drop`, `frames_golden_per_dialect`, `fuzz_m1pl_frames`, `bench_proxy_latency_rss`) are all adopted with their catalog rows as specification — fault = the Failure column, assertion = the Recovery/posture columns — and appear in the traceability matrix (§10) under their owning requirements. None is optional: 04 §10 has 46 rows and 46 tests exist.

---

## 7. Performance benchmarks with CI thresholds

### 7.1 The budgets that gate a merge

| Test | Budget | How measured |
|---|---|---|
| `bench_proxy_latency_rss` (F-06, NFR-LATENCY-001, NFR-FOOTPRINT-001) | **≤ 1 ms median added latency**; **≤ 35 MB peak RSS** | Golden streaming load (the §3.1 transcripts at recorded pacing, 64 concurrent streams, 10-min soak). **Paired A/B in one run:** the same harness drives direct-to-upstream and through-proxy against the same scripted upstream on the same machine; the gated number is the per-request latency **delta** distribution's median — runner noise affects both arms and cancels. RSS sampled at 1 Hz from `/proc`, gate on peak |
| `bench_shim_dispatch` (NFR-LATENCY-002) | observer hook **p99 ≤ 50 ms** exit, daemon up **and** daemon down (the fire-and-forget budget includes the 100 ms-connect-timeout spill path being off the critical path); cold-start (spawn→UDS write→exit) **p50 ≤ 10 ms** | `hyperfine`, 500 invocations per state; daemon-down state uses the SIGSTOP fixture |
| `bench_redact_throughput` | **≥ 80 MB/s** on the worst-case pattern corpus (plan's basis: rust/regex ≈100 MB/s worst case = 100× stream headroom; 80 keeps 80× headroom as the CI floor so a pattern addition that halves throughput is caught long before the headroom is real risk) | criterion over a 64 MiB mixed corpus (code, JSON, transcripts, planted secrets at density extremes) |
| `bench_cortexd_session_map` (FR-CORTEX-003, NFR-FOOTPRINT-003) | warm-index map generation **p95 ≤ 2 s** on the L fixture repo; token budget respected on every fixture (S=1k, M=20k, L=100k files — fixtures committed, generated deterministically) | criterion-style harness in cortexd's bench; budget-respect is the §2.7 unit property, timing is gated here |
| `bench_ingest_throughput_ack` (05 §2.7) | **≥ 1,000 events/s sustained per pod-equivalent** with **p99 ack ≤ 500 ms** at that rate (ack = request receipt → S3-landed 202) | Go bench harness against controld + MinIO + PG on the pinned runner; load shape = 05 §8.5's burst profile (mean + 100× diurnal spike for 60 s) |
| `bench_policy_eval` (NFR-LATENCY-004) | **≤ 1 µs**, zero allocations per evaluation on typed structs | criterion + counting allocator |
| `bench_fusion_gate_read` (FR-VERIFY-007's latency half) | gate cache read **≤ 100 µs** p99 (it is a cache read; if this number grows, someone put work on the gate path) | Go bench |

### 7.2 Hardware and variance handling

- **The pinned runner.** Absolute budgets gate only on one self-hosted runner class (fixed instance type, recorded in each result's metadata; the class is c7i.2xlarge-equivalent, chosen and frozen in `docs/runbooks/bench-runner.md` — changing it requires re-baselining every budget in the same PR). GitHub-hosted runners run the same benchmarks **report-only** across the 3-OS matrix — cross-OS numbers inform, never block, because their variance is not ours to control.
- **Anti-flake protocol,** in order:
  1. Paired A/B within one run wherever a delta is the budget (proxy) — the strongest variance killer.
  2. Median-of-5 process-level repetitions; the gated statistic is the median, never the mean.
  3. A run fails only if it exceeds the budget **and** exceeds the stored baseline by more than 3×MAD of the last 20 runs on the same runner class — so a genuinely noisy day cannot fail a build that didn't regress, and a real regression cannot hide inside the noise band because the absolute budget still caps it.
  4. One automatic re-run on failure; two consecutive failures = red. No manual re-run-until-green: the retry count is 1, in the workflow, visible.
- **Trend, not just threshold:** every result appends to `bench/history/` (committed on main); nightly job flags a >10% 7-day drift in any gated metric even while still under budget — budgets are ceilings, drift is the early warning.

### 7.3 What a benchmark failure means

A red benchmark blocks merge exactly like a red test. There is no "perf waiver" label. If a feature legitimately costs budget, the budget change is a PR against **this document and 02** (the numbers are requirements: NFR-LATENCY-001 etc.), reviewed as a requirement change — the code PR cannot self-serve a bigger budget.

---

## 8. Intelligence-plane correctness

You cannot unit-test a probability by asserting its value on live data. You can test it three ways, all used here: **against a worked example** (the papers' published tables are executable specifications), **against synthetic data with planted ground truth** (the estimator must recover what was planted), and **against a proved property** (the theorem's precondition→conclusion, simulated). A failure in this section never means "flaky statistics" — each row states exactly what it means.

| Test | Method | Pass criterion | A failure means |
|---|---|---|---|
| `test_paper2_posterior_table_reproduced` (FR-VERIFY-018; 06 §3.2) | Run ADJUDICATE on the synthetic verifier outputs from Paper II's worked example | Posterior 4-vectors and verdicts match the published table to 1e-9; `crowd-kit` (test-oracle only, never a runtime dep — asserted by lockfile scan) agrees on the same inputs | The implementation is not the algorithm the paper proved Bayes-optimal — the certification claim is unfounded. Merge-blocking |
| `test_spectral_ds_recovers_planted_matrices` (FR-VERIFY-012) | Generate ensembles from **known** confusion matrices, priors, correlation structures across regimes: identifiable (≥3 independent groups), volumes 10²–10⁵, degenerate (2 groups, near-chance verifiers, adversarial inversions) | Identifiable regime: recovered matrices within tolerance (Frobenius ≤ 0.05 at n=10⁴), and the tolerance-vs-n **recovery-rate curve** matches the estimator's theoretical rate (log-log slope within 15%); degenerate regime: the identifiability gate **refuses** — spectral path provably not taken, weighted-majority used, status honest | Estimator bug (identifiable case) or the worse failure: statistically-fictional certificates issued where the math cannot support them (degenerate case) — spec risk #5 realized |
| `test_identifiability_gate_degrades_honestly` (06 §13) | Feed the G1–G6 diagnostics boundary cases | Below-gate ⇒ weighted majority + `bootstrapping`/`uncertified` status; every §5.4 consumer (memory, corpus, reports) observed throttling itself | An uncertified verdict is flowing somewhere at certified strength — label integrity broken upstream of the corpus, the moat's failure mode |
| `test_paper1_tvo_reconciliation` (FR-SPINE-022, NFR-CORRECTNESS-002; 06 §8.6) | Run TVO engine v1 on the Paper I worked example's golden input, both cost bases | Every intermediate and the final TVO equal the hand-computed values exactly (integer token arithmetic; no float drift permitted); waste-taxonomy partition sums reconcile to total tokens | Every number ever quoted to a customer is wrong. Phase 1 does not pass while red |
| `test_admit_lcb_do_no_harm` (FR-REMEMBER-003; Paper III Thm 6.2) | Simulate artifact populations with known true utilities, including adversarial samplers at the theorem's preconditions (clipping φ, budget B, propensity floor p_min) | Over 10⁴ simulated admission runs: expected utility of the admitted set is never statistically below the no-admission baseline (one-sided test at α=0.01); zero-true-utility artifacts admitted at ≤ the LCB's nominal false-admit rate; boundary fixtures pin the confidence computation bit-exactly | The do-no-harm property the theorem PROVED does not hold in the implementation — memory can now hurt the customer it is supposed to help |
| `test_admit_lcb_rejects_stale_cert_samples` (06 §13) | Outcome samples backed by expired/demoted certificates | Excluded from `O_a`; artifact HOLDs | Admission is consuming labels its own certification layer disowned |
| `test_poisoning_influence_bound` (06 §13, §9.6) | One tenant inflates outcomes maximally within quota | Measured influence ≤ φB/p_min regardless of strategy; excess recorded-not-counted | The bounded-poisoning theorem's quota accounting has a hole; the shared pool is attackable |
| `test_ope_estimators_synthetic_ground_truth` (FR-LEARN-005) | Simulate a logging policy with known propensities and a candidate with **analytically known** true value; run DR and SNIPS | Both estimates within the estimator's own CI of truth; CI coverage calibrated (95% CI covers ≥ 93% over 10³ replications); `WIRE_ENFORCED`-only filter verified — planted `ADVISORY`/unjoined `CONFIG_STEERED` rows change nothing (FR-ROUTE-002) | Router promotion decisions are driven by a biased estimator — LEARN optimizes noise |
| `test_ope_ess_floor_blocks_promotion` (06 §13) | Candidate whose effective sample size is below the §11.3 floor | Verdict `insufficient_evidence`, inside the promotion transaction; no bundle change | A model can get promoted on evidence the diagnostics call insufficient — self-promotion by statistical accident |
| `test_promotion_pipeline_state_machine` (FR-LEARN-004; 06 §12.4) | Drive a learned artifact through every path of probation→shadow→LCB→canary, including every failure arm | No path reaches `active` without ≥500 shadow votes, LCB pass, canary records; rollback republishes prior content under a **higher** seq | The no-self-promotion law (C12) has a bypass |

All of §8 runs on PR (the simulations are seeded and take seconds at PR scale; nightly reruns them at full replication counts with fresh seeds). A fresh-seed nightly failure is not "flaky" — the seeds are logged, the counterexample is committed, and the estimator's tolerance either holds or the requirement is renegotiated in 02, never silently widened in the test.

---

## 9. The compliance test matrix

One row per in-code compliance enforcement point: the frozen plan's seven, plus the three the architecture spec (§9) carries beyond them — **evidence typing**, **training**, and **auditability against Omium itself** (spec points 4, 8, 9; the plan's seven map to spec points 1, 2, 3, 5, 6, 7, 10). This matrix is the test-side half of `10-security-threat-model.md`'s control matrix: **every control row in 10 must have a row here naming a live test, and a control with no row is a documentation bug** — reconciliation fails on it, and the `compliance-matrix-check` CI job (§10.3) fails on it mechanically once 10 lands. 10 is being authored in the same batch; whichever document lands second reconciles against the first, and the plan's own verification clause ("each of the seven … has a row in 10's control matrix and a named test in 12") is the arbiter.

| # | Enforcement point (plan/spec) | Proving tests | Home | Runs |
|---|---|---|---|---|
| 1 | **OAuth non-interception** (plan 1 / spec 1; CON-001) | `guard_no_forward_path` (F-37: negative — no code path forwards an unprovisioned credential, call-graph + runtime), `guard_contamination_killpath` (F-38: marker ⇒ session kill + rollback + receipted `oauth_contamination`), `canary_oauth_shape_classifier` + `canary_selftest_detects_planted_miss` (§3.3), `neg_no_classifier_override_in_binary` | proxy crate negatives + `conformance/canary/token-shapes/` | PR (negatives) + weekly (canary) + PR meta-test |
| 2 | **Credential custody** (plan 2 / spec 2; CON-002, CON-015) | `unit_secret_type_no_debug` (trybuild compile-fail), CI grep gate `ci_grep_raw_credential_types`, `neg_tee_field_allowlist` (tee output diffed against allow-list contains no auth material), `neg_gateway_zero_credential_bytes_on_disk` (filesystem audit under load), `neg_core_dumps_suppressed` (induced crash writes no core; RLIMIT/dumpable asserted), `neg_pool_key_identity` (two identities never share a pool) | proxy crate negatives (colocated) | every PR |
| 3 | **Egress admission / redaction** (plan 3 / spec 3; CON-008) | `redact_fails_closed` (F-35), `redact_substitution_pre_spool` (F-36: planted secrets are `⟨redacted:class:hash⟩` in every spooled artifact), `prop_redact_no_secret_survives` (§2.4), `neg_no_plaintext_persistence_path` (disk audit: no pre-redaction plaintext anywhere; no off switch exists — config/env/flag sweep), `shim_spill_replay` (F-10: spill is sanitized + encrypted), ingest arm: seeded-secret batch ⇒ quarantine + security event (FR-SPINE-012), and `neg_ingest_catches_what_the_edge_misses` — a secret matched by the ingest ruleset but by **no** edge rule is still quarantined, which is the defense-in-depth property; **not** rule-ID distinctness, which is a false proxy (five IDs are byte-identical today because two independent authors both call an AWS key `aws_access_key_id`). *Tenant alert is unbuilt: `ingest/pipeline.go` counts and returns.* | `mark1-redact` + shim + `controld` ingest (colocated) | every PR |
| 4 | **Evidence typing** (spec 4; CON-004, NFR-PRIVACY-001/-002) | `neg_wire_no_paths_no_excerpts` (wire capture of a default session: zero path strings, zero source excerpts), `unit_evidencerecord_schema_closed` (proto has no field capable of carrying a path or free text), `neg_digests_tenant_salted` (same content, two tenants ⇒ different digests; dictionary attack on fixtures fails), `neg_evidence_dir_never_uploaded` (default-config soak: zero bytes from `~/.omium/mark1/evidence/` on the wire) | `mark1d` negatives + proto unit tests | every PR (soak arm nightly) |
| 5 | **Anchor execution** (plan 4 / spec 5; CON-009, CON-013) | `bundle_command_string_rejects` (F-28) + `prop_bundle_no_command_decodes` + `fuzz_bundle_decode` (both languages), `neg_sandbox_probes` (FR-VERIFY-002: outbound connect fails, env scrubbed, write-outside-worktree fails, cap kills runaway, kill switch works), `neg_unconsented_anchor_never_runs` (FR-VERIFY-001), `off_byte_equality` (F-46) + disable-check-ordering unit (CON-013) | policy crates + `mark1d/internal/anchors` + `conformance/` | every PR |
| 6 | **Tenancy** (plan 5 / spec 6; CON-010) | the entire §4 isolation suite: seven adopted RLS tests + BYPASSRLS extensions + chokepoint fuzz/negatives + memory API + S3/KMS + `negative_envelope_tenant_spoof_rejected` | `conformance/tenancy/` | **every PR, required check** |
| 7 | **Federation** (plan 6 / spec 7; CON-011) | `neg_km_direct_sql_bypass`, `neg_span_below_m_never_publishes`, `neg_invariant_never_federates` (schema-level), `negative_epsilon_exhaustion_refuses`, `neg_release_requires_ledger_debit` (transactional coupling), `neg_unreviewed_never_publishes`, `neg_optout_spans_absent` | `conformance/tenancy/federation/` | every PR from Phase 5; Phase 5 gate |
| 8 | **Training** (spec 8; FR-LEARN-001…004, CON-011's ε ledger) | `test_corpus_refuses_uncertified_labels` (06 §13), `neg_cross_tenant_training_requires_receipted_optin`, `neg_dpsgd_debits_epsilon`, `test_canary_memorization_blocks_leaky_checkpoint`, `test_promotion_pipeline_state_machine` (§8), `test_mark1_row_roundtrip_preserves_completion` (§3.4) | `python/intel/tests/` + `conformance/vectors/` | PR (intel suites); Phase 6 gate for DP-SGD arms |
| 9 | **Auditability against Omium itself** (spec 9; FR-SPINE-015…020) | `prop_receipt_chain_tamper_evident` + `prop_merkle_inclusion_sound` + `unit_receipt_dual_sig` (§2.3), `conf_verifier_offline` (full chain + witness heads validated with every Omium endpoint blackholed; detects each of the five defect kinds on corrupted fixtures — FR-SPINE-020), `conf_witness_hourly_head` (FR-SPINE-019: tampered head fails witness comparison), `test_append_only_receipts` (§4.1) | `rust/verifier/tests/` + `conformance/e2e/` | every PR (offline verify is fixture-fast); witness arm nightly |
| 10 | **Scope of reading** (plan 7 / spec 10; CON-012, CON-014) | `neg_tailer_reads_inside_roots_only` (filesystem audit: zero reads outside enrolled roots), `neg_mark1ignore_honored` (ignored file appears in zero events, unindexed by cortexd), `unit_coverage_transitions_receipted` (FR-SPINE-026), `neg_report_refuses_below_floor` (FR-CLI-005: refusal, not a caveat), `unit_report_no_mixed_basis` (CON-014), `tailer_retention_gap` (F-16: gaps attributable, never silent) | `mark1d` + CLI negatives (colocated) | every PR |

Reading the matrix: rows 1–3, 5, 6, 10 are green-required at their phase gates per 02 §10 and stay required forever after; rows 7–8 activate with their phases but their *schemas'* negative tests (e.g. `neg_invariant_never_federates`) land with the migrations, not with the features — the constraint is tested the day the table exists.

---

## 10. Requirement → test traceability

This section fills `02` §11's `TBD-12` slots: at reconciliation, each `TBD-12 (...)` cell in 02's matrix is replaced by a pointer to the row below carrying the same requirement group. Grouping mirrors 02 §11 exactly so the two tables join by inspection. Category abbreviations: U unit, P property, C conformance, N negative, F fuzz, X chaos, B bench, M manual. Phase = the 02 §9 "holds by" phase after which the tests stay green permanently.

### 10.1 The matrix

| Requirement(s) | Tests (this doc's §) | Cat | Phase |
|---|---|---|---|
| CON-001, CON-002, NFR-SECURITY-001/-002/-005/-006 | `guard_no_forward_path`, `guard_contamination_killpath`, `canary_oauth_shape_classifier` + selftest, `unit_secret_type_no_debug`, `neg_core_dumps_suppressed`, `neg_tee_field_allowlist` (§9 rows 1–2) | N/C | 3 |
| CON-003, FR-AGENT-003, FR-CLI-004/-006 | `off_byte_equality` (F-46), `fragment_user_edit_refusal` (F-45), `conf_cli_doctor_diff`, `neg_vendor_binary_hash_identical` | C/N | 1 |
| CON-004, NFR-PRIVACY-001/-002/-005, FR-VERIFY-016 | `neg_wire_no_paths_no_excerpts`, `unit_evidencerecord_schema_closed`, `neg_digests_tenant_salted`, `neg_evidence_dir_never_uploaded`, `neg_e1_requires_redaction_receipt`, `neg_e2_outside_vpc_rejected` (§9 row 4) | N/U | 1 (E-tiers 4) |
| CON-005, NFR-OPERABILITY-002 | `ci_lockfile_no_otel` (cargo/go/uv lockfile scan), `conf_selfmetrics_ride_m1p` | N/C | 1 |
| CON-006, FR-VERIFY-020 | `unit_verdict_enum_diff` (proto/PG/Python against the four verdicts), `unit_infra_failure_maps_to_error`, `prop_fusion_posterior_valid` | U/P | 1 |
| CON-007, FR-POLICY-005/-006, NFR-AVAILABILITY-001…004 | `bundle_maxage_builtins`, 7-day fail-static soak, `chaos_no_spof_for_coding`, `chaos_proxy_kill_midstream`, `neg_gates_downgrade_only`, `chaos_daemon_crashloop`, supervision restart suite (§6) | X/N | 3 |
| CON-008, FR-SPINE-012/-025 | §9 row 3 in full; `unit_spill_ttl_receipted` (FR-SPINE-025) | N/P/U | 1 (spill 3) |
| CON-009, FR-POLICY-001…004/-010, FR-VERIFY-001 | `bundle_command_string_rejects`, `prop_bundle_no_command_decodes`, `fuzz_bundle_decode`, `prop_bundle_cbor_roundtrip`, `bundle_invalid_keeps_lkg` (F-27), `neg_bundle_wrong_section_key`, `conf_vectors_bundle_{rust,go}`, `neg_unconsented_anchor_never_runs` | N/P/F/C | 3 |
| CON-010, FR-SPINE-011, NFR-SECURITY-003, NFR-PRIVACY-004 | the §4 isolation suite, in full, as one required check | N/P | 1 |
| CON-011, FR-FED-001…007, NFR-PRIVACY-003 | §4.6 + §9 row 7 federation suite | N | 5 |
| CON-012, FR-SPINE-026, FR-CLI-002/-003/-005 | `neg_tailer_reads_inside_roots_only`, `neg_mark1ignore_honored`, `neg_capture_zero_from_unenabled_workspace`, `conf_cli_status_surface`, `neg_report_refuses_below_floor`, `unit_coverage_transitions_receipted` | N/C/U | 1 (report 4) |
| CON-013, FR-VERIFY-010 | `off_byte_equality`, `unit_disable_check_precedes_gate` (instrumented ordering), `prop_knee_caps_clamp_bundles` | C/U/P | 2 |
| CON-014, FR-CORTEX-008 | `unit_report_no_mixed_basis`, `unit_report_figures_carry_query_band_basis`, manual claim review per customer artifact | U/M | 4 |
| CON-015, FR-ENROLL-006 | `neg_pool_key_identity`, `neg_no_identity_failover_path`, `neg_fingerprint_mismatch_403` | N | 5 (guard arm 3) |
| FR-SPINE-001…003, FR-SPINE-023 | `unit_shim_stamps_uuidv7_seq`, `prop_uuidv7_burst_monotonic`, `conf_tailer_overcount_defeated`, `conf_m1p_schema_windows` (skip-and-retain + upgrade hint) | U/P/C | 1 |
| FR-SPINE-004…007, -024, NFR-DURABILITY-001…005, NFR-FOOTPRINT-002 | §2.1–2.2 property set, `fuzz_m1pl_frame`, `FuzzSpoolRecord`, `chaos_daemon_kill9`, `spool_billing_blocks_on_full`, `spool_disk_hardstop`, `spool_midfile_crc`, `unit_spool_ack_then_delete`, `fabric_symlink_refusal` (F-40), `loopback_host_origin` (F-39) | P/F/X/N | 1 |
| FR-SPINE-008…014 | `conf_ingest_roundtrip` (zstd protobuf batch, idempotent upsert, no gRPC port), `chaos_s3_outage_no_false_ack`, `uplink_park_requeue`, `uplink_4xx_quarantine`, `uplink_409_divergence`, `negative_envelope_tenant_spoof_rejected`, `conf_dedupe_three_layers` (duplicate injection per layer ⇒ one surviving row), `unit_ch_ddl_matches_adr` | C/X/N | 1 |
| FR-SPINE-015…020, NFR-CORRECTNESS-006 | §2.3 receipt property set, `conf_verifier_offline`, `conf_witness_hourly_head`, `test_append_only_receipts`, `unit_per_event_receipt_classes` (six classes and no seventh) | P/C/N/U | 1 |
| FR-SPINE-021/-022, NFR-CORRECTNESS-002 | `test_paper1_tvo_reconciliation`, `unit_taskopen_carries_seg_version`, `unit_unresolved_denominator_class`, `prop_waste_taxonomy_partitions`, `unit_no_shapley_symbol` | U/P | 1 |
| FR-VERIFY-001…005 | `neg_sandbox_probes`, `neg_unconsented_anchor_never_runs`, `neg_test_anchor_requires_sandbox`, `antitamper_path_shim` (F-32), `antitamper_worktree_suppression` (F-33), `anchor_integrity_incomplete` (F-34), `unit_anchorvote_six_integrity_fields` | N/U | 2 |
| FR-VERIFY-006…011 | `prop_fusion_*` + `prop_knee_*` (§2.6), `unit_gate_reads_cache_only` (zero anchor/network/fusion during gate — instrumented), `conf_fast_slow_split` (debounce + `REVISED` + next-turn correction), `conf_knee_ux_contract`, `anchor_error_not_violated` (F-31) | P/U/C | 2 |
| FR-VERIFY-012…019 | §8's adjudication battery + `neg_cert_below_threshold_uncertified`, `neg_gold_edge_indistinguishable` (behavior diff empty), `neg_cloud_judge_requires_consent_register_pin`, `unit_prior_deviation_routes_to_review` | U/N | 4 (Paper II repro 2) |
| FR-CORTEX-001…008, NFR-FOOTPRINT-003 | `prop_l0_merkle_content_sensitivity`, `prop_ppr_ranks_normalized`, `unit_l3_absence_degrades_rank_only`, `conf_map_budget_binary_search`, `neg_mcp_scope_traversal_refused`, `neg_cortexd_reads_scoped`, `unit_cortexinjection_emitted`, `unit_cache_key_5part_invalidation`, `cortex_shard_corrupt` (F-04) | P/U/N/X | 2 |
| FR-ROUTE-001…008 | `unit_routedecision_six_fields`, `neg_ope_fidelity_filter` (drops ADVISORY, joins CONFIG_STEERED), `neg_nonzero_epsilon_requires_optin`, `unit_knee_dual_basis`, `neg_rewrite_unreachable_without_guard` (call-graph + runtime), `unit_ladders_keep_prefix`, `ci_grep_routedecision_single_choicepoint`, `unit_policy_eval_allocation_free` | U/N | 3 (OPE arm 5) |
| FR-REMEMBER-001…008 | `unit_artifact_types_closed` (no free-text class), `neg_extraction_certified_only`, `test_admit_lcb_do_no_harm` + boundary fixtures, `conf_memory_delivery_contract` (TaskOpen pack, PostToolUseFailure reactive, `routing_hint` never injects), `unit_injection_outcome_events`, `neg_revoked_device_secret_delivery_refused`, `unit_single_vector_index`, `neg_memory_vector_search_scoped` | U/N/C | 4 |
| FR-LEARN-001…007 | `test_corpus_refuses_uncertified_labels`, `conf_dual_export_single_receipt` (Parquet + KTO pair, trainer loads unmodified), §9 row 8 training suite, `unit_corpusreader_api_diff` (constructor+method pair, no new trait), `conf_erasure_lineage_retrain` (toy corpus) | C/N/U | 5–6 |
| FR-AGENT-001…005 | `conf_adapter_fieldmap_bundle_push`, `adapter_version_sniff_drop`, `conf_hooks_*_replay` per pinned version, `conf_one_schema_all_agents` (two adapters, same families), fenced-provisioning byte-equality (§10.1 row 2) | C/N | 1–2 |
| FR-AGENT-010…016 | `conf_hooks_claudecode_*` + e2e replay (mark1d→controld→CH), overcount corpus; per-agent: spike go/no-go artifact **dispositioned before adapter code merges** (manual, checked by `ci_adapter_dir_requires_artifact` — the Crush arm asserts the directory stays empty) | C/M/N | 1–5 |
| FR-CLI-001…008 | `conf_cli_suite` (enroll/enable/status/doctor/report/off/verify-receipts against a test IdP + fixture estate), `unit_cli_exit_codes_exhaustive`, `neg_capture_zero_from_unenabled_workspace` | C/U/N | 1 (report 4) |
| FR-ENROLL-001…006 | `conf_oidc_device_code_flow`, `neg_token_expiry_rejected_parks_uploads`, `unit_keystore_custody_ladder` + `custody_floor` (F-42), `neg_revocation_effective_next_contact` + `identity_revoked_purge` (F-26) + `negative_revoked_token_60s_cutoff`, `unit_enroll_receipts`, `neg_fingerprint_mismatch_403` | C/N/U | 1 (fingerprint 3) |
| FR-POLICY-001…010 | §10.1 CON-009 row + `neg_policy_verification_triple` (missing sig/seq/proof ⇒ not applied), `conf_ack_gated_canarying`, `unit_publication_receipt_before_serve` (ordering), `neg_slsa_unverified_update_refused`, `bundle_skip_and_retain` (F-30), `chaos_tlog_outage_publication_halts` | N/C/U/X | 3 |
| FR-FED-001…007 | §4.6 suite + `unit_tenant_visible_epsilon_km` | N/U | 5 |
| NFR-LATENCY-001…005, NFR-FOOTPRINT-001 | `bench_proxy_latency_rss`, `bench_shim_dispatch`, `gate_timeout_allows`, `bench_policy_eval`, `unit_debounced_refresh_counter` | B/X/U | 2–3 |
| NFR-CORRECTNESS-001/-003/-004/-005 | `conf_tailer_overcount_defeated`, `conf_frames_<dialect>_golden`, `fuzz_m1pl_frame` + `FuzzSpoolRecord`, `conf_vectors_*` | C/F | 1–3 |
| NFR-PORTABILITY-001…004 | the 3-OS matrix itself (a red platform blocks merge), `conf_fabric_windows_named_pipes` (perms/framing/single-writer parity), `unit_shim_static_link_audit`, `unit_custody_degradation_visible` | C/U | 1 |
| NFR-OPERABILITY-001/-003/-004 | `chaos_loss_always_accounted` (induced shed/CRC/quarantine/version-drop each ⇒ matching `Dropped{}`, band reflects them), `unit_quarantine_visible_in_status`, `unit_boot_refusal_crashloops`, `unit_pool_exhaustion_503_retry_after` | X/U | 1 |
| NFR-SECURITY-004/-007/-008 | `ci_release_emits_slsa_sbom`, `cargo-deny`/`govulncheck` required checks (§11.3), `neg_local_perms_0600_everywhere`, `manual_pinned_dep_review` (token-path manifests) | C/N/M | 1 |

### 10.2 Machine-readable form

The table above is human-readable; the enforced artifact is `conformance/traceability.yaml`: one entry per requirement ID (all 181), each listing ≥1 test ID, its category, and its phase. Adopted LLD slugs carry a `source:` field (`04:F-20`, `05:§7.5`, `06:§13`) so the LLD → test contract is greppable both directions.

### 10.3 The CI check that fails when a requirement has no test

`tools/trace-check`, a required PR check, fails when:
1. any requirement ID present in 02 §9 is absent from `traceability.yaml` (parse 02's tables directly — the YAML cannot drift from the doc);
2. any mapped test ID is not found in the union of collected test names (`cargo test -- --list`, `go test -list '.*' ./...`, `pytest --collect-only -q`) — a renamed or deleted test orphans its requirement and turns CI red;
3. any test marked `phase: N` for a gate-listed requirement is not in the CI schedule lane its category demands (§1.3);
4. (once `10-security-threat-model.md` lands) any control ID in 10's matrix has no row in §9 above — the compliance-matrix completeness half, `compliance-matrix-check`.

Check 2 is the teeth: it is the mechanical form of §0.1's rule. A requirement whose test was quietly deleted does not degrade to "TBD" — it fails the build.

---

## 11. CI pipeline

### 11.1 Stages (PR pipeline)

```
stage 0  fast-fail lint (parallel per language)
         rust: cargo fmt --check · cargo clippy --all-targets -- -D warnings
         go:   gofmt -l · go vet · staticcheck
         py:   ruff check · ruff format --check
         proto: buf lint · buf breaking --against origin/main (WIRE_JSON)
         repo: gitleaks · hadolint · ci_grep gates (raw credential types,
               Shapley symbols, RouteDecision single-choicepoint, OTel imports)
stage 1  build (cargo build --locked · go build ./... · uv sync --locked)
         + supply chain: cargo-deny check · govulncheck ./... · pip-audit
stage 2  test (parallel):
         a. unit + property (fixed-seed) — 3-OS matrix
         b. conformance (fixtures + vectors) — 3-OS matrix
         c. isolation suite — Linux, real PG + CH + MinIO (§11.4), REQUIRED
         d. fuzz regression (60 s/target) — Linux
         e. chaos-fast (⚡ set) — Linux
         f. intelligence correctness (§8, PR scale) — Linux
stage 3  benchmarks — pinned runner only (§7.2)
stage 4  meta-gates: tools/trace-check · compliance-matrix-check ·
         skip-accounting assertion · coverage report (informational)
```

Estate conventions carried over exactly where they exist: the Rust gate set is the estate's (`fmt --check`, `clippy --all-targets -- -D warnings`, `build --locked`, `test --no-fail-fast`); Python is `python -m pytest tests -o asyncio_mode=auto` per service with flat `tests/`; Go is 1.25, `cmd/` + `internal/` layout. Images push `:sha7` only.

### 11.2 The three-OS matrix

macOS, Linux, Windows **from day one, on every PR** (NFR-PORTABILITY-001); a red platform blocks merge. Scope per OS: stages 0–2b run everywhere the code runs — edge components (mark1d, proxy, shim, cortexd, CLI, the Rust crates) on all three; cloud components (controld, adjudicator, intel) and store-backed suites on Linux only, because they deploy on Linux only. The Windows lane additionally runs `conf_fabric_windows_named_pipes` and the DACL/SID assertions (04 §11.1). Caching: `sccache`/`cargo` registry + target cache, Go build/module cache, `uv` cache, keyed per OS per lockfile hash; buf remote plugins pinned (estate convention) so codegen is reproducible.

### 11.3 Gates the estate lacks, added here

The estate's CI has gitleaks, trivy, hadolint, pip-audit — and **no `cargo-deny`, no `govulncheck`, no SBOM** (grounding delta 4). Since the plan promises SLSA-attested releases, `omium-mark1` carries its own:

| Gate | Tool | When | Blocking? |
|---|---|---|---|
| Rust dependency audit: advisories, licenses, bans, duplicate versions | `cargo-deny check` (config commits the allow-list; `mark1-hookshim` and `mark1-proxy` additionally have their whole resolved closures pinned to reviewed lists by `tools/ci/tokenpath_deps_gate.sh` per NFR-SECURITY-008 — *reconciled 2026-09-15: this row previously named `cargo vet`, which has never been configured in this tree; the closure gate is the control that exists*) | every PR | **blocks** |
| Go vulnerability scan | `govulncheck ./...` | every PR | **blocks** (call-graph-reachable findings; unreachable-in-binary findings report + 14-day fix window) |
| Python audit | `pip-audit` (estate-inherited) | every PR | **blocks** |
| SBOM | CycloneDX: `cargo cyclonedx` + `cyclonedx-gomod` + `cyclonedx-py`, merged per release artifact | release | **blocks release** (a release without an SBOM does not publish) |
| SLSA provenance | github attest / slsa-github-generator on every published artifact; edges verify per FR-POLICY-009 | release | **blocks release** |
| Proto governance | `buf lint` + `buf breaking` (WIRE_JSON) | every PR | **blocks** (FR-SPINE-002; this is also the estate's g1 gate shape, adopted) |
| Container scan | trivy (estate-inherited) | release | **blocks release** |

### 11.4 Postgres in CI — the decision

**Decision: real stores on every PR, provisioned as native binaries on the Linux runner — no Docker required, no testcontainers, and no skip-if-absent.** Mechanics: the isolation/integration job installs PostgreSQL 15 (apt; the GitHub Ubuntu runner ships it preinstalled), `clickhouse-server` (single static binary, official tarball, pinned version), and MinIO (single static binary) — starts all three as job-local processes, runs migrations via the `migrate-db.sh` pattern, exports the DSNs, and runs the suites with `M1_REQUIRE_STORES=1`, under which the estate's `skipif(no DSN)` idiom is **inverted**: a missing DSN is a hard error, and the job asserts zero skips in required suites (§0.3).

Justification, in order of weight:
1. The estate's env-DSN + `skipif` pattern exists because its CI has no Docker; the pattern's failure mode is that green can mean "skipped". Mark 1's centerpiece suites (§4) are exactly the ones that must never be skippable — the decorative-RLS incident was invisible precisely because nothing executed against a real Postgres with the real role. So the DSN idiom is kept (tests stay runnable on any dev machine with a DSN, Docker or not) but CI **always supplies the DSN** and forbids the skip.
2. All three stores install as plain binaries in <60 s with the runner cache warm; testcontainers/Docker would add a daemon dependency without adding fidelity, and would break if Mark 1's CI ever shares the estate's Docker-less runners. Native binaries are the portable lazy path.
3. Fidelity boundary stated honestly: CI's single-node PG is not multi-AZ RDS — `chaos_pg_failover_bounded_window` at full fidelity runs nightly against the compose profile and at phase gates against a staging RDS; the PR-lane version restarts the local primary, which exercises the reconnect/advisory-lock logic but not real failover timing. The PR lane proves logic; the nightly proves timing.

### 11.5 Blocking vs report-only — stated plainly

**Blocks a merge:** every stage-0 linter · `buf lint`/`buf breaking` · build on all three OSes · `cargo-deny`, `govulncheck`, `pip-audit` · unit, property (fixed-seed), conformance on the matrix · the isolation suite · fuzz regression · chaos-fast · §8 at PR scale · benchmarks on the pinned runner · `trace-check` · skip-accounting · the canary meta-test.
**Blocks a release (not each merge):** nightly full chaos green · nightly fuzz with no open findings in fail-closed components · SBOM + SLSA emission · trivy · mutation floor on load-bearing crates (§13) · weekly canary green.
**Report-only:** coverage percentages · cross-OS benchmark numbers · bench trend drift (<10%) · mutation scores outside the load-bearing set. Report-only is a stage, not a destiny: any report-only signal can be promoted to blocking by a PR against this section, and §13's floors name the ones already scheduled for promotion.

### 11.6 Wall-clock budget

PR pipeline ≤ **20 minutes** end to end (parallelism assumed: stages 2a–2f fan out; the long pole is the 3-OS conformance lane at ~12 min). The budget is enforced socially, not mechanically, with one mechanical backstop: a PR pipeline exceeding 30 min pages the owner of the slowest job, because a slow gate is a gate people learn to route around — the estate's excluded-tests failure began as a slow-tests problem. Nightly ≤ 4 h; weekly lanes unbounded.

---

## 12. Per-phase gate checklists

Each phase's bold **Gate:** sentence from the frozen plan, reproduced verbatim, then decomposed into the tests that must be green. Every item is traceable to 02 (requirement IDs in parentheses; the full ID→test binding is §10). A gate passes when its list passes — 02 §10's rule, made concrete.

### Phase 1 — Spine + subscription-legal capture

> **Gate: end-to-end certified usage events, verifiable offline by the customer.**

1. `conf_hooks_claudecode_*_replay` + e2e fixture replay through `mark1d` → `controld` → ClickHouse (FR-AGENT-004/-010)
2. `conf_tailer_overcount_defeated` — exactly one `Usage` per `(message.id, requestId)` on the overcount corpus (FR-SPINE-003, NFR-CORRECTNESS-001)
3. `test_paper1_tvo_reconciliation` (FR-SPINE-022, NFR-CORRECTNESS-002)
4. `conf_verifier_offline` — full chain + witness heads validated with every Omium endpoint blackholed (FR-SPINE-020, FR-CLI-007)
5. §2.3 receipt property set + `test_append_only_receipts` + `conf_witness_hourly_head` (FR-SPINE-015…019)
6. `fuzz_m1pl_frame` + `FuzzSpoolRecord` regression green (NFR-CORRECTNESS-004)
7. `chaos_daemon_kill9` + `spool_billing_blocks_on_full` + `chaos_s3_outage_no_false_ack` — billing-grade zero-loss (FR-SPINE-024, NFR-DURABILITY-001…003)
8. §4.1–4.5 isolation suite required-check green, including `test_app_role_nobypassrls` and `neg_bypassrls_role_connection_refused` (CON-010, NFR-SECURITY-003)
9. `redact_substitution_pre_spool` + `neg_no_plaintext_persistence_path` + ingest quarantine arm (CON-008, FR-SPINE-012)
10. `off_byte_equality` + fenced-provisioning byte-equality + `neg_vendor_binary_hash_identical` (CON-003, FR-CLI-006)
11. `neg_wire_no_paths_no_excerpts` + `unit_evidencerecord_schema_closed` + `neg_digests_tenant_salted` (CON-004, NFR-PRIVACY-001/-002)
12. `ci_lockfile_no_otel` (CON-005) · `unit_verdict_enum_diff` (CON-006) · `unit_no_shapley_symbol` (FR-SPINE-022)
13. 3-OS matrix green incl. `conf_fabric_windows_named_pipes` (NFR-PORTABILITY-001/-002); `cargo-deny`/`govulncheck`/SBOM gates live (NFR-SECURITY-004)
14. `chaos_loss_always_accounted` (NFR-OPERABILITY-001); `conf_cli_suite` Phase-1 arms; enrollment suite incl. `negative_revoked_token_60s_cutoff` (FR-ENROLL-001…004)
15. Non-test preconditions carried from 02 §10: ADR-0001 + ADR-0002 signed; ≥1-week dogfood run producing the first real TVO report; Codex/Gemini/Copilot spike artifacts dispositioned (gating adapter *slots*, not this phase).

### Phase 2 — VERIFY provisional loop + Cortex push

> **Gate: retry loops demonstrably arrested at the knee on live sessions; Cortex uplift measurable in the ledger.**

1. `prop_fusion_logspace_equals_direct` + golden fusion vectors (FR-VERIFY-006)
2. `unit_gate_reads_cache_only` — zero anchor/network/fusion work during gate evaluation (FR-VERIFY-007)
3. `prop_knee_decision_matches_inequality` under both cost bases + `conf_knee_ux_contract` (FR-VERIFY-009/-011)
4. `prop_knee_caps_clamp_bundles` + `unit_disable_check_precedes_gate` (FR-VERIFY-010, CON-013)
5. Anti-tamper triad: `antitamper_path_shim`, `antitamper_worktree_suppression`, mutated-worktree arm — each independently raises `tamper` (FR-VERIFY-004/-005)
6. `neg_sandbox_probes` + `neg_unconsented_anchor_never_runs` + `neg_test_anchor_requires_sandbox` + `anchor_error_not_violated` (FR-VERIFY-001…003, CON-009 catalog half)
7. Cortex: `prop_l0_merkle_content_sensitivity` (shared root, FR-CORTEX-001), L1/L2-required/L3-opportunistic units, `conf_map_budget_binary_search`, `neg_mcp_scope_traversal_refused`, `neg_cortexd_reads_scoped`, `unit_cortexinjection_emitted` (FR-CORTEX-002…006)
8. `test_paper2_posterior_table_reproduced` (FR-VERIFY-018) + `prop_fusion_posterior_valid`/stage-shape validation (FR-VERIFY-020)
9. `bench_shim_dispatch` + `gate_timeout_allows` + `chaos_no_spof_for_coding` (NFR-LATENCY-002/-003, NFR-AVAILABILITY-001)
10. `conf_hooks_codex_*` live if the spike dispositioned "go" (FR-AGENT-011); `conf_one_schema_all_agents` (FR-AGENT-005); `conf_cli_doctor_diff` (FR-CLI-004); `neg_evidence_dir_never_uploaded` (NFR-PRIVACY-005)
11. Evidence artifact: the A/B on our own tasks with/without the stop-gate — iteration-count delta with confidence intervals; cortex uplift as a ledger query (FR-CORTEX-008 methodology).

### Phase 3 — Wire proxy + ROUTE

> **Gate: zero client-visible streaming regressions under chaos; guard canary green.**

1. `chaos_proxy_stream_suite` in full — stall, reset, slow client, TLS-mid-body, kill-midstream, tee saturation — zero client-visible regression vs control (NFR-AVAILABILITY-002, CON-007)
2. `conf_frames_<dialect>_golden` byte-exact for every shipped dialect (NFR-CORRECTNESS-003)
3. `guard_no_forward_path` + `guard_contamination_killpath` + `canary_oauth_shape_classifier` + `canary_selftest_detects_planted_miss` (CON-001, NFR-SECURITY-005/-006)
4. `unit_secret_type_no_debug` + `neg_tee_field_allowlist` + `neg_core_dumps_suppressed` + `neg_gateway_zero_credential_bytes_on_disk` (CON-002, NFR-SECURITY-001/-002)
5. `bench_proxy_latency_rss` ≤ 1 ms / ≤ 35 MB (NFR-LATENCY-001, NFR-FOOTPRINT-001); `bench_policy_eval` (NFR-LATENCY-004)
6. Bundle plane: `prop_bundle_cbor_roundtrip` + `bundle_command_string_rejects` + `fuzz_bundle_decode` + `neg_policy_verification_triple` + `bundle_invalid_keeps_lkg` + `bundle_maxage_builtins` + `neg_gates_downgrade_only` + `conf_ack_gated_canarying` + `unit_publication_receipt_before_serve` + `conf_vectors_bundle_{rust,go}` (FR-POLICY-001…008/-010, CON-009 decode half)
7. Route: `unit_routedecision_six_fields` from the first routed request + `neg_nonzero_epsilon_requires_optin` + `unit_knee_dual_basis` + `neg_rewrite_unreachable_without_guard` (FR-ROUTE-001/-003/-004/-005)
8. `chaos_tlog_outage_publication_halts` + 7-day fail-static soak (NFR-AVAILABILITY-003) + `chaos_kms_throttle_tenant_isolated`
9. `neg_fingerprint_mismatch_403` (FR-ENROLL-006); `unit_spill_ttl_receipted` (FR-SPINE-025); `conf_hooks_gemini_*` live if spike "go" (FR-AGENT-012).

### Phase 4 — Adjudication at strength + REMEMBER

> **Gate: first noise-certified customer report with a coverage band.**

1. `test_spectral_ds_recovers_planted_matrices` + `test_identifiability_gate_degrades_honestly` (FR-VERIFY-012)
2. `neg_cert_below_threshold_uncertified` + `test_cert_state_machine_transitions` (FR-VERIFY-013)
3. `neg_gold_edge_indistinguishable` (FR-VERIFY-014) + `unit_prior_deviation_routes_to_review` (FR-VERIFY-019)
4. `neg_cloud_judge_requires_consent_register_pin` + client-side-default verification (FR-VERIFY-015, NFR-PRIVACY-006) + evidence-tier type gates (FR-VERIFY-016) + `test_judge_garbage_quarantine_path` (06 §13)
5. Memory: `unit_artifact_types_closed`, `neg_extraction_certified_only`, `test_admit_lcb_do_no_harm`, `test_admit_lcb_rejects_stale_cert_samples`, `conf_memory_delivery_contract`, `unit_injection_outcome_events`, `neg_revoked_device_secret_delivery_refused`, `neg_memory_vector_search_scoped` (FR-REMEMBER-001…005/-007/-008)
6. `neg_report_refuses_below_floor` + `unit_report_no_mixed_basis` + `unit_report_figures_carry_query_band_basis` (FR-CLI-005, CON-014)
7. opencode spike dispositioned; adapter conformance live on "go" (FR-AGENT-013)
8. The artifact itself: a generated report with noise-certified verdicts under an active certificate, coverage band ≥ floor, cost basis stated — each figure carrying its ledger query ref.

### Phase 5 — Enterprise + federation + LEARN

> **Gate: first cross-org artifact published through the full k,m∩ / DP / LCB / review pipeline.**

1. `neg_km_direct_sql_bypass` — the `HAVING`/trigger holds against raw SQL (FR-FED-003, CON-011)
2. `neg_span_below_m_never_publishes` (m−1 reconstruction test, FR-FED-002) + k−1/affiliated-collapse arm (FR-FED-001)
3. `neg_invariant_never_federates` (FR-FED-004) · `neg_release_requires_ledger_debit` + `negative_epsilon_exhaustion_refuses` (FR-FED-005, NFR-PRIVACY-003) · `neg_unreviewed_never_publishes` + `neg_optout_spans_absent` (FR-FED-006)
4. `test_corpus_refuses_uncertified_labels` + `conf_dual_export_single_receipt` + `unit_corpusreader_api_diff` + `test_mark1_row_roundtrip_preserves_completion` (FR-LEARN-001/-002/-006)
5. `neg_ope_fidelity_filter` (FR-ROUTE-002) + `test_ope_estimators_synthetic_ground_truth`
6. Gateway scope: `neg_pool_key_identity` + `neg_no_identity_failover_path` (CON-015); Copilot/Cursor spikes dispositioned, GitHub-billed-never-wire negative live (FR-AGENT-014/-015)
7. The artifact itself: the published cross-org artifact carrying its full receipt trail — (k,m) evidence, DP debit, LCB admission record, review sign-off.

### Phase 6 — Learned members + certified tier + self-host

> *(The frozen plan states no bold **Gate:** sentence for Phase 6 — the only phase without one. The checklist below uses the gate `02` §10 derived — "first learned component promoted to `active` through probation → shadow → LCB → canary, with cross-tenant training and T3 runs opt-in-gated" — and is marked **derived, not plan-verbatim**; 02 requires the derivation confirmed at reconciliation and recorded in `14-delivery-plan.md`.)*

1. `test_promotion_pipeline_state_machine` — no path to `active` without shadow votes + LCB + canary records (FR-LEARN-004)
2. `test_ope_ess_floor_blocks_promotion` + router promotion bar: candidate ≤ incumbent on held-out DR/SNIPS is not canaried (FR-LEARN-005)
3. `neg_cross_tenant_training_requires_receipted_optin` + `neg_dpsgd_debits_epsilon` + `test_canary_memorization_blocks_leaky_checkpoint` (FR-LEARN-003)
4. `conf_erasure_lineage_retrain` on a toy corpus (FR-LEARN-007)
5. Trigger discipline (manual checks recorded in the delivery plan): NATS/MSK evaluated only when a second independent ledger consumer exists (grounding delta 3 ADR); T3 opt-in only; self-host SKU behind its own gate.

---

## 13. Quality bar and coverage policy

### 13.1 What is measured

Line + branch coverage per component: `cargo llvm-cov` (Rust), `go test -coverprofile` with per-package reporting (Go), `coverage.py` branch mode (Python). Published per PR as a report; stored per main commit for trend.

### 13.2 Floors

| Scope | Floor | Enforcement |
|---|---|---|
| Load-bearing set: `m1p-wire`, `mark1-receipt`, `mark1-redact`, `mark1-policy`, `mark1d/internal/{spool,verdict,capture}`, `controld/{ingest,querychoke}`, `rust/verifier` | **90% branch** | blocks merge |
| Everything else | **75% line** per component | report-only until Phase 2, then blocks (the ratchet is dated, not aspirational) |
| Ratchet rule | coverage of a load-bearing component may never drop >1pp in a PR | blocks merge |

### 13.3 Why a raw percentage is a weak signal, and what is used instead

A percentage counts execution, not assertion: a test that calls everything and asserts nothing scores 100%. The estate is the proof by contradiction in the other direction — its problem was never a subtle assertion gap; it was that the tests that existed did not run. Both failure modes are invisible to a coverage number. The stronger signals, all mechanical:

1. **Mutation testing on the load-bearing set** — `cargo-mutants` (Rust) and `go-mutesting` (Go), nightly. Floor: **≥ 80% mutants killed** on the load-bearing set; below floor blocks *release*, and per §11.5 is scheduled for promotion to merge-blocking once the baseline stabilizes (target: Phase 2). A surviving mutant in `mark1-redact`'s admit axis or the querychoke predicate builder is triaged as a missing negative test, same-week.
2. **The traceability check** (§10.3) — every requirement has a live, collected, scheduled test. This is the signal coverage pretends to be: not "was this line executed" but "can this claim fail".
3. **The compliance-matrix completeness check** (§9, §10.3 check 4) — every control in 10 has a proving test here. A control with no row is a documentation bug and CI treats it as one.
4. **Skip accounting** (§0.3) — green means ran-and-passed, never didn't-run.

### 13.4 Flake policy

A **flake** is a test with ≥2 unexplained pass/fail flips within 7 days on unchanged code (tracked automatically from CI history).

- **Quarantine, never deletion, never retry-loops:** a confirmed flake is moved to the quarantine lane by PR — the test gains a `quarantined(issue=#N, expires=YYYY-MM-DD)` marker, runs non-blocking, and its issue carries the flip history. Silent `@retry` decorators and unmarked re-runs are banned; the §7.2 benchmark protocol's single structured re-run is the only sanctioned retry in the pipeline.
- **Deadline: 14 days.** On expiry, CI fails **repo-wide** until the test is either fixed (returns to blocking) or its requirement mapping is renegotiated in 02 (in which case deleting the test is a requirements change, reviewed as one — §10.3 check 1 enforces that it cannot simply vanish). Quarantine with no deadline is how a required suite decays into the estate's excluded directory; the expiry makes decay louder than fixing.
- **Gate-listed tests cannot be quarantined** (§12's checklists, the isolation suite, the canary meta-test): a flake there is a P1 outage of the quality system itself, fixed forward, because a gate that can be waived is not a gate.
- **Budget:** > 3 tests in quarantine simultaneously freezes feature merges on the owning component until the queue drains — flakiness is treated as debt with a credit limit.

### 13.5 The bar, restated

Mark 1's quality system is four interlocking checks — no exclusions (§0.3), no skips (§0.3), no unmapped requirements (§10.3), no untested controls (§9) — with coverage and mutation as instrumentation on top. The estate's lesson is encoded in the structure rather than in a number: every mechanism above turns "we forgot to test it" or "the test quietly stopped running" into a red build the same day, which is the only deadline that has ever worked.

---

*End of 12 — Testing, Conformance and Quality Gates. Requirements and acceptance criteria: `02`. Failure catalogs whose test slugs this document adopts: `04` §10, `05` §7.5/§9, `06` §13. Control matrix counterpart: `10`. CI/scaffold mechanics: `13`. Phase milestones: `14`.*
