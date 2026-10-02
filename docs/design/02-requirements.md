# 02 — Requirements

**Status:** Authored 2026-08-28 against the frozen execution plan (`docs/spec/execution-plan-v2.md`) and the authoritative architecture spec v2.0 (`docs/spec/architecture-spec.md`). Where this document and either of those disagree, they win.
**Audience:** anyone defining, building, or accepting scope. Glossary terms are used exactly as defined in `01-introduction.md` §9 and are never redefined here.
**Function:** this document converts the plan's six bold **Gate:** sentences into checkable criteria. Section 9 (the acceptance criteria table) is its centre of gravity; section 10 maps each phase gate to the requirement IDs that must all be green.

---

## 1. How to read this doc

### 1.1 ID scheme

| Prefix | Meaning | Namespace |
|---|---|---|
| `CON-NNN` | Hard constraint — legal, ToS, or structural invariant. Violation is a product-killing event, not a bug. | flat, three digits |
| `FR-<PLANE>-NNN` | Functional requirement. `<PLANE>` ∈ `SPINE, VERIFY, CORTEX, ROUTE, REMEMBER, LEARN, AGENT, CLI, ENROLL, POLICY, FED` | per plane |
| `NFR-<CLASS>-NNN` | Non-functional requirement. `<CLASS>` ∈ `LATENCY, FOOTPRINT, DURABILITY, AVAILABILITY, CORRECTNESS, PRIVACY, PORTABILITY, OPERABILITY, SECURITY` | per class |

IDs are permanent. A retired requirement keeps its ID marked `RETIRED`; IDs are never reused.

### 1.2 Priority

| Priority | Definition |
|---|---|
| **P0** | A phase gate (section 10) depends on it. The phase does not pass while this requirement is red. |
| **P1** | Required for the phase's output to be sellable, operable, or defensible, but not named by a gate sentence. |
| **P2** | Scheduled within a phase but deferrable inside it without moving a gate. |

### 1.3 The acceptance rule

Every requirement in this document carries an acceptance criterion **that a test can fail** (section 9, one row per requirement). A requirement whose criterion cannot fail is not a requirement and must not be added. Verification methods are drawn from a fixed set: `unit`, `conformance`, `fuzz`, `chaos`, `negative`, `manual`.

### 1.4 Vocabulary discipline

Normative statements use **must** and **must not** exclusively. The words "should", "appropriate", "robust", and "as needed" are banned from this document: each is an undischarged decision hiding in prose. Where the frozen plan or the spec fixes a number, that number appears here verbatim; where it does not, the requirement names the ADR that fixes it (section 12).

Verdict vocabulary is exactly `satisfied | violated | refused | error` everywhere, without exception (CON-006). Failure postures are exactly the normative matrix: **fail-open** for availability, **fail-static** for policy, **fail-closed** for legality and secrets (CON-007).

---

## 2. CON-* — hard constraints

Legal/ToS constraints first (CON-001…CON-005), then the in-code enforcement obligations. Each of the frozen plan's seven "Compliance enforcement — in code, not policy" points is covered by at least one CON; the mapping is the **Plan pt.** column. Every CON states the consequence of violating it and names the mechanism that enforces it — a CON without a mechanism is policy, and policy is not a control.

| ID | P | Constraint | Plan pt. | Consequence of violation | Enforcement mechanism |
|---|---|---|---|---|---|
| CON-001 | P0 | Mark 1 **must never** intercept, proxy, or route Anthropic subscription (OAuth) traffic. `mark1-proxy` **must** forward only a credential `mark1d` provisioned after `Detect()==apikey`, HMAC-fingerprint-matched to enrollment — named either by an `M1-Cred-Ref` header or, for agents with no custom-header surface, by the fingerprint of the credential itself after the shape gate (D-EI, 2026-09-16); unknown credential ⇒ 403. **No override path may exist in the shipped binary.** | 1 | Anthropic ToS violation with the customer's account as collateral; takedown precedent exists (2025-04); the product's legality-by-structure moat is destroyed | Provenance guard (primary); shape-inspection tripwire (secondary); upstream subscription-marker ⇒ session kill + config rollback + receipted `oauth_contamination` P0; weekly token-shape canary fails CI on classifier miss; sampled guard decisions receipted |
| CON-002 | P0 | Mark 1 **must not** collect, store, forward, or refresh any vendor credential or session token. Gateway credentials **must** be referenced from the customer's secret manager per request and never persisted. | 2 | Credential intermediation = explicit ToS breach; a leaked credential is an unbounded customer-side incident | `Secret<T>` newtype with no Debug/Display/Serialize (compile-time) + zeroize-on-drop; CI grep gate; tee built from an explicit field allow-list, never a request clone; `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`; by-reference fetch in gateway mode |
| CON-003 | P0 | Mark 1 **must not** modify any vendor binary. Integration surfaces are exactly: hooks, MCP, config includes/extensions, transcripts, and (API-key regime only) the wire. Config provisioning **must** use fenced, checksummed fragments in files Mark 1 does not exclusively own. | 1 | ToS breach; silent breakage of the customer's agent on vendor update; unfalsifiable "what did you change" audit posture | Fenced-fragment provisioner; `mark1 doctor` shows every provisioned line; `mark1 off` verified by byte-equality snapshot of agent config and behavior |
| CON-004 | P0 | Raw sessions, repository contents, and evidence **must** stay client-side by default. The default wire evidence type (`EvidenceRecord`) **must** be structurally unable to carry paths or free-text excerpts. Excerpt classes are per-tenant opt-in, structurally scrubbed, receipted per upload. | — (spec §9.4) | Code exfiltration; every enterprise security review fails; the §5.3 persona's ten minutes end the deal | Typed `EvidenceRecord` schema (no path/excerpt fields exist); E0/E1/E2 tier gating; per-tenant HMAC-salted digests; raw evidence held under `~/.omium/mark1/evidence/`, never uploaded by default |
| CON-005 | P0 | Mark 1 **must not** depend on OpenTelemetry anywhere — schema, transport, edge, cloud, or self-monitoring. All telemetry rides M1P (ADR-0005). | — (plan directive) | Reintroduces the rejected v1 stack; forks the capture fabric; violates the founder directive that froze the plan | Dependency-manifest CI gate (cargo/go/uv lockfile scan) failing on any OTel package; doc-set review gate ("no document references OpenTelemetry as a dependency") |
| CON-006 | P0 | Verdict vocabulary **must** be exactly `satisfied \| violated \| refused \| error` in every schema, enum, API, and report. Infrastructure failure **must** map to `error`, never `violated`. | — (spec reuse) | Conflating infrastructure failure with `violated` incurs provably unavoidable excess risk (Paper II Thm 5.2); vocabulary drift breaks the platform-enum reuse and every downstream join | PG enum adopted verbatim from platform migration `008`; proto enum in `m1p.v1`; conformance vectors shared across Rust/Go/Python decoders |
| CON-007 | P0 | The failure-posture matrix is normative: **fail-open** for availability (capture, hooks), **fail-static** for policy (bundles), **fail-closed** for legality and secrets (OAuth guard, upload admission, revocation). Every component's failure modes **must** be classified into exactly one posture. | — (plan §Deployment) | A miswired posture is either a customer outage (closed where open belongs) or a legal/leak incident (open where closed belongs) | Posture column mandatory in every LLD failure-mode table (04/05/06); chaos suite exercises each posture; bundle `gates` section may downgrade closed→open only, and fail-closed gating requires local on-disk tenant opt-in |
| CON-008 | P0 | Redaction's **admit-to-upload** axis **must** be fail-closed with **no off switch**. Flagged spans **must** become `⟨redacted:class:hash⟩` in every derived artifact before spool admission. No pre-redaction plaintext persistence may exist anywhere. `controld.ingest` **must** run an independent second ruleset and quarantine on a high-confidence hit. | 3 | Customer secrets land in Omium's stores; the corpus — the moat — is contaminated and unerasable | `mark1-redact` linked by both proxy and hookshim (even emergency spill is sanitized); spill files 0600, device-key-encrypted, ≤24 h TTL, receipted expiry; pre-egress scanner at ingest with quarantine + tenant alert; negative test proving no plaintext-persistence code path |
| CON-009 | P0 | Bundles **must not** name commands or carry code: any command string **must** fail decode; no `wasm_module` field exists in `m1p.v1` or PolicyBundle v1. Anchors are enabled by local-catalog ID only, from a locally derived, user-consented catalog, re-consented on change, visible in `mark1 doctor`. Anchor execution **must** be network-denied, env-scrubbed to an allow-list, read-only outside the worktree, resource-capped, and kill-switched. | 4 | Bundle channel becomes fleet RCE — the single worst security outcome the design deletes rather than mitigates | Decode-time rejection in `mark1-policy` (both Rust and Go decoders); schema has no field to carry code; sandbox as a security boundary; consent state on disk; `mark1 doctor` visibility |
| CON-010 | P0 | Tenant identity **must** be stamped server-side from verified token claims, never trusted from the envelope; envelope disagreement ⇒ reject + security event. ClickHouse **must** be reachable only through `controld.query-choke`, whose builder provably appends the tenant predicate to every generated query. Postgres uses platform RLS conventions with `*_app` NOBYPASSRLS roles; S3 uses per-tenant prefixes and per-tenant KMS keys. | 5 | Cross-tenant data exposure — a repeat of the estate's decorative-RLS failure, this time on customer code telemetry | Token-stamping in ingest; single-principal chokepoint; tenant-isolation negative tests on every PR across Postgres, ClickHouse, the memory API, and S3 prefixes; CI negative test for BYPASSRLS roles |
| CON-011 | P0 | Federation publication **must** enforce the (k,m)-intersection gate structurally: ≥k (25) contributors, bodies intersection-reconstructed from spans ≥m (5) billing/domain-verified organizations independently produced, with collusion collapse; `invariant` artifacts excluded by schema; all cross-tenant numbers pass the DP release layer debiting the ε ledger. | 6 | One tenant's proprietary span published to all tenants — an unerasable privacy incident in the flywheel's shared pool | `HAVING` clause + trigger constraint in Postgres; intersection reconstruction (a span no m tenants produced cannot publish); schema-level `invariant` exclusion; DP release layer + per-tenant ε ledger; human review queue |
| CON-012 | P0 | Tailers **must** operate only inside `mark1 enable`d workspaces; `.mark1ignore` honored; nothing outside enrolled roots is read. `mark1 status` **must** show the live read surface. Every enable/disable/bypass window **must** emit a receipted `CoverageTransition`. Guarantee-grade TVO reports **must** be refused — not caveated — below the coverage floor. | 7 | Unconsented reading = trust collapse with the security-reviewer persona; unattributable coverage gaps make every TVO number contestable | Workspace allow-list in `mark1d`; `.mark1ignore` in all tailers and cortexd; `CoverageTransition` per-event receipts; report generator's coverage-floor refusal path |
| CON-013 | P0 | `mark1 off` and `MARK1_DISABLE=1` **must** be uncircumventable and **must** be checked before any gate evaluation. Off **must** restore the agent's configuration to byte-equality. | 4 (gate DoS caps) / 7 | A gate that cannot be turned off is a denial-of-service on the customer's ability to code; UX blowback kills dev-machine adoption | Check ordered before gate evaluation in `mark1d` (unit-tested ordering); byte-equality snapshot test; off windows receipted as `CoverageTransition` |
| CON-014 | P1 | Every number in a customer-facing artifact **must** trace to a ledger query and **must** carry its coverage band and cost basis; the two cost bases **must never** be averaged together. The integrated end-to-end TVO-reduction number **must not** be quoted before the ledger produces it. | — (plan §Verification) | Claim-discipline breach — diligence death, and a fabricated number in a sales artifact | Report generator emits query + band + basis on every figure; claim tables in 01 §8 are normative; `manual` review gate on customer artifacts |
| CON-015 | P1 | Mark 1 **must not** resell usage, multiplex identities, pool keys, or mask identity. Gateway connection pools **must** be keyed `(upstream, credential-identity)`. | 2 | Violates OpenAI/Google/GitHub terms simultaneously; converts the proxy into exactly the gray-area gateway the non-goals forbid | Pool keying by construction; no failover/multiplexing code path; negative test that a second identity never reuses a pool |

The plan's seven compliance points map: pt.1 → CON-001, CON-003; pt.2 → CON-002, CON-015; pt.3 → CON-008; pt.4 → CON-009, CON-013; pt.5 → CON-010; pt.6 → CON-011; pt.7 → CON-012.

---

## 3. FR-SPINE-* — capture fabric, spool, uploader, ingest, ledger, receipts, witness, verifier

The spine is the TVO Ledger and everything an event crosses to reach it. Ownership: `m1p-wire` (framing/codegen), `mark1d` (spool, uploader), `controld.ingest`, Postgres/ClickHouse/S3, `mark1-receipt` + `python/shared/mark1_receipts`, `rust/verifier`.

| ID | P | Requirement |
|---|---|---|
| FR-SPINE-001 | P0 | Every M1P event **must** carry a UUIDv7 `event_id` (RFC 9562 Method-1 counter per daemon), a per-session monotonic `seq`, and the `session_epoch` that qualifies it. Causal order within a session **must** be read as the lexicographic pair `(session_epoch, seq)` and never as `seq` alone — `seq` lives in `mark1d`'s memory and restarts at 1 on daemon reboot, so `(session_id, seq)` is not unique across a restart while `(session_id, session_epoch, seq)` is. `event_id` **must** serve simultaneously as server dedupe key, ClickHouse ordering component, spool cursor, and receipt-checkpoint leaf. |
| FR-SPINE-002 | P0 | The schema **must** be `m1p.v1` protobuf, Buf-governed: `buf breaking` at WIRE_JSON in CI, deleted fields `reserved`, breaking change ⇒ new package `m1p.v2`, never in place. One proto source **must** generate prost, protoc-gen-go, and betterproto outputs. |
| FR-SPINE-003 | P0 | `Usage` events **must** carry `idem_key = HMAC_tenant(session_id, message.id, request_id)` with the sidechain rule baked in as a protocol invariant. Dedupe **must** defeat the verified ~2.5× streaming overcount (see NFR-CORRECTNESS-001). |
| FR-SPINE-004 | P0 | The local fabric **must** be UDS (named pipe on Windows) with M1PL framing `magic 'M1PL' \| u8 ver \| u32 len(bounded) \| payload`, socket perms 0600. Writers (hookshim, proxy, cortexd, tailers) **must** frame final `m1p.v1` events to `mark1d`, the **only** spool writer. |
| FR-SPINE-005 | P0 | Where an agent cannot exec the shim, the loopback listener **must** require a per-session bearer token (0600 file), literal-loopback Host validation, and Origin rejection. No unauthenticated localhost-HTTP fallback may exist. |
| FR-SPINE-006 | P0 | The spool **must** use 64 MiB append-only segments, record layout `len(bounded)\|crc32c\|record_id\|payload` with the leading 16 bytes = `event_id`; mmap'd ledger; fsync every 250–500 ms; mandatory drain on `SessionEnd`/shutdown; whole-file ack-then-delete; ~2 GiB cap with a 95%-disk hard stop. |
| FR-SPINE-007 | P0 | Spool per-class policy: `usage`/`verdict`/`receipt-checkpoint` classes **must** block on full (billing-grade); diagnostics **must** drop-newest; every shed, CRC loss, or quarantine **must** emit `Dropped{reason, durability_class, quantity}` in the next batch. |
| FR-SPINE-008 | P0 | The uploader **must** POST `/m1p/v1/ingest` as `application/x-m1p-protobuf` + zstd with a bearer device token, at-least-once with server idempotent upsert. Plain HTTPS only; gRPC **must not** be used to the edge. |
| FR-SPINE-009 | P0 | Upload retry **must** fire on network/5xx/429 only, exponential backoff + full jitter (base 6 s, cap 30 min, ~10 attempts) then park; 4xx ⇒ quarantine-and-report. |
| FR-SPINE-010 | P0 | Ingest **must** be S3-first: the batch is acked only after the object lands. The S3 object stream is the replay log. |
| FR-SPINE-011 | P0 | Ingest **must** stamp `tenant_id`/`device_id` from verified token claims; envelope disagreement ⇒ reject + security event (CON-010). |
| FR-SPINE-012 | P0 | Ingest **must** run a pre-egress secret scanner with a ruleset independent from the edge scanner; a high-confidence hit quarantines the batch and alerts the tenant (CON-008). |
| FR-SPINE-013 | P0 | The ClickHouse ledger **must** use `async_insert=1, wait_for_async_insert=1` and `ReplacingMergeTree` on `event_id` with the ordering key fixed by ADR-0001. **No production write may occur before ADR-0001 is signed.** |
| FR-SPINE-014 | P0 | Dedupe **must** be one key across three layers: transcript `(message.id, requestId)` at the edge → `event_id` idempotent upsert at ingest → ClickHouse replacing-merge. |
| FR-SPINE-015 | P0 | Receipts **must** use the checkpoint model: batch N events / T seconds → Merkle root → chained, dual-signed receipt; every event **must** carry `checkpoint_seq + inclusion_path`. |
| FR-SPINE-016 | P0 | Per-event receipts **must** be issued for exactly: noise certificates, memory admissions, bundle publications, corpus exports, coverage transitions, and guard contamination events — and for nothing else by default. |
| FR-SPINE-017 | P0 | The receipt chain **must** live in Postgres with a per-tenant gap-free sequence, `key_id` + rotation columns, and append-only enforcement (trigger + REVOKE, per the vendored `ro_012` template extended with `checkpoint_seq`, `inclusion_path`, and the server countersignature). Domain prefix **must** be `mark1-label-v1\0`. |
| FR-SPINE-018 | P0 | Every receipt **must** be dual-signed: device origin signature + server countersignature, both Ed25519, `key_id`'d, with rotation cross-signed per ADR-0004. |
| FR-SPINE-019 | P0 | Per-tenant chain heads **must** be witnessed externally hourly — transparency log and/or customer-controlled object-lock bucket. |
| FR-SPINE-020 | P0 | A standalone open-source verifier **must** validate the chain, checkpoints, inclusion paths, and witness heads offline, with every Omium server unreachable. It ships in Phase 1. |
| FR-SPINE-021 | P0 | Every `TaskOpen` **must** carry `task_seg_version`; segmentation follows `task_seg.v1` (ADR-0002); session-end-without-verdict **must** fall into the `unresolved` denominator class. |
| FR-SPINE-022 | P0 | TVO engine v1 **must** compute TVO per Paper I's closed form, with the coverage metric and the deterministic waste taxonomy (retry-loop tokens, re-exploration tokens cortex would have saved, over-model tokens vs the cheapest passing rung). No Shapley code may exist before ADR-0003. |
| FR-SPINE-023 | P1 | `m1p-registry` **must** record released schema versions and per-tenant accepted windows; out-of-window `M1P-Schema` ⇒ structured upgrade hint; receivers **must** skip-and-retain unknown event types within a major. |
| FR-SPINE-024 | P0 | `kill -9` of `mark1d` mid-batch **must** lose zero events in the billing-grade classes (see NFR-DURABILITY-002). |
| FR-SPINE-025 | P1 | The proxy's tee spill ring and the shim's emergency spill **must** be post-redaction only, 0600, device-key-encrypted, ≤24 h TTL, with receipted expiry. |
| FR-SPINE-026 | P0 | Every enable/disable/bypass window **must** emit a `CoverageTransition` event bound into a per-event receipt; the coverage band **must** be computable from these events alone. |

End of FR-SPINE.

---

## 4. FR-VERIFY-* — anchors, sandbox, anti-tamper, fusion, stop-gate, adjudication, certificates

Ownership: `mark1d` (anchor runner, verdict fusion, stop-gate, knee governor), `adjudicator-svc` (adjudication, certificates, gold sets).

| ID | P | Requirement |
|---|---|---|
| FR-VERIFY-001 | P0 | The anchor catalog **must** be locally derived from the workspace, user-consented at enable time, re-consented on any change, and visible in `mark1 doctor`. Bundles **must** reference anchors by local-catalog ID only (CON-009). |
| FR-VERIFY-002 | P0 | The anchor runner **must** execute every anchor network-denied, env-scrubbed to an allow-list, read-only outside the worktree, resource-capped, activity-aware, and kill-switched. The sandbox is a security boundary, not a convenience. |
| FR-VERIFY-003 | P0 | Default anchors **must** be side-effect-free static analysis (compilers, linters, type checkers). Test anchors **must** be per-repo opt-in and **must not** run unless the sandbox precondition holds. |
| FR-VERIFY-004 | P0 | Every `AnchorVote` **must** carry an `AnchorIntegrity` envelope: worktree merkle root, resolved binary hashes (effective-execution hashing, not glob hashing), env-scrub attestation, diff classification, suppression-directive delta, and a `tamper` flag. Votes **must** be device-signed at origin. |
| FR-VERIFY-005 | P0 | A mutated worktree and a PATH-shimmed anchor binary **must** each independently raise `tamper` on the affected vote. An injected suppression directive **must** be detected as a non-zero `AnchorIntegrity.suppression_directive_delta`: the vote **stands**, annotated, and the delta is fed to the spectral estimator as a feature (`verify.proto` `AnchorIntegrity`, 06 §2.4) — it is not `tamper`, because suppressions are sometimes legitimate and lying about them is what the delta exposes. Tamper-flagged votes **must** be excluded from corpus admission. *(Reconciled 2026-09-16 to proto/06 by founder ruling — D-EI; the earlier text made the suppression axis raise `tamper`.)* |
| FR-VERIFY-006 | P0 | Verdict fusion **must** run in `mark1d` as naive Bayes by direct product (D-AK: log-space withdrawn — IEEE-754 mandates correct rounding for `* / + −` and nothing for `Exp/Log`, so the product form is what is bit-identical across Go, Python and Rust; the log-space wording here was stale against `fuse.go:128-135` until 2026-09-15) over bundle-shipped confusion matrices, priors, correlation groups (syntactic ∪ {tests} as its own group), and abstention models, producing a cached `VerdictEvent{PROVISIONAL, posterior[4]}` per task. |
| FR-VERIFY-007 | P0 | **The stop-gate must read the cached verdict; it must never compute.** Gate evaluation must not block on any anchor, network call, or fusion pass. |
| FR-VERIFY-008 | P0 | Fast anchors (ruff, incremental tsc, warm `cargo check`) **must** refresh the cache on PostToolUse debounce; slow opt-in anchors **must** produce `REVISED` verdicts plus next-turn hook-context corrections. |
| FR-VERIFY-009 | P0 | The knee governor **must** stop when `p̂_LCB(n)·V(task) ≤ c(n)`, with `c(n)` computed under the bundle's `cost_basis` — `usd` for API-key tenants, `quota` (rate-limit-window fraction × wall-clock shadow price) for subscription tenants. |
| FR-VERIFY-010 | P0 | Local hard caps apply regardless of bundle content: **≤3 consecutive blocks per task**, an **hourly block ceiling**, and `MARK1_DISABLE=1` / `mark1 off` **checked before any gate evaluation** (CON-013). A bundle **must not** be able to raise these caps. |
| FR-VERIFY-011 | P0 | At the knee the gate **must** stop the loop and surface verdict + evidence to the human; below the knee it **must** return `decision:"block"` with the failure evidence as the continuation reason. |
| FR-VERIFY-012 | P0 | The adjudicator **must** use weighted majority + priors at bootstrap and spectral Dawid–Skene only behind the identifiability gate (≥3 effectively independent correlation groups + spectral diagnostics), with global estimation and hierarchical shrinkage at low volume. |
| FR-VERIFY-013 | P0 | Noise certificates **must** be preconditioned on a size- and freshness-gated, server-selected, edge-indistinguishable gold set plus identifiability diagnostics. Below threshold, status **must** be `uncertified/bootstrapping`, and such verdicts **must not** gate memory extraction or corpus admission. |
| FR-VERIFY-014 | P0 | Gold-set tasks **must** be server-selected and edge-indistinguishable from ordinary tasks; the edge **must** have no code path that treats a gold task differently. |
| FR-VERIFY-015 | P1 | Judge execution **must** default to client-side through the customer's own key, so evidence never leaves. Cloud judges **must** require tenant consent + subprocessor disclosure + region pinning, and **must** fire only where anchors are ambiguous. |
| FR-VERIFY-016 | P1 | Evidence tiers **must** be enforced at the type level: E0 typed `EvidenceRecord` only (default, modeled as a low-power ensemble member); E1 sanitized diff hunks, per-tenant opt-in, redaction-receipted; E2 full diff, VPC/self-host only. |
| FR-VERIFY-017 | P1 | Consistency votes **must** be scoped to escalation events and T3 runs only, and **must** be excluded from ensemble-size assumptions. |
| FR-VERIFY-018 | P1 | The adjudicator **must** reproduce Paper II's posterior/verdict table on synthetic verifier outputs, with crowd-kit as test oracle only (never a runtime dependency). |
| FR-VERIFY-019 | P1 | Cross-tenant deviation of estimated priors beyond bundle-configured bounds **must** route the tenant's certification to manual review. |
| FR-VERIFY-020 | P0 | `VerdictEvent.stage` **must** be exactly `PROVISIONAL \| CERTIFIED \| REVISED`, and `posterior` **must** be a 4-vector over exactly the CON-006 verdict vocabulary. |

End of FR-VERIFY.

---

## 5. FR-CORTEX-*, FR-ROUTE-*, FR-REMEMBER-*, FR-LEARN-*

### 5.1 FR-CORTEX-* — repo intelligence (`cortexd`)

| ID | P | Requirement |
|---|---|---|
| FR-CORTEX-001 | P0 | `cortexd` **must** maintain L0 (notify + BLAKE3 merkle file plane) whose root hash double-serves anchor anti-tamper (one hash table for both uses, C7). |
| FR-CORTEX-002 | P0 | `cortexd` **must** maintain L1 (vendored tree-sitter tags) and L2 (petgraph symbol graph with personalized PageRank); L3 (SCIP precision) **must** be opportunistic — its absence degrades ranking, never availability. |
| FR-CORTEX-003 | P0 | The session-start ranked map **must** be budgeted (1–8k tokens, budget binary search) and injected via SessionStart/UserPromptSubmit/BeforeModel surfaces only. |
| FR-CORTEX-004 | P0 | MCP pull tools (`repo_map`, `find_definition`, `find_references`, `expand`, `deps`) **must** be scoped to the calling session's enrolled workspace, loopback-token-authed, and path-traversal-refusing. |
| FR-CORTEX-005 | P0 | Every map or tool delivery **must** emit `CortexInjection{root_hash, index_clock}` into the ledger. |
| FR-CORTEX-006 | P0 | `cortexd` **must** read only inside `mark1 enable`d workspaces and **must** honor `.mark1ignore` (CON-012). |
| FR-CORTEX-007 | P1 | The local index **must** use redb graph shards + SQLite CAS keyed `(path, content_hash, grammar_rev, query_rev, indexer_rev)`; a key-component bump invalidates exactly the affected entries. |
| FR-CORTEX-008 | P1 | Cortex uplift **must** be measured per tenant via verdict joins in the ledger; the literature prior (+22pp/−95%) **must never** be asserted as Mark 1 performance (CON-014). |

### 5.2 FR-ROUTE-* — routing, propensity, knee tables

| ID | P | Requirement |
|---|---|---|
| FR-ROUTE-001 | P0 | Every `RouteDecision` **must** log `decision_id`, action, candidates, `propensity`, `fidelity`, and `bundle_seq`, from the **first** routed request onward. |
| FR-ROUTE-002 | P0 | `fidelity` **must** be exactly `WIRE_ENFORCED \| CONFIG_STEERED \| ADVISORY`. OPE **must** consume `WIRE_ENFORCED` decisions only; `CONFIG_STEERED` enters only after a served-model confirmation join from `Usage` events; `ADVISORY` **must never** enter. |
| FR-ROUTE-003 | P0 | ε (exploration) **must** default to 0 with propensity 1.0 logged honestly; nonzero ε (0.03–0.05) **must** be a per-tenant contractual opt-in carried in the bundle. |
| FR-ROUTE-004 | P0 | Knee tables **must** carry dual cost basis (`usd` \| `quota`); a TVO report **must** state the basis per cohort and **must never** average the two (CON-014). |
| FR-ROUTE-005 | P0 | Wire-level model rewrite **must** exist only in the API-key regime, behind the provenance guard (CON-001). In the subscription regime, routing influence is config/advisory only. |
| FR-ROUTE-006 | P1 | Bundles **must** carry CPVS routing tables and escalation ladders with `keep_prefix`; ladder evaluation follows the prefix principle. |
| FR-ROUTE-007 | P1 | `mark1d` **must** be the single choice point for route decisions; no second component may emit `RouteDecision`. |
| FR-ROUTE-008 | P1 | Bundle policy evaluation at the edge **must** operate on pre-decoded typed structs (decode once at bundle apply, evaluate in nanoseconds; see NFR-LATENCY-004). |

### 5.3 FR-REMEMBER-* — memory artifacts

| ID | P | Requirement |
|---|---|---|
| FR-REMEMBER-001 | P0 | Memory artifacts **must** be typed: workflow template, pitfall–remedy pair, invariant, routing hint. No free-text artifact class exists. |
| FR-REMEMBER-002 | P0 | Extraction **must** run only over sessions whose verdicts are `CERTIFIED` under an active noise certificate (FR-VERIFY-013); tamper-flagged sessions are excluded. |
| FR-REMEMBER-003 | P0 | Admission **must** be tenant-scoped ADMIT-LCB: admit only when the LCB of measured utility is strictly positive. |
| FR-REMEMBER-004 | P0 | Delivery: memory pack at `TaskOpen` via HOOK_CONTEXT (facets from prompt-digest features + cortex signals); pitfall-remedies fire reactively on PostToolUseFailure; `routing_hint` **must never** inject — it compiles into bundles only. |
| FR-REMEMBER-005 | P0 | Every delivery **must** emit `MemoryInjection`; every task close **must** emit `ArtifactOutcome` (the LCB fuel). |
| FR-REMEMBER-006 | P1 | Extraction **must** run as a nightly Batch-API cascade (cheap model first, escalate on ambiguity). |
| FR-REMEMBER-007 | P0 | Every memory admission **must** be per-event receipted (FR-SPINE-016), and admission of secret-bearing artifacts **must** re-check device revocation (fail-closed, CON-007). |
| FR-REMEMBER-008 | P1 | Error-signature fuzzy match **must** be the only vector-search case, implemented as one pgvector `halfvec` HNSW column; no second vector store may be introduced. |

### 5.4 FR-LEARN-* — corpus and training

| ID | P | Requirement |
|---|---|---|
| FR-LEARN-001 | P0 | Corpus admission **must** require certified labels with `label_confidence = f(posterior, noise cert)`; uncertified or tamper-flagged trajectories **must** be excluded (FR-VERIFY-013). |
| FR-LEARN-002 | P0 | The corpus exporter **must** emit both receipted Parquet (analytics) and the KTO `manifest.json` + `rows.jsonl` pair the trainer actually reads, with one receipt covering both artifacts (grounding delta 1). |
| FR-LEARN-003 | P0 | Training **must** be per-tenant by default. Cross-tenant training **must** require receipted contractual opt-in, DP-SGD with ε debited in the same ε ledger, per-tenant contribution caps, and a per-tenant canary memorization test as a checkpoint release gate. |
| FR-LEARN-004 | P0 | Trained artifacts **must** re-enter the system only via probation → shadow voting → LCB promotion → canary. No component may promote its own output (C12). |
| FR-LEARN-005 | P1 | A learned router **must** beat the incumbent on held-out DR/SNIPS before canary; DR/SNIPS inputs obey FR-ROUTE-002. |
| FR-LEARN-006 | P1 | The data-refinery integration **must** be an added constructor + method pair on the existing `CorpusReader` struct following its `scan_worm`/`read_train_rows` signatures — not an invented trait (grounding delta 2). |
| FR-LEARN-007 | P1 | Export-batch receipts **must** record checkpoint lineage sufficient to execute retrain-on-erasure, and the erasure path **must** be documented and testable. |

End of section 5.

---

## 6. FR-AGENT-* — the seven adapters

Capability differs by agent **and** by legal regime. The subscription-regime surface (hooks, transcript tails, artifact dirs; injection via hook context, gates, context files, MCP) and the API-key-regime surface (all of that **plus** the wire proxy and wire-level model rewrite) are fixed by CON-001; what varies per adapter is which of those surfaces the agent actually exposes and whether that exposure is verified. **Where a surface is unverified, the requirement is: a spike must produce a go/no-go artifact before this adapter slot opens.** No adapter code may be written against an unverified surface.

Common requirements (all adapters):

| ID | P | Requirement |
|---|---|---|
| FR-AGENT-001 | P0 | Per-agent hook field maps and tailer parser rules **must** ship as bundle data (`agent_maps` section), never as compiled code — an agent format break is a bundle push, not a release. |
| FR-AGENT-002 | P0 | Every adapter **must** version-sniff its agent at runtime; an unsupported version **must** emit `Dropped{unsupported_agent_version}` and disable capture for that surface — never parse blind. |
| FR-AGENT-003 | P0 | Agent provisioning **must** use only fenced, checksummed fragments and the agent's native include/extension mechanisms (CON-003); every provisioned line **must** appear in `mark1 doctor`. |
| FR-AGENT-004 | P0 | Each adapter **must** carry conformance fixtures (hook payloads, transcript samples) per pinned agent version, replayed in CI. |
| FR-AGENT-005 | P0 | Every adapter **must** emit the same `m1p.v1` event families — one trajectory schema across all agents and both regimes. |

Per-adapter requirements:

| ID | P | Adapter | Phase | Regime capability | Requirement |
|---|---|---|---|---|---|
| FR-AGENT-010 | P0 | `claudecode` | 1 | Subscription: hooks + transcript tailer + artifact dirs (verified surface — `~/.claude/projects/<munged-cwd>/<session-id>.jsonl` with `requestId`, `message.id`, full `usage` block). API-key: all of that + proxy + model rewrite when `Detect()==apikey`. | The adapter **must** capture hooks via `mark1-hookshim` and tail transcripts with `(message.id, requestId)` dedupe and the sidechain rule as protocol invariants. It is the reference adapter: gates, cortex injection, and memory injection land here first. |
| FR-AGENT-011 | P0 | `codex` | 2 | Subscription: hooks (~80% vocabulary overlap with Claude Code, verified directionally); usage via `TokenCountEvent` — **unverified**. API-key: + proxy (OpenAI dialects via `mark1-frames`). | The Codex `TokenCountEvent` spike **must** produce a go/no-go artifact before the adapter slot opens (spike runs concurrently with Phase 1). On go: adapter lands in Phase 2 reusing the hook vocabulary through bundle field maps. On no-go: the slot stays closed and the roadmap entry is re-planned — not worked around. |
| FR-AGENT-012 | P0 | `gemini` | 3 | Subscription (OAuth mode): `BeforeModel` hook — **unverified**. API-key: + proxy (gemini dialect) + `BeforeModel` routing. | The Gemini `BeforeModel`-in-OAuth-mode spike **must** produce a go/no-go artifact before the adapter slot opens. On go: adapter lands in Phase 3 with `BeforeModel` routing carrying `fidelity=CONFIG_STEERED` unless wire-enforced. |
| FR-AGENT-013 | P1 | `opencode` | 4 | Surfaces **unverified** in both regimes. | A spike **must** produce a go/no-go artifact enumerating usable hook/transcript/config surfaces per regime before the adapter slot opens in Phase 4. |
| FR-AGENT-014 | P1 | `copilot` | 5 | Subscription (GitHub-billed): capture limited to `events.jsonl` usage — **unverified**; no proxy ever (credentials are GitHub's, not the customer's). BYOK: customer API key ⇒ proxy eligible. | The Copilot `events.jsonl` usage spike **must** produce a go/no-go artifact before the slot opens. The adapter **must** distinguish GitHub-billed from BYOK sessions and enable the wire path only for BYOK (CON-001 applies to GitHub credentials identically). |
| FR-AGENT-015 | P1 | `cursor` | 5 | Subscription (Cursor-billed): observe/gate only — **unverified** surfaces; no proxy ever (Cursor's server-side keys are not customer-owned). BYOK where Cursor exposes it: proxy eligible per provenance. | A spike **must** produce a go/no-go artifact before the slot opens. The adapter **must** be observe/gate only unless credential provenance proves customer ownership. |
| FR-AGENT-016 | P2 | `crush` | — (slot reserved) | Surfaces **unverified** in both regimes; no phase assignment in the frozen plan. | A spike **must** produce a go/no-go artifact before any Crush work is scheduled; until then the adapter directory is a reserved name only. |

End of FR-AGENT.

---

## 7. FR-CLI-*, FR-ENROLL-*, FR-POLICY-*, FR-FED-*

### 7.1 FR-CLI-* — the `mark1` command surface

| ID | P | Requirement |
|---|---|---|
| FR-CLI-001 | P0 | `mark1 enroll` **must** run the OIDC device-code flow (FR-ENROLL-001) and store the device key per FR-ENROLL-003. |
| FR-CLI-002 | P0 | `mark1 enable <path>` **must** be the only way a workspace enters the read surface; enable is per-workspace, consent-recording, and emits a receipted `CoverageTransition`. |
| FR-CLI-003 | P0 | `mark1 status` **must** show the live read surface: enrolled workspaces, active tailers, provisioned surfaces, current bundle seq, and spool health. |
| FR-CLI-004 | P0 | `mark1 doctor` **must** show every fenced config line Mark 1 provisioned (diffable byte-for-byte) and the consented anchor catalog with consent timestamps. |
| FR-CLI-005 | P0 | `mark1 report` **must** emit TVO with coverage band and cost basis on every figure, and **must** refuse guarantee-grade output below the coverage floor (CON-012, CON-014). |
| FR-CLI-006 | P0 | `mark1 off` **must** disable all capture, injection, and gating; restore agent config to byte-equality; and emit a receipted `CoverageTransition`. It **must** be checked before any gate evaluation (CON-013). |
| FR-CLI-007 | P0 | `mark1 verify-receipts` **must** wrap the standalone verifier (FR-SPINE-020) and succeed with Omium servers unreachable. |
| FR-CLI-008 | P1 | Every CLI command **must** exit nonzero on failure with a typed error from the single error taxonomy (doc 08); no command may swallow a failure into exit 0. |
| FR-CLI-009 | P1 | `mark1 service install\|uninstall\|status\|start\|stop` **must** register `mark1d` to run at login as the current user on macOS (launchd LaunchAgent), Linux (systemd user unit, autostart fallback) and Windows (Task Scheduler logon task in the user's session — never a Windows Service, which cannot read the user's agent config files); registration is idempotent and byte-exactly reversible, and the artifacts carry no secret. `mark1 update [--check]` **must** apply a release only through the `verify-release` provenance gate, refuse a replayed manifest, and never swap binaries while a session is live or while the daemon has not stopped. *(Added 2026-09-16 for the desktop/dogfood phase, D-EI.)* |

### 7.2 FR-ENROLL-* — identity, enrollment, revocation

| ID | P | Requirement |
|---|---|---|
| FR-ENROLL-001 | P0 | Enrollment **must** use the OIDC device-code flow against the tenant IdP (or Omium-hosted auth); no password or long-lived shared secret may exist in the flow. |
| FR-ENROLL-002 | P0 | Device tokens **must** be short-lived (≤24 h) and refreshed via enrollment state; an expired token **must** park uploads (fail-open for capture: spool continues locally). |
| FR-ENROLL-003 | P0 | The device key **must** live in the OS keychain/TPM where available, with a 0600 file as the floor; it signs receipt origin tuples (FR-SPINE-018). |
| FR-ENROLL-004 | P0 | Revocation **must** be effective at next contact: a revoked device's uploads are rejected, its bundle fetches are refused, and memory-artifact / secret-bearing delivery re-checks revocation **fail-closed** (CON-007). |
| FR-ENROLL-005 | P1 | Tenant/device records **must** carry IdP binding and an offboarding audit trail; enrollment and revocation events are per-event receipted. |
| FR-ENROLL-006 | P1 | Enrollment tokens **must** bind the device fingerprint used for the proxy's credential HMAC match (CON-001); a fingerprint mismatch at the guard is a refusal, not a re-enroll. |
| FR-ENROLL-007 | P1 | An individual developer **must** be able to enroll without a corporate IdP: Omium-hosted sign-in (GitHub/Google via the platform's Supabase-backed `/auth` page, PKCE + loopback redirect per RFC 8252) mints a 1-hour ES256 user token (aud `mark1`, carrying `tenant_id`) that controld verifies against a pinned JWKS and exchanges, with a daemon-generated device key, for a personal tenant (`m1_tenants.kind='personal'`, id = the platform tenant id) and a device enrollment through the same state machine as the IdP path. Personal tenants share one pooled KMS key (ADR-0011) and never enter federation. No shared secret may mint an approval. *(Added 2026-09-16 for the desktop phase, D-EI.)* |
| FR-ENROLL-008 | P2 | A tenant's members, pending invites, shared-memory setting and 30-day TVO summary **must** be readable by any principal of that tenant and by no other (RLS), and an invite **must** be a hash-only, 7-day token minted server-side — the desktop Team screen (spec §5.10) has no other source. |

### 7.3 FR-POLICY-* — bundle distribution, ACK, transparency

| ID | P | Requirement |
|---|---|---|
| FR-POLICY-001 | P0 | PolicyBundle v1 **must** be canonical CBOR with monotonic `seq` per `(tenant, channel)`, `max_age`, and `prev_hash`, carrying exactly the sections `verify \| route \| memory \| cortex \| gates \| agent_maps`. |
| FR-POLICY-002 | P0 | Bundles **must** carry no command strings and no code; any command string **must** fail decode; no `wasm_module` field exists (CON-009). |
| FR-POLICY-003 | P0 | Bundle signing **must** use section-split, KMS-resident keys, rate-limited at the KMS; the update key **must not** equal the bundle key (ADR-0004); both keys appear in the transparency log. |
| FR-POLICY-004 | P0 | The edge **must** verify signature + monotonic seq + transparency-log inclusion proof before applying any bundle, and **must** persist last-known-good. |
| FR-POLICY-005 | P0 | Policy **must** be fail-static: control plane unreachable ⇒ run last-known-good indefinitely; past `max_age` ⇒ conservative built-in defaults (single-rung ladder, knee=1, detect-only redaction, gates open, verdicts flagged `stale_cert`). |
| FR-POLICY-006 | P0 | The `gates` section **must** only be able to downgrade closed→open; enabling any fail-closed gating **must** require local on-disk tenant opt-in. |
| FR-POLICY-007 | P0 | Distribution **must** be Etag poll + SSE push; edges heartbeat-ACK `(seq, hash)` into the ACK ledger; canary→fleet widening **must** occur only on ACK evidence + ledger-observed TVO; rollback is previous content under a **higher** seq. |
| FR-POLICY-008 | P0 | Every bundle publication **must** be per-event receipted and recorded in the transparency log before any edge can apply it. |
| FR-POLICY-009 | P1 | Edge binaries **must** verify SLSA provenance before applying any update; managed fleets **must** have daemon self-update off by default. |
| FR-POLICY-010 | P1 | The Go bundle decoder and the Rust `mark1-policy` decoder **must** agree on shared conformance vectors; a divergence fails CI. |

### 7.4 FR-FED-* — federation

| ID | P | Requirement |
|---|---|---|
| FR-FED-001 | P0 | An artifact **must** publish only when ≥k contributors exist, k ≥ 25, counting billing/domain-verified organizations with collusion collapse (affiliated orgs count once). |
| FR-FED-002 | P0 | Published bodies **must** be intersection-reconstructed from spans that ≥m organizations independently produced, m ≥ 5; a span fewer than m tenants produced structurally cannot publish (CON-011). |
| FR-FED-003 | P0 | The (k,m) gate **must** be enforced in the database as a `HAVING` clause plus trigger constraint — not in application code alone. |
| FR-FED-004 | P0 | `invariant`-type artifacts **must** be excluded from federation by schema. |
| FR-FED-005 | P0 | Every cross-tenant release **must** pass the DP release layer (Google DP Go integer mechanisms, pre-thresholding, contribution bounding) and debit the per-tenant ε ledger; ε exhaustion **must** block further release, never capture. |
| FR-FED-006 | P0 | Every federated publication **must** pass a human review queue before release; tenants **must** be able to opt out of contribution entirely. |
| FR-FED-007 | P1 | (k,m) defaults and the tenant's current ε balance **must** be tenant-visible. |

End of section 7.

---

## 8. NFR-* — non-functional requirements by class

### 8.1 NFR-LATENCY

| ID | P | Requirement |
|---|---|---|
| NFR-LATENCY-001 | P0 | `mark1-proxy` **must** add ≤1 ms median latency on the bytes-forward hot path, enforced by a CI benchmark that fails the build on regression. |
| NFR-LATENCY-002 | P0 | `mark1-hookshim` observer hooks **must** be fire-and-forget within 50 ms; gate hooks **must** honor bounded deadlines (per-agent, bundle-configured) and return the cached verdict path only (FR-VERIFY-007). |
| NFR-LATENCY-003 | P0 | A gate deadline miss **must** fail open for observers and fail per the gate's declared posture for gates — never hang the agent. |
| NFR-LATENCY-004 | P1 | Bundle policy evaluation **must** run on pre-decoded typed structs in nanosecond scale; no parsing, allocation spikes, or I/O on the gate path. |
| NFR-LATENCY-005 | P1 | Fast-anchor cache refresh **must** be debounced on PostToolUse so anchor churn never queues behind itself. |

### 8.2 NFR-FOOTPRINT

| ID | P | Requirement |
|---|---|---|
| NFR-FOOTPRINT-001 | P0 | `mark1-proxy` **must** hold ≤35 MB RSS under sustained streaming load. |
| NFR-FOOTPRINT-002 | P0 | The spool **must** cap at ~2 GiB with a hard stop at 95% disk usage; the hard stop applies even to billing-grade classes (which then block, FR-SPINE-007). |
| NFR-FOOTPRINT-003 | P1 | Cortex session-start maps **must** stay within their token budget (1–8k, binary-searched); over-budget maps are truncated by rank, never delivered oversized. |
| NFR-FOOTPRINT-004 | P1 | Anchor execution **must** be resource-capped (CPU/memory/time) and activity-aware (pause under user load). |

### 8.3 NFR-DURABILITY

| ID | P | Requirement |
|---|---|---|
| NFR-DURABILITY-001 | P0 | Billing-grade classes (`usage`, `verdict`, `receipt-checkpoint`) **must** block on spool-full rather than shed (FR-SPINE-007). |
| NFR-DURABILITY-002 | P0 | `kill -9` of `mark1d` at any point **must** lose zero acknowledged billing-grade events; recovery replays from the spool cursor. |
| NFR-DURABILITY-003 | P0 | Ingest **must** ack only after the S3 object lands (FR-SPINE-010); an acked batch **must** be recoverable from S3 alone. |
| NFR-DURABILITY-004 | P1 | Spool fsync interval **must** be 250–500 ms; `SessionEnd` and shutdown **must** force a drain. |
| NFR-DURABILITY-005 | P1 | Segment deletion **must** be whole-file ack-then-delete; a segment with any unacked record **must not** be deleted. |

### 8.4 NFR-AVAILABILITY

| ID | P | Requirement |
|---|---|---|
| NFR-AVAILABILITY-001 | P0 | No Mark 1 component may be a single point of failure for the customer's ability to code: capture and hooks fail open; the agent proceeds unmodified when any Mark 1 process is absent, crashed, or unreachable. |
| NFR-AVAILABILITY-002 | P0 | Proxy failure **must** trigger automatic, receipted bypass with capture degrading to transcripts — the client stream is never held hostage by the tee. |
| NFR-AVAILABILITY-003 | P0 | Control-plane unavailability **must** leave edges on last-known-good bundles indefinitely (fail-static, FR-POLICY-005). |
| NFR-AVAILABILITY-004 | P1 | `mark1d` **must** supervise proxy/cortexd/shim registrations and restart crashed children with backoff; supervision failure degrades to fail-open capture, never to agent blockage. |

### 8.5 NFR-CORRECTNESS

| ID | P | Requirement |
|---|---|---|
| NFR-CORRECTNESS-001 | P0 | Dedupe **must** defeat the verified ~2.5× streaming overcount: replaying a recorded session with streamed partials and sidechain traffic **must** produce exactly one `Usage` event per `(message.id, requestId)`. |
| NFR-CORRECTNESS-002 | P0 | TVO output **must** match hand-computed values from the Paper I worked example on golden input. |
| NFR-CORRECTNESS-003 | P0 | Proxy SSE passthrough **must** be byte-exact against golden transcripts per dialect. |
| NFR-CORRECTNESS-004 | P0 | The M1PL framing decoder and the spool decoder **must** carry fuzz targets, green in CI, with `len` bounds-checked. |
| NFR-CORRECTNESS-005 | P1 | Rust and Go decoders (M1P, bundle) **must** agree on shared conformance vectors; divergence fails CI. |
| NFR-CORRECTNESS-006 | P1 | Receipt canonicalization **must** match the vendored platform form (`sort_keys=True, separators=(",",":"), ensure_ascii=True`) with domain prefix `mark1-label-v1\0`; cross-language hash equality is CI-tested. |

### 8.6 NFR-PRIVACY

| ID | P | Requirement |
|---|---|---|
| NFR-PRIVACY-001 | P0 | Default wire evidence **must** carry no paths and no free text (CON-004); `path_role` is the only path-derived field. |
| NFR-PRIVACY-002 | P0 | All digests of low-entropy content **must** be per-tenant HMAC-salted; globally-joinable digests exist only post-(k,m). |
| NFR-PRIVACY-003 | P0 | Every DP release and DP-SGD run **must** debit the per-tenant ε ledger under tenant-level composition (FR-FED-005, FR-LEARN-003). |
| NFR-PRIVACY-004 | P0 | Per-tenant S3 prefixes and per-tenant KMS keys **must** govern all tenant data at rest in Omium's stores. |
| NFR-PRIVACY-005 | P1 | Raw evidence under `~/.omium/mark1/evidence/` **must never** be uploaded by default; E1/E2 movement is opt-in, scrubbed, receipted (FR-VERIFY-016). |
| NFR-PRIVACY-006 | P1 | All Anthropic-bound cloud-judge evidence **must** be gated on tenant consent flags, listed in the subprocessor register, and region-pinned. |

### 8.7 NFR-PORTABILITY

| ID | P | Requirement |
|---|---|---|
| NFR-PORTABILITY-001 | P0 | CI **must** run macOS, Linux, and Windows from day one; a platform-red build blocks merge. |
| NFR-PORTABILITY-002 | P0 | The local fabric **must** use named pipes on Windows with semantics equivalent to UDS (perms, framing, single-writer discipline). |
| NFR-PORTABILITY-003 | P1 | `mark1-hookshim` **must** be a single static binary per platform; no runtime dependency may be assumed on the customer machine. |
| NFR-PORTABILITY-004 | P1 | Key storage **must** degrade explicitly: keychain/TPM where available, 0600 file floor otherwise, with the degradation visible in `mark1 status`. |

### 8.8 NFR-OPERABILITY

| ID | P | Requirement |
|---|---|---|
| NFR-OPERABILITY-001 | P0 | Loss **must** be accounted, never silent: every shed, CRC loss, quarantine, or unsupported-version drop emits `Dropped{reason, durability_class, quantity}`, and `Dropped{}` feeds the coverage band as first-class product telemetry. |
| NFR-OPERABILITY-002 | P0 | Self-monitoring **must** ride M1P itself (CON-005): internal metrics are M1P events; no second telemetry stack exists. |
| NFR-OPERABILITY-003 | P1 | 4xx upload failures **must** quarantine-and-report with the batch inspectable by the operator; parked batches are visible in `mark1 status`. |
| NFR-OPERABILITY-004 | P1 | Every cloud service **must** expose health/readiness semantics under existing platform conventions (crashloop on boot refusal; 503 + `Retry-After` on pool exhaustion). |

### 8.9 NFR-SECURITY

| ID | P | Requirement |
|---|---|---|
| NFR-SECURITY-001 | P0 | Credentials **must** exist in code only as `Secret<T>` (no Debug/Display/Serialize, zeroize-on-drop) with a CI grep gate on the raw types (CON-002). |
| NFR-SECURITY-002 | P0 | Proxy and daemon processes **must** set `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` (platform equivalents on macOS/Windows). |
| NFR-SECURITY-003 | P0 | Tenant-isolation negative tests **must** run on every PR across Postgres (RLS + `*_app` roles), ClickHouse (chokepoint predicate), the memory API, and S3 prefixes (CON-010). |
| NFR-SECURITY-004 | P0 | Releases **must** be SLSA-attested with CycloneDX SBOM; `cargo-deny`/`cargo-vet` and `govulncheck` **must** be CI gates in `omium-mark1`'s own CI (they do not exist in estate CI to inherit — grounding delta 4). |
| NFR-SECURITY-005 | P0 | The weekly OAuth token-shape canary **must** fail CI when the classifier misses (CON-001). |
| NFR-SECURITY-006 | P0 | A negative test **must** prove no code path forwards an unprovisioned credential through the proxy. |
| NFR-SECURITY-007 | P1 | UDS sockets, spool files, spill rings, and token files **must** be 0600; loopback listeners require the per-session bearer token (FR-SPINE-005). |
| NFR-SECURITY-008 | P1 | Dependencies on token/hook paths **must** be pinned — exact version and checksum in `Cargo.lock`, every lane built `--locked`, and each path's resolved closure equal to a reviewed, checked-in list in both directions (`tools/ci/tokenpath_deps_gate.sh`), so an unreviewed crate on the shim or proxy path is a red build naming it; the shim's dependency tree is minimal by review. *(Reconciled 2026-09-15: earlier wording said "vendored"; 10 §8.1 reserves vendoring for tree-sitter and the receipt primitives and pins everything else through the lockfile, and no `cargo vendor` tree exists — the closure gate is what makes the pin reviewable.)* |

End of section 8.

---

## 9. Acceptance criteria table

One row per requirement — the document's centre of gravity. **Statement** is a compressed pointer; the normative text is in sections 2–8. **Holds by** names the assembly phase (section 10) after which the criterion must stay green permanently. **Verification** ∈ unit / conformance / fuzz / chaos / negative / manual.

### 9.1 CON-*

| ID | Statement | P | Acceptance criterion (a test can fail) | Holds by | Verification |
|---|---|---|---|---|---|
| CON-001 | No OAuth interception | P0 | A request without a valid `M1-Cred-Ref` receives 403; binary inspection finds no override flag/env/config; injected subscription-marker response kills the session, rolls back config, and produces a receipted `oauth_contamination` event | Phase 3 | negative |
| CON-002 | No credential intermediation | P0 | CI grep gate red on any raw credential type; tee output diffed against field allow-list contains no auth material; gateway run writes zero credential bytes to disk (filesystem audit) | Phase 3 | negative |
| CON-003 | No vendor binary modification | P0 | Vendor binaries hash-identical before/after install; `mark1 off` restores every touched config file to byte-equality | Phase 1 | conformance |
| CON-004 | Client-side residency default | P0 | Wire capture of a default-config session contains zero path strings and zero source excerpts; `EvidenceRecord` proto has no field capable of carrying either | Phase 1 | negative |
| CON-005 | Zero OpenTelemetry | P0 | Lockfile scan (cargo/go/uv) finds zero OTel packages; grep of docs finds no OTel-as-dependency reference | Phase 1 | negative |
| CON-006 | Exact verdict vocabulary | P0 | Schema/enum diff against `satisfied\|violated\|refused\|error` is empty in proto, PG, and Python constants; an injected infra failure yields `error`, not `violated` | Phase 1 | unit |
| CON-007 | Posture matrix normative | P0 | Chaos suite: control-plane blackhole ⇒ capture continues + last-known-good policy; forced guard uncertainty ⇒ refusal; each component's LLD posture table exists and matches observed behavior | Phase 3 | chaos |
| CON-008 | Fail-closed upload admission | P0 | Planted secrets appear as `⟨redacted:class:hash⟩` in every spooled artifact; no config/env/flag disables admit-to-upload; disk audit finds no pre-redaction plaintext; ingest scanner quarantines a seeded batch | Phase 1 | negative |
| CON-009 | No commands/code in bundles | P0 | A bundle containing any command string fails decode in both Rust and Go decoders; proto/CBOR schema contains no `wasm_module`; unconsented anchor never executes | Phase 3 | negative |
| CON-010 | Structural tenancy | P0 | Cross-tenant read attempts fail on every store (PG, CH via chokepoint, memory API, S3) in PR-gated negative tests; envelope/token tenant mismatch is rejected with a security event | Phase 1 | negative |
| CON-011 | (k,m) structural gate | P0 | Direct-SQL insert bypassing the `HAVING`/trigger fails; a span crafted from m−1 tenants never appears in any published body; `invariant` artifact publication fails at schema level | Phase 5 | negative |
| CON-012 | Consented read surface | P0 | Tailer reads outside enrolled roots = zero (filesystem audit); `.mark1ignore`'d file never appears in any event; below-floor guarantee-grade report request returns a refusal, not a report | Phase 1 | negative |
| CON-013 | Uncircumventable off | P0 | With `MARK1_DISABLE=1` set mid-task, the next gate evaluation is a no-op (verified ordering); `mark1 off` ⇒ byte-equality snapshot passes and a `CoverageTransition` receipt exists | Phase 2 | conformance |
| CON-014 | Ledger-traceable claims | P1 | Every figure in a generated report carries query ref + coverage band + cost basis; report generator refuses a mixed-basis aggregate | Phase 4 | unit |
| CON-015 | No multiplexing/resale | P1 | Two identities through one gateway never share a pool (pool-key assertion); no failover-to-other-identity code path exists | Phase 5 | negative |

End of §9.1.

### 9.2 FR-SPINE-*

| ID | Statement | P | Acceptance criterion | Holds by | Verification |
|---|---|---|---|---|---|
| FR-SPINE-001 | UUIDv7 + seq identity | P0 | Generated IDs parse as RFC 9562 Method-1 UUIDv7; burst generation is strictly monotonic per daemon; `seq` gaps within a session fail the check | Phase 1 | unit |
| FR-SPINE-002 | Buf-governed m1p.v1 | P0 | `buf breaking` (WIRE_JSON) wired into CI and red on a field deletion without `reserved`; all three codegen outputs compile from one source | Phase 1 | conformance |
| FR-SPINE-003 | idem_key invariant | P0 | Recorded streaming session replayed ⇒ exactly one `Usage` per `(message.id, request_id)`; sidechain lines excluded; HMAC keyed per tenant | Phase 1 | conformance |
| FR-SPINE-004 | M1PL fabric, single writer | P0 | Frame fuzz target green; socket perms 0600 asserted; a second spool-writer attempt fails (lock held by `mark1d`) | Phase 1 | fuzz |
| FR-SPINE-005 | Hardened loopback fallback | P0 | Requests lacking the bearer token, bearing a non-literal-loopback Host, or carrying an Origin header are rejected | Phase 1 | negative |
| FR-SPINE-006 | Spool segment format | P0 | Segment writer/reader round-trips golden segments; corrupt crc32c detected; 95%-disk simulation halts writes; drain on shutdown flushes all pending | Phase 1 | unit + fuzz |
| FR-SPINE-007 | Per-class full policy | P0 | Spool-full simulation: billing-grade writers block, diagnostics shed newest, and each shed produces a `Dropped{}` in the next uploaded batch | Phase 1 | chaos |
| FR-SPINE-008 | M1P/1 transport | P0 | Conformance client posts zstd protobuf batch, server upserts idempotently (duplicate batch ⇒ no duplicate rows); gRPC port does not exist | Phase 1 | conformance |
| FR-SPINE-009 | Retry discipline | P0 | Fault injection: 5xx/429/network retries with observed jittered backoff (base 6 s, cap 30 min, ~10 attempts, then park); 400 quarantines without retry | Phase 1 | chaos |
| FR-SPINE-010 | S3-first ack | P0 | Ack withheld until S3 PUT confirmed (fault injection on S3 ⇒ no ack); acked batch reconstructable from S3 alone | Phase 1 | chaos |
| FR-SPINE-011 | Token-stamped tenancy | P0 | Envelope claiming tenant B on tenant A's token ⇒ reject + security event row | Phase 1 | negative |
| FR-SPINE-012 | Ingest pre-egress scanner | P0 | Seeded high-confidence secret in a batch ⇒ batch quarantined + tenant alert emitted; scanner ruleset provably differs from edge ruleset (distinct rule IDs) | Phase 1 | negative |
| FR-SPINE-013 | CH ledger settings | P0 | DDL matches ADR-0001; insert path asserts `async_insert=1, wait_for_async_insert=1`; duplicate `event_id` collapses after merge; CI blocks CH DDL merge while ADR-0001 unsigned | Phase 1 | conformance |
| FR-SPINE-014 | One dedupe key, three layers | P0 | End-to-end duplicate injection at each layer (transcript, upload, CH) yields exactly one surviving row | Phase 1 | conformance |
| FR-SPINE-015 | Checkpoint receipts | P0 | Batch of events ⇒ one receipt; each event's `inclusion_path` verifies against the checkpoint Merkle root | Phase 1 | unit |
| FR-SPINE-016 | Per-event receipt classes | P0 | Each of the six classes produces a per-event receipt; a seventh event type does not | Phase 1 | unit |
| FR-SPINE-017 | Chain schema + append-only | P0 | UPDATE/DELETE/TRUNCATE on receipt rows fail (trigger + REVOKE); per-tenant seq gap detection red on a forced gap; `key_id` present on every row | Phase 1 | negative |
| FR-SPINE-018 | Dual signatures | P0 | Verifier rejects a receipt missing either signature; forged device signature detected; rotation cross-sign chain validates | Phase 1 | unit |
| FR-SPINE-019 | Hourly external witness | P0 | After one hour of writes, the current chain head is present in the witness target; a tampered head fails witness comparison | Phase 1 | conformance |
| FR-SPINE-020 | Offline verifier | P0 | Verifier validates a full chain + witness heads with all Omium endpoints blackholed; detects each of the five defect kinds on corrupted fixtures | Phase 1 | conformance |
| FR-SPINE-021 | task_seg stamping | P0 | Every `TaskOpen` in a dogfood ledger carries `task_seg_version`; a session ended without verdict lands in the `unresolved` class | Phase 1 | unit |
| FR-SPINE-022 | TVO engine v1 | P0 | Output equals Paper I worked-example values on golden input; waste taxonomy sums reconcile with total session tokens; no Shapley symbol exists in the codebase pre-ADR-0003 | Phase 1 | unit |
| FR-SPINE-023 | Schema version windows | P1 | Out-of-window `M1P-Schema` receives the structured upgrade hint; unknown event type within a major is retained, not dropped | Phase 1 | conformance |
| FR-SPINE-024 | kill -9 zero loss | P0 | Repeated `kill -9` during active batches: post-recovery ledger contains every acked billing-grade event exactly once | Phase 1 | chaos |
| FR-SPINE-025 | Encrypted spill rings | P1 | Spill files are 0600, non-plaintext (entropy check), expire ≤24 h, and each expiry produces a receipt | Phase 3 | unit |
| FR-SPINE-026 | CoverageTransition receipts | P0 | Enable/disable/off each yield a receipted `CoverageTransition`; coverage band recomputed from events matches the report's band | Phase 1 | unit |
| FR-SPINE-027 | External-writer session binding | P1 | An `ext:` `Hello` with an empty `session_id` is minted a UUIDv7 returned in `HelloAck.session_id`; an `Event` on that connection naming any other session closes it (`M1E-4003`) before admission; a first-party writer's events are never checked against its `Hello` (ADR-0012) | Phase 1 | unit |
| FR-SPINE-028 | External-writer event contract | P1 | The five-event minimum (`TaskOpen`, `TaskClose`, `Turn`, `Usage`, `ArtifactOutcome`) from an `ext:` session reaches the spool through the same admission door as the socket; the daemon stamps `Usage.idem_key` for an `ext:` session, overwriting any writer value; an undecodable `Event` is quarantined and accounted, never a connection close (08 §4.6) | Phase 1 | unit |
| FR-SPINE-029 | Partner JSONL file-tail transport | P1 | A JSONL file of protojson `Event`s with its `<basename>.manifest.json` sidecar is tailed from the configured paths and the well-known partner directory, resumes after restart, follows rotation, leaves a torn last line unconsumed, and yields an internal stream identical to the socket path's for the same input | Phase 1 | unit |
| FR-SPINE-030 | `mark1 validate-events` | P1 | Every line parses as an `Event`; required fields present; timestamps non-decreasing; causal order holds (`TaskClose` after its `TaskOpen`, `Turn` inside an open task, `ArtifactOutcome` and `Usage` after a `Turn`); unknown fields are warnings; `--json` is the contract; non-zero exit on any error | Phase 1 | unit |
| FR-SPINE-031 | Reference emitter and vectors | P1 | `conformance/emitter` writes a sample session as JSONL and pushes the same session over the socket; the golden lives in `conformance/vectors/ext/` and is registered in `EXPECTED`; the two transports produce identical internal streams and identical receipts for it | Phase 1 | conformance |
| FR-SPINE-032 | Host integration guide | P2 | `docs/integrating-a-host.md` is sufficient on its own: endpoint discovery, framing, `Hello` and session binding, the file-tail mode, one example per minimum event, `validate-events`, and the conformance checklist | Phase 1 | manual |
| FR-SPINE-033 | Host manifest on Hello | P1 | A valid `Hello.host_manifest` on an `ext:` connection resolves to a `hostprofile.Profile` stored on the session and reachable through the admission session context (ADR-0013) | Phase 2 | unit |
| FR-SPINE-034 | Host manifest via sidecar | P1 | The sidecar's `host_manifest` block goes through the same validator as `Hello.host_manifest`; the same input yields an identical `Profile` on both transports | Phase 2 | unit |
| FR-SPINE-035 | Default profile when absent | P0 | A session with no manifest — every first-party writer — resolves to exactly `hostprofile.Default` (`OwnsConfigSurface`, `OwnsMemory`, `ArrestMode: act`; nothing else set), and `Canonical(Default)` is byte-pinned | Phase 2 | unit |
| FR-SPINE-036 | Invalid manifest refused | P1 | Empty `host_id`/`host_version`, `arrest_mode` unspecified, `owns_execution` false on `ext:`, an unaccepted `schema_version`, or a manifest from a non-`ext:` writer closes the connection / leaves the file untailed with `M1E-4007`, admitting nothing | Phase 2 | negative |
| FR-SPINE-037 | Profile exposed to consumers | P1 | Provisioning `Apply`, the gate's `Answer` and memory's `record` read the session's profile and log it once per session at debug; with no manifest each reads `Default`; no decision changes on it in this feature | Phase 2 | unit |
| FR-SPINE-038 | Host registry | P2 | A checked-in `hosts.json` lists known hosts with their expected manifest, `cem888` first; `Lookup` hits and misses; the handshake logs known/unknown and refuses nothing | Phase 2 | unit |

End of §9.2.

### 9.3 FR-VERIFY-*

| ID | Statement | P | Acceptance criterion | Holds by | Verification |
|---|---|---|---|---|---|
| FR-VERIFY-001 | Consented local catalog | P0 | Catalog derives only from workspace inspection; unconsented anchor never runs; catalog change forces re-consent before next run; `mark1 doctor` lists it | Phase 2 | negative |
| FR-VERIFY-002 | Sandboxed runner | P0 | In-sandbox probes: outbound connect fails, non-allow-listed env var absent, write outside worktree fails, resource cap kills a runaway, kill switch terminates mid-run | Phase 2 | negative |
| FR-VERIFY-003 | Static default / opt-in tests | P0 | Default catalog contains only side-effect-free anchors; a test anchor refuses to run with the sandbox precondition unmet | Phase 2 | negative |
| FR-VERIFY-004 | AnchorIntegrity envelope | P0 | Every `AnchorVote` fixture carries all six integrity fields; binary hash is of the resolved executable (symlink/PATH-independent); vote signature verifies against device key | Phase 2 | unit |
| FR-VERIFY-005 | Tamper detection triad | P0 | Worktree mutation and PATH shim each raise `tamper` in the anti-tamper suite; an injected suppression directive yields a non-zero `suppression_directive_delta` on a vote that stands annotated; tamper-flagged vote excluded from corpus fixtures | Phase 2 | negative |
| FR-VERIFY-006 | Direct-product NB fusion | P0 | Fusion output matches hand-computed posteriors on golden vote sets, including correlation-group handling and abstention | Phase 2 | unit |
| FR-VERIFY-007 | Gate reads cache only | P0 | Gate handler instrumented: zero anchor executions, zero network calls, zero fusion passes during gate evaluation; latency bounded per NFR-LATENCY-002 | Phase 2 | unit |
| FR-VERIFY-008 | Fast/slow split | P0 | PostToolUse burst triggers exactly one debounced refresh; slow-anchor completion yields a `REVISED` verdict and a next-turn hook-context correction fixture | Phase 2 | conformance |
| FR-VERIFY-009 | Knee formula | P0 | Governor decision matches the inequality on a golden table of `(p̂_LCB, V, c)` triples under both `usd` and `quota` bases | Phase 2 | unit |
| FR-VERIFY-010 | Hard caps precede bundles | P0 | Bundle attempting >3 consecutive blocks or exceeding the hourly ceiling is clamped locally; disable check ordering verified before gate math executes | Phase 2 | negative |
| FR-VERIFY-011 | Knee UX contract | P0 | At-knee fixture surfaces verdict + evidence to the human; below-knee fixture returns `decision:"block"` with failure evidence as continuation reason | Phase 2 | conformance |
| FR-VERIFY-012 | Bootstrap → spectral D-S | P0 | With <3 independent groups, spectral path provably not taken (weighted majority used, status says so); with synthetic identifiable data, spectral estimates recover planted confusion matrices within tolerance | Phase 4 | unit |
| FR-VERIFY-013 | Certificate preconditions | P0 | Below gold-set size/freshness threshold, status is `uncertified/bootstrapping` and memory/corpus gates reject the verdict; above, a certificate issues with (ρ₊, ρ₋) | Phase 4 | negative |
| FR-VERIFY-014 | Edge-indistinguishable gold | P0 | Diff of edge-observable behavior on gold vs ordinary tasks is empty (no marker field, no timing tell in fixtures); selection is server-side only | Phase 4 | negative |
| FR-VERIFY-015 | Client-side-first judges | P1 | Default-config judge run makes zero cloud-judge calls; cloud path refuses without the consent flag + subprocessor entry + region pin | Phase 4 | negative |
| FR-VERIFY-016 | Evidence tiers typed | P1 | E1 payload without a redaction receipt fails admission; E2 payload outside VPC/self-host mode fails at type level | Phase 4 | negative |
| FR-VERIFY-017 | Scoped consistency votes | P1 | `ConsistencyVote` emitted only on escalation/T3 fixtures; ensemble-size accounting excludes them | Phase 4 | unit |
| FR-VERIFY-018 | Paper II reproduction | P1 | Adjudicator reproduces the posterior/verdict table on synthetic outputs; crowd-kit matches as oracle; crowd-kit absent from runtime deps | Phase 2 | unit |
| FR-VERIFY-019 | Prior-deviation review | P1 | Tenant with planted deviant priors is routed to manual review, not auto-certified | Phase 4 | unit |
| FR-VERIFY-020 | Verdict stage/posterior shape | P0 | Schema validation rejects any stage outside `PROVISIONAL\|CERTIFIED\|REVISED` and any posterior not a 4-vector over the CON-006 vocabulary | Phase 2 | unit |

End of §9.3.

### 9.4 FR-CORTEX-*, FR-ROUTE-*, FR-REMEMBER-*, FR-LEARN-*

| ID | Statement | P | Acceptance criterion | Holds by | Verification |
|---|---|---|---|---|---|
| FR-CORTEX-001 | L0 merkle, shared root | P0 | File mutation changes root within the notify window; anchor anti-tamper consumes the same table (one implementation, asserted by symbol reference) | Phase 2 | unit |
| FR-CORTEX-002 | L1/L2 required, L3 opportunistic | P0 | Tags and PPR ranks produced on fixture repos; SCIP absence degrades rank quality only — indexing completes and maps deliver | Phase 2 | unit |
| FR-CORTEX-003 | Budgeted session-start map | P0 | Map token count ≤ budget across fixture repos (binary-search convergence test); delivery only via the three named surfaces | Phase 2 | unit |
| FR-CORTEX-004 | Scoped MCP tools | P0 | Tool call for a path outside the enrolled workspace is refused; missing loopback token ⇒ refused; `../` traversal ⇒ refused | Phase 2 | negative |
| FR-CORTEX-005 | CortexInjection events | P0 | Every fixture delivery produces `CortexInjection{root_hash, index_clock}` in the ledger | Phase 2 | unit |
| FR-CORTEX-006 | Workspace-scoped reads | P0 | Filesystem audit of cortexd on a session shows zero reads outside enrolled roots; `.mark1ignore`d files unindexed | Phase 2 | negative |
| FR-CORTEX-007 | 5-part cache key | P1 | Bumping any key component invalidates exactly the affected entries (hit/miss accounting test) | Phase 2 | unit |
| FR-CORTEX-008 | Measured uplift only | P1 | Uplift figures in reports derive from tenant verdict joins (query ref present); literature numbers appear only as cited literature | Phase 2 | manual |
| FR-ROUTE-001 | Full RouteDecision logging | P0 | First routed request in a fixture session already carries all six fields; a missing propensity fails schema validation | Phase 3 | unit |
| FR-ROUTE-002 | Fidelity gating of OPE | P0 | OPE input assembler drops `ADVISORY` rows, admits `CONFIG_STEERED` only with a served-model join, and passes `WIRE_ENFORCED`; violation fixtures fail | Phase 5 | negative |
| FR-ROUTE-003 | ε=0 default | P0 | Default bundle yields propensity 1.0 on every decision; nonzero ε bundle refused without the tenant opt-in flag | Phase 3 | negative |
| FR-ROUTE-004 | Dual cost basis | P0 | Knee tables validate under both bases; report generator refuses a mixed-basis aggregate (shared with CON-014) | Phase 3 | unit |
| FR-ROUTE-005 | Rewrite only behind guard | P0 | Model-rewrite code path unreachable without a provenance-passed credential (call-graph + runtime negative test) | Phase 3 | negative |
| FR-ROUTE-006 | CPVS + keep_prefix ladders | P1 | Ladder evaluation honors `keep_prefix` on golden tables; prefix principle preserved under escalation fixtures | Phase 3 | unit |
| FR-ROUTE-007 | Single choice point | P1 | Grep/CI assertion: `RouteDecision` constructor referenced only from `mark1d`'s route module | Phase 3 | unit |
| FR-ROUTE-008 | Typed-struct evaluation | P1 | Gate-path profile shows zero decode/parse work per evaluation; structs built once at bundle apply | Phase 3 | unit |
| FR-REMEMBER-001 | Typed artifacts only | P0 | Schema rejects an artifact outside the four types; no free-text body field exists | Phase 4 | unit |
| FR-REMEMBER-002 | Certified-only extraction | P0 | Extraction over a corpus containing uncertified/tampered sessions consumes only certified, untampered ones (provenance check on outputs) | Phase 4 | negative |
| FR-REMEMBER-003 | ADMIT-LCB admission | P0 | Artifact with LCB ≤ 0 rejected; with LCB > 0 admitted; boundary fixtures pin the confidence computation | Phase 4 | unit |
| FR-REMEMBER-004 | Delivery contract | P0 | Memory pack appears at `TaskOpen` via HOOK_CONTEXT; pitfall-remedy fires on PostToolUseFailure fixture; `routing_hint` never appears in any injection payload | Phase 4 | conformance |
| FR-REMEMBER-005 | Injection/outcome events | P0 | Every delivery ⇒ `MemoryInjection`; every task close ⇒ `ArtifactOutcome`; joins reconstruct the LCB input | Phase 4 | unit |
| FR-REMEMBER-006 | Nightly batch cascade | P1 | Extraction job runs on the Batch API with cascade order verified (cheap rung first, escalation on ambiguity fixtures) | Phase 4 | unit |
| FR-REMEMBER-007 | Receipted admissions, revocation check | P0 | Every admission produces a per-event receipt; secret-bearing delivery to a revoked device is refused (fail-closed) | Phase 4 | negative |
| FR-REMEMBER-008 | One vector case | P1 | pgvector `halfvec` HNSW column is the only vector index in any migration; error-signature fuzzy match returns planted neighbors | Phase 4 | unit |
| FR-LEARN-001 | Certified corpus admission | P0 | Export over mixed corpus contains only certified, tamper-free trajectories, each with `label_confidence` populated | Phase 5 | negative |
| FR-LEARN-002 | Dual export artifact | P0 | One export run yields Parquet + `manifest.json`/`rows.jsonl` (KtoRow-shaped) with a single receipt covering both; trainer loads the JSONL pair unmodified | Phase 5 | conformance |
| FR-LEARN-003 | Per-tenant default training | P0 | Cross-tenant training job refuses without receipted opt-in; DP-SGD run debits ε ledger; canary memorization test blocks a leaking checkpoint | Phase 6 | negative |
| FR-LEARN-004 | Probation pipeline | P0 | A trained artifact cannot reach `active` without shadow votes + LCB promotion + canary records in the registry (state-machine test) | Phase 6 | negative |
| FR-LEARN-005 | Router promotion bar | P1 | Candidate router with held-out DR/SNIPS ≤ incumbent is not canaried (promotion gate test) | Phase 6 | unit |
| FR-LEARN-006 | CorpusReader extension | P1 | `mark1-parquet` source is a constructor + method pair on `CorpusReader` matching existing signatures; no new trait introduced (API diff) | Phase 5 | unit |
| FR-LEARN-007 | Erasure lineage | P1 | Given an erasure request fixture, lineage identifies every affected export/checkpoint and the retrain path executes on a toy corpus | Phase 6 | conformance |

End of §9.4.

### 9.5 FR-AGENT-*, FR-CLI-*, FR-ENROLL-*, FR-POLICY-*, FR-FED-*

| ID | Statement | P | Acceptance criterion | Holds by | Verification |
|---|---|---|---|---|---|
| FR-AGENT-001 | Maps as bundle data | P0 | A simulated agent field rename is fixed by a bundle push alone — no binary rebuilt; renamed-field fixture parses under the new map | Phase 1 | conformance |
| FR-AGENT-002 | Version sniffing | P0 | Unsupported-version fixture produces `Dropped{unsupported_agent_version}` and zero parsed events from that surface | Phase 1 | negative |
| FR-AGENT-003 | Fenced provisioning | P0 | Provisioned files carry fenced, checksummed fragments only; user content outside fences byte-identical after enable/off cycle; `mark1 doctor` lists every line | Phase 1 | conformance |
| FR-AGENT-004 | Pinned-version fixtures | P0 | CI replays hook + transcript fixtures per pinned agent version through the adapter; fixture drift fails the build | Phase 1 | conformance |
| FR-AGENT-005 | One schema, all agents | P0 | Events from any two adapters validate against the same `m1p.v1` families with no adapter-specific event type | Phase 2 | conformance |
| FR-AGENT-010 | Claude Code adapter | P0 | Golden hook fixtures + recorded transcripts replay end-to-end (`mark1d` → `controld` → ClickHouse); `(message.id, requestId)` + sidechain dedupe verified against the known ~2.5× overcount corpus | Phase 1 | conformance |
| FR-AGENT-011 | Codex spike then adapter | P0 | Go/no-go artifact for `TokenCountEvent` exists and is dispositioned **before** any adapter code merges; on go, Codex fixtures replay in CI | Phase 2 | manual + conformance |
| FR-AGENT-012 | Gemini spike then adapter | P0 | Go/no-go artifact for `BeforeModel`-in-OAuth exists and is dispositioned before adapter code; routing decisions carry honest fidelity | Phase 3 | manual + conformance |
| FR-AGENT-013 | opencode spike gate | P1 | Go/no-go artifact enumerating surfaces per regime exists before any opencode adapter code merges | Phase 4 | manual |
| FR-AGENT-014 | Copilot regime split | P1 | Go/no-go artifact for `events.jsonl` exists before adapter code; GitHub-billed session provably never touches the wire path (negative test) | Phase 5 | manual + negative |
| FR-AGENT-015 | Cursor observe/gate only | P1 | Go/no-go artifact exists before adapter code; no wire path reachable without customer-owned credential provenance | Phase 5 | manual + negative |
| FR-AGENT-016 | Crush reserved slot | P2 | No Crush code exists in the repo until a dispositioned go/no-go artifact does (CI check on directory contents) | — | negative |
| FR-CLI-001 | enroll | P0 | Device-code flow completes against a test IdP; key lands per FR-ENROLL-003 | Phase 1 | conformance |
| FR-CLI-002 | enable is the only door | P0 | Capture from an un-enabled workspace is zero events; enable emits consent record + receipted `CoverageTransition` | Phase 1 | negative |
| FR-CLI-003 | status | P0 | Output enumerates workspaces, tailers, surfaces, bundle seq, spool health; hidden active surface = test failure | Phase 1 | conformance |
| FR-CLI-004 | doctor | P0 | Output diffs byte-for-byte against actually provisioned lines; anchor catalog matches consent store | Phase 2 | conformance |
| FR-CLI-005 | report refusal | P0 | Below-floor request yields refusal; at-floor yields report with band + basis on every figure | Phase 4 | negative |
| FR-CLI-006 | off completeness | P0 | Byte-equality snapshot of agent config and behavior after `mark1 off`; receipted `CoverageTransition` present | Phase 1 | conformance |
| FR-CLI-007 | verify-receipts offline | P0 | Command validates the chain with Omium endpoints blackholed | Phase 1 | conformance |
| FR-CLI-008 | Typed CLI errors | P1 | Every failure path exits nonzero with a taxonomy error code (exhaustive table test) | Phase 1 | unit |
| FR-CLI-009 | Daemon lifecycle + self-update | P1 | Per-platform artifacts golden-pinned; supervisor argv proven through one exec seam; install→status→uninstall round-trip byte-exact; update refuses on failed verification, replayed manifest, live session or a daemon that will not stop | Phase 1 | unit |
| FR-ENROLL-001 | OIDC device-code only | P0 | No credential prompt exists in any enrollment path; flow conforms against a reference IdP | Phase 1 | conformance |
| FR-ENROLL-002 | ≤24 h tokens | P0 | Token older than 24 h rejected at ingest; expired-token edge parks uploads and keeps spooling | Phase 1 | negative |
| FR-ENROLL-003 | Keychain/TPM key custody | P0 | Key stored in platform keystore where available; fallback file is 0600; storage mode reported in `mark1 status` | Phase 1 | unit |
| FR-ENROLL-004 | Effective revocation | P0 | Post-revocation: upload rejected, bundle fetch refused, secret-bearing delivery refused (fail-closed) | Phase 1 | negative |
| FR-ENROLL-005 | Enrollment audit | P1 | Enroll/revoke each produce a per-event receipt; device row carries IdP binding + offboarding fields | Phase 1 | unit |
| FR-ENROLL-006 | Fingerprint binding | P1 | Credential HMAC mismatch at the guard ⇒ 403 (never a silent re-provision) | Phase 3 | negative |
| FR-ENROLL-007 | Personal tenants / Omium-hosted sign-in | P1 | HS256 or a non-P-256 pinned key refused; aud/iss/exp enforced; approve mints tenant + device once and re-issues idempotently; cross-tenant user token refused on the operator leg; a personal tenant cannot carry `org_id` (schema CHECK); pooled key selected by tenant kind only | Phase 1 | negative |
| FR-ENROLL-008 | Team v1 | P2 | Members/invites/shared-memory/TVO summary served under RLS to the tenant's principals only; cross-tenant read is empty; invite tokens are hashed at rest and expire in 7 days | Phase 4 | negative |
| FR-POLICY-001 | Bundle format | P0 | Canonical-CBOR round-trip stable; non-monotonic seq rejected; missing `prev_hash`/`max_age` rejected; unknown section rejected | Phase 3 | unit + fuzz |
| FR-POLICY-002 | No commands/code decode gate | P0 | Command-string-bearing bundle fails decode in both languages (shared with CON-009) | Phase 3 | negative |
| FR-POLICY-003 | Split KMS keys | P0 | Section signed with the wrong key fails verify; update key ≠ bundle key asserted in key inventory; both logged | Phase 3 | negative |
| FR-POLICY-004 | Edge verification triple | P0 | Bundle missing any of signature / higher seq / inclusion proof is not applied; last-known-good survives the rejection | Phase 3 | negative |
| FR-POLICY-005 | Fail-static + defaults | P0 | Control-plane blackhole: last-known-good runs indefinitely; clock past `max_age` ⇒ documented conservative defaults observed (knee=1, gates open, `stale_cert` flags) | Phase 3 | chaos |
| FR-POLICY-006 | Gates downgrade-only | P0 | Bundle attempting open→closed without local on-disk opt-in is clamped to open | Phase 3 | negative |
| FR-POLICY-007 | ACK-gated canarying | P0 | Fleet widening blocked until canary ACKs `(seq, hash)` + ledger TVO recorded; rollback publishes prior content under higher seq | Phase 3 | conformance |
| FR-POLICY-008 | Receipted, logged publication | P0 | Publication receipt + transparency-log entry exist before any edge ACK is possible (ordering test) | Phase 3 | unit |
| FR-POLICY-009 | SLSA-verified updates | P1 | Edge refuses an update lacking valid provenance; managed-fleet profile has self-update off | Phase 3 | negative |
| FR-POLICY-010 | Cross-language decoder parity | P1 | Go and Rust decoders agree on the shared conformance vector suite; divergence fails CI | Phase 3 | conformance |
| FR-FED-001 | k ≥ 25 verified orgs | P0 | Publication with 24 verified contributors fails; affiliated-org fixture collapses to one contributor | Phase 5 | negative |
| FR-FED-002 | m ≥ 5 intersection | P0 | Span present in only 4 tenants' contributions absent from every published body (reconstruction test) | Phase 5 | negative |
| FR-FED-003 | DB-level (k,m) | P0 | Direct SQL insert bypassing app code trips the trigger/`HAVING` constraint | Phase 5 | negative |
| FR-FED-004 | Invariants never federate | P0 | `invariant` artifact publication fails at schema level | Phase 5 | negative |
| FR-FED-005 | DP release + ε ledger | P0 | Release without a ledger debit is impossible (transactional coupling test); exhausted ε blocks release while capture continues | Phase 5 | negative |
| FR-FED-006 | Human review + opt-out | P0 | Unreviewed artifact cannot reach `published` state; opted-out tenant's spans absent from all pools | Phase 5 | negative |
| FR-FED-007 | Tenant-visible budgets | P1 | Tenant API/report exposes (k,m) defaults and current ε balance | Phase 5 | unit |

End of §9.5.

### 9.6 NFR-*

| ID | Statement | P | Acceptance criterion | Holds by | Verification |
|---|---|---|---|---|---|
| NFR-LATENCY-001 | Proxy ≤1 ms median | P0 | CI benchmark: median added latency ≤1 ms on the bytes-forward path under golden streaming load; regression fails the build | Phase 3 | conformance |
| NFR-LATENCY-002 | Shim 50 ms / bounded gates | P0 | Observer hook returns ≤50 ms regardless of daemon state (daemon-down fixture); gate deadline enforced by timer test | Phase 2 | unit |
| NFR-LATENCY-003 | Deadline-miss posture | P0 | Simulated deadline miss: observer path proceeds (fail-open), gate path follows its declared posture; agent never hangs | Phase 2 | chaos |
| NFR-LATENCY-004 | Nanosecond policy eval | P1 | Microbenchmark: policy evaluation allocation-free and sub-microsecond on typed structs | Phase 3 | unit |
| NFR-LATENCY-005 | Debounced refresh | P1 | N rapid PostToolUse events yield one refresh (counter test) | Phase 2 | unit |
| NFR-FOOTPRINT-001 | Proxy ≤35 MB RSS | P0 | Sustained-stream soak: RSS ≤35 MB; CI-enforced threshold | Phase 3 | conformance |
| NFR-FOOTPRINT-002 | 2 GiB / 95% caps | P0 | Fill simulation: cap honored, 95%-disk halts writes, billing classes block (shared with FR-SPINE-007) | Phase 1 | chaos |
| NFR-FOOTPRINT-003 | Map budget respected | P1 | No delivered map exceeds its bundle-configured budget across fixture repos | Phase 2 | unit |
| NFR-FOOTPRINT-004 | Capped, activity-aware anchors | P1 | Runaway anchor killed at cap; user-activity signal pauses scheduling (fixture) | Phase 2 | unit |
| NFR-DURABILITY-001 | Billing classes block | P0 | Spool-full: billing-grade write blocks (does not shed); unblocks on drain | Phase 1 | chaos |
| NFR-DURABILITY-002 | kill -9 safety | P0 | Same criterion as FR-SPINE-024 (one test, two IDs — the NFR is the budget, the FR is the mechanism) | Phase 1 | chaos |
| NFR-DURABILITY-003 | S3-first recoverability | P0 | Ledger wiped, replay from S3 alone reconstructs all acked events | Phase 1 | chaos |
| NFR-DURABILITY-004 | fsync + drain discipline | P1 | fsync cadence within 250–500 ms observed; `SessionEnd` forces drain (event-ordering test) | Phase 1 | unit |
| NFR-DURABILITY-005 | Ack-then-delete | P1 | Segment with one unacked record survives GC pass | Phase 1 | unit |
| NFR-AVAILABILITY-001 | No SPOF for coding | P0 | Kill each Mark 1 process in turn mid-session: the agent completes its task unmodified every time | Phase 2 | chaos |
| NFR-AVAILABILITY-002 | Receipted proxy bypass | P0 | Proxy crash mid-stream: client stream completes via bypass; bypass window receipted; capture continues via transcripts | Phase 3 | chaos |
| NFR-AVAILABILITY-003 | Indefinite fail-static | P0 | 7-day control-plane blackhole soak: edge behavior unchanged under last-known-good until `max_age` | Phase 3 | chaos |
| NFR-AVAILABILITY-004 | Supervised children | P1 | Crashed cortexd restarted with backoff; repeated crash degrades to fail-open capture, never agent blockage | Phase 2 | chaos |
| NFR-CORRECTNESS-001 | 2.5× overcount defeated | P0 | Overcount corpus replay: token totals match ground truth within exactness (no duplicate `Usage`) | Phase 1 | conformance |
| NFR-CORRECTNESS-002 | Paper I golden values | P0 | TVO engine output equals the worked example (shared with FR-SPINE-022) | Phase 1 | unit |
| NFR-CORRECTNESS-003 | Byte-exact SSE | P0 | Golden-transcript passthrough diff is empty per dialect | Phase 3 | conformance |
| NFR-CORRECTNESS-004 | Fuzzed decoders | P0 | M1PL + spool fuzz targets run in CI with no findings outstanding; oversized `len` rejected | Phase 1 | fuzz |
| NFR-CORRECTNESS-005 | Decoder parity | P1 | Shared conformance vectors pass in Rust and Go (shared with FR-POLICY-010, scope: M1P too) | Phase 3 | conformance |
| NFR-CORRECTNESS-006 | Canonical receipt hashing | P1 | Cross-language (Rust/Go/Python) hash equality on golden receipts with `mark1-label-v1\0` prefix | Phase 1 | unit |
| NFR-PRIVACY-001 | No paths/free text on wire | P0 | Wire-capture audit of default sessions: zero path strings, zero excerpts (shared with CON-004) | Phase 1 | negative |
| NFR-PRIVACY-002 | Salted digests | P0 | Same content under two tenants yields different digests; dictionary attack on fixture digests fails | Phase 1 | negative |
| NFR-PRIVACY-003 | ε accounting universal | P0 | Any DP release/DP-SGD run without a matching ledger debit is transactionally impossible | Phase 5 | negative |
| NFR-PRIVACY-004 | Per-tenant prefixes + KMS | P0 | Cross-tenant S3 read with tenant A's role on tenant B's prefix denied; KMS key policy per tenant verified | Phase 1 | negative |
| NFR-PRIVACY-005 | Evidence stays local | P1 | Default-config soak: zero bytes from `~/.omium/mark1/evidence/` on the wire | Phase 2 | negative |
| NFR-PRIVACY-006 | Consent-gated cloud judges | P1 | Cloud-judge call without consent flag + register entry + region pin refused (shared with FR-VERIFY-015) | Phase 4 | negative |
| NFR-PORTABILITY-001 | 3-OS CI | P0 | CI matrix runs macOS/Linux/Windows on every PR from the first commit; any red platform blocks merge | Phase 1 | conformance |
| NFR-PORTABILITY-002 | Windows named pipes | P0 | Fabric conformance suite passes on Windows with equivalent perms/framing/single-writer semantics | Phase 1 | conformance |
| NFR-PORTABILITY-003 | Static shim | P1 | `ldd`/dependency audit: shim binary has no dynamic runtime requirement beyond platform libc contract | Phase 1 | unit |
| NFR-PORTABILITY-004 | Explicit key-custody degradation | P1 | Fallback-to-file mode is visible in `mark1 status`; no silent downgrade | Phase 1 | unit |
| NFR-OPERABILITY-001 | Accounted loss | P0 | Induced shed/CRC/quarantine/version-drop each produce a matching `Dropped{}`; coverage band reflects them | Phase 1 | chaos |
| NFR-OPERABILITY-002 | Self-monitoring on M1P | P0 | Internal metrics arrive as M1P events; dependency scan shows no second telemetry stack (shared with CON-005) | Phase 1 | negative |
| NFR-OPERABILITY-003 | Visible quarantine | P1 | 4xx-parked batch listed in `mark1 status` with reason and retention | Phase 1 | unit |
| NFR-OPERABILITY-004 | Platform health conventions | P1 | Boot refusal crashloops (uncaught); pool exhaustion returns 503 + `Retry-After` | Phase 1 | unit |
| NFR-SECURITY-001 | Secret<T> discipline | P0 | Compile fails on Debug/Display/Serialize of a secret; CI grep gate red on raw credential types | Phase 3 | negative |
| NFR-SECURITY-002 | No core dumps | P0 | Process audit: `RLIMIT_CORE=0`, non-dumpable set; induced crash writes no core | Phase 3 | negative |
| NFR-SECURITY-003 | PR-gated isolation tests | P0 | The four-store negative suite is a required PR check (branch-protection audit) | Phase 1 | negative |
| NFR-SECURITY-004 | Supply-chain gates | P0 | Release pipeline emits SLSA attestation + CycloneDX SBOM; `cargo-deny` + `govulncheck` are required checks in omium-mark1 CI | Phase 1 | conformance |
| NFR-SECURITY-005 | Weekly token-shape canary | P0 | Canary job scheduled weekly; a planted classifier miss turns CI red | Phase 3 | negative |
| NFR-SECURITY-006 | No unprovisioned forward | P0 | Negative test proves no code path forwards an unprovisioned credential (shared with CON-001) | Phase 3 | negative |
| NFR-SECURITY-007 | 0600 everywhere local | P1 | Perm audit across sockets, spool, spill, token files; loopback rejects tokenless calls | Phase 1 | negative |
| NFR-SECURITY-008 | Pinned token-path deps | P1 | Vendored/pinned manifest for shim + proxy token paths; unpinned addition fails review gate | Phase 1 | manual |

End of section 9.

---

## 10. Phase gate checklists

For each assembly phase, the frozen plan's bold **Gate:** sentence is reproduced verbatim, then decomposed into the requirement IDs that must all be green. **A gate passes when its list passes; nothing else counts** — no demo, no judgment call, no partial credit. P1/P2 items scheduled in a phase but absent from its gate list do not block the gate.

### Phase 1 — Spine + subscription-legal capture

> **Gate: end-to-end certified usage events, verifiable offline by the customer.**

Green required: CON-003, CON-004, CON-005, CON-006, CON-008, CON-010, CON-012 · FR-SPINE-001…022, FR-SPINE-024, FR-SPINE-026 · FR-AGENT-001…004, FR-AGENT-010 · FR-CLI-001, FR-CLI-002, FR-CLI-003, FR-CLI-006, FR-CLI-007 · FR-ENROLL-001…004 · NFR-DURABILITY-001…003 · NFR-CORRECTNESS-001, -002, -004, -006 · NFR-PRIVACY-001, -002, -004 · NFR-PORTABILITY-001, -002 · NFR-OPERABILITY-001, -002 · NFR-SECURITY-003, -004 · NFR-FOOTPRINT-002. Plus: ADR-0001 and ADR-0002 signed (section 12), and the ≥1-week dogfood run producing the first real TVO report.

Concurrent spike artifacts (gate the *adapter slots*, not this phase): FR-AGENT-011, FR-AGENT-012, FR-AGENT-014 go/no-go artifacts produced.

### Phase 2 — VERIFY provisional loop + Cortex push

> **Gate: retry loops demonstrably arrested at the knee on live sessions; Cortex uplift measurable in the ledger.**

Green required: CON-009 (catalog/consent half), CON-013 · FR-VERIFY-001…011, FR-VERIFY-018, FR-VERIFY-020 · FR-CORTEX-001…006 · FR-AGENT-005, FR-AGENT-011 (adapter live, given a "go") · FR-CLI-004 · NFR-LATENCY-002, -003 · NFR-AVAILABILITY-001 · NFR-PRIVACY-005. Evidence: the A/B on our own tasks with and without the stop-gate, iteration-count delta reported with confidence intervals; cortex uplift as a ledger query (FR-CORTEX-008 methodology).

### Phase 3 — Wire proxy + ROUTE

> **Gate: zero client-visible streaming regressions under chaos; guard canary green.**

Green required: CON-001, CON-002, CON-007, CON-009 (decode half), CON-015 (pool keying, sidecar scope) · FR-SPINE-025 · FR-ROUTE-001, -003, -004, -005 · FR-POLICY-001…008 · FR-ENROLL-006 · FR-AGENT-012 (adapter live, given a "go") · NFR-LATENCY-001, -004 · NFR-FOOTPRINT-001 · NFR-AVAILABILITY-002, -003 · NFR-CORRECTNESS-003, -005 · NFR-SECURITY-001, -002, -005, -006.

### Phase 4 — Adjudication at strength + REMEMBER

> **Gate: first noise-certified customer report with a coverage band.**

Green required: CON-014 · FR-VERIFY-012…017, FR-VERIFY-019 · FR-REMEMBER-001…005, FR-REMEMBER-007 · FR-CLI-005 · FR-AGENT-013 (spike dispositioned; adapter live given a "go") · NFR-PRIVACY-006. The report itself is the artifact: noise-certified verdicts under an active certificate, coverage band ≥ floor, cost basis stated.

### Phase 5 — Enterprise + federation + LEARN

> **Gate: first cross-org artifact published through the full k,m∩ / DP / LCB / review pipeline.**

Green required: CON-011, CON-015 (gateway scope) · FR-FED-001…006 · FR-LEARN-001, -002, FR-LEARN-006 · FR-ROUTE-002 · FR-AGENT-014, FR-AGENT-015 (adapters live given "go"s) · NFR-PRIVACY-003. The published artifact must carry its receipt trail: (k,m) evidence, DP debit, LCB admission record, review sign-off.

### Phase 6 — Learned members + certified tier + self-host

> *(The frozen plan states no bold **Gate:** sentence for Phase 6 — the only phase without one. This checklist is therefore derived from the phase's content and is **not** plan-verbatim; the derivation must be confirmed at reconciliation and recorded in `14-delivery-plan.md`.)*

Derived gate: *first learned component promoted to `active` through probation → shadow → LCB → canary, with cross-tenant training and T3 runs opt-in-gated.* Green required: FR-LEARN-003, -004, -005, -007 · plus the Phase 6 triggers honored: NATS/MSK evaluation only when a second independent ledger consumer exists (ADR per grounding delta 3); T3 opt-in only; self-host SKU behind its phase gate.

End of section 10.

---

## 11. Traceability matrix

Requirement → owning component → design-doc section → test home in `12-testing-and-quality.md`. Documents 03–14 are not yet written, so downstream references use `TBD-<doc>`; section numbers must not be invented — the author of each downstream doc replaces its `TBD` on landing, and reconciliation fails while any row's owner disagrees with the doc that lands. Rows group contiguous IDs sharing an owner.

| Requirement(s) | Component(s) | Design doc | Test home |
|---|---|---|---|
| CON-001, CON-002, NFR-SECURITY-001/-002/-005/-006 | `mark1-proxy` (guard, tee), `mark1d.identity` | TBD-04, TBD-10 | TBD-12 (negative: guard; conformance: token-shape canary) |
| CON-003, FR-AGENT-003, FR-CLI-004/-006 | `mark1d` provisioner, `mark1` CLI | TBD-04, TBD-08 | TBD-12 (conformance: byte-equality snapshot) |
| CON-004, NFR-PRIVACY-001/-002/-005, FR-VERIFY-016 | `m1p.v1` EvidenceRecord, `mark1-redact`, adjudicator | TBD-07, TBD-10 | TBD-12 (negative: wire audit) |
| CON-005, NFR-OPERABILITY-002 | all (dependency policy), self-monitoring | TBD-11, ADR-0005 | TBD-12 (negative: lockfile scan) |
| CON-006, FR-VERIFY-020 | `m1p.v1`, PG enums, adjudicator | TBD-07 | TBD-12 (unit: enum diff) |
| CON-007, FR-POLICY-005/-006, NFR-AVAILABILITY-001…004 | `mark1d`, `mark1-proxy`, `mark1-policy` | TBD-04, TBD-05 | TBD-12 (chaos: posture suite) |
| CON-008, FR-SPINE-012/-025, NFR-PRIVACY-002 | `mark1-redact`, `mark1-hookshim`, `controld.ingest` | TBD-04, TBD-05, TBD-10 | TBD-12 (negative: plaintext-persistence audit) |
| CON-009, FR-POLICY-001…004/-010, FR-VERIFY-001 | `mark1-policy`, `controld.policydist`, Go decoder | TBD-04, TBD-05, TBD-07 | TBD-12 (negative: decode rejection; fuzz: CBOR) |
| CON-010, FR-SPINE-011, NFR-SECURITY-003, NFR-PRIVACY-004 | `controld.ingest`, `controld.querychoke`, migrations (RLS), S3/KMS | TBD-05, TBD-07, TBD-09 | TBD-12 (negative: four-store isolation suite) |
| CON-011, FR-FED-001…007, NFR-PRIVACY-003 | `mark1-intel.memory`, `controld.dprelease`, migrations | TBD-06, TBD-07 | TBD-12 (negative: federation suite) |
| CON-012, FR-SPINE-026, FR-CLI-002/-003/-005 | `mark1d.tailers`, `mark1d.coverage`, `mark1` CLI | TBD-04, TBD-08 | TBD-12 (negative: read-surface audit) |
| CON-013, FR-VERIFY-010 | `mark1d.verdict` (gate path), `mark1` CLI | TBD-04 | TBD-12 (conformance: off snapshot; unit: check ordering) |
| CON-014, FR-CORTEX-008 | `mark1-intel.tvo` report generator | TBD-06 | TBD-12 (unit + manual: claim review) |
| CON-015, FR-ENROLL-006 | `mark1-proxy` gateway pooling | TBD-04, TBD-10 | TBD-12 (negative: pool keying) |
| FR-SPINE-001…003, FR-SPINE-023 | `m1p-wire`, proto/m1p/v1, `m1p-registry` | TBD-07, TBD-08 | TBD-12 (unit; conformance: schema windows) |
| FR-SPINE-004…007, FR-SPINE-024, NFR-DURABILITY-001…005, NFR-FOOTPRINT-002 | `mark1d.spool`, `m1p-wire` framing | TBD-04, TBD-07 (binary layout) | TBD-12 (fuzz: decoders; chaos: kill/full/95%) |
| FR-SPINE-008…014 | `mark1d.uplink`, `controld.ingest`, ClickHouse DDL | TBD-05, TBD-07, TBD-08 | TBD-12 (conformance: ingest; chaos: retry/S3) |
| FR-SPINE-015…020, NFR-CORRECTNESS-006 | `mark1-receipt`, `python/shared/mark1_receipts`, `controld`, `rust/verifier` | TBD-05, TBD-07, TBD-10 (ceremony) | TBD-12 (unit: chain; conformance: offline verify; negative: append-only) |
| FR-SPINE-021/-022, NFR-CORRECTNESS-002 | `mark1-intel.tvo`, ADR-0002 | TBD-06 | TBD-12 (unit: golden TVO) |
| FR-VERIFY-001…005 | `mark1d.anchors`, `cortexd` (merkle) | TBD-04 | TBD-12 (negative: sandbox + anti-tamper suite) |
| FR-VERIFY-006…011 | `mark1d.verdict` (fusion, gate, knee) | TBD-04 | TBD-12 (unit: fusion/knee golden; conformance: gate UX) |
| FR-VERIFY-012…019 | `adjudicator-svc` | TBD-06 | TBD-12 (unit: Paper II reproduction; negative: cert preconditions) |
| FR-CORTEX-001…008, NFR-FOOTPRINT-003 | `cortexd` | TBD-04 | TBD-12 (unit: index/rank; negative: scoping) |
| FR-ROUTE-001…008 | `mark1d.policy`+`verdict`, `mark1-intel.policy_compiler`, `mark1-intel.ope` | TBD-04, TBD-06 | TBD-12 (unit: ladders/knee; negative: fidelity gating) |
| FR-REMEMBER-001…008 | `mark1-intel.memory`, migrations (pgvector) | TBD-06, TBD-07 | TBD-12 (unit: LCB; negative: certified-only; conformance: delivery) |
| FR-LEARN-001…007 | `mark1-intel.corpus`, `omium-training-plane` (data-refinery `CorpusReader`), adjudicator (registry) | TBD-06 | TBD-12 (conformance: dual export; negative: opt-in/probation) |
| FR-AGENT-001…005 | `mark1d.adapters` (shared), `mark1-hookshim`, bundles `agent_maps` | TBD-04, TBD-08 | TBD-12 (conformance: fixture replay; negative: version sniff) |
| FR-AGENT-010…016 | `mark1d/adapters/{claudecode,codex,gemini,opencode,copilot,cursor,crush}` | TBD-03 (capability matrix), TBD-04 | TBD-12 (conformance per pinned version; manual: spike artifacts) |
| FR-CLI-001…008 | `go/mark1` | TBD-08 | TBD-12 (conformance: CLI suite) |
| FR-ENROLL-001…006 | `controld.enroll`, `mark1d.identity`, keystore integration | TBD-05, TBD-10 | TBD-12 (conformance: device-code; negative: revocation/expiry) |
| FR-POLICY-001…010 | `controld.policydist`, `mark1-policy`, `mark1-intel.policy_compiler`, transparency log | TBD-05, TBD-07 (CBOR schema) | TBD-12 (negative: verification triple; chaos: fail-static; fuzz) |
| FR-FED-001…007 | `mark1-intel.memory` (federation), `controld.dprelease`, migrations | TBD-06, TBD-07 | TBD-12 (negative: (k,m)/DP suite) |
| NFR-LATENCY-001…005, NFR-FOOTPRINT-001 | `mark1-proxy`, `mark1-hookshim`, `mark1-policy` | TBD-04, TBD-11 (SLOs) | TBD-12 (conformance: CI benchmarks) |
| NFR-CORRECTNESS-001/-003/-004/-005 | `mark1d.tailers`, `mark1-proxy`+`mark1-frames`, `m1p-wire` | TBD-04 | TBD-12 (conformance: golden SSE/overcount; fuzz) |
| NFR-PORTABILITY-001…004 | CI matrix, fabric, shim, keystore | TBD-13 | TBD-12 (conformance: 3-OS matrix) |
| NFR-OPERABILITY-001/-003/-004 | `mark1d`, `controld`, cloud services | TBD-11 | TBD-12 (chaos: loss accounting; unit) |
| NFR-SECURITY-004/-007/-008 | release pipeline, local file surfaces, dep manifests | TBD-09 (edge distribution), TBD-13 | TBD-12 (conformance: SLSA/SBOM gates; negative: perms) |

End of section 11.

---

## 12. Open requirements — blocked on the four ADRs

These requirements are stated above but cannot be finally accepted until their ADR is signed. Each ADR is a founder-sign-off item per the frozen plan ("Decisions to make before code"); the blocked requirements list what its signature unblocks. No code for a blocked area may merge before its ADR.

**Signature record (2026-09-16, D-EI):** ADR-0001, ADR-0002, ADR-0004, ADR-0009 and ADR-0010 are **Accepted**, signed by the founder as recommended. Their blocked requirements below are unblocked; ADR-0003 stays Proposed/deferred by the same ruling.

| ADR | Decision | Blocked requirements | What unblocks each |
|---|---|---|---|
| **ADR-0001** — ClickHouse ordering key | `ReplacingMergeTree` layout and `ORDER BY (tenant_id, toDate(occurred_at), session_id, event_id)` — the one irreversible decision | FR-SPINE-013 (final DDL), FR-SPINE-014 (merge semantics), and every §9 criterion that queries the ledger by that key | Signature before the first production write. The DDL in `07-data-model.md` must cite the signed ADR; CI blocks the ClickHouse migration until it does |
| **ADR-0002** — `task_seg.v1` merge rules | The exact values of "follow-up within N turns touching the same files", the file-set comparison, and the `unresolved` class boundaries — the TVO denominator, hence every number ever quoted | FR-SPINE-021, FR-SPINE-022, NFR-CORRECTNESS-002 (the golden values depend on segmentation), CON-014 (a report is only ledger-traceable if its denominator is versioned) | Signature before TVO engine v1 emits any customer-visible number. Dogfood may run earlier with the draft algorithm, labeled draft |
| **ADR-0003** — the Shapley game | Players and `v(S)` for waste attribution | None currently normative — by design. FR-SPINE-022 requires the *deterministic taxonomy* and explicitly bans Shapley code pre-ADR. A future `FR-SPINE-0xx` (Shapley attribution) enters this document only after signature | Signature converts the ban into a requirement; until then the taxonomy ships alone |
| **ADR-0004** — key ceremony | Device keys, server chain key, section-split bundle keys, update key ≠ bundle key, rotation and cross-signing, witness selection | FR-SPINE-017…020 (rotation/cross-sign details), FR-POLICY-003 (which KMS keys, split boundaries), FR-ENROLL-003 (custody hierarchy), NFR-SECURITY-004 (what provenance signs releases) | Signature before Phase 1's receipt code freezes its schema columns (`key_id`, rotation) and before the witness target is provisioned |

Two further items are tracked here because they gate requirement *acceptance* without being ADRs: the founder/counsel review of Anthropic §D.4 gates any FR-LEARN work touching the training clause (FR-LEARN-003 onward), and the Phase 6 gate sentence gap (section 10) must be resolved at reconciliation before `14-delivery-plan.md` freezes its milestone table.

---

*End of 02 — Requirements. 181 requirements: 15 CON, 120 FR, 46 NFR. Every phase gate in section 10 resolves to rows in section 9; every row in section 9 names a verification method a test can fail.*
