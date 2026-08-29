# Omium Mark 1 — Final System Architecture Specification

**Status:** Authoritative merged spec, v2.0 (2026-08-24). Supersedes the three companion designs (D1 system-architect, D2 dataplane-architect, D3 intelligence-architect). All naming, ownership, and contract conflicts between them are resolved here; where this spec and any predecessor disagree, this spec wins.

---

## 0. Critique disposition (read once, then the spec stands alone)

**Accepted in full (with the fix integrated below):**

| Critique | Disposition |
|---|---|
| C1.1 judge-evidence contradiction | Accepted. Tiered evidence levels (E0/E1/E2) + **client-side judge execution through the customer's own key** as the default where available — strictly better than any design had. |
| C1.2 gate-time vs anchor-time physics | Accepted. Fast/slow anchor classes; the stop-gate **reads cached state, never computes**. |
| C1.4 D-S identifiability at v1 volumes | Accepted. Global estimation + hierarchical shrinkage; test anchors are their own correlation group; spectral D-S activates behind an identifiability gate, weighted-majority + priors before that, cert status honestly labeled. |
| C1.5 TVO denominator undefined | Accepted. `task_seg.v1` is a versioned, receipted algorithm; `task_seg_version` stamps every TaskOpen. |
| C1.6 auto-run test suites | Accepted. Default anchors are side-effect-free static analysis; test anchors are per-repo opt-in with sandbox-as-precondition; `git worktree` + merkle tamper hashes replace full snapshots. |
| C1.8 ε-exploration on paying traffic; OPE fidelity | Accepted. ε defaults to 0 (opt-in per tenant, contractual); `fidelity` field on every RouteDecision; DR/SNIPS runs only over `WIRE_ENFORCED` or served-model-confirmed decisions. |
| C1.9 knee economics on subscription plans | Accepted. Dual `cost_basis: usd \| quota` in bundles; TVO reports state cost basis per cohort. |
| C1.10 receipt hot lock | Accepted. **Merkle checkpoint receipts** for high-volume events; per-event receipts reserved for rare, high-stakes items. |
| C1.11 / S3-19 cgo spool boundary | Accepted. cgo deleted. The daemon-path spool is implemented **in Go inside mark1d** (single writer, so "one durability implementation" survives); the proxy keeps a separate, simpler, redacted+encrypted tee spill ring in Rust. Spool decoder is fuzzed; `len` is bounds-checked. |
| C1.12 / S2-10.4 config clobbering | Accepted. Fenced, checksummed fragments and native include/extension mechanisms only; never rewrite files we don't exclusively own. |
| C1.13 unverified adapter surfaces | Accepted. Go/no-go spike artifacts gate each adapter slot; field maps and parser rules ship **as bundle data**, not compiled code; runtime version-sniffing with `Dropped{unsupported_agent_version}`. |
| C1.14 / S3-19 naming skew | Accepted. Canonical registry in §2; canonical names: `mark1d`, `mark1-proxy`, `mark1-hookshim`, `cortexd`; verdict fusion is owned by `mark1d` (§4, C3). |
| C1.15 self-host at launch | Accepted. Cloud-only until the stack stabilizes; `deploy/compose/` is an internal dev environment; self-host is a priced enterprise deliverable, phase-gated. |
| C1.16 "free" consistency votes | Accepted. Scoped to escalation events and T3 runs only; excluded from ensemble-size assumptions. |
| C1.17 undefined Shapley | Accepted. Deterministic waste taxonomy ships first; the Shapley game (players, v(S)) is an ADR precondition for any Shapley code. |
| C1.18 / S1-4 excerpt egress | Accepted. Typed error grammar is the default evidence; free-text excerpts are per-tenant opt-in, scrubbed, receipted. |
| S1-1 OAuth guard is a regex | Accepted. Allow-list credential **provenance** (`M1-Cred-Ref`) is primary; shape inspection demoted to second signal; upstream tripwire; weekly token-shape canary in CI; sampled receipted guard decisions. |
| S1-2 plaintext credentials | Accepted. `Secret<T>` newtype (no Debug/Display/Serialize, zeroize-on-drop); tee built from an explicit copied field subset, never a request clone; `RLIMIT_CORE=0` + non-dumpable; gateway credentials are **referenced** from a customer-run secret store, never persisted by Mark 1. |
| S1-3 pre-redaction persistence; detect ≠ don't-upload | Accepted. No plaintext pre-redaction persistence anywhere (shim links `mark1-redact`; spill files 0600/encrypted/TTL'd); redaction split into **mutate-in-transit** (default off) and **admit-to-upload** (fail-closed, no off switch); independent pre-egress scanner at ingest. |
| S1-4 digests as PII vectors; subprocessing | Accepted. Per-tenant HMAC-salted digests; structural normalization of error signatures; subprocessor register + tenant consent flags + region pinning for all Anthropic-bound evidence. |
| S1-5 bundle→RCE | Accepted. Anchors are **never server-named** (locally-derived catalog, bundle enables by ID only); sandbox is a security boundary (network-deny, env-scrub, RO binds); `wasm_module` **deleted from the v1 wire format**; split signing keys + transparency log with edge-verified inclusion proofs. |
| S1-6 operator-forgeable receipts | Accepted. Dual signature (device origin + server countersign); external witness anchoring of chain heads; `key_id` + rotation/revocation in schema; standalone open-source offline verifier. |
| S1-7 CH isolation repeating the RLS failure | Accepted. Ingest stamps `tenant_id` from the verified token, never the envelope; all analytics reads go through one query-chokepoint module with predicate-assertion tests; per-tenant S3 prefixes + KMS keys; negative isolation tests as CI gates on every store. |
| S1-8 (k,m) counts the wrong thing | Accepted. **Intersection-reconstructed bodies** (only spans ≥m tenants independently produced publish); m counts billing/domain-verified orgs with collusion collapse; k≥25/m≥5 defaults, tenant-visible; human review queue + tenant opt-out. |
| S1-9 corpus/training privacy | Accepted. Per-tenant models are the default; cross-tenant training is contractual opt-in with DP-SGD ε accounted in the same ledger, per-tenant canary memorization tests as a release gate, and checkpoint lineage + retrain-on-erasure written down. |
| S2-10…S2-16, S3-17, S3-18 | Accepted; integrated in §§2, 6, 9 (supply chain/SLSA, loopback tokens, gate DoS caps, effective-execution anti-tamper, gold-set-gated certificates, workspace-scoped tailers, OIDC enrollment + revocation, MCP scoping, coverage metric). |

**Rejected or modified:**

- **C1.3 (cut v1 to a fraction of the machine): rejected as scope reduction, accepted as consolidation + sequencing.** The founder directive is the full third-order system, designed completely; the correct response to team-size reality is (a) collapsing ~20 deployables into **9 canonical components** (§2) — the cloud side is two binaries, not seven — and (b) a dependency-driven assembly order (§8) in which every phase ships a working, revenue-relevant machine. Nothing is deleted from the design; construction is ordered.
- **C1.7 (defer the proxy "wholesale"): modified.** The proxy is fully specified now (its invariants shape the protocol and the legal posture) and is built in Phase 2 of assembly, after the hooks/transcript path proves the ledger end-to-end. Gateway mode and Bedrock/Vertex dialects are Phase 4. This captures the critique's sequencing benefit without orphaning the API-key/VPC segment the Mark 1 wedge research identifies as the viable enterprise path.
- **S1-5.4 alternative ("if wasm must exist, second HSM key"): the deletion branch is taken.** `wasm_module` does not exist in `m1p.v1` or `PolicyBundle v1` at all. Learned policies that need code ship in a future `PolicyBundle v2` with a second, differently-held signing key and per-tenant opt-in — one field number of cost, zero attack surface today.

---

## 1. System overview

Mark 1 is five planes around one spine, wrapped around coding agents through two structurally-separated capture regimes:

- **VERIFY** — an ensemble of weak verifiers (client-side anchors, LLM rubric judges, reward models, escalation-scoped consistency checks) fused by oracle-free adjudication into calibrated four-verdict outcomes (`satisfied|violated|refused|error`) with self-certified noise rates. It arrests retry loops at the compute-optimal knee *before* the human re-prompts.
- **REMEMBER** — typed experience artifacts (workflow templates, pitfall-remedy pairs, invariants, routing hints) distilled from certified sessions; per-tenant first, federated later behind (k,m)-intersection + DP + LCB do-no-harm gates.
- **CONTEXTUALIZE** — `cortexd`, local repo intelligence (BLAKE3 merkle file plane, tree-sitter tag plane, petgraph symbol graph with personalized PageRank, opportunistic SCIP precision) injected as budgeted ranked maps and MCP tools.
- **ROUTE** — signed, sequenced policy bundles carrying cost-per-verified-success routing tables, escalation ladders (prefix principle), and stop-at-knee governors, evaluated at the edge in nanoseconds, fail-static.
- **LEARN** — the existing omium-training-plane consuming certified-label Parquet exports to train verifiers, rankers, and routing policies that re-enter the system only through probation, noise certification, OPE, and canary.

**The spine — the TVO Ledger:** every event from every capture path lands, deduplicated, in S3→ClickHouse; every consequential decision (verdicts, admissions, bundles, exports, coverage transitions) is bound into a dual-signed, externally-witnessed Ed25519 receipt chain in Postgres. Tokens-per-verified-outcome, with its own coverage band and loss accounting, is the product artifact.

```
                     ┌────────────────────────── OMIUM CLOUD ──────────────────────────┐
                     │ controld(Go): ingest│enroll│policy-dist│dp-release│query-choke   │
                     │        │ S3-first ─► ClickHouse (ledger) ◄─ intel jobs           │
                     │ adjudicator-svc(Py)   mark1-intel(Py: memory│tvo│policy│ope│corpus)│
                     │ Postgres: receipts(dual-signed)│artifacts│certs│bundles│ε-ledger  │
                     │ external witness (transparency log / customer object-lock S3)    │
                     │ omium-training-plane (Rust+Py, LEARN)                             │
                     └────────▲───────────────────────────────────┬─────────────────────┘
              M1P/1 HTTPS     │ zstd protobuf batches   signed, sequenced, logged bundles
                              │                                   ▼
   ┌──────────────────────────┴────────────────────────────────────────────────────────┐
   │ CUSTOMER SIDE (dev sidecar / VPC gateway) — allow-listed workspaces only          │
   │  mark1d (Go): adapters(7) │ tailers │ anchor runner │ verdict fusion │ Go spool   │
   │              │ uploader │ policy client │ supervision │ coverage accounting       │
   │  mark1-hookshim(Rust, links redact) ─UDS─► mark1d ◄─UDS─ cortexd(Rust)            │
   │  mark1-proxy(Rust; API-key traffic ONLY; cred-provenance guard; bytes-forward)    │
   │  agents: Claude Code │ Codex │ Gemini CLI │ opencode │ Copilot │ Cursor │ Crush   │
   └───────────────────────────────────────────────────────────────────────────────────┘

FLYWHEEL: capture → VERIFY labels (noise-certified) → dual-signed receipts →
REMEMBER distillation (k,m∩+DP+LCB) → CONTEXT+memory injection → ROUTE bundles →
LEARN retraining → better bundles → lower TVO → more sessions → richer corpus → repeat.
```

**Two legal regimes, one schema (structural, not procedural):**

| Regime | Capture | Injection | Proxy |
|---|---|---|---|
| Subscription/OAuth | Hooks, transcript tails (dedup by `(message.id, requestId)` + sidechain rule), artifact dirs | Hook context, stop/tool gates, context files, MCP | **Never** — provenance-gated refusal, not shape-guessing |
| Customer API key (ANTHROPIC_BASE_URL / Bedrock / Vertex / Azure) | All of the above **plus** the Rust wire proxy | All of the above **plus** wire-level model rewrite | Yes — customer creds pass through by reference, unmodified |

---

## 2. Component inventory (canonical registry — 9 deployables + 2 client crates-as-binaries)

**Edge (customer machines):**

| Component | Lang | Role | Key choices (winning evidence) |
|---|---|---|---|
| **mark1d** | Go | The one long-lived edge daemon: 7 agent adapters, transcript tailers (workspace-allow-listed), anchor runner, **verdict fusion** (log-space NB from bundle matrices), Go segment spool (single writer), M1P uploader, policy client, coverage accounting, supervision of proxy/cortexd/shim | Tailscale/lefthook-shaped work is Go's home turf (R2 §1.3); spool moved into the single writer kills the cgo distribution tax (C1.11); verdict fusion is trivial math and belongs where the gates fire |
| **mark1-proxy** | Rust | API-key-only micro-proxy, `--mode=sidecar\|gateway`; bytes-forward hot path, tee-on-clone dialect parsing, inline request redaction, model rewrite | tokio+hyper1+tower+rustls — linkerd2-proxy budget proof (sub-ms, 15–30 MB), Helicone comparable (<5 ms p95/64 MB), Pingora rejected (pre-1.0, no Windows tier-1, CVE-2025-4366, River stall) (R1 §§1,6,7) |
| **mark1-hookshim** | Rust | One static binary registered into every agent's hook config; per-agent JSON field maps **loaded from bundle data**; stamps UUIDv7+seq; 50 ms fire-and-forget / bounded gate deadlines; links `mark1-redact` so even emergency spill is sanitized | Hook vocabularies converged on Claude Code's (~80% Codex overlap, R6 §0.1); maps-as-data makes format breaks a bundle push, not a release (C1.13) |
| **cortexd** | Rust | Per-workspace repo intelligence: notify+BLAKE3 merkle L0, vendored tree-sitter tags L1, petgraph+PPR L2, opportunistic SCIP L3; push ranked maps + pull MCP tools, session-scoped | stack-graphs archived, embeddings lose 77.4 vs 58.8 Acc@10 (LocAgent), mtime races — all rejected per R3; the L0 root hash double-serves anchor anti-tamper |
| **mark1-redact** (crate) | Rust | teddy/aho-corasick prefilter → regex confirm → randomness test; carry-over window `max_pattern_len−1`; two axes: mutate-in-transit (default off) and **admit-to-upload (fail-closed, no off)** | rust/regex ~100 MB/s worst case = 100× stream headroom; vectorscan optional only (archived upstream) (R1 §4) |
| **mark1-receipt / mark1-policy** (crates) | Rust | Vendored Ed25519 chain primitives; bundle verify (sig+seq+inclusion proof)+decode → typed nanosecond eval structs | One signing discipline product-wide; Go carries a parallel decoder validated by shared conformance vectors |

**Cloud (Omium control plane) — two binaries + two service groups:**

| Component | Lang | Role | Key choices |
|---|---|---|---|
| **controld** | Go | Modules in one binary: **ingest** (M1P, S3-first, tenant stamped from token, pre-egress secret scanner, CH async-insert), **enroll** (OIDC device-code flow, short-lived tokens, revocation), **policy-dist** (Etag poll + SSE push, ACK ledger, transparency-log publisher), **dp-release** (Google DP Go integer mechanisms, pre-thresholding, contribution bounding, ε ledger), **query-choke** (the only CH principal; asserts tenant predicate on every generated query) | Consolidation per C1.3; the chokepoint is the anti-`rds_superuser` answer for ClickHouse (S1-7) |
| **adjudicator-svc** | Python | Judge orchestration (client-side-first, see §4/C4), spectral Dawid-Skene (~500 LoC numpy, crowd-kit as test oracle only), certification, noise certificates, gold-set management | EM is dense matmuls; global estimation + hierarchical shrinkage; identifiability-gated activation (C1.4, S2-14) |
| **mark1-intel** | Python | Job modules in one service: memory (extraction/admission/retrieval), tvo-engine (metric + waste taxonomy; DuckDB embedded for batch), policy-compiler (CPVS/knee/ladders → signed bundles), ope (OBP DR/SNIPS over `WIRE_ENFORCED` decisions), corpus-exporter (receipted Parquet) | FastAPI, existing platform conventions; batch-API distillation cascades (R7 §5) |
| **omium-training-plane** | Rust+Py | Existing estate: data-refinery gains a `mark1-parquet` source; KTO/QLoRA trainer; outputs re-enter only via probation/OPE/canary | Reuse, not rebuild; corpus is valuable as data even while the plane's gradient blockers are open |

**CLI:** `mark1` (Go) — `enroll`, `enable` (per-workspace), `status` (live "what Mark 1 is reading"), `doctor` (consented anchor catalog, fenced-config diffs), `report`, `off` (uncircumventable, checked before any gate), `verify-receipts` (wraps the open-source verifier).

Supply chain (S2-10): reproducible builds, CycloneDX SBOM, cargo-vet/cargo-deny + govulncheck CI gates, vendored pinned deps on token/hook paths, SLSA provenance verified by mark1d before applying any update; **no daemon self-update on managed fleets by default**; update key ≠ bundle key; both in the transparency log.

---

## 3. M1P — the proprietary protocol (no OpenTelemetry anywhere)

Three layers, one schema from hook stdin to ClickHouse row.

### 3.1 Schema (`m1p.v1`, protobuf, Buf-governed)

- `buf breaking` at WIRE_JSON in CI; deleted fields `reserved`; breaking change = new package `m1p.v2`, never in-place. One proto source → prost / protoc-gen-go / betterproto.
- **Identity:** UUIDv7 `event_id` (RFC 9562 Method-1 counter per daemon) is simultaneously server dedupe key, CH ordering component, spool cursor, and receipt-checkpoint leaf. Per-session monotonic `seq` carries causal order (dev clocks drift); `sent_at` stamped at send time; server computes skew.
- **Event families:** `SessionStart/End`, `TaskOpen/Close` (carries `task_seg_version`), `Turn`, `ToolUse`, `ModelRequest/Response` (proxy), `Usage` (transcript; `idem_key = HMAC_tenant(session_id, message.id, request_id)`, sidechain-replay rule baked in — the ~2.5× overcount defense as a protocol invariant), `AnchorVote{EvidenceRecord, AnchorIntegrity}`, `JudgeVote`, `RmScore`, `ConsistencyVote` (escalation-scoped), `VerdictEvent{stage: PROVISIONAL|CERTIFIED|REVISED, posterior[4], noise_cert_id}`, `CortexInjection{root_hash, index_clock}`, `MemoryInjection`, `ArtifactOutcome`, `RouteDecision{decision_id, action, candidates, propensity, fidelity: WIRE_ENFORCED|CONFIG_STEERED|ADVISORY, bundle_seq}`, `CoverageTransition{enable|disable|bypass, duration}`, `GuardDecision` (sampled), `ReceiptCheckpoint`, `Dropped{reason, category, quantity}`.
- **Evidence is typed, not free-text:** `EvidenceRecord{tool, diagnostic_code, category, counts, path_role: test|src|config|vendor, output_hmac}` — no paths, no excerpts. Free-text excerpts exist only as a per-tenant opt-in event class, structurally scrubbed, receipted (C1.18/S1-4). All digests of low-entropy content are per-tenant HMAC-salted; globally-joinable digests exist only post-(k,m).
- **No `wasm_module` field exists in v1.**

### 3.2 Cloud transport (M1P/1)

```
POST /m1p/v1/ingest
Content-Type: application/x-m1p-protobuf   Content-Encoding: zstd
Authorization: Bearer <short-lived device token>   M1P-Schema: m1p.v1
M1P-Batch-Id: <uuidv7>
Body: m1p.v1.Batch{ batch_id, session_id, sdk, sent_at, events[], dropped[] }
```

- Plain HTTPS POST, never gRPC to the edge (Cursor/Sentry/PostHog/Tailscale/Datadog convergence; middleboxes). At-least-once + server idempotent upsert on `event_id`/`idem_key`.
- **`tenant_id`/`device_id` are NOT in the envelope's trust path**: controld stamps both from the verified token claims; envelope disagreement → reject + security event (S1-7).
- Retry: network/5xx/429 only; exponential backoff + full jitter (base 6 s, cap 30 min, ~10 attempts) then park; 4xx = quarantine-and-report. `M1P-Rate-Limits` per category (Sentry grammar). Large artifacts multipart `attach.{event_id}.{name}`.
- **Pre-egress scanner** in controld.ingest (independent ruleset from the edge scanner): high-confidence secret in a batch → quarantine + tenant alert. Client-side-only redaction never gets to be the last line (S1-3).

### 3.3 Local fabric

UDS (named pipe on Windows), framing `magic 'M1PL' | u8 ver | u32 len(bounded) | payload`; socket perms 0600; frames are final `m1p.v1` events. Writers: hookshim, proxy, cortexd, tailers → mark1d, which is the **only spool writer** and runs redaction admit-to-upload policy before admission. The localhost-HTTP hook fallback is removed; where an agent cannot exec the shim, a loopback listener requires a per-session bearer token (0600 file), literal-loopback Host validation, and Origin rejection (S2-10.3).

### 3.4 Durable spool (Go, inside mark1d)

Vector-disk-v2 shape: 64 MiB append-only segments, `len(bounded)|crc32c|record_id|payload` (leading 16 bytes = event_id, so spool cursor = wire idempotency key); mmap'd 4-field ledger; fsync 250–500 ms + rotation + mandatory drain on SessionEnd/shutdown; whole-file ack-then-delete; ~2 GiB cap, 95%-disk hard stop. **Per-class policy:** `usage/verdict/receipt-checkpoint` block-on-full (billing-grade), diagnostics drop-newest — and every shed, CRC loss, or quarantine emits `Dropped{}` into the next batch. Decoder fuzzed in CI (S3-19). The proxy's tee spill ring is a separate Rust artifact: post-redaction only, 0600, device-key-encrypted, ≤24 h TTL with receipted expiry — the same rules bind the shim's emergency spill file (S1-3).

### 3.5 Versioning

`m1p-registry` records released versions and per-tenant accepted windows; out-of-window `M1P-Schema` → structured upgrade hint. Receivers skip-and-retain unknown event types within a major.

---

## 4. Data contracts between planes (canonical; ownership column is normative)

| # | Producer → Consumer | Contract | Keys | Owner | Notes |
|---|---|---|---|---|---|
| C1 | adapters → all | `TaskOpen/Close` + lifecycle events; `task_seg.v1` (versioned merge rules: follow-up ≤N turns touching same files = same task; session-end-without-verdict → `unresolved` denominator class) | `event_id, task_id, task_seg_version` | mark1d | TVO denominator is a spec, not a heuristic (C1.5) |
| C2 | anchor runner → adjudicator | `AnchorVote + EvidenceRecord + AnchorIntegrity{worktree_merkle_root, resolved_binary_hashes, env_scrub_attestation, diff_classification, suppression_directive_delta, tamper}` | `vote_id, attempt_id` | mark1d | Effective-execution hashing, not glob hashing (S2-13); device-signed at origin (S1-6) |
| C3 | bundle → **mark1d verdict fusion** | confusion matrices, priors, correlation groups (syntactic ∪ {tests} as separate group), abstention models → log-space NB → `VerdictEvent{PROVISIONAL}` cached per task | `bundle_seq → task_id` | mark1d | **The gate reads this cache; it never computes.** Fast anchors (ruff, incremental tsc, warm cargo check) refresh it on PostToolUse debounce; slow anchors (opt-in tests) produce REVISED verdicts + next-turn HOOK_CONTEXT corrections (C1.2) |
| C4 | evidence → judges | Tiered: **E0** typed EvidenceRecord only (modeled as low-power ensemble member); **E1** sanitized diff hunks + prompt digest, redaction-receipted (opt-in class); **E2** full diff (VPC/self-host only). **Default execution: client-side judges through the customer's own API key/proxy** — evidence never leaves; cloud judges (Haiku 4.5 cascade, cached rubric prefix, Batch API for re-adjudication) require tenant consent + subprocessor disclosure + region pinning | `vote_id` | adjudicator-svc | Resolves C1.1; `cache_read_input_tokens>0` is an SLO; judges fire only where anchors are ambiguous (prefix principle on the verifier plane itself) |
| C5 | adjudicator → ledger/edge | `VerdictEvent{CERTIFIED/REVISED}` + noise certificates. Certificate preconditions: **size- and freshness-gated gold set** (server-selected, edge-indistinguishable) + identifiability diagnostics; below threshold → status `uncertified/bootstrapping`, and such verdicts do not gate memory extraction or corpus admission | `noise_cert_id, checkpoint_seq` | adjudicator-svc | Global confusion estimation, per-tenant shrinkage; cross-tenant prior deviation → manual review (C1.4, S2-14) |
| C6 | cortexd → agent / ledger | ranked map (1–8k tokens, budget-binary-search) via SessionStart/UserPromptSubmit/BeforeModel; MCP tools `repo_map/find_definition/find_references/expand/deps` scoped to the calling session's enrolled workspace, loopback-token-authed, traversal-refusing; `CortexInjection` + `cortex.localization_hit` events | `root_hash, index_clock` | cortexd | The +22pp/−95% claim is measured per tenant via verdict joins, never asserted (S3-17, R3 risk 5) |
| C7 | cortexd → anchor runner | anchor-relevant merkle roots + whole-worktree root | `task_id` | cortexd | One hash table serves cortex provenance and anti-tamper |
| C8 | memory → agent | memory pack at TaskOpen (facets from prompt-digest features + cortex signals) via HOOK_CONTEXT; pitfall-remedies fire reactively on PostToolUseFailure; `routing_hint` never injects — it compiles into bundles | `artifact_id[]` | mark1-intel.memory | Every delivery → `MemoryInjection`; task close → `ArtifactOutcome` (LCB fuel) |
| C9 | edge → OPE | `RouteDecision` with propensity + **fidelity**; DR/SNIPS consumes `WIRE_ENFORCED` only; `CONFIG_STEERED` enters after served-model confirmation join from Usage events; `ADVISORY` never enters | `decision_id, bundle_seq` | mark1d single choice point | ε defaults 0 (propensity 1.0, logged honestly); ε=0.03–0.05 is per-tenant contractual opt-in (C1.8) |
| C10 | policy-compiler → edges | `PolicyBundle v1` (§6.3): verify/route/memory/cortex/gates/agent-field-maps sections; **no command strings, no code** | `(tenant, channel, seq)` | mark1-intel.policy | Anchors referenced by local-catalog ID only (S1-5) |
| C11 | corpus-exporter → data-refinery | `TrajectoryRecord`/`PreferencePair` Parquet; certified-only, tamper-excluded; label confidence = f(posterior, noise cert). **Per-tenant sets by default**; cross-tenant sets require opt-in + DP-SGD ε-ledgered + per-tenant contribution caps + canary memorization gate; export batches receipted with checkpoint lineage (erasure → retrain path) | `task_id, checkpoint_seq` | mark1-intel.corpus | S1-9 in full |
| C12 | LEARN → registry/compiler | trained artifact + eval card → `verifier_registry(kind='learned', status='probation')`; shadow votes → D-S-measured confusion → LCB promotion; learned routers must beat incumbent on held-out DR/SNIPS, then canary | `verifier_id@version` | adjudicator-svc | No self-promotion — the do-no-harm theorem applied to LEARN's own outputs |
| C13 | all planes → receipts | **Checkpoint model**: batch N events / T seconds → Merkle root → chained, dual-signed receipt; events carry `checkpoint_seq + inclusion_path`. Per-event receipts only for: noise certs, memory admissions, bundle publications, corpus exports, coverage transitions, guard contamination events | `(tenant, receipt_seq, key_id)` | controld + mark1d (origin sigs) | C1.10 + S1-6: device key signs origin tuples; server countersigns; heads witnessed externally hourly; standalone verifier validates offline |

**Knee governor (ROUTE, enforced at C3's gate):** stop when `p̂_LCB(n)·V(task) ≤ c(n)` where `c(n)` is computed under the bundle's `cost_basis`: `usd` (tokens×price + verifier spend) for API-key tenants; `quota` (rate-limit-window fraction from transcript-observed limit events + wall-clock shadow price) for subscription tenants (C1.9). At the knee: stop and surface verdict+evidence to the human. Below it: `decision:"block"` with the failure evidence as continuation reason. Local hard caps regardless of bundle: ≤3 consecutive blocks/task, hourly block ceiling, `MARK1_DISABLE=1` and `mark1 off` checked before any gate evaluation (S2-12).

---

## 5. Data stores and why

| Store | Holds | Why |
|---|---|---|
| **Postgres** (Omium RLS conventions, `*_app` roles — the BYPASSRLS lesson enforced by CI negative tests) | tenants/devices (with IdP binding, revocation, offboarding audit), receipt chain (per-tenant gap-free seq; checkpoint model keeps the `FOR UPDATE` row cool), noise certificates, verifier registry, memory artifacts (+ one pgvector `halfvec` HNSW column for error-signature fuzz — the only vector case; Qdrant rejected: second stateful system for a 90%-relational 10⁴–10⁶-row workload), artifact contributions (exact distinct counts for (k,m)), bundle catalog + ACK ledger, ε ledger, gold sets | Chain integrity needs transactional, gap-free, read-your-writes ordering — ClickHouse structurally cannot provide it (R5 §5) |
| **ClickHouse** (single node day 1) | the token-event ledger: every M1P event; MV rollups for TVO | Category-converged engine; `async_insert=1, wait_for_async_insert=1` kills the day-one bus; `ReplacingMergeTree` on `event_id`, `ORDER BY (tenant_id, toDate(occurred_at), session_id, event_id)` — **the one irreversible decision, signed off as an ADR before first production write.** Access exclusively via controld.query-choke (per-tenant predicate asserted by construction + fuzz tests) — row policies alone repeat the estate's decorative-RLS failure (S1-7) |
| **S3** | S3-first ingest (ack only after object lands — the replay log), Parquet corpus mirrors, opt-in evidence blobs. Per-tenant prefixes with per-tenant KMS keys and bucket policies | Durability + replay without a broker (Langfuse/Helicone pattern) |
| **External witness** | hourly per-tenant chain-head hashes → public transparency log and/or customer-controlled object-lock bucket | Converts "trust Omium" into "verify Omium" (S1-6) — without it the receipt product is decoration |
| **Local (edge)** | redb graph shards + SQLite CAS (cortexd, keyed `(path, content_hash, grammar_rev, query_rev, indexer_rev)`), Go spool segments, encrypted spill rings, raw evidence under `~/.omium/mark1/evidence/` (never uploaded by default) | Raw sessions/code stay client-side by default — the hard constraint made physical |

**Dedupe is one key across three layers:** transcript `message.id` at the edge → `event_id` idempotent upsert at ingest → CH replacing-merge. **No event bus at pilot;** NATS JetStream inserted exactly when the second independent consumer exists. Heavy batch analytics = embedded DuckDB over Parquet exports, never a hot store. Waste attribution ships as a deterministic taxonomy first (retry-loop tokens, re-exploration tokens cortex would have saved, over-model tokens vs cheapest-passing rung); Shapley requires a game-definition ADR before any code (C1.17).

---

## 6. Deployment topologies and policy distribution

Same binaries, three profiles (Envoy/Tailscale/Oxy config-not-code). Identical capture semantics in all three ⇒ one trajectory schema ⇒ one corpus.

### 6.1 Dev-machine sidecar (default)

`mark1 enroll` (OIDC device-code flow against the tenant IdP; ≤24 h tokens; device key in OS keychain/TPM where available, 0600 file floor) → `mark1 enable` **per workspace** (capture is allow-listed; `.mark1ignore` honored; nothing outside enrolled roots is read — `file-history/` snapshots are not read at all unless tenant-enabled, and even then only local diff stats compute) (S2-15/16). mark1d provisions agents via fenced, checksummed fragments and native include/extension mechanisms only; `mark1 doctor` shows every provisioned line and the consented anchor catalog. Budgets: proxy ≤1 ms median added latency / ≤35 MB RSS; anchors network-denied + env-scrubbed + resource-capped, activity-aware, kill-switched; ~2 GiB spool. Sidecar proxy listener: random high port, per-boot loopback token, Origin-rejecting, upstream set pinned to a bundle-declared hostname allow-list (S2-11). CI on macOS/Linux/Windows from day one.

### 6.2 VPC gateway (enterprise)

`mark1-proxy --mode=gateway` + `mark1d --fleet` on customer infrastructure fronting Bedrock/Vertex/Azure. Credentials are **referenced from the customer's secret manager per request, never persisted by Mark 1**; connection pools keyed `(upstream, credential-identity)`; no multiplexing, no identity masking — satisfying OpenAI/Google/GitHub terms simultaneously and resolving the D1/D2 custody contradiction (S1-2.4). Bedrock request path observe-only until customer-held re-signing hardens. E2 judge evidence and self-host become available here. Dev machines still run sidecars for hooks/transcripts/cortex.

### 6.3 Omium cloud + policy distribution

Kubernetes under existing GitOps conventions: controld, adjudicator-svc, mark1-intel, Postgres/CH/S3, GPU pool attached at the T2/LEARN trigger (~300 K verifications/mo or first learned verifier). Cloud-only at launch; `deploy/compose/` is internal dev; self-host is a phase-gated enterprise SKU (C1.15).

**PolicyBundle v1** (canonical CBOR, monotonic seq per (tenant, channel), `max_age`, `prev_hash`):
`verify` (confusion matrices, priors, correlation groups, quarantine list, **anchor enables by local-catalog ID + thresholds — any command string fails decode**), `route` (CPVS tables, ladders with `keep_prefix`, knee tables, `cost_basis`, exploration config), `memory` (injection rules, budgets), `cortex` (map budgets, channels), `gates` (bundle may downgrade closed→open only; fail-closed requires local on-disk tenant opt-in), `agent_maps` (hookshim field maps, tailer parser rules — format drift is a bundle push).

Distribution: Etag poll + SSE push; edge verifies **signature (section-split keys, KMS-resident, rate-limited) + monotonic seq + transparency-log inclusion proof**; persists last-known-good; **fail-static** — control plane vanishes → run last-known-good indefinitely; past `max_age` → conservative built-in defaults (single-rung ladder, knee=1, detect-only redaction, gates open, verdicts flagged `stale_cert`). Exception: memory-artifact and secret-bearing delivery re-checks device revocation — **fail-static for routing, fail-closed for secrets** (S2-16). Heartbeat ACKs `(seq, hash)`; canary→fleet widens only on ACK evidence + ledger-observed TVO; canary cohorts double as OPE randomization units. Rollback = previous content under a higher seq. The failure-posture matrix is normative: *fail-open for availability (capture, hooks), fail-static for policy, fail-closed for legality and secrets (OAuth guard, upload admission, revocation).*

---

## 7. Repo layout — `omium-mark1/`

```
omium-mark1/
├── proto/m1p/v1/                    # envelope, events, intelligence, policy, artifacts
│                                    # buf breaking @ WIRE_JSON; no wasm field exists
├── rust/
│   ├── mark1-proxy/                 # guard(provenance)/router/request/upstream/response/tee
│   ├── mark1-frames/                # anthropic-sse | openai-responses | openai-chat |
│   │                                #   gemini | bedrock-eventstream  (independently versioned)
│   ├── mark1-redact/                # two-axis scanner; linked by proxy AND hookshim
│   ├── mark1-receipt/               # vendored Ed25519 chain primitives (+ key_id/rotation)
│   ├── mark1-policy/                # bundle verify+decode → typed eval structs
│   ├── mark1-hookshim/              # static shim; bundle-supplied field maps; sanitized spill
│   ├── cortexd/                     # L0 merkle / L1 tags / L2 PPR graph / L3 scip; MCP server
│   └── m1p-wire/                    # prost codegen + M1PL framing (bounded len; fuzzed)
├── go/
│   ├── mark1d/                      # adapters/{claudecode,codex,gemini,opencode,copilot,cursor,crush}
│   │   └── internal/{capture,tailers,anchors,verdict,spool,uplink,policy,coverage,supervise,identity}
│   ├── mark1/                       # CLI incl. verify-receipts
│   └── controld/                    # modules: ingest | enroll | policydist | dprelease | querychoke
├── python/
│   ├── adjudicator/                 # judges, spectral D-S, certs, gold sets
│   ├── intel/                       # memory | tvo | policy_compiler | ope | corpus  (one service)
│   └── shared/mark1_receipts/       # vendored from recovery-orchestrator app/receipts/
├── tools/verifier/                  # standalone open-source receipt/chain/witness verifier
├── conformance/                     # golden SSE transcripts, hook fixtures per pinned agent
│                                    #   version, OAuth token-shape canaries, isolation negative tests
├── deploy/{helm/, compose/(dev-only), packaging/}   # SLSA-attested releases
├── migrations/                      # registry, certs, artifacts, contributions, ε, bundles, receipts
└── docs/adr/                        # CH ordering key, task_seg.v1, Shapley game, key ceremony, …
```

---

## 8. Assembly order (construction sequence for the full machine)

Dependency-driven; every phase ends with a working, receipted, revenue-relevant system. Nothing here is a cut — it is the order in which the full machine is erected. Hard gates in **bold**.

**Phase 1 — Spine + subscription-legal capture (the moat starts accruing).**
`m1p.v1` protos + M1PL framing → Go spool + uploader + controld.ingest (S3-first, token-stamped tenancy, pre-egress scanner) → ClickHouse **ADR sign-off on ordering key** → receipts vendored, checkpoint model, device origin-signing, external witness, standalone verifier → hookshim + Claude Code adapter (hooks + transcript tailer with sidechain dedupe) → `task_seg.v1` ADR → TVO engine v1 with coverage metric + deterministic waste taxonomy. **Gate: end-to-end certified usage events, verifiable offline by the customer.** Empirical spikes run concurrently: Codex `TokenCountEvent`, Copilot `events.jsonl` usage, Gemini `BeforeModel` in OAuth mode — each produces a go/no-go artifact that gates its adapter slot.

**Phase 2 — VERIFY provisional loop + Cortex push.**
Local anchor catalog + consent flow + sandboxed runner (static-analysis anchors default; test anchors opt-in behind the sandbox precondition) → anti-tamper envelope (effective-execution hashes, env scrub, worktree merkle) → verdict fusion in mark1d with fast/slow split and cached gate reads → stop-gate on Claude Code → cortexd L0–L2 + budgeted session-start map + MCP pull tools (scoped) → adjudicator-svc with weighted-majority + priors, gold-set bootstrap, `bootstrapping` cert status. **Gate: retry loops demonstrably arrested at the knee on live sessions; cortex uplift measurable in the ledger.** Codex adapter lands here (~80% vocabulary reuse).

**Phase 3 — Wire proxy + ROUTE.**
mark1-proxy sidecar (Anthropic dialect first): provenance guard + tripwire + token-shape canary CI, bytes-forward + tee + frames, golden-transcript + chaos suites, `Secret<T>` discipline → PolicyBundle v1 + distribution loop + transparency log + ACK canarying → propensity logging (`fidelity` field) from the first routed request → knee tables with dual cost basis → Gemini adapter (BeforeModel routing). **Gate: zero client-visible streaming regressions under chaos; guard canary green.**

**Phase 4 — Adjudication at strength + REMEMBER.**
Spectral D-S behind the identifiability gate, global estimation + shrinkage, noise certificates with gold-set preconditions → T1 judges (client-side default, E0/E1 tiers, subprocessor register for cloud path) → memory extraction (nightly Batch-API cascade), tenant-scope LCB admission, reactive pitfall injection → opencode adapter. **Gate: first noise-certified customer report with coverage band.**

**Phase 5 — Enterprise + federation + LEARN.**
Gateway mode + mTLS + Bedrock/Vertex dialects (Bedrock observe-only requests) + referenced-credential integration → Copilot BYOK + Cursor observe/gate adapters → federation: intersection-reconstruction (k≥25, m≥5 verified orgs), DP release layer + ε ledger, review queue → corpus-exporter + data-refinery `mark1-parquet` source; per-tenant training first → OPE (DR/SNIPS) scoring candidate bundles. **Gate: first cross-org artifact published through the full k,m∩/DP/LCB/review pipeline.**

**Phase 6 — Learned members + certified tier + self-host.**
T2 RM (Qwen3-based, Apache-2.0, vLLM on the shared A10) entering via probation/shadow/LCB → learned cortex ranker → learned router via OPE+canary → cross-tenant training (opt-in, DP-SGD, canary memorization gate) → T3 Firecracker certified runs (opt-in; rent E2B/Daytona first) → NATS JetStream when the second independent ledger consumer exists → self-host SKU.

---

## 9. Compliance/privacy enforcement points — in code, not policy

1. **OAuth non-interception:** proxy accepts only requests bearing `M1-Cred-Ref` naming a credential mark1d provisioned after `Detect()==apikey`, HMAC-fingerprint-matched to enrollment; unknown credentials → 403, no override path exists in the binary. Shape inspection is a secondary tripwire; upstream subscription-marker responses trigger session kill + config rollback + receipted `oauth_contamination` P0. Weekly token-shape canary fails CI on a classifier miss. Sampled guard decisions are receipted — refusal is *provable*, not asserted.
2. **Credential custody:** `Secret<T>` with no Debug/Display/Serialize (compile-time), zeroize-on-drop, CI grep gate; tee constructed from an explicit field allow-list, never a request clone; `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`; gateway credentials fetched by reference per request, never written.
3. **Egress admission:** redaction's admit-to-upload axis is fail-closed with no off switch — flagged spans become `⟨redacted:class:hash⟩` in every derived artifact before spool admission; no pre-redaction plaintext persistence exists (shim links the scanner; spill files 0600, device-key-encrypted, TTL-swept with receipted expiry); controld.ingest runs an independent second scanner and quarantines.
4. **Evidence typing:** the default evidence wire type carries no paths, no free text; excerpt classes are per-tenant opt-in, structurally scrubbed, receipted per upload. Low-entropy digests are per-tenant HMAC-salted — dictionary inversion and cross-tenant correlation are cryptographically closed, not policied.
5. **Anchor execution:** bundles cannot name commands (decode-time rejection); the catalog is locally derived, user-consented, re-consented on change, visible in `mark1 doctor`; execution is network-denied, env-scrubbed to an allow-list, read-only outside the worktree, resource-capped, kill-switched.
6. **Tenancy:** ingest stamps tenant from the verified token; ClickHouse is reachable only through the query chokepoint whose builder provably appends the tenant predicate (fuzz + negative tests on every PR, across PG, CH, memory API, and S3 prefixes); S3 per-tenant prefixes + KMS keys.
7. **Federation:** the (k,m) gate is a `HAVING` clause + trigger constraint over billing/domain-verified orgs with collusion collapse; published bodies are intersection-reconstructed — a span no m tenants independently produced *cannot* publish; `invariant` artifacts are excluded by schema; all cross-tenant numbers pass the DP release layer with a per-tenant ε ledger.
8. **Training:** corpus admission requires certified labels; cross-tenant sets require receipted contractual opt-in, DP-SGD with ledgered ε, contribution caps, and a per-tenant canary memorization test as a checkpoint release gate; export-batch receipts give checkpoint lineage → documented retrain-on-erasure.
9. **Auditability against Omium itself:** dual signatures (device origin + server chain, `key_id`'d, rotation cross-signed), external witness anchoring, and the open-source offline verifier — the chain is checkable by the customer without any Omium server.
10. **Scope of reading:** tailers operate only inside `mark1 enable`'d workspaces; `.mark1ignore`; `mark1 status` shows live read surface; `CoverageTransition` receipts make every enable/disable/bypass window attributable — TVO reports carry a coverage band and refuse guarantee-grade issuance below the floor.

---

## 10. Top 10 risks and mitigations

1. **Anchor reward-hacking** (product integrity). Effective-execution hashing, env/PATH pinning, suppression-directive tracking, whole-tree merkle + diff classification, tamper flags receipted, anchor-vs-T3 divergence monitored per tenant as an adversarial-ML metric — an evolving defense, not a rule set.
2. **Subscription contamination** (legal). Provenance allow-list + tripwire + canary CI + receipted refusals; the proxy simply has no code path that forwards an unprovisioned credential.
3. **Bundle/update supply chain = fleet RCE.** No server-named commands, no code in v1 bundles, split KMS keys, transparency-log inclusion proofs verified at the edge, SLSA-attested releases, no default self-update.
4. **Streaming regression destroys trust.** Bytes-forward/parse-on-clone invariant, golden-transcript + chaos suites per dialect, tee structurally unable to hold the client write, automatic bypass (receipted) with capture degrading to transcripts — no Mark 1 component is a single point of failure for the customer's ability to code.
5. **Statistically-fictional noise certificates.** Identifiability-gated spectral activation, global estimation + shrinkage, gold-set preconditions, `bootstrapping` status honesty, cross-tenant prior bounds.
6. **TVO credibility attacks** (denominator, coverage, cost basis). Versioned `task_seg`, receipted coverage transitions, dual cost basis, self-reported loss — the metric ships with its own error bars.
7. **Corpus contamination / privacy incident** — the moat is unerasable if poisoned. Double scanning, typed evidence, salted digests, intersection publication, DP-SGD + canaries, lineage + deletion story.
8. **Dev-machine UX blowback.** Static-only default anchors, activity-aware pausing, caps, block ceilings, visible kill switch, `mark1 off` completeness tested by byte-equality snapshot.
9. **Agent-surface drift** (7 agents, monthly churn). Field maps/parsers as bundle data, version sniffing with typed drops, spike-gated roadmap slots, conformance fixtures per pinned version.
10. **Team-capacity overrun.** 9 deployables, one edge daemon, two cloud binaries, consolidation enforced in the registry; NATS/T3/self-host/Shapley each behind explicit triggers — complexity is admitted only when its precondition fires.

---

## 11. What makes this uncopyable

A competitor can copy any single plane; the moat is the **closed loop that only forms when all five share one certified spine**:

1. **The corpus is outcome-labeled with self-certified error bars.** Everyone can log agent sessions; nobody else attaches a calibrated four-verdict label with a published confusion matrix, a gold-set-tethered noise certificate, and a dual-signed, externally-witnessed receipt to every trajectory. Training data whose label quality is itself a measured input (C11's `label_confidence`) is categorically better fuel than scraped transcripts — and the quality gap compounds through every LEARN cycle.
2. **The propensity log makes routing learnable only for us.** Choice-time propensities with fidelity annotations, joined to certified delayed rewards through a tamper-evident chain, is the substrate for off-policy improvement no one can retrofit (the Decision Service lesson): a copier starting today starts with zero valid decisions, and their naive averages of a deterministic router's own choices are statistically unusable.
3. **The planes feed each other signals that don't exist standalone.** Cortex ranks with the live recent-edit set from capture (aider never had it); VERIFY reuses cortex's merkle table for anti-tamper; memory's LCB is powered by verdict joins; ROUTE's knee is fit from the ledger; LEARN's outputs are certified by the same estimator that certifies everything else. Each pairwise wire raises the copying bar multiplicatively — a third-order system in the literal sense: the product improves the loop that improves the product.
4. **Legality-by-structure is a distribution moat.** Identical capture semantics across subscription and API-key regimes, on the vendors' own sanctioned surfaces, means Mark 1 can sit where interceptors legally cannot — and the receipted refusal record makes it defensible to vendor counsel, which no gray-area proxy can claim.
5. **The metric is externally verifiable.** Coverage-banded, cost-basis-honest, offline-verifiable TVO turns "trust our dashboard" into "run the verifier yourself" — a claim structure competitors without a witness-anchored chain cannot make, and the one that closes enterprise deals.

Every session a customer runs makes the verifiers sharper, the maps tighter, the routes cheaper, and the receipts longer. The flywheel's inputs are proprietary by construction, its labels are certified by mathematics rather than assertion, and its history is anchored outside our own control. That is the product, the proof, and the moat — the same data.