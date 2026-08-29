# Mark 1 — Execution Plan (v2, the full machine)

## Context

Mark 1 is Omium's second product line: a layer that wraps coding agents (Claude Code first, seven agents eventually) to cut **tokens-per-verified-outcome (TVO)** while raising output quality, and that turns every session into outcome-labeled trajectory data — the corpus is the moat. It productizes the four-phase adversarially-verified research program (`mark1-research-dossier.md`) and the three theory papers (`mark1-research/`): five planes (Verify / Remember / Contextualize / Route / Learn) around one spine (the TVO Ledger), with the algorithms (TVO accounting, ADJUDICATE, ADMIT-LCB) and the hard legal constraints already fixed. A paying enterprise prospect (AIOS) awaits a demo; the founder's own $10–15k/month spend is the first test population.

**Why this is v2.** v1 was rejected by the founder as timid and wrong-stack: it planned an instrument-first MVP and used OpenTelemetry as the primary token source. The directive is the *final advanced product* — a third-order system, designed completely, with a **proprietary capture fabric (M1P) and zero OpenTelemetry anywhere**, built in Rust + Go + Python with each language where it provably wins. Build cost is explicitly not a constraint; integrity of the end-state machine is. This plan is the execution form of the authoritative architecture spec produced by a 13-agent research→design→adversarial-critique→synthesis pass (7 technology researchers with web access, 3 independent architects, 2 ruthless critics — feasibility and security/compliance — and a chief-architect synthesis that dispositioned every finding). Full spec: `/tmp/mark1_spec.md` (48 KB; copy into `omium-mark1/docs/` as the first commit).

**Scope discipline.** This builds in a NEW standalone repo, `omium-mark1/`. Zero changes to Omium-platform. The critique's "cut it to a fraction" was rejected as scope reduction and accepted as *consolidation + sequencing*: ~20 candidate deployables collapse to **9**, and construction is dependency-ordered so every phase ends with a working, receipted, revenue-relevant system. Nothing in the design is deleted.

## The machine in one screen

Five planes, one spine, two structurally-separated legal regimes.

```
        ┌───────────────────── OMIUM CLOUD ─────────────────────┐
        │ controld(Go): ingest│enroll│policy-dist│dp-release│    │
        │                     query-choke                       │
        │      S3-first ─► ClickHouse (ledger) ◄─ intel jobs    │
        │ adjudicator-svc(Py)   mark1-intel(Py)                 │
        │ Postgres: receipts│artifacts│certs│bundles│ε-ledger    │
        │ external witness (transparency log / object-lock S3)  │
        │ omium-training-plane (Rust+Py, LEARN)                 │
        └────────▲──────────────────────────┬──────────────────-┘
   M1P/1 HTTPS   │ zstd protobuf batches    │ signed sequenced bundles
                 │                          ▼
  ┌──────────────┴────────────────────────────────────────────────┐
  │ CUSTOMER SIDE — allow-listed workspaces only                  │
  │  mark1d (Go): adapters │ tailers │ anchors │ verdict fusion   │
  │               │ spool │ uploader │ policy │ coverage │ superv.│
  │  mark1-hookshim(Rust) ─UDS─► mark1d ◄─UDS─ cortexd(Rust)      │
  │  mark1-proxy(Rust; API-key traffic ONLY; provenance guard)    │
  └───────────────────────────────────────────────────────────────┘

FLYWHEEL: capture → VERIFY labels (noise-certified) → dual-signed receipts →
REMEMBER distillation (k,m∩ + DP + LCB) → CONTEXT + memory injection →
ROUTE bundles → LEARN retraining → better bundles → lower TVO → repeat.
```

| Regime | Capture | Injection | Proxy |
|---|---|---|---|
| Subscription / OAuth | hooks, transcript tails (dedupe by `(message.id, requestId)` + sidechain rule), artifact dirs | hook context, stop/tool gates, context files, MCP | **Never** — provenance-gated refusal, not shape-guessing |
| Customer API key (ANTHROPIC_BASE_URL / Bedrock / Vertex / Azure) | all of the above **+** the Rust wire proxy | all of the above **+** wire-level model rewrite | Yes — customer creds pass through by reference, unmodified |

## Component registry (9 deployables + 4 client crates) — canonical names

**Edge**

| Component | Lang | Role | Why this choice |
|---|---|---|---|
| `mark1d` | Go | The one long-lived edge daemon: 7 agent adapters, workspace-allow-listed transcript tailers, anchor runner, **verdict fusion** (log-space naive Bayes from bundle matrices), segment spool (single writer), M1P uploader, policy client, coverage accounting, supervision of the other edge processes | Tailscale/lefthook-shaped work is Go's home turf; putting the spool in the single writer kills the cgo distribution tax; fusion is cheap math and belongs where the gates fire |
| `mark1-proxy` | Rust | API-key-only micro-proxy, `--mode=sidecar\|gateway`; bytes-forward hot path, tee-on-clone dialect parsing, inline request redaction, model rewrite | tokio + hyper1 + tower + rustls. linkerd2-proxy proves the sub-ms/15–30 MB budget; Pingora rejected (pre-1.0, no tier-1 Windows, CVE-2025-4366, River stalled) |
| `mark1-hookshim` | Rust | One static binary registered into every agent's hook config; per-agent JSON field maps **loaded from bundle data**; stamps UUIDv7 + seq; 50 ms fire-and-forget / bounded gate deadlines; links `mark1-redact` so even emergency spill is sanitized | Hook vocabularies converged on Claude Code's (~80% Codex overlap); maps-as-data makes a format break a bundle push, not a release |
| `cortexd` | Rust | Per-workspace repo intelligence: notify + BLAKE3 merkle (L0), vendored tree-sitter tags (L1), petgraph + personalized PageRank (L2), opportunistic SCIP (L3); pushes ranked maps, serves MCP pull tools, session-scoped | stack-graphs is archived; embeddings lose to graph-guided localization (77.4 vs 58.8 Acc@10, LocAgent); the L0 root hash double-serves anchor anti-tamper |
| crates: `mark1-redact`, `mark1-receipt`, `mark1-policy`, `m1p-wire` | Rust | two-axis secret scanner (linked by both proxy and shim); Ed25519 chain primitives; bundle verify+decode → typed nanosecond eval structs; prost codegen + M1PL framing | rust/regex ≈100 MB/s worst case = 100× stream headroom; one signing discipline product-wide; Go carries a parallel decoder validated by shared conformance vectors |

**Cloud**

| Component | Lang | Role |
|---|---|---|
| `controld` | Go | One binary, five modules: **ingest** (M1P, S3-first, tenant stamped from token, pre-egress secret scanner, ClickHouse async-insert), **enroll** (OIDC device-code, ≤24 h tokens, revocation), **policy-dist** (Etag poll + SSE push, ACK ledger, transparency-log publisher), **dp-release** (Google DP Go integer mechanisms, pre-thresholding, contribution bounding, ε ledger), **query-choke** (the only ClickHouse principal; asserts the tenant predicate on every generated query) |
| `adjudicator-svc` | Python | Judge orchestration (client-side-first), spectral Dawid–Skene (~500 LoC numpy; crowd-kit as test oracle only), certification, noise certificates, gold-set management |
| `mark1-intel` | Python | One service, five job modules: memory (extraction/admission/retrieval), tvo-engine (metric + waste taxonomy, embedded DuckDB for batch), policy-compiler (CPVS/knee/ladders → signed bundles), ope (DR/SNIPS over `WIRE_ENFORCED` decisions), corpus-exporter (receipted Parquet) |
| `omium-training-plane` | Rust+Py | **Existing estate, reused**: data-refinery gains a `mark1-parquet` source; KTO/QLoRA trainer; outputs re-enter only via probation → shadow → LCB promotion → canary |

**CLI** `mark1` (Go): `enroll`, `enable` (per workspace), `status` (live "what Mark 1 is reading"), `doctor` (consented anchor catalog, fenced-config diffs), `report`, `off` (uncircumventable, checked before any gate), `verify-receipts`.

## M1P — the proprietary protocol (replaces OpenTelemetry entirely)

- **Schema** `m1p.v1`, protobuf, Buf-governed: `buf breaking` at WIRE_JSON in CI, deleted fields `reserved`, breaking change ⇒ new package `m1p.v2` never in place. One proto source → prost / protoc-gen-go / betterproto.
- **Identity:** UUIDv7 `event_id` (RFC 9562 Method-1 counter per daemon) is simultaneously the server dedupe key, the ClickHouse ordering component, the spool cursor, and the receipt-checkpoint leaf. Per-session monotonic `seq` carries causal order because dev clocks drift.
- **Event families:** `SessionStart/End`, `TaskOpen/Close` (carries `task_seg_version`), `Turn`, `ToolUse`, `ModelRequest/Response`, `Usage` (`idem_key = HMAC_tenant(session_id, message.id, request_id)` — the verified ~2.5× streaming overcount defense is a *protocol invariant*, not parser etiquette), `AnchorVote`, `JudgeVote`, `RmScore`, `ConsistencyVote`, `VerdictEvent{stage, posterior[4], noise_cert_id}`, `CortexInjection`, `MemoryInjection`, `ArtifactOutcome`, `RouteDecision{propensity, fidelity}`, `CoverageTransition`, `GuardDecision`, `ReceiptCheckpoint`, `Dropped{reason, category, quantity}`.
- **Evidence is typed, never free text:** `EvidenceRecord{tool, diagnostic_code, category, counts, path_role, output_hmac}` — no paths, no excerpts. Excerpts are a per-tenant opt-in class, structurally scrubbed and receipted. Low-entropy digests are per-tenant HMAC-salted, so dictionary inversion and cross-tenant correlation are cryptographically closed rather than policied.
- **No `wasm_module` field exists in v1** (the bundle→RCE branch is deleted, not mitigated).
- **Transport:** `POST /m1p/v1/ingest`, `application/x-m1p-protobuf` + zstd, bearer device token, at-least-once with idempotent upsert. Plain HTTPS, never gRPC to the edge. `tenant_id`/`device_id` are **not** in the envelope trust path — controld stamps both from verified token claims; disagreement ⇒ reject + security event. Retry on network/5xx/429 only, exponential backoff + full jitter (base 6 s, cap 30 min, ~10 attempts) then park; 4xx ⇒ quarantine-and-report.
- **Local fabric:** UDS (named pipe on Windows), framing `magic 'M1PL' | u8 ver | u32 len(bounded) | payload`, perms 0600. Writers (hookshim, proxy, cortexd, tailers) → mark1d, the **only spool writer**. Where an agent cannot exec the shim, a loopback listener requires a per-session bearer token, literal-loopback Host validation, and Origin rejection.
- **Spool:** Vector-disk-v2 shape — 64 MiB append-only segments, `len(bounded)|crc32c|record_id|payload` (leading 16 bytes = event_id, so the spool cursor *is* the wire idempotency key), mmap'd ledger, fsync 250–500 ms, mandatory drain on SessionEnd/shutdown, ~2 GiB cap with a 95%-disk hard stop. Per-class policy: usage/verdict/receipt-checkpoint **block on full** (billing-grade), diagnostics drop-newest; every shed or CRC loss emits `Dropped{}` in the next batch. Decoder fuzzed in CI.

## Data contracts that must be right before code

The full normative table is §4 of the spec. The load-bearing ones:

- **C1 `task_seg.v1`** — the TVO *denominator* is a versioned, receipted algorithm (follow-up within N turns touching the same files = same task; session-end-without-verdict = `unresolved` denominator class), stamped on every `TaskOpen`. An ADR precedes the code.
- **C3 verdict fusion** — bundles ship confusion matrices, priors, correlation groups (syntactic ∪ {tests} as its own group) and abstention models; `mark1d` does log-space naive Bayes into a cached `VerdictEvent{PROVISIONAL}` per task. **The stop-gate reads that cache; it never computes.** Fast anchors (ruff, incremental tsc, warm `cargo check`) refresh on PostToolUse debounce; slow opt-in anchors produce `REVISED` verdicts plus next-turn hook-context corrections.
- **C4 evidence tiers** — E0 typed record only (modeled as a low-power ensemble member), E1 sanitized diff hunks (opt-in, redaction-receipted), E2 full diff (VPC/self-host only). **Default judge execution is client-side through the customer's own key**, so evidence never leaves; cloud judges require tenant consent + subprocessor disclosure + region pinning.
- **C5 noise certificates** — gated on a size- and freshness-gated, server-selected, edge-indistinguishable gold set plus identifiability diagnostics; below threshold the status is honestly `uncertified/bootstrapping`, and such verdicts do not gate memory extraction or corpus admission.
- **C9 propensity + fidelity** — every `RouteDecision` logs its propensity and a `fidelity` of `WIRE_ENFORCED | CONFIG_STEERED | ADVISORY`; DR/SNIPS consumes only wire-enforced (or served-model-confirmed) decisions. ε defaults to **0** (propensity 1.0, logged honestly); exploration is a per-tenant contractual opt-in.
- **C13 receipts** — checkpoint model: batch N events / T seconds → Merkle root → chained, **dual-signed** (device origin + server countersign) receipt; events carry `checkpoint_seq + inclusion_path`. Per-event receipts only for noise certs, memory admissions, bundle publications, corpus exports, coverage transitions, and guard contamination events. Heads are witnessed externally hourly; a standalone open-source verifier validates the chain offline.
- **Knee governor** — stop when `p̂_LCB(n)·V(task) ≤ c(n)`, with `c(n)` computed under the bundle's `cost_basis`: `usd` for API-key tenants, `quota` (rate-limit-window fraction × wall-clock shadow price) for subscription tenants. Local hard caps regardless of bundle: ≤3 consecutive blocks per task, an hourly block ceiling, and `MARK1_DISABLE=1` / `mark1 off` checked *before* any gate evaluation.

## Data stores

| Store | Holds | Why |
|---|---|---|
| **Postgres** (platform RLS conventions, `*_app` roles — the `rds_superuser`/BYPASSRLS lesson enforced by CI negative tests) | tenants/devices, receipt chain (per-tenant gap-free seq), noise certificates, verifier registry, memory artifacts (+ one pgvector `halfvec` HNSW column for error-signature fuzz — the only vector case), artifact contributions, bundle catalog + ACK ledger, ε ledger, gold sets | Chain integrity needs transactional, gap-free, read-your-writes ordering, which ClickHouse structurally cannot provide |
| **ClickHouse** (single node day one) | the token-event ledger + materialized rollups for TVO | `async_insert=1, wait_for_async_insert=1` removes the day-one bus; `ReplacingMergeTree` on `event_id`, `ORDER BY (tenant_id, toDate(occurred_at), session_id, event_id)` — **the one irreversible decision; ADR signed before the first production write.** Reachable only through `controld.query-choke` |
| **S3** | S3-first ingest (ack only after the object lands = the replay log), Parquet corpus mirrors, opt-in evidence blobs; per-tenant prefixes with per-tenant KMS keys | Durability + replay without a broker |
| **External witness** | hourly per-tenant chain-head hashes → transparency log and/or customer object-lock bucket | Converts "trust Omium" into "verify Omium"; without it the receipt product is decoration |
| **Local (edge)** | redb graph shards + SQLite CAS for cortexd (keyed `(path, content_hash, grammar_rev, query_rev, indexer_rev)`), Go spool segments, encrypted spill rings, raw evidence under `~/.omium/mark1/evidence/` (never uploaded by default) | "Raw sessions and code stay client-side" made physical |

Dedupe is one key across three layers: transcript `message.id` at the edge → `event_id` idempotent upsert at ingest → ClickHouse replacing-merge. **No event bus at pilot**; NATS JetStream is inserted exactly when a second independent consumer exists. Heavy batch analytics run in embedded DuckDB over Parquet, never in a hot store. Waste attribution ships as a deterministic taxonomy first (retry-loop tokens, re-exploration tokens Cortex would have saved, over-model tokens vs the cheapest passing rung); **Shapley requires a game-definition ADR before any Shapley code is written.**

## Deployment and policy distribution

Same binaries, three profiles (config not code), identical capture semantics in all three ⇒ one trajectory schema ⇒ one corpus.

1. **Dev sidecar (default).** `mark1 enroll` (OIDC device-code against the tenant IdP; device key in keychain/TPM, 0600 file floor) → `mark1 enable` **per workspace**; `.mark1ignore` honored; nothing outside enrolled roots is read. Agents are provisioned via fenced, checksummed fragments and native include/extension mechanisms only — we never rewrite a file we don't exclusively own. Budgets: proxy ≤1 ms median added latency and ≤35 MB RSS; anchors network-denied, env-scrubbed, resource-capped, activity-aware, kill-switched. CI on macOS/Linux/Windows from day one.
2. **VPC gateway (enterprise).** `mark1-proxy --mode=gateway` + `mark1d --fleet` fronting Bedrock/Vertex/Azure. Credentials are **referenced from the customer's secret manager per request and never persisted**; pools keyed `(upstream, credential-identity)`; no multiplexing, no identity masking. Bedrock request path stays observe-only until customer-held re-signing hardens. E2 judge evidence and self-host unlock here.
3. **Omium cloud.** Kubernetes under existing GitOps conventions; GPU pool attached at the T2/LEARN trigger (~300 K verifications/month or the first learned verifier). Cloud-only at launch; `deploy/compose/` is internal dev; self-host is a phase-gated enterprise SKU.

**PolicyBundle v1** (canonical CBOR, monotonic seq per `(tenant, channel)`, `max_age`, `prev_hash`) carries sections `verify | route | memory | cortex | gates | agent_maps`. **No command strings and no code** — anchors are enabled by local-catalog ID only; any command string fails decode. The edge verifies signature (section-split, KMS-resident keys) + monotonic seq + transparency-log inclusion proof, persists last-known-good, and is **fail-static**: if the control plane vanishes it runs last-known-good indefinitely; past `max_age` it falls to conservative built-in defaults. The normative posture matrix: **fail-open for availability (capture, hooks), fail-static for policy, fail-closed for legality and secrets (OAuth guard, upload admission, revocation).**

## Repo layout — `omium-mark1/`

```
omium-mark1/
├── proto/m1p/v1/                 # envelope, events, intelligence, policy, artifacts
├── rust/
│   ├── mark1-proxy/              # guard(provenance)/router/request/upstream/response/tee
│   ├── mark1-frames/             # anthropic-sse | openai-responses | openai-chat |
│   │                             #   gemini | bedrock-eventstream (independently versioned)
│   ├── mark1-redact/             # two-axis scanner; linked by proxy AND hookshim
│   ├── mark1-receipt/            # vendored Ed25519 chain primitives (+ key_id/rotation)
│   ├── mark1-policy/             # bundle verify+decode → typed eval structs
│   ├── mark1-hookshim/           # static shim; bundle-supplied field maps; sanitized spill
│   ├── cortexd/                  # L0 merkle / L1 tags / L2 PPR graph / L3 scip; MCP server
│   └── m1p-wire/                 # prost codegen + M1PL framing (bounded len; fuzzed)
├── go/
│   ├── mark1d/                   # adapters/{claudecode,codex,gemini,opencode,copilot,cursor,crush}
│   │   └── internal/{capture,tailers,anchors,verdict,spool,uplink,policy,coverage,supervise,identity}
│   ├── mark1/                    # CLI incl. verify-receipts
│   └── controld/                 # ingest | enroll | policydist | dprelease | querychoke
├── python/
│   ├── adjudicator/              # judges, spectral D-S, certs, gold sets
│   ├── intel/                    # memory | tvo | policy_compiler | ope | corpus (one service)
│   └── shared/mark1_receipts/    # vendored from recovery-orchestrator app/receipts/
├── tools/verifier/               # standalone open-source receipt/chain/witness verifier
├── conformance/                  # golden SSE transcripts, hook fixtures per pinned agent version,
│                                 #   OAuth token-shape canaries, tenant-isolation negative tests
├── deploy/{helm/, compose/(dev-only), packaging/}   # SLSA-attested releases
├── migrations/                   # registry, certs, artifacts, contributions, ε, bundles, receipts
└── docs/adr/                     # CH ordering key, task_seg.v1, Shapley game, key ceremony, …
```

## Assembly order (erecting the full machine; hard gates in bold)

**Phase 1 — Spine + subscription-legal capture (the moat starts accruing).** `m1p.v1` protos + M1PL framing → Go spool + uploader + `controld.ingest` (S3-first, token-stamped tenancy, pre-egress scanner) → ClickHouse **ordering-key ADR sign-off** → receipts vendored, checkpoint model, device origin-signing, external witness, standalone verifier → hookshim + Claude Code adapter (hooks + transcript tailer with sidechain dedupe) → `task_seg.v1` ADR → TVO engine v1 with coverage metric and deterministic waste taxonomy. **Gate: end-to-end certified usage events, verifiable offline by the customer.** Concurrent spikes, each producing a go/no-go artifact that gates its adapter slot: Codex `TokenCountEvent`, Copilot `events.jsonl` usage, Gemini `BeforeModel` in OAuth mode.

**Phase 2 — VERIFY provisional loop + Cortex push.** Local anchor catalog + consent flow + sandboxed runner (side-effect-free static analysis by default; test anchors per-repo opt-in behind a sandbox precondition) → anti-tamper envelope (effective-execution hashes, env scrub, worktree merkle) → verdict fusion in `mark1d` with the fast/slow split and cached gate reads → stop-gate on Claude Code → `cortexd` L0–L2 + budgeted session-start map + scoped MCP pull tools → `adjudicator-svc` with weighted-majority + priors, gold-set bootstrap, `bootstrapping` cert status. **Gate: retry loops demonstrably arrested at the knee on live sessions; Cortex uplift measurable in the ledger.** Codex adapter lands here (~80% vocabulary reuse).

**Phase 3 — Wire proxy + ROUTE.** `mark1-proxy` sidecar, Anthropic dialect first: provenance guard + tripwire + token-shape canary CI, bytes-forward + tee + frames, golden-transcript and chaos suites, `Secret<T>` discipline → PolicyBundle v1 + distribution loop + transparency log + ACK canarying → propensity logging (`fidelity`) from the first routed request → knee tables with dual cost basis → Gemini adapter. **Gate: zero client-visible streaming regressions under chaos; guard canary green.**

**Phase 4 — Adjudication at strength + REMEMBER.** Spectral Dawid–Skene behind the identifiability gate with global estimation + hierarchical shrinkage → noise certificates with gold-set preconditions → T1 judges (client-side default, E0/E1 tiers, subprocessor register for the cloud path) → memory extraction (nightly Batch-API cascade), tenant-scope LCB admission, reactive pitfall injection → opencode adapter. **Gate: first noise-certified customer report with a coverage band.**

**Phase 5 — Enterprise + federation + LEARN.** Gateway mode + mTLS + Bedrock/Vertex dialects + referenced-credential integration → Copilot BYOK and Cursor observe/gate adapters → federation: intersection-reconstruction (k ≥ 25, m ≥ 5 verified orgs), DP release layer + ε ledger, human review queue → corpus-exporter + data-refinery `mark1-parquet` source (per-tenant training first) → OPE (DR/SNIPS) scoring candidate bundles. **Gate: first cross-org artifact published through the full k,m∩ / DP / LCB / review pipeline.**

**Phase 6 — Learned members + certified tier + self-host.** T2 reward model (Qwen3-based, Apache-2.0, vLLM on the shared A10) entering via probation → shadow → LCB promotion → learned Cortex ranker → learned router via OPE + canary → cross-tenant training (opt-in, DP-SGD, canary memorization gate) → T3 Firecracker certified runs (opt-in; rent E2B/Daytona first) → NATS JetStream when the second independent ledger consumer exists → self-host SKU.

## Compliance enforcement — in code, not policy

1. **OAuth non-interception.** The proxy accepts only requests bearing an `M1-Cred-Ref` naming a credential `mark1d` provisioned after `Detect()==apikey`, HMAC-fingerprint-matched to enrollment. Unknown credential ⇒ 403, and **no override path exists in the binary**. Shape inspection is a secondary tripwire; an upstream subscription-marker response triggers session kill + config rollback + a receipted `oauth_contamination` P0. A weekly token-shape canary fails CI on a classifier miss, and sampled guard decisions are receipted — refusal is *provable*.
2. **Credential custody.** `Secret<T>` with no Debug/Display/Serialize (compile-time), zeroize-on-drop, CI grep gate; the tee is built from an explicit field allow-list and never a request clone; `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`; gateway credentials are fetched by reference per request and never written.
3. **Egress admission.** Redaction's admit-to-upload axis is fail-closed **with no off switch**; flagged spans become `⟨redacted:class:hash⟩` in every derived artifact before spool admission; no pre-redaction plaintext persistence exists anywhere; `controld.ingest` runs an independent second ruleset and quarantines.
4. **Anchor execution.** Bundles cannot name commands (decode-time rejection); the catalog is locally derived, user-consented, re-consented on change, visible in `mark1 doctor`; execution is network-denied, env-scrubbed to an allow-list, read-only outside the worktree, resource-capped, kill-switched.
5. **Tenancy.** Ingest stamps tenant from the verified token; ClickHouse is reachable only through the query chokepoint whose builder provably appends the tenant predicate, with fuzz and negative tests on every PR across Postgres, ClickHouse, the memory API, and S3 prefixes.
6. **Federation.** The (k,m) gate is a `HAVING` clause plus a trigger constraint over billing/domain-verified orgs with collusion collapse; published bodies are **intersection-reconstructed**, so a span no *m* tenants independently produced cannot publish; `invariant` artifacts are excluded by schema.
7. **Scope of reading.** Tailers operate only inside `mark1 enable`d workspaces; `.mark1ignore`; `mark1 status` shows the live read surface; `CoverageTransition` receipts make every enable/disable/bypass window attributable, and TVO reports carry a coverage band and refuse guarantee-grade issuance below the floor.

## What we reuse from the estate (verified by exploration)

- **Receipt spec** — vendor `canonical.py` (standalone: `DOMAIN_PREFIX`, `canonical_json/bytes`, `receipt_hash`) and the `keys.py` Ed25519 Signer protocol from `Omium-platform/core-services/recovery-orchestrator/app/receipts/`; domain prefix becomes `mark1-label-v1\0`. `chain.py`'s two-table design (`effect_receipts` + `receipt_chain_head`, migration `ro_012`) is the schema template, extended with `key_id`, rotation, and the checkpoint/inclusion-path columns.
- **Four-verdict vocabulary** — `satisfied|violated|refused|error`, authoritative as the PG enum in platform migration `008`; adopted unchanged (Paper II proves it Bayes-optimal, and that conflating infrastructure failure with `violated` incurs unavoidable excess risk).
- **Service conventions** — FastAPI, pydantic v2, asyncpg raw SQL, numbered idempotent `.sql` migrations, flat `tests/` (template: recovery-orchestrator). RLS in the platform's exact two-arg `current_setting('app.tenant_id', true)` form, with `*_app` non-superuser roles from day one.
- **Probe pattern** — the `PROBE_HANDLERS` dict-of-async-handlers style in `app/verify/probes.py` for the anchor/verifier registry; the tiered `tier1_deterministic.py` / `tier2_judge.py` / `ensemble.py` precedent informs the ensemble.
- **Training plane** — `omium-training-plane` consumed in Phases 5–6 via a new `mark1-parquet` source in data-refinery; its Rust VRR crates and the KTO/QLoRA trainer are reused, not rebuilt.
- **MCP precedent** — Omium-MCP's FastMCP decorator pattern for any Python-side MCP tools; `cortexd` serves MCP natively in Rust.
- **Confirmed greenfield:** no token metering and no Claude Code hooks usage exist anywhere in the estate. Both are net-new.

## Critical files, in build order (Phase 1)

1. `omium-mark1/proto/m1p/v1/*.proto` — envelope + event families. Everything in three languages compiles against this. **First commit, with `buf breaking` wired into CI immediately.**
2. `omium-mark1/rust/m1p-wire/` — prost codegen + M1PL framing with bounded `len` and a fuzz target.
3. `omium-mark1/go/mark1d/internal/spool/` — 64 MiB segments, crc32c, mmap'd ledger, per-class full-policy, `Dropped{}` accounting. Fuzz the decoder here too.
4. `omium-mark1/go/controld/ingest/` — S3-first landing, token-stamped tenancy, idempotent upsert, pre-egress scanner, ClickHouse async-insert.
5. `omium-mark1/migrations/` + `docs/adr/0001-clickhouse-ordering-key.md` — the receipt/registry/bundle schema and **the one irreversible ADR**, signed before the first production write.
6. `omium-mark1/python/shared/mark1_receipts/` — vendored `canonical.py`/`keys.py`, plus checkpoint Merkle + dual-signature + `key_id`.
7. `omium-mark1/tools/verifier/` — the standalone offline verifier. It ships in Phase 1 because "verify Omium" is the sales claim.
8. `omium-mark1/rust/mark1-hookshim/` + `go/mark1d/adapters/claudecode/` — hooks and the transcript tailer, with `message.id` sidechain dedupe as a protocol invariant.
9. `omium-mark1/python/intel/tvo/` — TVO engine v1, coverage metric, deterministic waste taxonomy.

## Verification

- **Phase 1:** golden hook fixtures and recorded transcripts (per pinned Claude Code version) replayed through `mark1d` → `controld` → ClickHouse; TVO output matches hand-computed values from the Paper I worked example; the standalone verifier validates a chain built end-to-end **with the Omium server offline**; spool decoder and M1PL framing fuzz targets green; deliberate kill -9 mid-batch loses nothing in the billing-grade classes. Dogfood on our own repos for ≥1 week ⇒ the first real TVO report.
- **Phase 2:** adjudicator unit tests against synthetic verifier outputs reproducing Paper II's posterior/verdict table; anti-tamper suite (mutated worktree, PATH-shimmed binary, injected suppression directive must each raise `tamper`); A/B on our own tasks with and without the stop-gate, iteration-count delta reported with confidence intervals.
- **Phase 3:** proxy conformance — byte-exact SSE passthrough against golden transcripts per dialect, chaos suite (upstream stall, mid-stream reset, slow client) with zero client-visible regression, tee provably unable to hold a client write; latency benchmark enforcing ≤1 ms median in CI; **OAuth token-shape canary must fail CI when the classifier misses**; negative test proving no code path forwards an unprovisioned credential.
- **Cross-cutting, every PR:** tenant-isolation negative tests across Postgres, ClickHouse, the memory API, and S3 prefixes (the decorative-RLS failure must be structurally impossible to repeat); `mark1 off` verified by byte-equality snapshot of the agent's config and behavior.
- **Ongoing:** every claim made to AIOS traces to a ledger query, and every number in a customer report carries its coverage band and cost basis.

## Decisions to make before code (ADRs, not code review)

1. ClickHouse ordering key and `ReplacingMergeTree` layout — irreversible once production writes start.
2. `task_seg.v1` merge rules — this defines the TVO denominator and therefore every number we will ever quote.
3. The Shapley game (players and `v(S)`) — precondition for any Shapley code; the deterministic waste taxonomy ships first regardless.
4. Key ceremony: device keys, server chain key, bundle signing keys (section-split), update key ≠ bundle key, rotation and cross-signing, witness selection.
5. **Founder/counsel items already tracked, unchanged by this plan:** the AIOS one-question email (API-key vs subscription seats), counsel review of Anthropic §D.4 before any training-leg work, and the a16z brief's traction blanks.

---

# Appendix A — Design documentation program (added 2026-08-28)

**Everything above this line is the canonical plan and is frozen.** This appendix does not revise it; it is the gate that stands between the approved plan and the first line of code. The founder's instruction: the plan is right, but HLD, LLD, infrastructure design and the introductory/architectural material must exist *before* implementation starts. Authoring is done by **Fable** agents (founder directive); reconciliation, contradiction-hunting and sign-off are done by the lead (Opus).

**Why this phase exists.** The approved plan names the components and the assembly order. It does not yet fix the things that are expensive to change after code exists: exact message definitions, table DDL, module boundaries, function-level contracts, failure semantics, IAM and network topology, and the test gates that make each phase's "Gate:" line objectively checkable. Writing those down now is what makes Phase 1 mechanical instead of exploratory.

## Deliverable: `omium-mark1/docs/` (docs only — zero code)

Creating the repo root now with only `docs/` inside means nothing has to move later. `mark1-architecture-spec.md` and `mark1-architecture-inputs.md` are copied in as `docs/spec/` on the first pass.

| # | Document | What it fixes |
|---|---|---|
| 00 | `README.md` | Index, reading order, doc status table, how to keep docs and code in sync |
| 01 | `01-introduction.md` | Problem, thesis, product definition, personas, scope/non-goals, **full glossary** (TVO, anchor, verdict, bundle, artifact, plane names, M1P, knee, coverage band), relationship to the three papers and the dossier, claim discipline (what we may and may not assert) |
| 02 | `02-requirements.md` | Numbered functional requirements (FR-*), non-functional requirements (NFR-*: latency, durability, availability, privacy budgets), hard constraints (ToS/legal), and an **acceptance criterion per requirement** — this is what turns each phase Gate into a checklist |
| 03 | `03-hld.md` | C4 L1/L2 context and container diagrams, the five planes and the flywheel, the two legal regimes, per-agent capability matrix, and **sequence diagrams for the 9 core flows**: subscription capture, API-key proxied request, anchor→fusion→gate, cortex injection, memory injection, policy-bundle distribution, receipt checkpoint + witness, corpus export, kill-switch/bypass |
| 04 | `04-lld-edge.md` | `mark1d`, `mark1-proxy`, `mark1-hookshim`, `cortexd` + the four Rust crates: module trees, key types/traits/interfaces, concurrency and ownership model, state machines, hot-path budgets, backpressure, every failure mode and its posture |
| 05 | `05-lld-cloud.md` | `controld`'s five modules end to end: ingest pipeline stages, OIDC device-code enrollment and revocation, policy distribution + ACK ledger + transparency log, DP release mechanics and the ε ledger, and the query chokepoint's construction-proof |
| 06 | `06-lld-intelligence.md` | `adjudicator-svc` and `mark1-intel`: ADJUDICATE implementation, spectral Dawid–Skene with the identifiability gate, gold-set lifecycle, noise certificates, TVO computation and waste taxonomy, policy compiler, OPE estimators, memory extraction/admission/retrieval, corpus exporter |
| 07 | `07-data-model.md` | The **actual** `m1p.v1` protobuf definitions, complete Postgres DDL (tables, indexes, RLS policies, `*_app` roles), ClickHouse DDL (tables, materialized views, TTL), PolicyBundle CBOR schema, spool segment binary layout, Parquet corpus schema |
| 08 | `08-api-contracts.md` | M1P/1 HTTP contract, control-plane REST surface, MCP tool schemas, per-agent hook contracts, CLI command surface, the UDS frame protocol, and a single error taxonomy with status-code mapping |
| 09 | `09-infrastructure.md` | AWS account and network topology, EKS, RDS, ClickHouse deployment shape, S3 layout + KMS, IAM/IRSA, Helm charts and GitOps wiring under existing conventions, environments, **capacity model and cost estimate with scaling triggers**, DR/backup, and edge distribution (packaging, signing, update channels) |
| 10 | `10-security-threat-model.md` | Trust boundaries, STRIDE per boundary, the OAuth-guard control in detail, credential custody, redaction, tenancy isolation, supply chain/SLSA, **key management and ceremony**, DP/(k,m) controls, reward-hacking and abuse, and a compliance control matrix mapping each of the plan's seven in-code enforcement points to its test |
| 11 | `11-observability-and-slo.md` | Self-monitoring **without OpenTelemetry**: internal metrics catalog, health/readiness semantics, SLIs/SLOs/error budgets, alert rules, runbooks, and `Dropped{}`/coverage accounting treated as first-class product telemetry rather than ops noise |
| 12 | `12-testing-and-quality.md` | Test pyramid, conformance suites (golden SSE, hook fixtures, token-shape canary), fuzz targets, chaos suites, tenant-isolation negative tests, performance benchmarks with CI thresholds, and the per-phase gate checklists |
| 13 | `13-repo-scaffold.md` | The exact file-by-file scaffold, build tooling (cargo workspace, go workspace, uv, buf, justfile), lint/format/pre-commit config, versioning and release strategy, CODEOWNERS |
| 14 | `14-delivery-plan.md` | Workstreams mapped to the six assembly phases, dependency graph, milestones, gate checklists, risk register with owners |
| — | `adr/0001…0008` | ClickHouse ordering key; `task_seg.v1`; the Shapley game; key ceremony; **no-OTel / why M1P exists**; language-boundary rationale; spool durability classes; client-side-first judges |

Diagrams are Mermaid embedded in the markdown so they render in GitHub and version as text. A polished visual set (Figma) is deliberately deferred — that is a customer/investor artifact, not an engineering one.

## Grounding facts (verified 2026-08-28 by three read-only estate scans)

These are the conventions the docs must mirror, with the file each was read from. They are inputs to the doc authors, not new plan decisions.

**Reuse targets, confirmed present and shaped as the plan assumed**
- Receipts: `recovery-orchestrator/app/receipts/{canonical,keys,chain}.py` — `DOMAIN_PREFIX = b"omium-receipt-v1\0"`, `canonical_json` = `sort_keys=True, separators=(",",":"), ensure_ascii=True`, `Signer` Protocol with derived `key_id = "ed25519:"+sha256(pub)[:16]`, and `verify_chain` reporting five defect kinds plus both `intact_prefix_seq` and `last_good_seq`. Migration `ro_012_effect_receipts.sql`: `effect_receipts` + `receipt_chain_head` (a locked row, deliberately **not** a sequence), `payload` stored as **`text` not `jsonb`**, 32/32/64-byte length CHECKs, genesis equivalence CHECK, and append-only enforced three ways (BEFORE UPDATE/DELETE trigger, BEFORE TRUNCATE trigger, REVOKE). Mark 1's chain is this schema plus `checkpoint_seq`, `inclusion_path`, and the server countersignature.
- Four verdicts: `CREATE TYPE sweep_verdict AS ENUM ('satisfied','violated','refused','error')` in recovery-orchestrator migration `008`, mirrored in Python as plain string constants (`V_SATISFIED`…), cast explicitly in SQL (`$15::sweep_verdict`). Adopt verbatim.
- RLS canonical form: `ENABLE` + `FORCE ROW LEVEL SECURITY`, `DROP POLICY IF EXISTS` then `CREATE POLICY tenant_isolation USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)` — the `NULLIF` is what makes an unset GUC match nothing. Set via `tenant_guc_setup` as the asyncpg pool `setup=` callback plus `FastAPI(dependencies=[Depends(tenant_context_dependency)])`; workers use `set_local_tenant` (`set_config(..., true)` inside the tx). `*_app` NOBYPASSRLS roles are created in `omium-gitops/prod/schema/07_service_roles.sql`.
- Probe registry: `app/verify/probes.py` `PROBE_HANDLERS` dict with `assert set(PROBE_HANDLERS) == set(_PROBE_HANDLED_KINDS)`; handlers return `tuple[bool, dict]`; unimplemented kinds are *refused*, never faked. The anchor registry copies this shape including the asserts.
- Service skeleton: `main.py` with `configure_logging` before config import, `lifespan` owning the pool + httpx client, deliberate un-caught boot refusals so the pod crashloops, `instrument_app`, `install_exception_handlers`, `asyncio.TimeoutError`/`asyncpg.InterfaceError` → 503 + `Retry-After`. Config is pydantic-settings with DSNs as `@property` (note `sslmode=require` — asyncpg's default `prefer` can silently fall back to plaintext).
- Migrations: plain numbered `.sql`, service-prefixed (`ro_0NN_*.sql`), idempotent by house style, run by `scripts/migrate-db.sh` tracking `schema_migrations` keyed `"${service}__${filename}"`; in prod they run as an Argo CD Sync-hook `Job` (`omium-gitops/prod/db-migrate-job.yaml`).
- Tests: flat `tests/`, `python -m pytest tests -o asyncio_mode=auto`, real-Postgres suites gated on an env DSN (`pytest.mark.skipif`) rather than testcontainers — CI has no Docker.

**Infrastructure the docs must build on**
- Terraform: `global/{bootstrap,org}` + `modules/` + `envs/{staging,prod}`; **no `.tfvars` anywhere** — defaults live inline in each env's `variables.tf`. S3+DynamoDB backend, one state key per env. Pins: TF ≥1.9, AWS provider ~>5.60, EKS 1.30, RDS Postgres 15. Prod RDS `db.r6g.large`, multi-AZ, 14-day backups, deletion protection; pgvector ships with RDS PG15.
- Helm: one YAML per service holding Deployment + Service + HPA; security defaults (`runAsNonRoot`, uid 65532, `readOnlyRootFilesystem`, `drop: [ALL]`, `seccompProfile: RuntimeDefault`) applied through `omium.podSecurityContext`/`omium.containerSecurityContext` helpers with per-service overrides; an `omium.spread` helper exists after a 2026-08-13 single-node incident. Scraping is by **pod annotation** — no ServiceMonitor objects exist anywhere.
- GitOps: plain Applications (no ApplicationSets), app-of-apps from `bootstrap/prod-root.yaml`, multi-source charts with `$values` pointing at `omium-gitops/helm/values.prod.yaml`, `automated: {prune, selfHeal}` + `ServerSideApply=true`. Releases are `imageTag: "<sha7>"` pins; `latest` was retired 2026-08-13 because a floating tag on an IMMUTABLE ECR repo is a permanent pin, not a pointer.
- Secrets: External Secrets Operator + AWS Secrets Manager + IRSA — `ClusterSecretStore omium-aws-secrets` with JWT auth, one `ExternalSecret` per k8s Secret at sync-wave −1. No SealedSecrets. Mark 1's signing keys arrive this way (as `RECEIPT_SIGNING_KEY` already does).
- Rust build: virtual Cargo workspace, all versions in `[workspace.dependencies]`, release profile `opt-level=2, lto="thin", strip=true`; `rust:1.91-slim-bookworm` builder → `gcr.io/distroless/cc-debian12:nonroot` (**glibc, not musl**); CI runs `fmt --check`, `clippy --all-targets -- -D warnings`, `build --locked`, `test --no-fail-fast`, and pushes only `:sha7`.
- Go already exists: `checkpoint-manager` and `policy-engine` (go 1.25, `cmd/main.go` + `internal/{...}`, an `obs` package, gRPC + Prometheus, local `replace` to the generated-contracts module). Mark 1's Go is not a new language in the estate — mirror this layout.
- Protobuf: buf v2 with **pinned remote plugins** and committed outputs under `shared/proto/gen/{go,python,rust,ts}`; the Rust planes `include!` the committed gen and run no `build.rs`. Gates `g1_contracts.sh` (lint/breaking) and `g2_codegen_fresh.sh` exist.
- OpenTelemetry in the estate today: only `omium-training-plane` (optional, fail-soft, activated by `OTEL_EXPORTER_OTLP_ENDPOINT`) and a platform OTLP *ingest* endpoint. No collector is deployed; the observability module explicitly defers logs/traces. **Mark 1 taking no OTel dependency costs nothing and breaks nothing.**
- Claude Code transcripts confirmed: `~/.claude/projects/<munged-cwd>/<session-id>.jsonl`; assistant lines carry both `requestId` and `message.id`, and `usage` with `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`, `service_tier`. The dedupe key the plan specifies is constructible from what is actually on disk.

**Four deltas the docs must resolve explicitly (none change the plan; all change how it lands)**
1. **The trainer does not read Parquet.** `training-jobs/.../dataset.py` reads `manifest.json` + `rows.jsonl` (`KtoRow`: prompt / completion_ref / label / reward / propensity / holdout_bucket / …) from a local dir or `s3://` prefix, and states why Arrow shards alone cannot drive KTO — they carry no label column. `06`/`07` specify the corpus exporter emitting **receipted Parquet for analytics plus the KTO JSONL+manifest pair for the trainer**, with the receipt covering both.
2. **`data-refinery` has no pluggable source trait.** The source is the concrete `CorpusReader` struct (`scan_worm` / `read_train_rows`, env-configured, currently HTTP against the orchestrator). `06` specifies `mark1-parquet` as an added constructor + method pair on `CorpusReader` following its existing signatures, not an invented trait.
3. **Neither ClickHouse nor NATS exists in any Terraform module or GitOps manifest — but MSK/Kafka does** (3 brokers, IAM auth, TLS, KMS, both envs). `09` writes the new ClickHouse module and records in an ADR that when the second ledger consumer appears, the estate's existing MSK is evaluated before NATS is introduced.
4. **CI has no `cargo-deny`, no `govulncheck` and no SBOM generation** (only gitleaks, trivy, hadolint, pip-audit). Since the plan promises SLSA-attested releases, `12`/`13` specify those as new gates in `omium-mark1`'s own CI rather than assuming inheritance. `10` also notes that prod has no monitoring kustomization (staging only) and that AWS account IDs in `terraform/README.md` have drifted from the live backends — infrastructure docs cite the live values.

## How the docs get produced

1. **Ground first** — done; the facts above are the input.
2. **Author in dependency order, in parallel batches**, each Fable agent receiving the frozen plan, the architecture spec, and the relevant grounding facts. Batch 1 fixes the contracts everything else cites (01, 02, 07, 08); batch 2 the designs that consume them (03, 04, 05, 06); batch 3 the operational envelope (09, 10, 11, 12); batch 4 execution (13, 14) plus the ADRs.
3. **Reconcile.** The lead reads the full set and hunts contradictions across documents — a field named one way in 07 and another in 04, a latency budget in 09 that disagrees with 04, a control claimed in 10 with no test in 12. Every contradiction is resolved in favour of the frozen plan and the spec.
4. **Adversarially review.** A security/compliance reader and a staff-engineer reader attack the doc set as they attacked the designs, and their surviving findings are folded in. `/ponytail-review` and `/ponytail-audit` become standing gates once code exists.

## Verification (how we know this phase is done)

- Every component in the plan's registry has an LLD section; every LLD section names its types, its failure modes, and its tests.
- Every table in the plan's data-stores section has real DDL in `07`, and every RLS policy has a matching negative test named in `12`.
- Each of the six assembly phases' **Gate:** lines resolves to a numbered, checkable acceptance criterion in `02`.
- Each of the seven in-code compliance enforcement points has a row in `10`'s control matrix and a named test in `12`.
- All eight ADRs are written with a decision recorded — the four flagged in "Decisions to make before code" are signed off by the founder before Phase 1 begins.
- No document references OpenTelemetry as a dependency anywhere.
- A reader who has never seen this conversation can go from `01-introduction.md` to writing `proto/m1p/v1/*.proto` without asking a question.
