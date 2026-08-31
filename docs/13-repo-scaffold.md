# 13 — Repository Scaffold and Build Tooling

**Status:** Authored 2026-08-28 against the frozen execution plan (`docs/spec/execution-plan-v2.md`), the LLDs (`04`/`05`/`06`), and the estate conventions verified in the plan's grounding facts. Where this document and the plan disagree, the plan wins.
**Scope:** the exact file-by-file scaffold of `omium-mark1/`, every build-tooling config written out in full, lint/format/pre-commit, CI gates, packaging, versioning, contribution discipline, and the first-commit sequence into Phase 1. This is the document someone opens to make the first commit.
**Config blocks in this document are normative:** they are the intended initial contents of the named files, byte-for-byte where a pin is stated. A pin changed at implementation time is a PR-visible diff against this document (per the sync rule in `00-README.md`).

## 0. Principles

### 0.1 One monorepo, three languages, one rule each

The plan's component registry fixes **9 deployables + 4 client crates** (`mark1-redact`, `mark1-receipt`, `mark1-policy`, `m1p-wire`), plus `mark1-frames` as a proxy-internal crate listed separately. Everything lives in one repository because the thing being versioned is *one machine*: a proto change, its three bindings, the edge code, the cloud code, and the contract documents land in one atomic commit or not at all.

The language rule, applied mechanically — a new component goes where its column says, and a component that seems to need two columns is two components:

| Language | Wins when | Mark 1 components |
|---|---|---|
| **Rust** | hostile-input parsing, sub-ms/small-RSS budgets, memory-safety as a security property, static single binaries shipped to machines we don't own | `mark1-proxy`, `mark1-hookshim`, `cortexd`, the four client crates, `mark1-frames`, `tools/verifier` |
| **Go** | long-lived daemons, process supervision, network plumbing, one-binary-many-modules services, fast cross-compile for a CLI | `mark1d`, `controld`, `mark1` CLI |
| **Python** | numerics (numpy-only spectral D-S), judge orchestration, batch jobs over DuckDB/Parquet, FastAPI service skeleton inherited from the estate | `adjudicator-svc`, `mark1-intel`, `shared/mark1_receipts` |

### 0.2 One proto source, three generated bindings

`proto/m1p/v1/*.proto` is the single source. `buf generate` (pinned **remote** plugins, §5) emits committed outputs under `proto/gen/{go,python,rust}`:

- **Rust** `include!`s the committed gen — **no `build.rs` anywhere in the workspace** (§2.4). Mirrors the estate exactly (`omium-training-plane` consumes `shared/proto/gen/rust` the same way).
- **Go** imports the committed gen as a local module via `replace` (§3.3). Mirrors `checkpoint-manager`.
- **Python** imports the committed betterproto dataclasses as a uv workspace package (§4.4).

Committed codegen means: no protoc/buf toolchain at build time, byte-identical bindings for every builder, and drift is impossible to hide — the CI freshness gate (`just gen-check`, §5.5) regenerates and fails on any diff, exactly the estate's `g2_codegen_fresh.sh` discipline.

There is **no `gen/ts`**: Mark 1 has no TypeScript surface in v1. The estate's fourth binding is a dashboard concern; adding one later is a `buf.gen.yaml` diff, not a design change.

### 0.3 What this repository deliberately does not contain

- **No OpenTelemetry, anywhere, including transitively.** Enforced mechanically in all three languages: `cargo-deny` bans, `.golangci.yml` depguard, ruff `banned-api` + lockfile scans — §7.5. Self-observation is the `obs` packages, `Dropped{}` accounting, and coverage transitions (doc 11).
- **No gRPC.** M1P is plain HTTPS + protobuf to the edge; the local fabric is M1PL over UDS/named pipes; cloud services speak REST. Consequently no tonic, no grpc-go, no grpcio — the buf plugin set (§5.2) generates messages only. (Divergence from the estate's plugin list, recorded in §5.2.)
- **No code changes to Omium-platform.** Reuse is by *vendoring* (`mark1_receipts` from recovery-orchestrator, the `obs` file into `controld`) with the source path recorded in the vendored file's header. The training plane is consumed in Phases 5–6 from its own repo.
- **No Terraform.** Cloud infra modules land in the estate's existing Terraform tree under its conventions (doc 09); this repo carries Helm values, compose (dev-only), and edge packaging.
- **No floating tags.** Images are `<sha7>`; base images are version-pinned; `latest` appears nowhere (§9.5).
- **No `wasm_module`, no command strings in bundles, no OTel exporter "just in case".** Deleted branches stay deleted; the scaffold has no directory waiting for them.

### 0.4 Reconciliation flags found while authoring

For the lead's contradiction pass; this document takes the stated side.

| # | Disagreement | Sides | Side taken here |
|---|---|---|---|
| R-13.1 | `buf breaking` category | plan §M1P: `WIRE_JSON`; estate `shared/proto/buf.yaml`: `FILE` | **the plan** — `WIRE_JSON` is the weakest category that still guarantees wire + JSON compatibility, which is what a versioned-by-package protocol needs; the estate's `FILE` is stricter about source-level moves Mark 1 does not need to freeze. Divergence recorded in §5.1 |
| R-13.2 | Go runtime image | estate `checkpoint-manager/Dockerfile`: `alpine:latest` runtime stage; doc 09 §capacity: "All Go/Rust images are distroless" | **doc 09 / distroless** — `alpine:latest` is a floating tag, the exact class retired 2026-08-13; the estate's own Dockerfile contradicts its stated posture. Mark 1 uses `gcr.io/distroless/static-debian12:nonroot` for Go (§8.1) |
| R-13.3 | Migrations location | plan tree: one root `migrations/`; 06 trees: per-service `python/adjudicator/migrations/` (`adj_0NN_`) and `python/intel/migrations/` (`in_0NN_`) | **both** — root `migrations/` holds the controld-owned core schema (`m1_0NN_`, per 05 §7); the Python services keep their estate-convention service-local dirs. One runner (`scripts/migrate-db.sh` pattern), three prefixes. Treated as an expansion of the plan tree, not a contradiction of it |
| R-13.4 | Python version | estate skeleton is `python:3.11-slim`; Mark 1 is a new repo | **3.12** — a greenfield repo pins the current stable line; the estate's 3.11 is the skeleton *source*, not a ceiling. `requires-python = ">=3.12"` (§4.2) |

---

## 1. The full tree

Expanded from the plan's normative "Repo layout" tree; module internals match `04` §2/§3/§4/§5/§6/§7, `05` §1, and `06` §1/§7 exactly. Annotations say what each entry is *for*; the LLDs say what is *in* it.

```
omium-mark1/
├── .editorconfig                    # §7.7
├── .gitattributes                   # proto/gen/** linguist-generated; *.ring/*.bin binary
├── .gitignore                       # target/, dist/, .venv/, uv cache, spool/test artifacts
├── .gitleaks.toml                   # estate gitleaks config, path-scoped allowlist for conformance fixtures
├── .pre-commit-config.yaml          # §7.6
├── .golangci.yml                    # §7.3 — includes the depguard no-OTel + querychoke-only-ClickHouse rules
├── ruff.toml                        # §7.4 — includes the banned-api no-OTel rule
├── rustfmt.toml                     # §7.1
├── clippy.toml                      # §7.2 — allow-unwrap-in-tests
├── rust-toolchain.toml              # channel "1.91" — matches the rust:1.91-slim-bookworm builder
├── Cargo.toml                       # §2 — the virtual workspace root (no [package])
├── Cargo.lock                       # committed; CI builds --locked
├── deny.toml                        # §7.5 — cargo-deny: OTel ban, license policy, advisories
├── go.work                          # §3.1 — dev ergonomics over the three Go modules + gen module
├── go.work.sum
├── pyproject.toml                   # §4.1 — uv workspace root (no code; workspace table + shared tool config)
├── uv.lock                          # committed; CI syncs --frozen
├── justfile                         # §6 — the one entry point for every build/test/lint/gen verb
├── CODEOWNERS                       # §10.1 — root file; GitHub resolves it, no .github/ copy exists
├── LICENSE                          # UNLICENSED (proprietary) — except tools/verifier/LICENSE (Apache-2.0)
│
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md     # §10.2
│   └── workflows/
│       ├── ci.yml                   # 3-OS matrix; every gate in §6.3's table
│       ├── release.yml              # tag-triggered: build, sign, notarize, SBOM, SLSA attestation (§8/§9)
│       └── canary.yml               # weekly: OAuth token-shape canary vs recorded shapes (plan §Compliance 1)
│
├── docs/                            # this documentation set, 00–14 + adr/ + spec/ (already present)
│   └── adr/                         # 0001 CH ordering key … 0008 client-side-first judges
│
├── proto/
│   ├── buf.yaml                     # §5.1 — lint STANDARD, breaking WIRE_JSON
│   ├── buf.gen.yaml                 # §5.2 — pinned remote plugins → proto/gen/{go,python,rust}
│   ├── buf.lock                     # §5.3
│   ├── m1p/v1/
│   │   ├── envelope.proto           # Batch, Event envelope, Dropped{}, idem/event_id fields (07 §2)
│   │   ├── events.proto             # Session/Task/Turn/ToolUse/ModelRequest/Response/Usage/…
│   │   ├── verify.proto             # AnchorVote, JudgeVote, RmScore, ConsistencyVote, VerdictEvent, AnchorIntegrity
│   │   ├── intelligence.proto       # CortexInjection, MemoryInjection, RouteDecision, CoverageTransition
│   │   ├── policy.proto             # bundle ACK types, GuardDecision (bundle body itself is CBOR, 07)
│   │   └── artifacts.proto          # ArtifactOutcome, ReceiptCheckpoint, EvidenceRecord
│   └── gen/                         # COMMITTED codegen — never hand-edited (freshness gate §5.5)
│       ├── go/                      # its own module: go.mod (github.com/Omium-ai/omium-mark1/proto/gen/go)
│       ├── python/                  # betterproto dataclasses + a minimal pyproject.toml (uv workspace member)
│       └── rust/                    # m1p.v1.rs — include!'d by m1p-wire; no build.rs
│
├── rust/                            # all crates are members of the root virtual workspace (§2)
│   ├── mark1-proxy/
│   │   ├── Cargo.toml
│   │   ├── src/{main.rs, guard/provenance.rs, router/, request/, upstream/, response/, tee/}   # 04 §3
│   │   └── benches/latency.rs       # the ≤1 ms median CI threshold (12)
│   ├── mark1-frames/
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, anthropic_sse/, openai_responses/, openai_chat/, gemini/, bedrock_eventstream/}  # 04 §4, per-module DIALECT_REV
│   ├── mark1-redact/
│   │   ├── Cargo.toml
│   │   ├── src/{lib.rs, rules.rs, scan.rs, admit.rs, entropy.rs}          # 04 §7.1 — two axes; admit has no off switch
│   │   ├── benches/throughput.rs    # the ~100 MB/s worst-case CI bench (12)
│   │   └── fuzz/                    # cargo-fuzz crate (workspace-excluded): fuzz_targets/admit.rs
│   ├── mark1-receipt/
│   │   ├── Cargo.toml
│   │   └── src/{lib.rs, canonical.rs, chain.rs, merkle.rs, keyring.rs}    # 04 §7.2 — DOMAIN_PREFIX mark1-label-v1\0
│   ├── mark1-policy/
│   │   ├── Cargo.toml
│   │   ├── src/{lib.rs, verify.rs, decode.rs, sections.rs, builtin.rs}    # 04 §7.3 — command-string grammar rejection; conservative built-ins
│   │   └── fuzz/                    # fuzz_targets/bundle_decode.rs
│   ├── mark1-hookshim/
│   │   ├── Cargo.toml               # NO tokio — synchronous by design (04 §5)
│   │   └── src/{main.rs, maps.rs, emit.rs, fabric.rs, gate.rs, spill.rs}
│   ├── cortexd/
│   │   ├── Cargo.toml
│   │   └── src/{main.rs, l0_merkle/, l1_tags/, l2_graph/, l3_scip/, cas/, shards/, map/, mcp/, fabric/, session/}  # 04 §6
│   └── m1p-wire/
│       ├── Cargo.toml
│       ├── gen/m1p.v1.rs            # symlink-free COPY staged from proto/gen/rust by `just gen` (§2.4)
│       ├── src/{lib.rs, frame.rs}   # M1PL framing, bounded len, incremental FrameDecoder (04 §7.4)
│       └── fuzz/                    # fuzz_targets/frame_decode.rs — corpus doubles as Go conformance vectors
│
├── go/
│   ├── mark1d/
│   │   ├── go.mod                   # §3.2 — module github.com/Omium-ai/omium-mark1/go/mark1d
│   │   ├── cmd/main.go              # flag parse, config, obs init, run loop — nothing else (04 §2)
│   │   ├── adapters/{claudecode,codex,gemini,opencode,copilot,cursor,crush}/   # 04 §2.10; only claudecode has logic at Phase 1
│   │   ├── internal/{capture,tailers,anchors,verdict,spool,uplink,policy,coverage,supervise,identity,fabric,obs}/  # 04 §2 exactly (+fabric, 04 §2 note)
│   │   └── Dockerfile               # dev/fleet container only; the edge artifact is the packaged binary (§8.4)
│   ├── mark1/
│   │   ├── go.mod
│   │   ├── cmd/main.go
│   │   └── internal/{enroll,enable,status,doctor,report,off,verifyreceipts}/   # one package per subcommand (plan §CLI)
│   └── controld/
│       ├── go.mod
│       ├── cmd/controld/main.go     # boot order per 05 §1.2
│       ├── internal/{config,server,auth,obs,pg,ingest,enroll,policydist,dprelease,querychoke}/  # 05 §1 exactly (ingest/{pipeline,scanner,s3land,chproj,sidefx}, querychoke/chconn…)
│       └── Dockerfile               # §8.2 — the representative Dockerfile, in full
│
├── python/
│   ├── adjudicator/
│   │   ├── pyproject.toml           # §4.3
│   │   ├── app/{main,config,logging,db,errors}.py + {receipts→shared, registry/, adjudicate/, spectral/, certs/, gold/, judges/, jobs/}   # 06 §1 exactly
│   │   ├── migrations/              # adj_0NN_*.sql (R-13.3)
│   │   ├── tests/                   # flat; python -m pytest tests -o asyncio_mode=auto; crowd-kit as dev-only oracle
│   │   └── Dockerfile
│   ├── intel/
│   │   ├── pyproject.toml
│   │   ├── app/{main,config,logging,db,errors,scheduler,jobs}.py + {memory/, tvo/, policy_compiler/, ope/, corpus/}   # 06 §7 exactly
│   │   ├── migrations/              # in_0NN_*.sql
│   │   ├── tests/
│   │   └── Dockerfile
│   └── shared/
│       └── mark1_receipts/
│           ├── pyproject.toml       # uv workspace member, imported by both services
│           ├── src/mark1_receipts/{canonical.py, keys.py, checkpoint.py, __init__.py}  # vendored from recovery-orchestrator app/receipts/ + checkpoint Merkle/dual-sig/key_id
│           └── tests/
│
├── tools/
│   ├── verifier/                    # STANDALONE OPEN-SOURCE offline receipt/chain/witness verifier
│   │   ├── Cargo.toml               # workspace member; depends only on mark1-receipt + serde/clap
│   │   ├── LICENSE                  # Apache-2.0 — "verify Omium" requires the verifier be inspectable
│   │   └── src/main.rs
│   ├── trace-check                  # 12 §10.3 — requirement → test gate; its own `just` recipe and
│   │                                #   its own CI job, because it is built to go red on an unproven
│   │                                #   requirement and that signal must not share a lane
│   └── ci/                          # the custom mechanical gates, each a small POSIX script
│       ├── otel_gate.sh             # §7.5 — lockfile scans, all three languages
│       ├── secret_type_gate.sh      # §7.5 — the Secret<T> grep gate
│       ├── override_pattern_gate.sh # 04 §3.1(4) — no guard-override cfg/flag names in mark1-proxy
│       ├── build_tag_gate.sh        # §7.5 — every Go build tag documented in the justfile inventory
│       ├── contracts_sync_check.sh  # §10.3 — contract diff ⇒ 07/08 must be in the same PR
│       ├── conformance_crosslang.sh # runs shared vectors through Rust + Go + Python implementations
│       └── gen_fresh.sh             # §5.5 — buf generate && git diff --exit-code proto/gen rust/m1p-wire/gen
│
├── conformance/                     # fixtures are DATA, versioned with the code that must pass them
│   ├── frames/<dialect>/<vendor-version>/*.sse       # golden SSE transcripts, byte-exact passthrough + parse snapshots
│   ├── hooks/<agent>/<pinned-version>/*.json         # hook fixtures; an adapter slot opens only when its spike fixture lands
│   ├── canary/token-shapes/                           # OAuth token-shape corpus for the weekly classifier canary
│   ├── vectors/{m1pl,redact,receipt,bundle,fusion}/   # cross-language vectors: the implementations must agree bit-identically
│   │                                                  #   (fusion is Go↔Python only — ADJUDICATE has no Rust twin, 06 §3)
│   ├── tenancy/                                       # tenant-isolation negative-test specs (PG, CH, memory API, S3 prefixes)
│   └── traceability.yaml                              # 12 §10.2 — every 02 §9 requirement → the tests that prove it
│
├── deploy/
│   ├── helm/                        # estate shape: one YAML per cloud service (controld, adjudicator, intel) + values
│   ├── compose/                     # DEV ONLY — postgres, clickhouse, minio, the three services; never deployed
│   └── packaging/
│       ├── macos/                   # pkgbuild + notarytool scripts, LaunchAgent plist
│       ├── windows/                 # WiX .wxs, Azure Trusted Signing config, per-user service install
│       ├── linux/                   # nfpm.yaml (deb+rpm), systemd user unit, repo metadata signing
│       └── manifest/                # the CDN update manifest source + ring pins (09 §11.2) — version-controlled, CI-signed
│
├── migrations/                      # m1_0NN_*.sql — controld-owned core schema: tenants/devices, receipt chain,
│                                    #   certs, verifier registry, artifacts, contributions, ε ledger, bundles, gold sets (05 §7)
└── scripts/
    ├── migrate-db.sh                # estate runner pattern; schema_migrations keyed "m1__${filename}"
    └── bootstrap.sh                 # §6.4 — clean-machine setup (with bootstrap.ps1 for Windows)
```

Deployables ↔ tree check (the registry discipline): `mark1d`, `mark1-proxy`, `mark1-hookshim`, `cortexd`, `mark1` CLI, `controld`, `adjudicator-svc`, `mark1-intel` are eight; the ninth, `omium-training-plane`, is the existing estate repo consumed in Phases 5–6 and deliberately **absent from this tree**. The four client crates and `mark1-frames` are all under `rust/`. Nothing in the plan's tree is renamed, moved, or dropped.

---

## 2. Cargo workspace

### 2.1 Root `Cargo.toml` — written out

Virtual workspace (no `[package]` at root), mirroring `omium-training-plane/Cargo.toml`: all versions in `[workspace.dependencies]`, the estate release profile verbatim. Pins are the current stable lines as of 2026-08; prost stays on the 0.13 line because the pinned `neoeinstein-prost:v0.4.0` remote plugin (§5.2, same as the estate) generates 0.13-idiom code.

```toml
# omium-mark1 — virtual Cargo workspace. Estate conventions (omium-training-plane):
# all versions in [workspace.dependencies]; release opt-level=2, lto="thin", strip=true;
# committed proto gen is include!'d — NO build.rs exists anywhere in this workspace (§2.4).
[workspace]
resolver = "2"
members = [
    "rust/m1p-wire",
    "rust/mark1-redact",
    "rust/mark1-receipt",
    "rust/mark1-policy",
    "rust/mark1-frames",
    "rust/mark1-hookshim",
    "rust/mark1-proxy",
    "rust/cortexd",
    "tools/verifier",
]
# cargo-fuzz crates need nightly and their own profiles; they build via `just fuzz`, not the workspace.
exclude = [
    "rust/m1p-wire/fuzz",
    "rust/mark1-redact/fuzz",
    "rust/mark1-policy/fuzz",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "UNLICENSED"     # tools/verifier overrides: license = "Apache-2.0"
authors = ["Omium"]
rust-version = "1.91"

[workspace.lints.clippy]
# Hot-path crates opt in via [lints] workspace = true (§7.2). Tests are exempt via clippy.toml.
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
dbg_macro = "deny"
print_stdout = "deny"      # edge processes log via tracing or not at all; stdout belongs to hook replies (shim allows locally)

[workspace.dependencies]
# --- async runtime + HTTP (proxy, cortexd MCP; the shim is synchronous and takes NONE of these) ---
tokio = { version = "1.47", features = ["rt-multi-thread", "net", "io-util", "time", "sync", "signal", "fs", "process", "macros"] }
hyper = { version = "1.7", features = ["http1", "http2", "client", "server"] }
hyper-util = { version = "0.1", features = ["tokio", "client-legacy", "server-auto"] }
http = "1.3"
http-body-util = "0.1"
tower = { version = "0.5", features = ["util", "timeout", "limit"] }
tokio-util = "0.7"
axum = "0.8"                                     # cortexd MCP loopback server only
bytes = "1.10"
futures = "0.3"

# --- TLS: rustls with the ring provider — one crypto backend across all edge triples
#     (aws-lc-rs complicates Windows/macOS cross-builds for zero benefit here) ---
rustls = { version = "0.23", default-features = false, features = ["ring", "tls12", "logging"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }
rustls-pemfile = "2.2"
webpki-roots = "1.0"

# --- proto + framing (committed gen; 0.13 line pinned to the neoeinstein-prost 0.4.0 plugin output) ---
prost = "0.13"
prost-types = "0.13"

# --- cortexd index stack ---
tree-sitter = "0.25"
tree-sitter-python = "0.23"                      # grammar crates are pinned individually; a bump is a
tree-sitter-rust = "0.24"                        #   grammar_rev bump in the CAS key (04 §6.1), so pins
tree-sitter-go = "0.23"                          #   are load-bearing, not hygiene
tree-sitter-typescript = "0.23"
tree-sitter-javascript = "0.23"
petgraph = "0.8"
redb = "2.6"
rusqlite = { version = "0.34", features = ["bundled"] }   # CAS; bundled keeps the binary self-contained
notify = "8"
memmap2 = "0.9"

# --- crypto: hashing, signing, sealing, custody ---
blake3 = "1.8"
sha2 = "0.10"
hmac = "0.12"
subtle = "2.6"                                   # constant-time comparisons (guard fingerprint match)
ed25519-dalek = { version = "2.2", features = ["rand_core", "zeroize"] }
x25519-dalek = { version = "2.0", features = ["static_secrets"] }   # device spill sealing (04 §5.4)
chacha20poly1305 = "0.10"                        # spill-ring AEAD under the sealed key
zeroize = { version = "1.8", features = ["derive"] }
rand = "0.8"                                     # rand_core 0.6 line, matching ed25519-dalek 2.x
constant_time_eq = "0.3"

# --- redaction scanner ---
regex = "1.11"
aho-corasick = "1.1"                             # prefilter (04 §7.1)

# --- wire + bundle encodings ---
zstd = "0.13"
crc32c = "0.6"
ciborium = "0.2"                                 # PolicyBundle CBOR decode; canonical-form checks live in mark1-policy
uuid = { version = "1.17", features = ["v7"] }   # RFC 9562 UUIDv7, Method-1 counter

# --- serde / errors / logging (tracing has NO OTel bridge — deny.toml enforces) ---
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
clap = { version = "4.5", features = ["derive"] }   # cortexd, tools/verifier; the shim parses NO args

# --- platform ---
libc = "0.2"                                     # prctl/PR_SET_DUMPABLE, RLIMIT_CORE, ioprio
windows-sys = { version = "0.60", features = ["Win32_System_Pipes", "Win32_System_JobObjects", "Win32_Security", "Win32_Foundation", "Win32_Storage_FileSystem"] }

# --- intra-workspace ---
m1p-wire = { path = "rust/m1p-wire" }
mark1-redact = { path = "rust/mark1-redact" }
mark1-receipt = { path = "rust/mark1-receipt" }
mark1-policy = { path = "rust/mark1-policy" }
mark1-frames = { path = "rust/mark1-frames" }

# --- dev/test only ---
tempfile = "3"
criterion = { version = "0.6", features = ["html_reports"] }
proptest = "1"

# Estate release profile, verbatim (omium-training-plane).
[profile.release]
opt-level = 2
lto = "thin"
strip = true
```

### 2.2 Per-crate `Cargo.toml` shape

Every crate inherits the workspace tables and names no version locally — a version literal in a member `Cargo.toml` is a review-rejectable diff. Representative (`rust/mark1-hookshim/Cargo.toml`):

```toml
[package]
name = "mark1-hookshim"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true
rust-version.workspace = true

[lints]
workspace = true            # unwrap/expect/panic denied crate-wide; tests exempt via clippy.toml

[dependencies]
m1p-wire = { workspace = true }
mark1-redact = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
x25519-dalek = { workspace = true }
chacha20poly1305 = { workspace = true }
zeroize = { workspace = true }
libc = { workspace = true }
# NOTE: no tokio, no clap, no config crate — the shim is a synchronous, argument-less,
# config-less binary by design (04 §5): startup cost is the budget.

[target.'cfg(windows)'.dependencies]
windows-sys = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

Which crates take `[lints] workspace = true`: **all of them.** The rule is workspace-wide because every Rust component is either on a hot path (proxy, shim, frames, wire, redact) or a long-lived unattended daemon (cortexd) or a correctness tool (receipt, policy, verifier) — there is no crate where a panic on hostile input is acceptable. Cold paths that genuinely cannot fail use `expect` in `#[cfg(test)]` or justify a targeted `#[allow(clippy::unwrap_used)]` with a comment; the diff makes the justification reviewable.

### 2.3 Binary size and static linking

Edge binaries build from this same workspace with the same release profile, targeting the platform triples directly (09 §11.1): `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` (glibc — matching the distroless-cc container decision; **not musl**), `aarch64-apple-darwin` + `x86_64-apple-darwin` (lipo'd Universal2), `x86_64-pc-windows-msvc`. `rusqlite`'s `bundled` feature and rustls-with-ring keep the dependency closure free of system OpenSSL/SQLite, which is what makes the same crate set build on all five triples without a per-OS dependency matrix.

### 2.4 The committed-codegen decision (no `build.rs`) — rationale and the gate that keeps it honest

**Decision:** `proto/gen/rust/m1p.v1.rs` is generated by `buf generate` (remote plugin, §5.2), staged by `just gen` into `rust/m1p-wire/gen/m1p.v1.rs` as a plain copied file, committed, and `include!`'d:

```rust
// rust/m1p-wire/src/lib.rs
pub mod pb {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/gen/m1p.v1.rs"));
}
```

**Why (mirroring the estate, which learned this the hard way):**
1. **No protoc at build time.** A contributor, the CI runner, and the Docker builder all compile the same bytes; there is no "works with my protoc" class of failure and no network dependency inside `cargo build`.
2. **The generated code is reviewable.** A proto change shows its exact Rust surface in the PR diff, next to the `.proto` diff and the `07` diff — the contract-sync rule (§10.3) is checkable by a reader, not just a tool.
3. **`build.rs` is a supply-chain surface.** A workspace whose build executes no arbitrary code at compile time is a materially smaller SLSA story (§8.5); `cargo-deny` + `--locked` then cover everything that runs.
4. **The staged copy (not a `../../proto/gen` path `include!`)** keeps the crate self-contained for `cargo publish`-style packaging of the open-source verifier's dependency closure, and keeps Docker build contexts simple.

**The freshness gate:** `tools/ci/gen_fresh.sh` runs `buf generate` + the stage step and fails CI on any `git diff` in `proto/gen/` or `rust/m1p-wire/gen/` — the estate's `g2_codegen_fresh.sh`, verbatim in spirit. Hand-editing generated code is therefore not "forbidden", it is *impossible to land*: the next CI run regenerates and diffs. `.gitattributes` marks `proto/gen/** linguist-generated` so review tooling collapses it by default while keeping it diffable on demand.

---

## 3. Go workspace

### 3.1 `go.work`

Three service modules plus the generated-contracts module. The estate predates `go.work` (its two Go services live in separate corners of a polyglot repo); Mark 1 has three modules in one repo, so a workspace file is the ergonomic addition that costs nothing — it affects local dev only and is **not** consulted by Docker or release builds (`GOFLAGS=-mod=mod` never set; builds run `-mod=readonly` against each module's `go.sum`).

```
// go.work
go 1.25.14

use (
    ./go/controld
    ./go/mark1
    ./go/mark1d
    ./proto/gen/go
)
```

### 3.2 Module layout and the `internal/` discipline

Estate convention verbatim (`checkpoint-manager`, `policy-engine`): `cmd/main.go` + `internal/{...}`. Everything except `cmd/` and (for `mark1d`) `adapters/` lives under `internal/`, so no package in one service can import another service's guts — cross-service sharing happens through the generated proto module or not at all. `mark1d/adapters/` sits outside `internal/` deliberately: adapters are the documented extension surface (a future eighth agent is a new adapter package + a conformance fixture), and keeping them importable makes the adapter contract testable from `conformance/` harnesses.

The `obs` question, resolved (there are two, on purpose):
- **`controld/internal/obs/obs.go`** is the estate file, vendored byte-identical (05 §1: `omium_http_*` metric families, promauto, pod-annotation scraping). Cloud posture: Prometheus on `:9092`.
- **`mark1d/internal/obs/`** is the edge posture from 04 §2.11: `slog` to a rotating 0600 local file + atomic counter/gauge tables read by `mark1 status --json`. **No metrics port** — a laptop daemon exposing Prometheus is attack surface with no scraper.

These are different programs with different threat models, not a DRY violation; a shared `obs` module would force the union of their dependencies (prometheus/client_golang) onto the edge binary. Go's `internal/` mechanics enforce the separation for free.

### 3.3 The generated protobuf module

The estate wires generated contracts as a local module with a `replace` (`checkpoint-manager/go.mod` → `../../shared/proto/gen/go`). **Followed exactly** — it is the only arrangement that (a) keeps committed gen importable without publishing a module, (b) survives Docker builds that stage the monorepo layout, and (c) pins the gen to the working tree rather than a proxy cache.

`proto/gen/go/go.mod` (emitted once, stable):

```
module github.com/Omium-ai/omium-mark1/proto/gen/go

go 1.25.0

require google.golang.org/protobuf v1.36.11
```

The `go` directive here is the one that reads `1.25.0` while every other module and `go.work` read `1.25.14`, and that is not drift: buf emits this file, so the line says what the generator writes, not what the toolchain pin is. A hand-edit would be reverted by the next `just gen` and `gen_fresh.sh` would then fail on a file nobody remembers touching. It is a language-version floor, not a toolchain selector, so it constrains nothing the pinned toolchain does not already satisfy.

### 3.4 Service `go.mod` files — pins written out

`go/mark1d/go.mod`:

```
module github.com/Omium-ai/omium-mark1/go/mark1d

go 1.25.14

require (
    github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
    github.com/fsnotify/fsnotify v1.9.0           // transcript discovery watchers (04 §2.1)
    github.com/google/uuid v1.6.0                 // UUIDv7 (RFC 9562)
    github.com/klauspost/compress v1.18.0         // zstd batch compression (04 §2.5)
    golang.org/x/crypto v0.37.0                   // spill-ring unseal: the X25519 + ChaCha20-Poly1305 twin of spill.rs (04 §5.4)
    golang.org/x/sys v0.42.0                      // unix/windows syscall surface (fabric perms, statfs, job objects)
    google.golang.org/protobuf v1.36.11
    lukechampine.com/blake3 v1.4.1                // checkpoint Merkle (04 §7.2 names BLAKE3; stdlib has none — pure Go, cgo-free)
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
```

Notable absences, each deliberate: **no crc32c module** — `hash/crc32` with the Castagnoli table is stdlib and hardware-accelerated; **no HTTP framework** — the uplink is one `net/http` client, the fabric is not HTTP; **no config library** — env-driven typed struct per the estate (05 §1.3 pattern); **no prometheus** (§3.2).

`go/mark1/go.mod` (the CLI):

```
module github.com/Omium-ai/omium-mark1/go/mark1

go 1.25.14

require (
    github.com/Omium-ai/omium-mark1/go/mark1d v0.0.0  // adapters/ ONLY — see below
    github.com/spf13/cobra v1.9.1                 // 7 subcommands with flags/help; the one boring choice
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
replace github.com/Omium-ai/omium-mark1/go/mark1d => ../mark1d
```

**The CLI imports the daemon module, and only for `adapters/`** (D-BD). This looks like a layering violation and is the opposite: the 08 §8 fence engine has three callers — `enable` applies the fragment, `doctor` classifies it, `off` reverts it — and **all three must work with the daemon down**, so the algorithm cannot live behind the socket. A second copy is the worse option, not the safer one: a revert implemented twice silently *under*-reverts, and each copy's own byte-equality test keeps passing while the two disagree about what a fence is. The import is narrow by construction — nothing under `go/mark1d/internal/` is reachable — and it is the reason this module carries the forward-pinned indirects (`fsnotify`, `blake3`, `klauspost/*`) that a CLI would otherwise have no business holding. Those pins stay — and they did: `go mod tidy` was scheduled into the CI-green wave rather than run mid-phase (a tidy that moves a pin under an unverified CI is a change nobody can attribute), and when it ran there, every forward-pinned indirect survived. What did not survive were three *direct* requires for code that was never written — `go-keyring` in both modules, `x/oauth2` here, `fxamacker/cbor` in the daemon — each carrying a comment naming the feature it implemented, and none of them imported by a single file (D-CF). The lesson is narrower than "dead deps": with no `tools.go` blank import, an unused pin is not a pin. It survives until the next `tidy` and no longer, so a comment promising it will be there for a future rung is promising something the toolchain will not honour. `go mod tidy -diff` now runs per module in `lint-go`, which makes the honest state — no pin ahead of an import — the only representable one.

`go/controld/go.mod`:

```
module github.com/Omium-ai/omium-mark1/go/controld

go 1.25.14

require (
    github.com/Omium-ai/omium-mark1/proto/gen/go v0.0.0
    github.com/ClickHouse/clickhouse-go/v2 v2.34.0        // imported ONLY under internal/querychoke + internal/ingest/chproj — depguard-enforced (§7.3)
    github.com/aws/aws-sdk-go-v2 v1.36.3                  // NOT 1.36.0: service/s3 v1.79.0 requires ≥1.36.3, so MVS cannot hold the lower pin — a pin set must be resolvable or it pins nothing
    github.com/aws/aws-sdk-go-v2/config v1.29.0           // IRSA credential chain
    github.com/aws/aws-sdk-go-v2/service/kms v1.38.0      // section-split bundle signing, server chain key (05 §4.5)
    github.com/aws/aws-sdk-go-v2/service/s3 v1.79.0       // S3-first landing (05 §2)
    github.com/coreos/go-oidc/v3 v3.12.0                  // tenant-IdP token verification (enroll)
    github.com/fxamacker/cbor/v2 v2.7.0                   // canonical-CBOR bundle assembly (policydist)
    github.com/google/differential-privacy/go/v3 v3.0.0   // integer mechanisms ONLY (05 §5.2)
    github.com/google/uuid v1.6.0
    github.com/jackc/pgx/v5 v5.7.5                        // pgxpool + tenant-GUC AfterConnect (05 §7.2)
    github.com/klauspost/compress v1.18.0                 // zstd ingest decompression
    github.com/prometheus/client_golang v1.19.0           // estate pin; pod-annotation scraping
    google.golang.org/protobuf v1.36.11
)

replace github.com/Omium-ai/omium-mark1/proto/gen/go => ../../proto/gen/go
```

(Indirect requirements land in `go.sum` at `go mod tidy` time; the blocks above are the direct-dependency contract. Any new direct dependency is a PR discussion, per §10.2's checklist.)

### 3.5 Go build/test discipline

- `CGO_ENABLED=0` for all three modules, always — cross-compiles for the CLI/daemon matrix and static distroless images fall out for free. Nothing in the closure needs cgo. CI asserts it (`go env CGO_ENABLED` check in `ci.yml`) so a cgo dependency cannot sneak in as a transitive default; the constraint binds hardest on the custody ladder's future keychain/TPM rungs, where the obvious libraries are cgo wrappers, so whichever one is chosen must be pure Go.
- Tests: stdlib `testing` + native `go test -fuzz` for the spool record decoder and fabric frame reader (plan §Critical-files 3). No testify, no mocks framework — the estate writes table tests against interfaces, and so does Mark 1.
- `govulncheck ./...` per module is a required CI gate — **new machinery**; the estate CI lacks it (grounding delta 4), and NFR-SECURITY-004 requires it in Mark 1's own CI.

---

## 4. Python workspace

### 4.1 uv workspace root

The estate installs from `requirements.txt` with pip; Mark 1 uses `uv` (a plan-level given) with one lockfile for the whole Python surface — the workspace model gives the estate's "shared package installed editable into each service" pattern without the `pip install -e /opt/...` Dockerfile choreography.

Root `pyproject.toml` (no code at root — workspace declaration + shared tool config only):

```toml
[project]
name = "omium-mark1-workspace"
version = "0.1.0"
requires-python = ">=3.12"
# Root is not an installable package; it exists so `uv sync` and `uv run` have one anchor.

[tool.uv.workspace]
members = [
    "python/adjudicator",
    "python/intel",
    "python/shared/mark1_receipts",
    "proto/gen/python",
]

[tool.uv]
# One resolution, one uv.lock at repo root, committed. CI installs with --frozen.
package = false
```

`.python-version` at root: `3.12` (R-13.4). `uv.lock` is committed; every CI job and Dockerfile runs `uv sync --frozen` — an unlocked install is unrepresentable.

### 4.2 `python/shared/mark1_receipts` — the vendored receipt package

Vendored from `Omium-platform/core-services/recovery-orchestrator/app/receipts/` (plan §Reuse): `canonical.py` (`canonical_json` = `sort_keys=True, separators=(",",":"), ensure_ascii=True`, `receipt_hash`) and `keys.py` (the Ed25519 `Signer` protocol, `key_id = "ed25519:"+sha256(pub)[:16]`) copied with their source path and commit recorded in each file's header; `DOMAIN_PREFIX` becomes `b"mark1-label-v1\0"`. New here: `checkpoint.py` — BLAKE3 Merkle root over `event_id` leaves, inclusion paths, dual-signature (device origin + server countersign) assembly, and the `"p256:"` `key_id` prefix extension for KMS countersignatures (09 §6's Ed25519/KMS finding, pending ADR-0004).

```toml
# python/shared/mark1_receipts/pyproject.toml
[project]
name = "mark1-receipts"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "blake3>=1.0",           # checkpoint Merkle leaves — same hash as the Rust crate, vector-verified
    "cryptography>=44.0",    # Ed25519 + P-256 verification; signing stays in keys.py's Signer protocol
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/mark1_receipts"]
```

Cross-language honesty gate: `conformance/vectors/receipt/` holds canonical-bytes → hash → signature vectors that this package, the `mark1-receipt` Rust crate, and the Go origin-signing mirror in `mark1d.identity` must all reproduce bit-identically; `tools/ci/conformance_crosslang.sh` runs all three in CI. The vendored discipline is worthless if the three implementations drift — the vectors are the anti-drift mechanism.

### 4.3 Service `pyproject.toml` — pins written out

`python/adjudicator/pyproject.toml`:

```toml
[project]
name = "mark1-adjudicator"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    # Estate skeleton (recovery-orchestrator floors, uv.lock pins exact)
    "fastapi>=0.135.0",
    "uvicorn[standard]>=0.30.0",
    "pydantic>=2.9.0",
    "pydantic-settings>=2.5.0",
    "asyncpg>=0.29.0",             # raw SQL, tenant_guc_setup pool setup= (06 §1)
    "httpx>=0.27.0",               # one AsyncClient owned by lifespan
    # Adjudicator-specific
    "numpy>=2.0.0",                # the ENTIRE numeric surface of spectral/ (06 §4: numpy only, ~500 LoC)
    "mark1-receipts",              # workspace
    "m1p-proto",                   # workspace (proto/gen/python)
]

[dependency-groups]
dev = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "crowd-kit>=1.4",              # TEST ORACLE ONLY (06 §4.5) — a runtime import of crowdkit fails ruff banned-api
    "ruff>=0.8",
]

[tool.uv.sources]
mark1-receipts = { workspace = true }
m1p-proto = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`python/intel/pyproject.toml` — same skeleton block, plus:

```toml
dependencies = [
    "fastapi>=0.135.0",
    "uvicorn[standard]>=0.30.0",
    "pydantic>=2.9.0",
    "pydantic-settings>=2.5.0",
    "asyncpg>=0.29.0",
    "httpx>=0.27.0",
    "numpy>=2.0.0",
    "duckdb>=1.1.0",               # embedded batch analytics — heavy queries NEVER hit a hot store (plan §Data stores)
    "pyarrow>=18.0.0",             # Parquet corpus mirrors + receipted export (06 §12)
    "boto3>=1.34.0",               # S3 corpus/replay access (estate pin floor)
    "xxhash>=3.4.0",               # holdout bucket hash, estate-identical so buckets match the trainer's
    "mark1-receipts",
    "m1p-proto",
]
```

`proto/gen/python/pyproject.toml` declares `name = "m1p-proto"` with `dependencies = ["betterproto>=2.0.0b7"]` — the plan names betterproto as the Python binding; its dataclasses are the natural fit for services that consume M1P events as values, not as gRPC stubs (there is no grpcio anywhere, §0.3).

### 4.4 Conventions inherited from the estate skeleton (binding, per 05/06)

- `app/main.py`: `configure_logging()` **before** config import; `lifespan` owns the asyncpg pool + one `httpx.AsyncClient` (+ the scheduler task in intel); **boot refusals are deliberately uncaught** so a misconfigured pod crashloops instead of half-serving.
- `app/config.py`: pydantic-settings, DSNs as `@property` with `sslmode=require` baked in (asyncpg's default `prefer` silently falls back to plaintext — the estate's scar, not repeated).
- `app/db.py`: `tenant_guc_setup` as the pool `setup=` callback; FastAPI `dependencies=[Depends(tenant_context_dependency)]`; workers use `set_local_tenant` inside the transaction. Services connect as `adjudicator_app` / `intel_app` — NOBYPASSRLS roles from day one (the rds_superuser lesson, enforced by the CI negative tests in `conformance/tenancy/`).
- `app/errors.py`: `install_exception_handlers`; `asyncio.TimeoutError`/`asyncpg.InterfaceError` → 503 + `Retry-After`.
- Migrations: numbered, idempotent, service-prefixed (`adj_0NN_`, `in_0NN_`), run by the `scripts/migrate-db.sh` runner tracking `schema_migrations` keyed `"${service}__${filename}"`; in prod, an Argo CD PreSync Job (05 §7).
- Tests: flat `tests/`, `python -m pytest tests -o asyncio_mode=auto`; real-Postgres suites gated on an env DSN via `pytest.mark.skipif` — **no testcontainers; CI has no Docker** (estate grounding).

---

## 5. Protobuf and buf

### 5.1 `proto/buf.yaml`

```yaml
# m1p — the Mark 1 protocol, single source of truth.
# buf lint + buf breaking run in CI on every PR and fail the build on drift.
version: v2
modules:
  - path: .
lint:
  use:
    - STANDARD
  # No ignore_only blocks. The estate's ignores are grandfathered naming debt in a
  # brownfield module; m1p is greenfield and starts clean. Adding an ignore here
  # requires an ADR reference in the same commit.
breaking:
  use:
    - WIRE_JSON
```

**The divergence, recorded (R-13.1):** the estate's `shared/proto/buf.yaml` runs `breaking: use: [FILE]`; the frozen plan mandates **`WIRE_JSON`** for `m1p` ("buf breaking at WIRE_JSON in CI"). The plan wins. Rationale for the plan's choice, so the divergence is a decision rather than an accident: `m1p`'s compatibility contract is *the wire and its JSON projection* — deleted fields are `reserved`, breaking change ⇒ new package `m1p.v2` never in place — and `WIRE_JSON` checks exactly that invariant. `FILE` additionally freezes source-level organization (which file declares what), a constraint the estate needs because four languages of committed gen import by file path; `m1p`'s three bindings do too, but a file move would be caught by the freshness gate + compile anyway. Whoever next touches the estate's buf config should not "harmonize" this repo to `FILE` without reading this paragraph.

### 5.2 `proto/buf.gen.yaml`

```yaml
# Codegen for the three languages from the single m1p source. REMOTE plugins, PINNED —
# deterministic output is what keeps the freshness gate (tools/ci/gen_fresh.sh) stable.
# Outputs are COMMITTED under proto/gen/. Run via `just gen` (never bare buf generate:
# the just recipe also stages rust gen into rust/m1p-wire/gen/).
version: v2
managed:
  enabled: true
  override:
    - file_option: go_package_prefix
      value: github.com/Omium-ai/omium-mark1/proto/gen/go
plugins:
  # ---- Go (mark1d, mark1 CLI, controld) — messages only; there is no gRPC in Mark 1 ----
  - remote: buf.build/protocolbuffers/go:v1.36.6
    out: gen/go
    opt: paths=source_relative

  # ---- Python (adjudicator, intel) — betterproto dataclasses per the plan ----
  - remote: buf.build/community/danielgtaylor-betterproto:v2.0.0b7
    out: gen/python

  # ---- Rust (m1p-wire) — prost 0.13 line; same pinned plugin as the estate ----
  - remote: buf.build/community/neoeinstein-prost:v0.4.0
    out: gen/rust
    opt:
      - compile_well_known_types
```

Two deliberate departures from the estate's plugin list, both consequences of "no gRPC" (§0.3): `buf.build/grpc/go` and `buf.build/grpc/python` are absent (nothing serves or calls gRPC), and `neoeinstein-tonic` is absent (no tonic in the workspace). `bufbuild/es` is absent because there is no TS binding (§0.2). The estate's `protocolbuffers/python` + `pyi` pair is replaced by betterproto because the plan names betterproto explicitly ("One proto source → prost / protoc-gen-go / betterproto") and the services consume events as typed values in pydantic-adjacent code, not as raw descriptor-backed messages.

### 5.3 `proto/buf.lock`

Committed. With no BSR module dependencies (m1p imports only well-known types, compiled in by the prost plugin option), the lock is initially the empty v2 stanza:

```yaml
# Generated by buf. DO NOT EDIT.
version: v2
```

It exists from the first commit so that the day a dependency *is* added (e.g. `buf.build/googleapis/googleapis` for a status type), the pin lands in review rather than in a CI runner's cache. Remote *plugin* pinning lives in `buf.gen.yaml` version suffixes above — that, plus committed outputs, is the estate's determinism discipline.

### 5.4 Where generated code lands, and who consumes it

| Output | Committed at | Consumed by | Wiring |
|---|---|---|---|
| Go | `proto/gen/go/m1p/v1/*.pb.go` | all three Go modules | local module + `replace` (§3.3) |
| Python | `proto/gen/python/m1p/v1/__init__.py` (betterproto emits per-package modules) | adjudicator, intel | uv workspace member `m1p-proto` (§4.3) |
| Rust | `proto/gen/rust/m1p.v1.rs` → staged copy `rust/m1p-wire/gen/m1p.v1.rs` | every Rust crate, via `m1p-wire::pb` | `include!`, no `build.rs` (§2.4) |

Only `m1p-wire` includes the Rust gen; every other crate depends on `m1p-wire` — one owner for the generated surface, so a proto change has exactly one Rust compile boundary.

### 5.5 CI gates on the proto path

| Gate | Command | Fails when | New vs estate |
|---|---|---|---|
| Lint | `buf lint proto` | any STANDARD violation | estate-inherited |
| Breaking | `buf breaking proto --against '.git#branch=main,subdir=proto'` | wire/JSON-incompatible change to `m1p.v1` | estate-inherited, category diverges (§5.1) |
| Freshness | `tools/ci/gen_fresh.sh` (= `just gen && git diff --exit-code proto/gen rust/m1p-wire/gen`) | committed gen ≠ regenerated gen | estate-inherited (`g2_codegen_fresh.sh`) |
| Cross-language vectors | `tools/ci/conformance_crosslang.sh` | Rust/Go/Python disagree on any `conformance/vectors/` case (M1PL frames, redact, receipts, bundle decode) | **new** — the plan's "Go carries a parallel decoder validated by shared conformance vectors" made mechanical |

The breaking gate is wired **in the very first proto commit** (plan §Critical-files 1: "First commit, with `buf breaking` wired into CI immediately") — there is no window in which `m1p.v1` exists without its compatibility ratchet.

---

## 6. Build orchestration

### 6.1 Why `just`

Three languages, one repo, one muscle-memory surface. `just` over `make` because recipes are shell-explicit (no `.PHONY` liturgy, no tab semantics), it runs identically on all three OSes (`just` ships single-binary; recipes below avoid bashisms where Windows matters or set `shell`), and CI calls the *same* recipes developers do — a gate that passes locally passes in CI or the recipe is wrong, not the environment.

### 6.2 The `justfile` — written out

```just
# omium-mark1 — every verb in the repo. CI runs THESE recipes; if you're typing a raw
# cargo/go/uv/buf command that has a recipe, you're doing it wrong.

set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

default: lint test

# ---------- codegen ----------

# Regenerate committed proto bindings and stage the Rust gen into m1p-wire.
gen:
    cd proto && buf generate
    cp proto/gen/rust/m1p.v1.rs rust/m1p-wire/gen/m1p.v1.rs

# The freshness gate: committed gen must equal regenerated gen.
gen-check: gen
    git diff --exit-code proto/gen rust/m1p-wire/gen

# ---------- build ----------

build: build-rust build-go build-py

build-rust:
    cargo build --workspace --locked

build-go:
    cd go/mark1d   && go build ./...
    cd go/mark1    && go build ./...
    cd go/controld && go build ./...

build-py:
    uv sync --frozen

# Release-profile edge binaries for the host triple (packaging matrices live in release.yml).
build-edge:
    cargo build --release --locked -p mark1-proxy -p mark1-hookshim -p cortexd
    cd go/mark1d && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../dist/mark1d ./cmd
    cd go/mark1  && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../dist/mark1  ./cmd

# ---------- test ----------

test: test-rust test-go test-py conformance

test-rust:
    cargo test --workspace --locked --no-fail-fast

test-go:
    cd go/mark1d   && go test ./...
    cd go/mark1    && go test ./...
    cd go/controld && go test ./...

test-py:
    uv run --frozen -m pytest python/shared/mark1_receipts/tests -o asyncio_mode=auto
    uv run --frozen -m pytest python/adjudicator/tests -o asyncio_mode=auto
    uv run --frozen -m pytest python/intel/tests -o asyncio_mode=auto

# Cross-language conformance vectors: Rust ↔ Go ↔ Python must agree bit-identically.
conformance:
    tools/ci/conformance_crosslang.sh

# Integration suites gate on env DSNs (estate convention — CI has no Docker).
# Provide M1_TEST_PG_DSN / M1_TEST_CH_DSN / M1_TEST_S3_ENDPOINT, e.g. from `just dev-up`.
test-integration:
    uv run --frozen -m pytest python/adjudicator/tests python/intel/tests -o asyncio_mode=auto -m integration
    cd go/controld && go test -tags=integration ./...

# ---------- lint / fmt ----------

lint: lint-rust lint-go lint-py lint-proto gates

lint-rust:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo deny check

lint-go:
    cd go/mark1d   && golangci-lint run
    cd go/mark1    && golangci-lint run
    cd go/controld && golangci-lint run
    cd go/mark1d   && govulncheck ./...
    cd go/mark1    && govulncheck ./...
    cd go/controld && govulncheck ./...

lint-py:
    uv run --frozen ruff format --check python
    uv run --frozen ruff check python
    uv export --frozen --no-emit-workspace -o /tmp/mark1-reqs.txt && pip-audit -r /tmp/mark1-reqs.txt

lint-proto:
    buf lint proto
    buf breaking proto --against '.git#branch=main,subdir=proto'

# The design-enforcing custom gates (§7.5). Small scripts, zero tolerance.
gates:
    tools/ci/otel_gate.sh
    tools/ci/secret_type_gate.sh
    tools/ci/override_pattern_gate.sh
    tools/ci/build_tag_gate.sh

fmt:
    cargo fmt --all
    cd go/mark1d && gofmt -w . && cd ../mark1 && gofmt -w . && cd ../controld && gofmt -w .
    uv run --frozen ruff format python
    uv run --frozen ruff check --fix python

# ---------- fuzz / bench ----------

# Nightly toolchain; smoke duration in CI, long runs by hand or scheduled job.
fuzz duration="60":
    cd rust/m1p-wire      && cargo +nightly fuzz run frame_decode  -- -max_total_time={{duration}}
    cd rust/mark1-redact  && cargo +nightly fuzz run admit         -- -max_total_time={{duration}}
    cd rust/mark1-policy  && cargo +nightly fuzz run bundle_decode -- -max_total_time={{duration}}
    cd go/mark1d && go test -fuzz=FuzzSpoolRecordDecode -fuzztime={{duration}}s ./internal/spool
    cd go/mark1d && go test -fuzz=FuzzM1plFrameRead     -fuzztime={{duration}}s ./internal/fabric

# Benches with CI thresholds (12 owns the numbers): proxy ≤1 ms median, redact ~100 MB/s, shim cold start ≤10 ms.
bench:
    cargo bench -p mark1-proxy -p mark1-redact
    cargo build --release --locked -p mark1-hookshim && tools/ci/shim_coldstart_bench.sh

# ---------- db / dev loop ----------

# Apply core + service migrations to a target DSN (idempotent; safe to re-run).
migrate dsn:
    DATABASE_URL={{dsn}} scripts/migrate-db.sh migrations m1
    DATABASE_URL={{dsn}} scripts/migrate-db.sh python/adjudicator/migrations adj
    DATABASE_URL={{dsn}} scripts/migrate-db.sh python/intel/migrations in

# Local dev stack (postgres, clickhouse, minio, the three cloud services). DEV ONLY.
dev-up:
    docker compose -f deploy/compose/compose.yaml up -d

dev-down:
    docker compose -f deploy/compose/compose.yaml down -v

# ---------- supply chain ----------

sbom:
    syft dir:. -o cyclonedx-json > dist/sbom.cdx.json

# Everything a PR must pass, in the order CI runs it.
ci: gen-check lint test fuzz
```

### 6.3 What CI actually runs

`ci.yml` is a thin matrix over the recipes — **the justfile is the CI contract**:

| Job | OS | Recipes | Required |
|---|---|---|---|
| `gen` | ubuntu | `gen-check`, `lint-proto` | yes, from first proto commit |
| `rust` | ubuntu + macos + windows | `lint-rust`, `test-rust` | yes |
| `go` | ubuntu + macos + windows | `lint-go`, `test-go` | yes |
| `python` | ubuntu | `lint-py`, `test-py` | yes |
| `gates` | ubuntu | `gates`, `conformance` | yes |
| `fuzz-smoke` | ubuntu | `fuzz 60` | yes once each target exists (§11) |
| `bench` | ubuntu (pinned runner class) | `bench` vs 12's thresholds | yes from Phase 3 (proxy) |
| `integration` | ubuntu (DSN-gated services via GH service containers) | `migrate` + `test-integration` + `conformance/tenancy` | yes from commit C5 (§11) |
| security scans | ubuntu | gitleaks, hadolint (Dockerfiles) | yes — estate-inherited |

**`trivy` is not in the PR lane; it runs at release against the built images (12 §11.3, `release.yml`).** A PR has no released image to scan — scanning one built locally for the occasion spends CI minutes on a result the release scan already produces, against an artifact nobody ships. The two PR-lane scanners are the ones whose subject exists in the diff: gitleaks reads the source, hadolint reads the Dockerfiles.

Three-OS coverage for Rust and Go is non-negotiable from day one (plan §Deployment: "CI on macOS/Linux/Windows from day one") — the edge ships to all three, and §11.5 of `04` documents real per-OS semantic differences, not just build differences.

### 6.4 Clean-machine bootstrap

`scripts/bootstrap.sh` (macOS/Linux) and `scripts/bootstrap.ps1` (Windows) install exactly the tool list below, verify versions, and stop — they do not touch the repo. What a new engineer runs:

**macOS**
```sh
brew install just uv go buf golangci-lint syft pre-commit && brew install rustup && rustup-init -y
git clone git@github.com:Omium-ai/omium-mark1 && cd omium-mark1
./scripts/bootstrap.sh --check     # verifies: rust 1.91 (from rust-toolchain.toml), go 1.25, uv, buf, just, golangci-lint
just gen-check && just build && just test
```

**Linux (Debian/Ubuntu)**
```sh
curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y          # picks up rust-toolchain.toml
curl -LsSf https://astral.sh/uv/install.sh | sh
# go 1.25 from go.dev tarball; just/buf/golangci-lint/syft from their release binaries (bootstrap.sh does this)
git clone git@github.com:Omium-ai/omium-mark1 && cd omium-mark1
./scripts/bootstrap.sh             # installs the non-apt tools into ~/.local/bin, then --check
just gen-check && just build && just test
```

**Windows**
```powershell
winget install Rustlang.Rustup Golang.Go astral-sh.uv Casey.Just bufbuild.buf GolangCI.golangci-lint
git clone git@github.com:Omium-ai/omium-mark1; cd omium-mark1
./scripts/bootstrap.ps1 -Check
just gen-check; just build; just test
```

Then, once: `pre-commit install` (§7.6), and for anyone touching fuzz targets: `rustup toolchain install nightly && cargo install cargo-fuzz`. `just dev-up` brings the local cloud stack when integration tests are wanted; nothing else in the loop needs Docker.

---

## 7. Lint, format, pre-commit — and the design-enforcing gates

### 7.1 `rustfmt.toml`

Stable-channel options only (nightly-only options silently no-op on stable and rot):

```toml
edition = "2021"
max_width = 100
newline_style = "Unix"
use_field_init_shorthand = true
use_try_shorthand = true
```

### 7.2 `clippy.toml`

```toml
# Workspace lints (root Cargo.toml) deny unwrap/expect/panic/dbg/print_stdout crate-wide.
# These two keys exempt #[cfg(test)] code so tests stay ergonomic — the denial is a
# production-path rule, not a test-style rule.
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-panic-in-tests = true
avoid-breaking-exported-api = false
```

**The no-`unwrap()`-in-hot-paths rule, exactly as enforced:** `[workspace.lints.clippy] unwrap_used/expect_used/panic = "deny"` (§2.1) + `[lints] workspace = true` in every member + `cargo clippy --all-targets -- -D warnings` in `lint-rust`. Scope is deliberately *the whole workspace*, not just hot paths — see §2.2 for why. An intentional exception is a written `#[allow(clippy::unwrap_used)] // reason` at the expression, which is grep-auditable (`just gates` prints a count trend; a PR that raises it explains itself).

### 7.3 `.golangci.yml`

```yaml
# golangci-lint v2 config — one file at repo root, all three modules run it (§6.2 lint-go).
version: "2"

linters:
  default: none
  enable:
    - errcheck        # an ignored error on the spool/uplink path is silent data loss
    - govet
    - staticcheck
    - ineffassign
    - unused
    - gosec           # G-series: exec, file perms, weak crypto
    - depguard        # the mechanical import-boundary gate — rules below
    - forbidigo       # no fmt.Print* outside cmd/ (edge logs via obs or not at all)
  settings:
    depguard:
      rules:
        no-otel:
          deny:
            - pkg: "go.opentelemetry.io"
              desc: "Mark 1 has zero OpenTelemetry (CON-005 / ADR-0005). Telemetry rides M1P."
        clickhouse-choke:
          files:
            - "!**/internal/querychoke/**"
            - "!**/internal/ingest/chproj/**"
          deny:
            - pkg: "github.com/ClickHouse/clickhouse-go"
              desc: "ClickHouse is reachable ONLY through controld.querychoke (05 §6); chproj projects rows for ingest."
        no-grpc:
          deny:
            - pkg: "google.golang.org/grpc"
              desc: "No gRPC in Mark 1 — M1P is plain HTTPS; the fabric is M1PL."
    gosec:
      excludes:
        - G304   # file inclusion via variable — tailers/spool open computed paths by design, behind WorkspaceSet
    forbidigo:
      forbid:
        - pattern: "^fmt\\.Print"
  exclusions:
    rules:
      - path: _test\.go
        linters: [gosec, forbidigo]

formatters:
  enable:
    - gofmt
    - goimports
```

depguard is doing real architectural work here, not style work: the **querychoke rule makes 05's "the only ClickHouse principal" claim a compile-gate** (05 §8's import-negative test, implemented as config), and the OTel/gRPC rules make two of §0.3's "does not contain" claims mechanical for Go.

### 7.4 `ruff.toml`

```toml
# One config at root; both services + shared package + gen (gen excluded from lint).
target-version = "py312"
line-length = 100
extend-exclude = ["proto/gen/python"]

[lint]
select = [
    "E", "F", "W",     # pycodestyle/pyflakes
    "I",               # isort
    "UP",              # pyupgrade
    "B",               # bugbear
    "ASYNC",           # blocking-call-in-async — the estate skeleton is async end to end
    "S",               # bandit subset
    "T20",             # no print() — services log via configure_logging
]
ignore = ["S101"]      # asserts are the estate's registry discipline (PROBE_HANDLERS asserts)

[lint.flake8-tidy-imports.banned-api]
"opentelemetry".msg = "Mark 1 has zero OpenTelemetry (CON-005 / ADR-0005)."
"crowdkit".msg = "crowd-kit is a TEST ORACLE only (06 §4.5) — import it in tests/, never in app/."
"pandas".msg = "The numeric surface is numpy-only (06 §4.5); DuckDB/pyarrow own columnar work."

[lint.per-file-ignores]
"**/tests/**" = ["S", "T20"]
"**/tests/test_spectral_against_crowdkit.py" = ["TID251"]   # the one sanctioned crowdkit import
```

### 7.5 The three design-enforcing gates — exactly how each is enforced

**1. The no-OTel gate** (CON-005; "say how that is enforced mechanically"):

| Layer | Mechanism | Catches |
|---|---|---|
| Rust | `deny.toml` `[bans]` (below) via `cargo deny check` in `lint-rust` | any crate named `opentelemetry*`, `tracing-opentelemetry` — **including transitive** (bans walk the resolved graph in `Cargo.lock`) |
| Go | depguard `no-otel` rule (§7.3) for direct imports, **plus** `tools/ci/otel_gate.sh` scanning `go.sum` for `go.opentelemetry.io` | direct and transitive — **with exactly one waiver, D-M** (RECONCILIATION; founder-visible). Verified 2026-08-28: every maintained Go ClickHouse client, the §3.4-mandated `clickhouse-go/v2` included, unconditionally package-imports the OTel API *stub* (`otel`/`otel/trace`: interface types, nothing executes), so "zero OTel in `go.sum`" and "a ClickHouse ledger" are jointly unsatisfiable and a gate demanding the impossible is a gate someone deletes. The waiver is not an allowlist: on a dependency-file hit the gate switches from the string proxy to the executable claim — `go list -deps -test ./...` must contain no SDK/exporter/OTLP/metric/bridge/contrib package, `go.mod`'s otel lines must all be `// indirect`, and no first-party `.go` file may import `go.opentelemetry.io` — and its summary line says `OK WITH D-M WAIVER`, never plain OK |
| Python | ruff `banned-api` (§7.4) for imports, **plus** `otel_gate.sh` scanning `uv.lock` for `name = "opentelemetry` | direct and transitive |

```toml
# deny.toml (root) — cargo-deny. NEW machinery: the estate CI has no cargo-deny (grounding delta 4).
[graph]
all-features = true

[advisories]
yanked = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0", "MPL-2.0", "CDLA-Permissive-2.0"]

[bans]
multiple-versions = "warn"
deny = [
    { crate = "opentelemetry",         reason = "CON-005: zero OTel anywhere; telemetry rides M1P (ADR-0005)" },
    { crate = "opentelemetry_sdk",     reason = "CON-005" },
    { crate = "opentelemetry-otlp",    reason = "CON-005" },
    { crate = "tracing-opentelemetry", reason = "CON-005" },
    { crate = "openssl",               reason = "rustls-only TLS; keeps all five target triples system-lib-free (§2.3)" },
    { crate = "openssl-sys",           reason = "as above" },
    { crate = "tonic",                 reason = "no gRPC in Mark 1 (§0.3)" },
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

`otel_gate.sh` is the belt to cargo-deny/depguard/ruff's suspenders — three greps over the three lockfiles, ~20 lines, so even a linter misconfiguration cannot let an OTel package reach a lockfile unnoticed.

**2. The `Secret<T>` grep gate** (`tools/ci/secret_type_gate.sh`, plan §Compliance 2). Ripgrep over `rust/mark1-proxy/` and any crate that later declares a `Secret` type, failing on:
- `impl\s+(std::fmt::)?(Debug|Display)\s+for\s+Secret` and `impl\s+(serde::)?Serialize\s+for\s+Secret` — no manual impls;
- `derive\([^)]*(Debug|Serialize)[^)]*\)` on the lines adjacent to `struct Secret` — no derived impls;
- `\.0\b` escapes outside `secret.rs` itself (the inner value is reachable only through the module's `expose_for_upstream()` sealed path);
- absence check: the gate **fails if `zeroize` is not in `mark1-proxy`'s dependency list**, so deleting the drop-guard is as loud as printing the secret.

This is a grep gate by design, not a poor cousin of the type system: the type system enforces the property *inside* the compiler's view; the grep refuses the diffs that would change what the compiler is asked to enforce.

**3. The guard-override pattern gate** (`tools/ci/override_pattern_gate.sh`, 04 §3.1 step 4). Ripgrep over `rust/mark1-proxy/` failing on any `cfg(feature = ...)`, env-var read (`env::var`, `option_env!`), or clap attribute whose identifier matches `(?i)(bypass|override|allow_unprovisioned|skip_guard|insecure|no_guard)`. Together with 12's negative test ("no code path forwards an unprovisioned credential"), this makes "no override path exists in the binary" a two-sided claim: the test proves the binary that exists refuses; the gate refuses the source patterns that would build a different binary.

**4. The build-tag gate** (`tools/ci/build_tag_gate.sh`, D-CB). `go test ./...` cannot see a tag-gated file, so a build tag is the one edit that removes a whole suite from a run while leaving every recipe, every job name and every exit code unchanged. The justfile carries an inventory against exactly that; it listed `integration` and `chaos` and named no platform tag at all, missing nine tagged files at HEAD (six `unix`, three `linux`), which is how most of `mark1d`'s suite stayed invisible to `go (windows-2022)` with nothing red anywhere. This gate extracts the distinct tag tokens from `go/**/*.go` and fails on any that the inventory does not name. The direction is deliberate and is the whole point: it derives the set **from the tree** and checks the prose against it, never the reverse, so renaming or moving a tagged file changes nothing and only a genuinely new tag can fail it. It also refuses to run if the inventory block is missing — comparing against nothing would otherwise pass.

### 7.6 `.pre-commit-config.yaml`

Pre-commit is a courtesy accelerator; **CI is the authority** — every hook here has a CI twin, so a skipped hook changes nothing except how late you find out.

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-merge-conflict
      - id: check-added-large-files
        args: ["--maxkb=1024"]   # conformance fixtures are the sanctioned exception, via .gitattributes lfs if ever needed
  - repo: local
    hooks:
      - id: rustfmt
        name: cargo fmt --check
        entry: cargo fmt --all -- --check
        language: system
        types: [rust]
        pass_filenames: false
      - id: gofmt
        name: gofmt
        entry: gofmt -l -w
        language: system
        types: [go]
      - id: ruff
        name: ruff check + format
        entry: uv run ruff check --fix --exit-non-zero-on-fix
        language: system
        types: [python]
      - id: buf-lint
        name: buf lint
        entry: buf lint proto
        language: system
        files: ^proto/
        pass_filenames: false
      - id: otel-gate
        name: no-OTel lockfile gate
        entry: tools/ci/otel_gate.sh
        language: system
        files: (Cargo\.lock|go\.sum|uv\.lock)$
        pass_filenames: false
```

### 7.7 `.editorconfig`

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{go,just}]
indent_style = tab

[*.{yaml,yml,toml,json,md,proto}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false
```

---

## 8. Dockerfiles and packaging

Containers exist for the **cloud** deployables (`controld`, `adjudicator`, `intel`) and a dev/fleet image of `mark1d`; the edge ships packaged *binaries* (§8.4). Build context is always the repo root (the estate pattern — the `replace`/workspace paths must resolve in Docker as they do locally). Every base image is tag-pinned; hadolint runs on every Dockerfile in CI.

### 8.1 The representative Dockerfile, in full — `go/controld/Dockerfile`

```dockerfile
# controld — one Go binary, five modules (05). Multi-stage, distroless, nonroot.
# Build from the repo ROOT:  docker build -f go/controld/Dockerfile -t omium/mark1-controld:<sha7> .
#
# R-13.2: runtime is distroless/static, NOT the estate checkpoint-manager's alpine:latest —
# a floating base tag is the exact class of pin the estate retired for image tags on 2026-08-13.

# ---------- builder ----------
FROM golang:1.25-bookworm AS builder
WORKDIR /build

# Generated contracts module first (the `replace` target) — layer-cache friendly.
COPY proto/gen/go ./proto/gen/go

# Module files, then deps, then source — standard cache ordering.
COPY go/controld/go.mod go/controld/go.sum ./go/controld/
WORKDIR /build/go/controld
RUN go mod download

COPY go/controld/ ./

# Static build: CGO off (repo invariant, §3.5); trimpath + stripped for reproducibility and size.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /build/controld ./cmd/controld

# ---------- runtime ----------
# distroless/static (not cc): a CGO_ENABLED=0 Go binary needs no libc at all.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/controld /usr/local/bin/controld
EXPOSE 8443 9092
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/controld"]
```

### 8.2 The Rust and Python patterns (shape fixed; contents analogous)

**Rust** (`mark1d --fleet` companion images, and any future Rust cloud component) follows the estate's `omium-training-plane` Dockerfile verbatim in shape: `rust:1.91-slim-bookworm` builder, `COPY Cargo.toml Cargo.lock rust/ tools/` + the staged gen (already committed in-tree, so no vendor step is needed — an *improvement* the committed-gen layout buys over the training plane's `vendor/proto-gen` staging), `cargo build --release --locked -p <crate>`, then `gcr.io/distroless/cc-debian12:nonroot` (**cc**, not static: Rust release binaries link glibc — the plan's "glibc, not musl" decision), `USER nonroot:nonroot`, `ENTRYPOINT` the binary.

**Python** (`python/adjudicator/Dockerfile`, `python/intel/Dockerfile`) — the estate skeleton modernized to uv, same posture:

```dockerfile
# adjudicator-svc — estate FastAPI skeleton on uv. Build from repo root.
FROM ghcr.io/astral-sh/uv:0.8-python3.12-bookworm-slim AS builder
WORKDIR /build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
# Workspace metadata + lock first for layer caching; then the members this service needs.
COPY pyproject.toml uv.lock ./
COPY proto/gen/python ./proto/gen/python
COPY python/shared/mark1_receipts ./python/shared/mark1_receipts
COPY python/adjudicator ./python/adjudicator
RUN uv sync --frozen --no-dev --package mark1-adjudicator

FROM python:3.12-slim-bookworm
WORKDIR /app
# uid 65532 = the estate's runAsNonRoot convention (matches distroless nonroot).
RUN groupadd -g 65532 nonroot && useradd -u 65532 -g 65532 -m nonroot
COPY --from=builder --chown=65532:65532 /build/.venv /app/.venv
COPY --from=builder --chown=65532:65532 /build/python/adjudicator/app /app/app
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8010
USER 65532:65532
# Probes are HTTP GETs from kubelet (estate helm convention) — no curl HEALTHCHECK needed in-image.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
```

All images run under the estate Helm security helpers (`runAsNonRoot`, uid 65532, `readOnlyRootFilesystem`, `drop: [ALL]`, `seccompProfile: RuntimeDefault`, `omium.spread`) — `deploy/helm/` sets nothing weaker than `omium.podSecurityContext` defaults.

### 8.3 Image tagging

`omium/mark1-{controld,adjudicator,intel}:<sha7>` — seven-hex git SHA, nothing else, pushed to the immutable ECR repos. No `latest`, no semver tags on images (§9.5 has the reason). GitOps pins `imageTag: "<sha7>"` per the estate's promote-by-SHA workflow.

### 8.4 Edge packaging per OS (mechanics owned by 09 §11; the repo artifacts live in `deploy/packaging/`)

| OS | Artifact | Signing | In this repo |
|---|---|---|---|
| macOS | Universal2 (lipo aarch64+x86_64) signed `.pkg`; Homebrew tap | Developer ID + `codesign --options runtime` + `notarytool submit` + staple — notarization is **not optional** (Gatekeeper vs a background daemon) | `deploy/packaging/macos/`: pkgbuild scripts, LaunchAgent plist, notarize.sh |
| Windows | MSI (WiX), per-user service; winget manifest | Authenticode via **Azure Trusted Signing** (OIDC-scoped CI identity; no hardware-token custody for a one-founder company) | `deploy/packaging/windows/`: `.wxs`, signing config |
| Linux | `.deb` + `.rpm` (nfpm) + tarball; GPG-signed repo metadata | repo GPG key + per-binary detached signatures, verified by `mark1 verify-release` | `deploy/packaging/linux/`: `nfpm.yaml`, systemd user unit |

All three install the same layout: `mark1` CLI on PATH; `mark1d`, `mark1-proxy`, `mark1-hookshim`, `cortexd` under the install root; `mark1d` supervises the rest (04 §1). The update manifest source (ring pins, artifact digests) is version-controlled at `deploy/packaging/manifest/` and CI-signed with the update key — a ring promotion is a reviewed git commit (09 §11.2).

### 8.5 SLSA attestation and SBOM — new machinery, in `release.yml`

The estate CI has none of this (grounding delta 4); NFR-SECURITY-004 requires it here. On a release tag, `release.yml`:

1. Builds every artifact (images, five-triple edge binaries, packages) from a clean checkout with `--locked`/`--frozen`/`-mod=readonly`.
2. Emits a **CycloneDX SBOM** per artifact (`syft`, the `just sbom` recipe) and attaches it to the release.
3. Generates **SLSA provenance** via GitHub's `attest-build-provenance` (`gh attestation`) binding artifact digest → repo → workflow → commit SHA.
4. Signs per §8.4 and publishes; `mark1 verify-release` checks signature **and** provenance before any binary is executed (09 §11.2).

Because the workspace has no `build.rs` and no cgo, "what ran during the build" is the toolchains plus the lockfile-pinned dependency graph — the honest precondition for the provenance statement meaning anything (§2.4).

---

## 9. Versioning and release

### 9.1 Version scheme per artifact class

Four artifact classes, four schemes — because they have four different compatibility audiences:

| Class | Scheme | Bump discipline |
|---|---|---|
| **Wire protocol** (`m1p`) | `m1p/1.<minor>` — the proto package major (`m1p.v1`) plus a contract minor counted in `07`'s changelog | minor = additive only, enforced by `buf breaking` WIRE_JSON; **breaking = new package `m1p.v2`, never in place** (deleted fields stay `reserved`). The edge may trail controld by ≤2 contract minors; controld never trails the edge (09 §11.3) |
| **Edge binaries** (`mark1d`, `mark1`, `mark1-proxy`, `mark1-hookshim`, `cortexd`) | one semver for the supervised set: `edge/vX.Y.Z` git tag | the five ship **together** — mark1d supervises the others and adopts children by binary hash (04 §1), so mixed-version edge sets are not a supported state. Patch = fixes; minor = features/new adapter; major = never expected pre-`m1p.v2` |
| **Cloud services** (`controld`, `adjudicator`, `intel`) | **no semver — `<sha7>` only** | continuously deployable; "version" is the deployed SHA in GitOps, promoted per the estate's promote-by-SHA workflow. Compatibility is carried by the wire contract, not by service version numbers |
| **PolicyBundles / update manifests** | monotonic `seq` per `(tenant, channel)` / `manifest_seq` | not versions at all — sequenced signed documents; rollback is *new content under a higher seq* (04 §9.4, 09 §11.2). No semver semantics ever attach to them |

Crate versions (`0.1.0` workspace-wide) and Python package versions are internal bookkeeping — nothing is published to crates.io or PyPI except `tools/verifier`, which carries its own semver from its first public release (it is the one artifact whose downstream we do not control).

Dialect parsers version independently *inside* the edge version: each `mark1-frames` module carries its `DIALECT_REV` (04 §4), bumped with a new golden fixture — a vendor format churn is a fixture+rev diff, not an edge release semantics change. Same pattern for `task_seg_version`, `grammar_rev`/`query_rev`/`indexer_rev` (cortexd CAS): **data-plane revisions ride inside artifacts; only binaries get semver.**

### 9.2 Edge ↔ control-plane compatibility policy (normative source: 09 §11.3)

- controld advertises `min_edge_version` in enroll and policy responses; an edge below it keeps capturing and spooling (fail-open) but uploads are refused `426 Upgrade Required` and park (fail-closed for admission). The 2 GiB spool cap is the deliberate pressure to update.
- Unknown protobuf fields skip-and-retain; unknown bundle *section* versions skip-and-retain per section (08 §10.3).
- CI enforcement: a `conformance/` skew suite replays previous-minor-tagged fixture batches against current controld (n-1 and n-2), so "the edge may trail by two minors" is a tested property, not a policy sentence.

### 9.3 Release process

1. **Cloud:** merge to `main` → CI green → image built + pushed as `<sha7>` → GitOps PR bumps `imageTag` (staging values first, prod by promote-by-SHA). No tags, no ceremonies; migrations ride the Argo PreSync Job (05 §7).
2. **Edge:** tag `edge/vX.Y.Z` → `release.yml` builds the five-triple matrix, runs the full gate set including benches at 12's thresholds, signs/notarizes per §8.4, emits SBOM + SLSA (§8.5), publishes artifacts + detached signatures to the release CDN, and opens a PR editing `deploy/packaging/manifest/` to point **ring 0** at the new version. Ring promotions (0 → dogfood, 1 → consenting canary tenants, 2 → GA) are subsequent reviewed manifest commits (09 §11.2).
3. **Rollback:** cloud = GitOps revert to the previous `<sha7>`; edge = a *new, higher-seq* manifest pointing at the previous artifacts — monotonic seq means a downgrade is always a signed forward decision, never a replay.

### 9.4 Update channels

`stable` (ring 2), `canary` (ring 1), `dogfood` (ring 0) — selected server-side per tenant, carried in the update manifest; `mark1d` pulls the manifest, verifies the update-key signature + monotonic `manifest_seq`, and self-updates its supervised set. Package-manager installs (brew/winget/apt) are notified, never overwritten. Update key ≠ bundle key, deliberately: a compromised bundle key can steer policy but not ship code; a compromised update key can ship code only through the staged-ring + SLSA gate but not alter policy (09 §11.2).

### 9.5 The `<sha7>` discipline — and why `latest` is banned

Images are tagged with the seven-hex commit SHA and nothing else. `latest` was retired estate-wide on 2026-08-13 for a reason worth restating because it is counter-intuitive: **on an IMMUTABLE ECR repository, a floating tag is a permanent pin, not a pointer** — the first push of `:latest` wins forever and every subsequent "update" of the tag is rejected, so `latest` silently freezes at whatever was pushed first while everyone reads it as "newest". `<sha7>` makes every reference exact, every promotion a diff, and every rollback a revert. The same reasoning pins base images (§8) and tool versions (§6.4): a floating reference is a statement about *time*, and nothing in a build should depend on when it ran.

---

## 10. CODEOWNERS, contribution and PR discipline

### 10.1 `CODEOWNERS` — written out

Two GitHub teams under `Omium-ai`: `@Omium-ai/mark1-core` (default owners) and `@Omium-ai/mark1-security` (the security-relevant paths). Today both teams resolve to the founder — the file is written for the org shape, not the headcount, so growing the team is a membership change, not a CODEOWNERS rewrite. Branch protection on `main`: required CI checks (§6.3's "required" column), required review from code owners, no force-push, no direct pushes.

```
# omium-mark1 CODEOWNERS — most-specific-last wins (GitHub semantics).

# Default: everything needs a core review.
*                                   @Omium-ai/mark1-core

# --- Contract surfaces: a change here is a change to what Mark 1 *is* ---
/proto/                             @Omium-ai/mark1-core @Omium-ai/mark1-security
/migrations/                        @Omium-ai/mark1-core @Omium-ai/mark1-security
/docs/07-data-model.md              @Omium-ai/mark1-core @Omium-ai/mark1-security
/docs/08-api-contracts.md           @Omium-ai/mark1-core @Omium-ai/mark1-security
/docs/adr/                          @Omium-ai/mark1-core @Omium-ai/mark1-security

# --- Security-relevant code paths: legality, secrets, tenancy, signing ---
/rust/mark1-proxy/src/guard/        @Omium-ai/mark1-security
/rust/mark1-redact/                 @Omium-ai/mark1-security
/rust/mark1-receipt/                @Omium-ai/mark1-security
/rust/mark1-policy/src/verify.rs    @Omium-ai/mark1-security
/go/mark1d/internal/identity/       @Omium-ai/mark1-security
/go/mark1d/internal/capture/        @Omium-ai/mark1-security
/go/controld/internal/auth/         @Omium-ai/mark1-security
/go/controld/internal/querychoke/   @Omium-ai/mark1-security
/go/controld/internal/dprelease/    @Omium-ai/mark1-security
/python/shared/mark1_receipts/      @Omium-ai/mark1-security
/tools/verifier/                    @Omium-ai/mark1-security

# --- The gates that enforce the design must not be quietly weakened ---
/tools/ci/                          @Omium-ai/mark1-security
/deny.toml                          @Omium-ai/mark1-security
/.golangci.yml                      @Omium-ai/mark1-security
/.github/workflows/                 @Omium-ai/mark1-security
/CODEOWNERS                         @Omium-ai/mark1-security

# --- Conformance fixtures are evidence; changing evidence is a security review ---
/conformance/canary/                @Omium-ai/mark1-security
/conformance/tenancy/               @Omium-ai/mark1-security
```

The last stanza matters: relaxing a lint config, editing a CI gate script, or "updating" the token-shape canary corpus is precisely how mechanical guarantees erode, so the enforcement surfaces own themselves.

### 10.2 `.github/PULL_REQUEST_TEMPLATE.md`

```markdown
## What

<!-- One paragraph. Link the doc section or ADR this implements. -->

## Contract check (mechanically enforced by contracts_sync_check — this is the human half)

- [ ] No proto/message, table, bundle-section, error-code, or hook-payload change — OR —
- [ ] `docs/07-data-model.md` / `docs/08-api-contracts.md` updated **in this PR**

## Discipline

- [ ] No new direct dependency — OR — the dependency is named below with why the ladder
      (stdlib → existing dep → small code) doesn't hold
- [ ] No new `#[allow(clippy::unwrap_used)]` / lint suppression — OR — each carries a reason comment
- [ ] Failure postures of new paths stated (open/static/closed) and matched to 04/05's matrix
- [ ] Tests: the behavior this PR adds has the test 12 names (or this PR adds it)

## New dependency justification (if any)

<!-- name, version pin, license, transitive count, why not stdlib/existing -->
```

### 10.3 The contract-sync rule as a mechanical check

The rule from `00-README.md`: *"A change to a proto message, a table, a bundle section, an error code, or a hook payload lands in `07`/`08` in the same pull request as the code, or the pull request is incomplete."* `tools/ci/contracts_sync_check.sh` enforces the checkable core of it against the PR's merge-base diff:

```sh
#!/bin/sh
# contracts_sync_check.sh — if the diff touches a contract surface, it must also touch
# the owning contract document. BASE_REF is provided by ci.yml (the PR base SHA).
set -eu
CHANGED=$(git diff --name-only "${BASE_REF}"...HEAD)
touches() { echo "$CHANGED" | grep -qE "$1"; }

if touches '^proto/m1p/' && ! touches '^docs/07-data-model\.md'; then
  echo "FAIL: proto change without docs/07-data-model.md in the same PR (00-README sync rule)"; exit 1
fi
if touches '^(migrations|python/adjudicator/migrations|python/intel/migrations)/' \
   && ! touches '^docs/07-data-model\.md'; then
  echo "FAIL: migration change without docs/07-data-model.md in the same PR"; exit 1
fi
if touches 'sections\.rs|policydist/catalog\.go|policy_compiler/' && ! touches '^docs/07-data-model\.md'; then
  echo "FAIL: bundle-section change without docs/07 in the same PR"; exit 1
fi
if touches 'errors?\.(rs|go|py)$|M1E-' && ! touches '^docs/08-api-contracts\.md'; then
  echo "FAIL: error-taxonomy change without docs/08-api-contracts.md in the same PR"; exit 1
fi
if touches '^go/mark1d/adapters/|^rust/mark1-hookshim/src/maps\.rs' && ! touches '^docs/08-api-contracts\.md'; then
  echo "FAIL: hook/adapter contract change without docs/08 in the same PR"; exit 1
fi
echo "contracts_sync_check: OK"
```

The grep patterns are deliberately over-broad (an error-message-only edit can trip the `M1E-` pattern): the *failure mode* of this gate is a reviewer typing "docs unaffected because …" and adding a one-line note to 07/08's changelog — thirty seconds — while the failure mode of the inverse gate is a silently drifted contract document. Over-trigger is the correct bias. What the script cannot check (whether the doc edit is *truthful*), the CODEOWNERS review of `docs/07`/`08` does.

### 10.4 Review requirements for security-relevant paths

Any path owned by `@Omium-ai/mark1-security` (§10.1) additionally requires in review: the PR names which of the plan's seven in-code compliance enforcement points it touches (or states "none"), and the matching `10` control-matrix row + `12` test are cited. A PR that weakens a gate script, a deny rule, or a canary fixture without an ADR reference is rejected on sight — the gates are part of the product's legal posture, not its style guide.

---

## 11. First-commit sequence — the handoff into Phase 1

The plan's nine "Critical files, in build order" as an actual commit sequence. Each commit is a PR that leaves `main` green with strictly more gates on than before; "verifiably working" names what a reviewer can run. C0 is the scaffold this document specifies; C1–C9 are the plan's nine, in the plan's order.

| # | Commit contains | CI gate that turns ON with it | Verifiably working after merge |
|---|---|---|---|
| **C0** | The scaffold: root `Cargo.toml`/`go.work`/`pyproject.toml`+locks, `justfile`, all §7 configs, `deny.toml`, `tools/ci/*.sh`, root `CODEOWNERS` (§10.1 — root file, no `.github/` copy), `.github/` (ci.yml skeleton + PR template), `.pre-commit-config.yaml`, `scripts/bootstrap.*`, empty-but-structured `conformance/` dirs. No product code | fmt/clippy/golangci/ruff (against nothing, but wired), gitleaks, **otel gate**, `cargo deny`, branch protection + CODEOWNERS review | `just` runs end to end on a clean checkout on all three OSes; a PR adding an OTel dep is already rejected |
| **C1** | `proto/m1p/v1/*.proto` (envelope + all event families per 07), `buf.yaml`/`buf.gen.yaml`/`buf.lock`, first committed `proto/gen/{go,python,rust}`, `proto/gen/go/go.mod`, `m1p-proto` pyproject | **`buf lint` + `buf breaking` (WIRE_JSON) + `gen_fresh.sh` + `contracts_sync_check.sh`** — the ratchet exists before any consumer | `buf lint` clean; a test PR deleting a field is rejected by `buf breaking`; all three bindings compile/import standalone |
| **C2** | `rust/m1p-wire`: staged gen include, M1PL framing with bounded `len`, incremental `FrameDecoder`, `fuzz/frame_decode` + seed corpus in `conformance/vectors/m1pl/` | Rust 3-OS matrix becomes required; **fuzz-smoke (60 s)**; the workspace `--locked` build gate | `cargo test -p m1p-wire` round-trips every event family; the fuzzer survives its smoke run; hostile length prefixes provably cannot allocate past the bound |
| **C3** | `go/mark1d` skeleton (`cmd/main.go`, `internal/{obs,fabric,capture}` stubs) + **`internal/spool` in full** (07 §6: 64 MiB segments, crc32c, mmap ledger, per-class policy, `Dropped{}` accounting, recovery scan) + Go frame reader + `FuzzSpoolRecordDecode`/`FuzzM1plFrameRead` | Go 3-OS matrix required; **govulncheck**; Go fuzz smoke; **`conformance_crosslang.sh`** (first two-language vectors: Rust↔Go frames) | `kill -9` mid-append test shows billing-grade loss = 0 beyond the fsync window, all loss accounted as `Dropped{CRC_LOSS}`; Rust-encoded frames decode identically in Go |
| **C4** | `go/controld` skeleton (`internal/{config,server,auth,obs,pg}`) + **`internal/ingest` in full** (S3-first landing, token-stamped tenancy, idempotent upsert, pre-egress scanner, CH async-insert via `chproj`) | depguard querychoke/no-grpc rules now bite real code; ingest integration tests (DSN-gated, `just dev-up` stack) | `mark1d` spool → uplink → controld → MinIO+ClickHouse end to end in compose; replaying a batch is idempotent by `event_id`; a tenant-mismatch batch is rejected + security event |
| **C5** | `migrations/m1_001…` (tenants/devices, receipt chain per `ro_012` template + `key_id`/checkpoint columns, verifier registry, certs, artifacts, contributions, ε ledger, bundles, gold sets — 07's DDL) + `scripts/migrate-db.sh` + **`docs/adr/0001-clickhouse-ordering-key.md` signed** | migration idempotency check (apply twice); **`conformance/tenancy/` RLS negative tests** (the `*_app` NOBYPASSRLS discipline, mechanically un-repeatable) | `just migrate` twice = no-op; RLS negative suite proves cross-tenant reads impossible as the app roles; **the one irreversible ADR is signed before any production write** |
| **C6** | `python/shared/mark1_receipts` (vendored `canonical.py`/`keys.py` + `checkpoint.py`) + `conformance/vectors/receipt/` + the Go origin-sign mirror in `mark1d/internal/identity` | Python CI (ruff, pytest, pip-audit); receipt vectors join `conformance_crosslang.sh` — **three languages now locked together** | one vector set produces identical canonical bytes, hashes, and verifiable dual signatures in Python, Rust, and Go |
| **C7** | `tools/verifier` (Rust, Apache-2.0): chain walk, checkpoint Merkle + inclusion paths, dual-sig + KeyRing rotation verification, witness-head cross-check, offline by construction | verifier e2e in CI: build a chain via C3–C6 components **with no server running**, verify it | the sales claim is demonstrable: `mark1-verifier verify --chain … --witness …` passes offline; any single tampered byte fails with a named defect |
| **C8** | `rust/mark1-hookshim` (off-check-first, maps-as-data, spill ring) + `go/mark1d/adapters/claudecode` + `internal/tailers` (sidechain dedupe as protocol invariant) + `conformance/hooks/claudecode/<pinned>/` fixtures | hook-fixture replay suite; shim cold-start bench (≤10 ms) + 50 ms deadline test; `secret_type_gate` now covers the shim's redact link | recorded Claude Code sessions replay through shim+tailer → spool → ingest with zero duplicate `Usage` (the ~2.5× overcount defense proven by fixture); daemon-down replay via spill ring works |
| **C9** | `python/intel` skeleton + **`app/tvo/` in full** (closed forms, engine, deterministic waste taxonomy, coverage metric, report) + `in_0NN` migrations | TVO golden test: output must match the hand-computed Paper I worked example; coverage-floor refusal test (`M1E-5004`) | **the Phase 1 gate**: end-to-end certified usage events from a real session, TVO computed, verifiable offline by the customer — dogfood week starts |
| **R1** | first `edge/v0.1.0` tag (no new code) | `release.yml`: 5-triple build, signing/notarization, **SBOM + SLSA attestation** (the last two new-vs-estate gates turn on) | `mark1 verify-release` validates signature + provenance on a dogfood laptop; ring 0 manifest committed |

Reading rule for the sequence: **no commit ships a consumer before its producer's gate exists** — the ratchet (C1) precedes the wire (C2), the wire precedes the spool (C3), durability precedes ingest (C4), schema + the irreversible ADR precede anything that writes receipts (C5→C6), and the verifier (C7) precedes the capture surfaces (C8) because "verifiable offline" must be true of the *first* customer-visible event, not retrofitted onto it. Everything after R1 is Phase 1 dogfood and the Phase 2 workstreams of `14-delivery-plan.md`.

---

*End of 13 — Repository Scaffold and Build Tooling. Delivery plan and workstreams: 14. Test definitions for every gate named here: 12. Infra the images land on: 09.*
