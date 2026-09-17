# 04 — Low-Level Design: The Edge

**Status:** Authored 2026-08-28 against the frozen execution plan (`docs/spec/execution-plan-v2.md`) and the architecture spec v2.0 (`docs/spec/architecture-spec.md`). Where this document and either of those disagree, they win.
**Scope:** the four edge processes — `mark1d` (Go), `mark1-proxy` (Rust), `mark1-hookshim` (Rust), `cortexd` (Rust) — the four client crates (`mark1-redact`, `mark1-receipt`, `mark1-policy`, `m1p-wire`) and the proxy-internal crate `mark1-frames`. Cloud internals are 05; intelligence services are 06.
**Code blocks are illustrative design detail**, not compiled code: they fix names, signatures, ownership and semantics; the implementation may differ in mechanics but not in contract.

## 0. Scope, conventions and how to read this

### 0.1 What this document fixes vs what 07 and 08 fix

| Concern | Owner | This document |
|---|---|---|
| `m1p.v1` protobuf, M1PL framing bytes, spool segment binary layout, cross-layer dedupe | **07** (`07-data-model.md`) | Cites; never restates a byte offset |
| M1P/1 HTTP contract, control-plane REST, hook contracts, MCP tool schemas, CLI surface, `M1E-*` error taxonomy, provisioning/fence algorithms | **08** (`08-api-contracts.md`) | Cites; never restates a schema or status table |
| Module trees, exported types/interfaces, goroutine/task/ownership models, state machines, hot-path budgets, backpressure, failure modes and their postures | **this document** | Normative here |

A failure mode named here always carries an existing `M1E-*` code from 08 §9; this document introduces no new codes.

### 0.2 Notation

- **State machines** are Mermaid `stateDiagram-v2`; every transition is labeled `trigger / action`. An unlabeled action means "none beyond the state change".
- **Budgets** are written `value @ enforcement point` — e.g. `≤1 ms median @ proxy self-timer + CI bench threshold (12)`. A budget without an enforcement point is a wish, so none appears here without one.
- **Postures** use the frozen matrix verbatim: **fail-open** for availability (capture, hooks, gates), **fail-static** for policy, **fail-closed** for legality and secrets (OAuth guard, upload admission, revocation).
- Go code follows the estate conventions: `cmd/main.go` + `internal/`, an `obs` package, go 1.25, no OTel. Rust follows the estate build: virtual Cargo workspace, all versions in `[workspace.dependencies]`, release profile `opt-level=2, lto="thin", strip=true`, `rust:1.91-slim-bookworm` builder → `gcr.io/distroless/cc-debian12:nonroot` (glibc, not musl) for anything containerized.

### 0.3 Edge-wide invariants (restated once, relied on everywhere)

1. **`mark1d` is the only spool writer.** Every other producer (shim, proxy, cortexd, tailers, loopback listener) reaches durability only through `mark1d`'s single admission path. One durability implementation, one redaction chokepoint, by construction.
2. **`mark1 off` / `MARK1_DISABLE=1` is checked before any gate evaluation** — before any policy read, bundle read, or verdict-cache read, in every component that gates (shim, `mark1d`, proxy). No bundle, server, or config state can re-enable gating while off (08 §7.6).
3. **Nothing outside an enabled workspace is read.** Tailers, cortexd, and anchors operate only inside `mark1 enable`'d roots, honor `.mark1ignore`, and the live read surface is auditable via `mark1 status`.
4. **Verdict vocabulary is `satisfied | violated | refused | error`**, and `posterior[4]` is ordered exactly that way (07 §4). Infrastructure failure is `error`, never `violated`.
5. **No pre-redaction plaintext persistence exists anywhere.** The admit-to-upload axis is fail-closed with no off switch; even emergency spill is post-redaction.
6. **Zero OpenTelemetry anywhere.** Edge self-observation is the `obs` package, `Dropped{}` accounting, and coverage transitions — product telemetry, not ops noise (11).
7. **Registry discipline:** 9 deployables + 4 client crates per the frozen plan; `mark1-frames` is a proxy-internal crate listed separately. (The spec §2 heading reading "2 crates" is a known spec typo; the plan wins. Likewise the spec §0 C1.7 disposition placing the proxy in "Phase 2 of assembly" is a known spec error: the proxy is built in **Phase 3**, gateway mode in **Phase 5**, per the plan.)

### 0.4 Reconciliation flags found while authoring (for the lead's contradiction pass)

These are disagreements between already-written documents. This document takes the stated side but does not resolve them — resolution belongs to the reconciliation pass.

| # | Disagreement | Sides | Side taken here |
|---|---|---|---|
| R-1 | M1PL frame `len` bound | 07 §5: `len ≤ 4 MiB` (and spool record bound derived from it); 08 §4.2 *as originally written*: `len ≤ 1 MiB` with `HelloAck{max_frame: 1048576}` | **07** — it owns the framing bytes; 08's `max_frame` value follows. **RESOLVED (D-A):** 08 §4.2 now reads `0 < len ≤ M1PL_MAX_FRAME = 4_194_304` and §4.3 `HelloAck{max_frame: M1PL_MAX_FRAME}`. One symbolic constant, one owner; the literal `1048576` survives nowhere but this row's history. Kept, not deleted — a reader arriving from §5.2's pointer needs to learn the bound was contested and how it settled |
| R-2 | Fabric endpoint path/name | 07 §5: `$XDG_RUNTIME_DIR/omium-mark1/m1p.sock` (fallback `~/.omium/mark1/m1p.sock`), Windows `\\.\pipe\omium-mark1-<user-SID>`; 08 §4.1: `~/.omium/mark1/mark1d.sock`, Windows `\\.\pipe\omium-mark1d` | **07** — the SID-qualified pipe name closes a squatting collision 08's name does not |
| R-3 | cortexd MCP tool set | 08 §6: `repo_map / find_definition / find_references / deps / ranked_files / memory_recall`; spec §4 C6: `repo_map/find_definition/find_references/expand/deps` (has `expand`, lacks `ranked_files`/`memory_recall`) | **08** — per instruction; `expand` does not exist in the wire contract |
| R-4 | Who stamps `seq` | plan/spec §2: hookshim "stamps UUIDv7 + seq"; 07 §2: per-session `seq` is "assigned by mark1d at admission" | **07** — one authority for causal order; the shim stamps `event_id` only. A shim-local counter cannot be session-monotonic across the shim's many short-lived processes |

---

## 1. Edge process topology and supervision

### 1.1 Process tree and scoping

```mermaid
flowchart TD
    OS["OS-native supervisor\nlaunchd (macOS) / systemd --user (Linux) /\nper-user service (Windows)"] -->|starts, restarts| D["mark1d\n(Go, per-user singleton)"]
    CLI["mark1 CLI\n(enroll / enable / off / status / doctor)"] -->|installs unit, adopts running daemon| D
    D -->|"supervise: spawn per enabled workspace"| C1["cortexd (ws A)"]
    D -->|"supervise: spawn per enabled workspace"| C2["cortexd (ws B)"]
    D -->|"supervise: spawn when Detect()==apikey\n(sidecar mode; Phase 3+)"| P["mark1-proxy --mode=sidecar"]
    A["agent process\n(Claude Code, …)"] -->|"exec per hook event"| H["mark1-hookshim\n(transient, ≤50 ms)"]
    H -->|M1PL frames| D
    C1 -->|M1PL frames| D
    P -->|M1PL frames| D
    A -->|MCP loopback| C1
    A -->|"HTTPS via ANTHROPIC_BASE_URL\n(API-key regime only)"| P
```

**Scoping decisions, with WHY:**

- **`mark1d` is per-machine-per-user, not per-workspace.** One spool, one uplink identity, one device key, one fabric socket, one policy client. Workspaces are *data* (an allow-list the tailers/coverage consult), not processes — a per-workspace daemon would mean N spools with N durability implementations and N device identities, recreating the cgo-era distribution tax in another axis.
- **`cortexd` is per-workspace.** Index size, memory ceilings, and session scoping are per-repo properties; a panic or OOM while indexing one monorepo must not stall another workspace's map serving. The per-workspace process is also what makes MCP session scoping (08 §6) enforceable by construction: the process literally has no other workspace's shards open.
- **`mark1-proxy` sidecar is per-user, spawned on demand** (an API-key-regime agent is enabled), one listener for all API-key agents. In gateway mode the customer deploys and supervises it; `mark1d --fleet` only distributes policy to it.
- **`mark1-hookshim` is not a process to supervise** — it is exec'd by the agent per hook event and exits. Its "restart policy" is the next hook event.

### 1.2 Who starts whom, restart policy

| Process | Started by | Restart policy | Crash-loop breaker |
|---|---|---|---|
| `mark1d` | OS supervisor (installed by `mark1 enroll`); `mark1` CLI adopts a running instance via pidfile + binary-hash check | supervisor-native: `KeepAlive` / `Restart=on-failure`, supervisor backoff | supervisor-native; additionally `mark1 status` surfaces restart count |
| `cortexd` | `mark1d.supervise` at `mark1 enable` and on session activity in an enabled root | exponential backoff, base 500 ms, ×2, cap 60 s, decorrelated jitter | >5 restarts in 60 s ⇒ child marked `FAILED`, indexing off for that workspace, MCP tools refuse (`M1E-6404`), **capture unaffected** |
| `mark1-proxy` (sidecar) | `mark1d.supervise` when an enabled adapter reports `Detect()==apikey` | same backoff as cortexd | >5/60 s ⇒ `FAILED` + **receipted `CoverageTransition{BYPASS, reason_code:"proxy_failed"}`**, agent base-URL fragment reverted so traffic flows direct — capture degrades to transcripts, the developer is never blocked |
| `mark1-hookshim` | the agent, per hook event | n/a | n/a — a persistently failing shim shows up as missing hook events, surfaced by `mark1 doctor` |

**Crash isolation is directional and deliberate:** capture (tailers, spool, uplink — all inside `mark1d`) depends on nothing else. A `cortexd` panic costs ranked maps and the anchors' merkle-root freshness (anchor votes then carry an incomplete integrity envelope and never certify — §2.3), nothing more. A proxy crash costs wire capture and `WIRE_ENFORCED` routing; the client's next request bypasses (fail-open, receipted). A `mark1d` crash is the only one that pauses capture admission — and the shim's spill ring plus the on-disk transcripts mean the events are not lost, only delayed (§1.4).

### 1.3 Resource ceilings

| Process | Ceiling | Enforced at |
|---|---|---|
| `mark1d` | ≤200 MB RSS steady state @ self-watchdog (obs gauge; >300 MB ⇒ controlled restart with drain); ≤2 GiB spool + 95%-disk hard stop @ spool (07 §6) | self-watchdog + spool policy |
| `mark1-proxy` | **≤35 MB RSS and ≤1 ms median added latency** @ proxy self-timer, `mark1d.supervise` RSS poll, CI bench threshold (12) | the frozen-plan budget, verbatim |
| `cortexd` | ≤500 MB RSS per workspace @ self-watchdog (over ⇒ shed L3 SCIP, then coarsen L2 shards, then refuse with `M1E-6404`); full-index passes at idle priority (§6.6) | self-watchdog |
| `mark1-hookshim` | ≤50 ms wall fire-and-forget, ≤10 ms cold start @ its own deadline timers (§5.3); transient RSS ~5 MB | shim-internal deadlines |
| anchors | per-catalog-entry: CPU-seconds, `memory.max` 512 MiB default, `pids.max`, wall timeout (60 s fast / 600 s slow class) @ sandbox (§2.3) | sandbox, kill-switched |

### 1.4 What happens when — machine sleep, network death, SIGKILL

**Machine sleeps.** All timers are monotonic-clock based, so a wake does not fire a burst of "missed" retries; the uplink treats wake (network-change signal) as a park re-queue trigger (08 §2.5). Tailers re-`stat` their files on wake and resume from persisted cursors. The anchor scheduler treats wake as an activity burst: slow anchors stay deferred until the session idles again. On macOS, launchd may terminate `mark1d` during sleep — indistinguishable from SIGKILL, handled identically (below).

**Network dies.** Capture is untouched (fail-open): tailers, hooks, anchors, fusion, and gates all run local. The spool accumulates; billing-grade classes block-on-full rather than shed (07 §6). The uplink runs the 08 §2.5 automaton to PARKED. Policy is fail-static: last-known-good bundle runs indefinitely; past `max_age`, conservative built-ins with `stale_cert` flagging (`M1E-3006`). Token refresh failure does not stop capture — tokens gate egress only. The one hard dependency on the network is enrollment itself.

**`mark1d` is SIGKILLed.**
- *Spool:* recovery per 07 §6 — A/B ledger slot selection, forward scan, torn-tail truncation; billing-grade loss is bounded by the fsync cadence (250 ms when billing-grade records are pending) and accounted as `Dropped{CRC_LOSS}` in the first batch after restart. Never silent.
- *hookshim:* connect fails in ≤100 ms ⇒ sanitized encrypted spill ring; replayed by `mark1d` after restart (§5.4). Gate queries fail-open to allow with `Dropped{gate_timeout}`.
- *tailers:* transcripts are files on disk; the restart resumes from the persisted cursor, and `idem_key` dedupe makes any re-read harmless (07 §7).
- *proxy:* keeps serving — the client path never depends on `mark1d`. Tee events go to its own spill ring; the guard keeps its last registry snapshot (fail-static for the registry, fail-closed per request: an unprovisioned credential is still refused).
- *cortexd:* keeps running orphaned; the restarted `mark1d` adopts it via pidfile + binary-hash check, or kills and respawns on mismatch. MCP serving continues throughout.
- *Restart:* OS supervisor brings `mark1d` back with supervisor backoff; children are adopted; parked batches re-queue.

**`mark1 off`** is not a failure but is listed for symmetry: off-marker written first, fragments reverted to byte-equality, tailers stopped, proxy detached, cortexd idled, `CoverageTransition{disable}` receipted (08 §7.6). Works with the network down; no server round-trip on the critical path.

---

## 2. `mark1d` (Go) — module tree and internals

```
go/mark1d/
├── cmd/main.go                  # flag parse, config load, obs init, run loop — nothing else
├── adapters/
│   ├── claudecode/              # Phase 1: hooks + transcript tailer + sidechain dedupe
│   ├── codex/                   # Phase 2 (spike-gated)
│   ├── gemini/                  # Phase 3 (spike-gated)
│   ├── opencode/                # Phase 4 (spike-gated)
│   ├── copilot/                 # Phase 5 (spike-gated, BYOK)
│   ├── cursor/                  # Phase 5 (spike-gated, observe/gate)
│   └── crush/                   # roadmap slot; registry completeness only
└── internal/
    ├── capture/                 # the single admission pipeline into the spool
    ├── tailers/                 # workspace-allow-listed transcript tailing
    ├── anchors/                 # catalog, consent, sandboxed runner, anti-tamper
    ├── verdict/                 # log-space NB fusion + the gate-read cache
    ├── spool/                   # 07 §6 made code; the single writer
    ├── uplink/                  # batching, zstd, the 08 §2.5 retry automaton
    ├── policy/                  # bundle fetch/verify/decode (Go parallel decoder), fail-static
    ├── coverage/                # attributable enable/disable/bypass windows
    ├── supervise/               # child lifecycle (§1.2)
    ├── identity/                # device key custody, token refresh, revocation
    ├── fabric/                  # M1PL server (UDS/named pipe) + loopback fallback listener
    └── obs/                     # slog structured logging + atomic counters; no OTel
```

`fabric` is listed beyond the plan's ten-package enumeration because the M1PL server must live somewhere and belongs to none of the ten; it is transport, not policy. Everything else matches the plan's `internal/{capture,tailers,anchors,verdict,spool,uplink,policy,coverage,supervise,identity}` exactly.

### 2.0 `capture` — the single admission pipeline

Every producer converges here; this is what makes invariants 1 and 5 (§0.3) structural.

```go
package capture

// Admitter is the ONLY path to the spool. The constructor is called once in
// cmd/main.go and the write side of the spool is moved into it — no other
// package can obtain a spool write handle.
type Admitter interface {
    // Admit runs: normalize → redact-admit (fail-closed) → seq-stamp →
    // class-tag → spool append. Billing-grade events block under backpressure;
    // diagnostics return ErrShed (accounted, never silent).
    Admit(ctx context.Context, ev *m1pv1.Event) error
}

var ErrShed = errors.New("capture: diagnostic event shed under backpressure")

// redactAdmit is the Go implementation of mark1-redact's admit-to-upload axis:
// same ruleset source, validated bit-identical against the Rust crate by shared
// conformance vectors in CI — the same discipline the plan mandates for the Go
// bundle decoder. There is no parameter, config field, or build tag that
// disables it. Scanner failure ⇒ the event is locally quarantined
// (Dropped{LOCAL_QUARANTINE}), never admitted raw.
func redactAdmit(ev *m1pv1.Event) (admitOutcome, error)
```

Stage order is load-bearing: redaction runs **before** the seq stamp and spool append, so no pre-redaction bytes ever reach disk; `seq` is assigned here (one authority, per R-4) from a per-session atomic counter; the durability class byte (07 §6 `record_id[16]`) is tagged here from the event family so the spool applies full-spool policy without decoding protobuf.

Goroutine model: `Admit` is called on the caller's goroutine (fabric connection readers, tailer goroutines, adapter goroutines); it sends into the spool goroutine's bounded channel (cap 1024). Billing-grade sends block (backpressure propagates to the fabric read loop, which stops reading its socket — 08 §4.4); diagnostic sends use `select`/`default` and shed to `ErrShed`.

### 2.1 `tailers` — transcripts in, Usage out

```go
package tailers

// WorkspaceSet answers "may I read this path?" — the §0.3 invariant 3 oracle.
// Canonicalized enabled roots + .mark1ignore (gitignore syntax, evaluated at
// the workspace root). Consulted on every file DISCOVERY, not just once.
type WorkspaceSet interface {
    Allowed(absPath string) bool
    Roots() []string
}

// Cursor is persisted after every emitted Usage flush (atomic write+rename,
// fsync'd), keyed by file identity — not path — so rotation is detectable.
type Cursor struct {
    Path     string
    FileID   FileID // (dev, inode) on unix; volume+file index on Windows
    Offset   int64  // byte offset of the first unconsumed line
    SavedAt  time.Time
}

// Tailer follows one transcript stream (a session's main transcript or one
// subagent transcript, each its own stream under the parent session_id).
type Tailer struct { /* file handle, cursor, pending Usage map, line scanner */ }

// pendingKey implements the dedupe rule as a protocol invariant.
type pendingKey struct{ MessageID, RequestID string }
```

**Behavioral contract, point by point:**

- **Discovery.** Primary source is the `transcript_path` field on hook payloads (08 §5.1); fallback is the derived `~/.claude/projects/<munged-cwd>/` path. Every discovered path is checked against `WorkspaceSet` — a transcript whose `cwd` resolves outside an enabled root is not opened, full stop.
- **`(message.id, requestId)` sidechain dedupe.** One *pending* `Usage` per unique key, last-write-wins: streaming rewrites of one assistant message replace the pending entry rather than appending (the verified ~2.5× overcount defense). A pending entry is emitted when a newer key appears on the stream, on the `Stop` hook, or after a 2 s quiesce debounce — whichever first. **Post-emission rewrites of an already-emitted key** — a late transcript line after the quiesce flush — are resolved by identity, not suppression: identical numbers are suppressed (the true duplicate), *updated* numbers re-emit once under the SAME `idem_key`, and the ledger's `Usage` rollup keeps the latest by `max(event_id)` (`07` §7's worked example is explicit about this shape). A strictly-once reading here would silently drop corrected cumulative counts and under-bill, which is worse than the duplicate it prevents. Sidechain (subagent replay) lines in the parent transcript are dropped before emission; subagent transcripts are tailed as their own streams. Even a dedupe bug here cannot double-bill: `idem_key` upsert at ingest is the backstop (07 §7).
- **Rotation.** The tailer holds its file handle open. On a poll where the path's `FileID` changed: drain the old handle to EOF, close, open the new file at offset 0. Nothing is lost because the old inode stays readable while held.
- **Truncation.** Same `FileID`, size < cursor offset ⇒ the file was truncated/rewritten: reset to offset 0 and re-scan. Replays are safe (idempotency), so the cheap response is the correct one.
- **Resume-after-restart.** Load cursors; `stat` each file; if the cursor's `FileID` no longer matches or the file shrank, re-scan from 0. A missing file (vendor retention sweep — transcripts auto-delete per `cleanupPeriodDays`, 08 §5.1) is a **coverage gap, never a silent hole**: emit `CoverageTransition{BYPASS, reason_code:"transcript_retention_gap"}` when the gap is attributable to tailer downtime longer than the retention window.
- **Failure posture: fail-open.** An I/O error on one stream logs, emits `Dropped{}`, and never stops sibling tailers.

Goroutine model: one fsnotify-class watcher per workspace root (for discovery) + one goroutine per tailed stream. Watcher overflow degrades to periodic (5 s) directory polls — tailing is latency-tolerant; the dedupe and idempotency layers absorb any resulting burst.

### 2.2 `anchors` — catalog, consent, sandboxed runner, anti-tamper

```go
package anchors

// CatalogEntry is LOCALLY DERIVED — never server-named. Derivation probes the
// worktree (ruff config present, tsconfig.json, Cargo.toml, …) and the PATH
// for the matching tool. Bundles enable entries by ID only; any command
// string in a bundle fails decode upstream (M1E-3005).
type CatalogEntry struct {
    ID          string   // "ruff@cat-3" — stable per (tool, derivation rule)
    Tool        string   // public tool name, EvidenceRecord.tool vocabulary
    Argv        []string // derived locally, shown verbatim in `mark1 doctor`
    Class       Class    // Fast | Slow (test anchors are always Slow, per-repo opt-in)
    BinaryPath  string   // resolved at consent time
    BinaryHash  []byte   // BLAKE3 at consent time — the PATH-shim reference
    ConsentedAt time.Time
}

// Registry mirrors the platform's PROBE_HANDLERS discipline: a map of anchor
// kind → handler, with an init-time assert that handled kinds == registered
// kinds. An unimplemented kind is REFUSED (vote never emitted), never faked.
type Registry map[Kind]Handler

type Handler func(ctx context.Context, e CatalogEntry, sb Sandbox) (Vote, error)

// Sandbox is the security boundary, not a convenience wrapper.
type Sandbox interface {
    Run(ctx context.Context, spec RunSpec) (RunResult, error) // kill-switched via ctx
}

type RunSpec struct {
    Argv       []string
    WorktreeRO string            // read-only outside this path; RW only in scratch
    Env        map[string]string // the allow-list, nothing inherited
    Limits     Limits            // cpu, memory.max, pids.max, wall timeout
}
```

**The sandbox, per platform mechanics (§11 has the deltas):** network-denied (Linux: new net namespace via `unshare` or seccomp deny; macOS: `sandbox-exec` deny-network profile; Windows: job object + WFP block — weakest, see §11.5), env scrubbed to an explicit allow-list (`PATH` set to the resolved catalog directories only, `HOME` to a scratch dir, plus `LANG`/`TZ`; nothing else inherited), read-only outside the worktree, resource-capped per `Limits`, kill-switched (context cancel ⇒ SIGKILL the process group; `mark1 off` cancels all running anchors immediately, before its other steps).

**Consent catalog lifecycle:** derived at `mark1 enable`, consented per entry (interactive, or `--anchors`/`--no-anchors`), persisted at `~/.omium/mark1/anchors/catalog.json` (0600), re-consent required on any derivation change (argv, binary path, tool version) — the changed entry is disabled until re-consented and `mark1 doctor` shows the diff. Test-class anchors additionally require the per-repo opt-in and the sandbox precondition: if the sandbox cannot be established on this platform, test anchors refuse to run rather than run unsandboxed.

**Activity-aware scheduling:** fast anchors (ruff, incremental tsc, warm `cargo check`) run on PostToolUse debounce (300 ms, coalesced per `(task, anchor)` — only the latest matters); slow anchors run only when the session is idle (no tool events for 30 s) or at `Stop`, are deferred on battery-saver and on sustained high load, and are paused entirely by an activity burst. WHY: the developer's machine is the substrate; an anchor that makes typing lag is a product-killer regardless of its statistical value.

**The anti-tamper envelope** (fills `AnchorIntegrity`, 07 §4) — computed per run, device-signed at origin:

| Field | How it is computed | What it defeats |
|---|---|---|
| `resolved_binary_hashes` | BLAKE3 of the file at the **resolved** exec path (post env-scrub, so `PATH` is only catalog dirs), compared to the consent-time `BinaryHash` | PATH shims and swapped binaries — "effective-execution hashing, not glob hashing" |
| `worktree_merkle_root` | cortexd's L0 root, cached in `mark1d` from cortexd's push on every index-clock bump (§6.7) | worktree mutation between what the agent edited and what the anchor saw |
| `env_scrub_attestation` | hash of the exact env map passed to `RunSpec` | env-var-based tool suppression (`RUFF_NO_CACHE`, `SKIP=`, …) |
| `diff_classification` | classifier over the task's touched-file set (src/test/config/suppression) | test-gaming and config-gaming detection input |
| `suppression_directive_delta` | count delta of lint-suppression directives (`# noqa`, `// eslint-disable`, `#[allow]`, …) across the attempt | the cheapest reward-hacking tell |
| `tamper` | true if any of the above fails its check | tampered votes never certify, downstream |

If cortexd is down and no fresh L0 root exists, the envelope is **incomplete**: the vote is still emitted (fusion is fail-open for availability) but carries `tamper`-unknown semantics — the adjudicator treats incomplete-integrity votes as low-power and they never feed certification. Honest degradation beats a fabricated root.

**Failure posture:** an anchor that crashes, times out, or cannot start its sandbox produces `AnchorVote{vote: VERDICT_ERROR}` with an `EvidenceRecord` naming the failure category — `error`, never `violated` (§0.3 invariant 4). The run loop is fail-open: one anchor's failure never blocks another's schedule.

### 2.3 `verdict` — fusion and the gate cache

```go
package verdict

// Fuser is pure math over bundle data. It is NOT exported to the fabric or
// gate paths — structurally, the gate cannot compute.
type Fuser struct {
    m BundleMatrices // confusion matrices, priors, correlation groups
    // (syntactic ∪ {tests} as its own group) — all from the bundle's verify
    // section; nothing here is edge-invented. D-R: there is NO separate
    // abstention model — each confusion4x3 row's third (abstain) column IS
    // the abstention likelihood, consumed by an EXPLICIT abstain vote (D-V).
}

// Fuse: log-space naive Bayes. Votes are first collapsed WITHIN each
// correlation group (group-majority with the group's joint confusion row),
// then treated as independent ACROSS groups:
//   score(v) = log prior(v) + Σ_g log P(collapsed_vote_g | v)
//
// DECISION D-V (lead, binding). SILENCE IS NOT AN OBSERVATION. This clause
// previously read "absent/abstaining members contribute their abstention
// likelihood, not silence"; that is now reversed. Fuse multiplies likelihoods
// ONLY over members that actually voted. An explicit abstain vote consumes the
// confusion4x3 abstain column; absence consumes nothing at all. Rationale:
// under the fast/slow split below, absence overwhelmingly means "has not run
// yet", not "ran and could not decide" — synthesising an abstain column for
// every not-yet-reported slow anchor makes the PROVISIONAL posterior a
// function of which anchors happen to be slow, and was measured flipping a
// real verdict to VIOLATED, i.e. blocking a developer on evidence nobody
// gathered. Informative missingness is a genuine effect, but modelling it
// needs a missingness model the bundle does not carry; it must never be
// smuggled in through the abstain column. This makes the edge agree with
// 06 §3.1, which iterates received votes — the two implementations must now
// agree on identical (bundle, votes), in the precise sense D-AC fixes below.
//
// DECISION D-W (lead, binding). Every deterministic tie-break in group
// collapse — accept branch, reject branch, all-abstain branch — resolves to
// the LEXICALLY SMALLEST verifier id. Reject and all-abstain already did on
// both sides; the accept branch did not, and the two implementations picked
// opposite members on equal likelihood ratios, producing different wire
// posteriors from one input.
//
// DECISION D-X (lead, binding). A vote from a verifier the bundle does not
// list contributes NO likelihood — the signed bundle is the sole source of
// fusion parameters at the edge, and a hardcoded per-kind default is exactly
// the "edge-invented" the struct comment above forbids. It is not silently
// discarded either: the unknown voter is counted in Cached for accounting.
// The adjudicator's calibrated per-kind fallback is legitimate ONLY on the
// certification path, where no bundle exists, and any fusion that consumed a
// fallback row is at best BOOTSTRAPPING (D-T), never CERTIFIED.
//
// DECISION D-AB (lead, binding). MEMBERSHIP GATES COVERAGE, NOT ONLY
// LIKELIHOOD. The D1 evidence-coverage count is incremented ONLY for votes
// that survive the membership filter — a verifier the bundle does not list,
// or lists as quarantined, contributes neither a likelihood term nor a unit
// of coverage. Both implementations independently took the permissive reading
// (count first, filter second), and the referee generator replicated it, so
// the conformance family ratified the bug instead of catching it. Measured
// consequence: a task whose only LISTED verifier abstains answers
// ALLOW/REFUSED at coverage 0; adding one vote from an UNLISTED verifier
// turns it into a BLOCK whose posterior is provably unchanged — an unknown
// party unlocking a block while contributing zero evidence. Coverage is the
// difference between ALLOW and BLOCK, so it is exactly the quantity D-X's
// principle must govern: the signed bundle is the sole source of truth about
// who counts. D-X fixed the likelihood and was silent on coverage; this
// closes it. Quarantined is not a weaker unknown — it is an explicit
// distrust, and must be at least as excluded.
//
// DECISION D-AC (lead, binding). D-V's literal "bit-identical" requirement is
// WITHDRAWN and replaced, because it is not achievable: Go's pure-Go
// math.Log/math.Exp and CPython's platform libm differ by up to 1 ULP, and
// 8 of 17 fusion vectors were measured differing in the last bit. Shipping
// our own transcendentals to close a 2.2e-16 gap is not a cost this buys.
// The binding requirement is now TWO clauses:
//   (a) posteriors agree within 1e-12 absolute — the referee tolerance the
//       conformance family already enforces per-language; and
//   (b) the DERIVED VERDICT is identical, tested BETWEEN the two languages
//       and not merely between each language and a manifest. Clause (b) had
//       no test at all, which is why the divergence shipped.
// (b) does not follow from (a) for free: the Chow comparison is a threshold
// at exactly eta = 1/3, and a 1-ULP difference straddles it. Three of 57
// swept constructions flipped — with ROUND NUMBERS (priors 0.4, c 0.3), not
// adversarial ones — the edge answering VIOLATED where the cloud answered
// REFUSED, i.e. the fail-closed divergence D-V exists to kill. Therefore both
// implementations round the posterior before the Chow comparison, by exactly
// this rule so that no third reading is possible:
//     p_cmp[i] = floor(p[i] * 1e12 + 0.5) / 1e12
// half-away-from-zero on a non-negative value, NOT the language's native
// round() (Python's is banker's, Go's is not). The REPORTED posterior on the
// wire stays unrounded; only the comparison is quantised. This does not make
// divergence impossible — it makes it require the two values to straddle a
// 1e-12 grid line rather than a single ULP — and clause (b)'s cross-language
// test is the backstop that would catch the residue.
//
// DECISION D-AK (lead, binding, 2026-08-30). D-AC's QUANTISATION IS WITHDRAWN.
// It was treating the symptom, and its own closing sentence conceded as much.
// A pre-release review swept the residue D-AC predicted and found it: of 27
// constructions built to sit on the grid line, EIGHT flipped verdict, in both
// directions, one of them a single verifier with priors [0.4,0.4,0.1,0.1]. All
// 21 frozen fusion vectors sit off that set, so clause (b) — the backstop —
// was green throughout. A backstop that cannot see the failure it was posted
// to catch is the decorative-control disease in test form.
//
// Rounding cannot fix this, and neither can the obvious repair of rounding to
// an INTEGER count and comparing in int64: the integer is still derived from
// the transcendental, so a 1-ULP difference in p still lands n on either side
// of the boundary. Every variant of "round, then compare" only relocates the
// straddle set.
//
// THE ROOT CAUSE IS THE TRANSCENDENTALS, AND THEY ARE REMOVABLE. IEEE-754
// mandates correctly-rounded results for + - * / and sqrt; it mandates nothing
// for exp and log. Those four operations are therefore bit-identical across Go
// and CPython on identical inputs in identical order, and exp/log are the only
// reason this fusion is not. Log-space buys underflow headroom and nothing
// else here. So:
//
//   1. Fuse by DIRECT MULTIPLICATION of likelihoods — no Log, no Exp anywhere
//      on the verdict path.
//   2. Prevent underflow EXACTLY: whenever all four class masses fall below
//      2^-512, multiply all four by 2^512. Scaling by a power of two is exact
//      in IEEE-754 (it shifts the exponent, touching no mantissa bit) and it
//      cancels in the normalisation, so determinism is preserved with zero
//      error introduced. This is what log-space was actually protecting, and
//      it protects it without leaving the exactly-rounded operations.
//   3. Compare by CROSS-MULTIPLICATION, never division: the Chow branch is
//      u_S * R <= A * total, not u_S/total <= A/R.
//   4. Go only: the spec permits fusing x*y+z into an FMA, which would make Go
//      disagree with itself across architectures. Every intermediate on this
//      path is bound through an explicit float64(...) conversion, which the Go
//      spec requires to round. A test asserting a known product must be part
//      of the fix, because this hazard is invisible on amd64.
//   5. SUMMATION ORDER IS FIXED, not only product order. `total` is a sum of
//      four doubles and + is correctly rounded but NOT associative, so the
//      normaliser is accumulated in class-index order [satisfied, violated,
//      refused, error] in both implementations. Clause 1 without clause 5 is
//      the same defect one operator over.
//
// Two properties that look like exceptions and are not. Subnormals: a class
// mass may still lose precision when a SIBLING mass is large enough to hold
// the rescale off. That costs accuracy on a posterior already ~1e-170 from
// the leader — and it costs no DETERMINISM, because subnormal multiplication
// and its rounding are IEEE-mandated too. We require identity, not accuracy,
// and identity survives where accuracy does not. Exact zero: a zero
// likelihood annihilates its class and stays annihilated through any rescale,
// which is the arithmetically correct reading of "this verifier assigns this
// class probability zero" and matches what log-space encoded as -inf.
//
// Bit-identity — D-V's original requirement — is thereby RESTORED, by deleting
// the cause rather than rounding around it. Clause (a)'s 1e-12 tolerance and
// clause (b)'s cross-language verdict test both stay, now as regression
// guards on a property that holds exactly rather than as the primary defence.
// The reported posterior is the same bit-identical value; there is no longer a
// "comparison" copy distinct from the wire copy.
//
// Iteration order over correlation groups is SORTED BY GROUP ID, never map
// order: float products are not associative, and 06 §3's cross-implementation
// conformance is exact under D-AK.
//
// DECISION D-AO (lead, binding, 2026-08-30). AMENDS D-AK CLAUSES 2, 3 AND 5.
// Wave D implemented D-AK and a serial review then broke it. Three amendments,
// each from a demonstration, not an argument.
//
// (a) CLAUSE 5 WAS ONE LEVEL TOO SHALLOW, AND THIS IS THE PASS'S REAL LESSON.
//     Clause 5 fixed the ORDER of the summation. The defect was the
//     ALGORITHM. CPython's built-in sum() over floats has used Neumaier
//     compensated summation since 3.12; Go's fold is plain sequential. Both
//     visit the same four elements in the same order and disagree by an ulp:
//     sum([0.1]*10) is exactly 1.0, the fold is 0x1.fffffffffffffp-1. On the
//     failing vector that single ulp in `total` IS the verdict. Seven of 25
//     vectors diverged; one flipped.
//     IEEE-754 pins BINARY +. It says nothing about an n-ary reduction, and a
//     language's standard-library reduction is free to compensate — CPython's
//     started to, in a point release. THE RULE: only IEEE-754-mandated binary
//     operations may appear on the verdict path. No library reduction, on
//     either leg, ever — `sum()`, `math.fsum`, `numpy.sum`, `slices` helpers
//     are all banned here by name. Accumulate in an explicit loop.
//     Note what happened: D-AK removed exp/log because they are unmandated,
//     and left in place a reduction that is unmandated for exactly the same
//     reason. The audit was run against a list of functions instead of
//     against the property, so it caught the members it had thought of.
//
// (b) CLAUSE 2's FIXED 2^-512 THRESHOLD IS INSUFFICIENT; RESCALE FROM THE
//     DATA. With max(u) pinned near 2^-512 only ~154 decimal orders remain
//     above the smallest subnormal, so a single 1e-300 likelihood exhausts
//     the headroom and the mass underflows to hard zero — demonstrated on the
//     `extreme_log_scores` vector under every placement of the fixed pair.
//     Renormalise before each clique multiply by the leader's own exponent:
//     frexp(max(u)) then ldexp(x, -exp2), which Go and CPython both provide
//     with identical semantics. This is the same exact mechanism — a
//     power-of-two shift, no mantissa bit touched, cancelling in both the
//     normalisation and the cross-multiplied comparison — with the shift
//     taken from the data instead of guessed in advance. Clause 2's INTENT
//     survives; its constant does not.
//
// (c) CLAUSE 3's JUSTIFICATION WAS WRONG, THOUGH ITS CONCLUSION STANDS.
//     "Never divide ⇒ exact" overstates: IEEE-754 mandates correct rounding
//     for ÷ too, so division was never the determinism risk — both forms are
//     bit-portable. The real difference is accuracy, and it is
//     threshold-dependent. Measured over 300k boundary samples against an
//     exact-rational oracle: at the satisfied threshold cross-multiplication
//     is wrong 35,616 times against division's 57,384 (division must first
//     round the DERIVED constant 1 − A/D); at the violated threshold with D4
//     costs division is wrong 0 times against cross-multiplication's 22,682
//     (there A/R is exactly representable and division rounds once, the
//     cross-product twice). Cross-multiplication remains the rule — it needs
//     no derived constant, it is scale-invariant under (b)'s rescale, and it
//     wins the case that recurs — but it is chosen on accuracy, not on
//     determinism, and `u_s * R` rounds like anything else.
//
// DECISION D-AP (lead, binding, 2026-08-30). BIT-IDENTITY GETS A CONTROL OR
// STOPS BEING CLAIMED. The fusion family compared each leg to the manifest
// within a 1e-12 tolerance — roughly four orders looser than an ulp at these
// magnitudes — and compared the two legs only by VERDICT NAME. So five of the
// six live cross-language divergences were green, and the sixth was red only
// because it happened to cross a Chow boundary. The claim was true by
// assertion and never by test: the sixteenth pass's disease, in the one
// family written to cure it.
// `conformance_crosslang.sh` now dumps BOTH legs' posteriors as hex and diffs
// them. Cross-leg equality is asserted between the legs, never against the
// manifest — which resolves the tension Wave D hit head-on: an exact-rational
// oracle rounds ONCE and any float implementation rounds per multiply, so an
// independent generator and a bit-comparable manifest are mutually exclusive.
// We keep the independent generator and move the bit-assertion to where both
// operands are floats.
//
// DECISION D-AQ (lead, binding, 2026-08-30). AT A CONSTRUCTED BOUNDARY, THE
// EXACT-RATIONAL ORACLE IS NOT AUTHORITATIVE ON THE VERDICT. A vector built
// to sit ON the Chow threshold can have an exact rational answer that no
// float64 evaluation reaches — `chow_boundary_eta_exactly_one_minus_a_over_d`
// is exactly this, and after D-AO(a) BOTH legs agree on `refused` while the
// oracle says `satisfied`. Agreement was the property under test and the
// vector was reporting it as failure.
// A generator that places a case within a few ulps of a threshold marks it
// `boundary: true`. Boundary vectors assert CROSS-LEG IDENTITY of posterior
// and verdict, and do not assert the verdict against the rational oracle.
// Interior vectors assert both. A family that cannot tell "the two legs
// disagree" from "float cannot represent the exact answer here" is reporting
// one number for two different failures.
//
// Output posterior[4] is the normalised mass vector — mass[i] / total under
// D-AK, NOT softmax(score); there is no score and no exp on this path any
// more. Ordered [satisfied, violated, refused, error].
func (f *Fuser) Fuse(taskID TaskID, votes []AnchorVote) m1pv1.VerdictEvent

// Cache is what gates read. A lock-free snapshot: writers publish via
// atomic.Pointer swap; readers never block and never trigger computation.
type Cache struct{ p atomic.Pointer[map[TaskID]Cached] }

type Cached struct {
    Verdict   m1pv1.VerdictEvent // stage: PROVISIONAL (or REVISED, superseding)
    Knee      KneeState          // p̂_LCB(n), V(task), c(n) under the bundle cost_basis
    Blocks    BlockCounters      // consecutive-per-task and hourly counters
    ComputedAt time.Time
}

// Reader is the ONLY interface the fabric's GateQuery handler receives.
// It has no method that computes anything.
type Reader interface{ Get(TaskID) (Cached, bool) }
```

**The hard rule, mechanically enforced:** the stop-gate reads a cached `VerdictEvent{PROVISIONAL}` and **never computes**. The fabric server's `GateQuery` handler is constructed with a `verdict.Reader`, and `Fuser` is unexported beyond the recompute goroutine — a future engineer cannot wire fusion into the gate path without a visible API change. The `GateQuery`→`GateVerdict` round-trip is a map lookup: **≤5 ms @ the 08 §4.2 budget, asserted in the 12 gate-latency test**.

**Fast/slow split:** fast anchors refresh the cache on the PostToolUse debounce; slow anchors (opt-in tests) complete asynchronously and publish `VerdictEvent{REVISED}` — the cache entry is superseded and a next-turn hook-context correction is queued for the shim (08 §5.1 PostToolUse row). A gate that fired on the provisional verdict before the revision is correct by contract, not a bug: that is what PROVISIONAL means, and the REVISED event repairs the ledger.

**Knee evaluation at the gate:** stop when `p̂_LCB(n)·V(task) ≤ c(n)`, `c(n)` under the bundle's `cost_basis` (`usd` | `quota`). Evaluated at cache-publish time and stored in `KneeState`, so the gate read stays a lookup. Local hard caps are checked in the gate handler itself, before the cache read and after the off-check: `MARK1_DISABLE=1`/`mark1 off` first (invariant 2), then ≤3 consecutive blocks per task, then the hourly block ceiling (`M1E-5002` ⇒ allow).

> **DECISION D-Y (lead, binding) — what resets the consecutive-block streak.**
> The streak resets on **any cache publish for that task** (new evidence, whether `PROVISIONAL` refresh or `REVISED`), and on task close. It does **not** reset on an allow. "Consecutive" means consecutive blocks *on the same evidence*: three blocks in a row without the agent producing anything that moves the verdict is a stuck loop the cap exists to break, and the moment new evidence lands it is no longer the same situation. Recorded because the cap short-circuits **before** the cache read (the order above is normative and unchanged), so an allow can never carry a reset — without a publish-side reset the cap degrades to "three blocks per task per daemon lifetime" and per-task blocking is permanently dead after the third.
>
> **D-Y(b) — `n` below the knee table's first row.** `Stop` is **false**, always. You cannot be past the knee before the first attempt exists, and clamping up to row 1 evaluates attempt-1 economics for attempt 0. Absent rows are not conservative defaults; they are absent.
>
> **D-Y(c) — exactly at the knee.** The inequality is `≤`, so `p̂_LCB(n)·V(task) == c(n)` is **at the knee and stops**: the expected value of one more attempt equals its cost, and a governor that lets a coin-flip attempt run is a governor that runs forever on a flat curve. The gate therefore ALLOWS the Stop hook (the agent may stop) and the ladder evaluator STAYS (no escalation on a verdict the economics already closed) — `TestStopGateAllowsAtTheKnee`, `TestGateKneeStops`, `ladder_test.go` `three: violated at the knee stays`. Posture: fail-open for availability (an unevaluable knee never blocks), fail-static for the table (last-known-good rows), never fail-closed.
>
> **D-Y(c) — `deadline_ms == 0`.** Proto3 cannot distinguish "zero" from "unset", so `0` means **unspecified**, never "already expired". The daemon applies its own 5 ms cache-read budget and answers normally. Reading 0 as expired silently disables gating for any writer that forgets the field while accounting the result as timeouts — a product feature quietly off, with telemetry that says everything is fine.

**Failure posture: fail-static then fail-open.** No bundle matrices (never received, or `max_age` exceeded) ⇒ conservative built-ins: gates answer allow, verdicts flagged `stale_cert` (`M1E-3006`). Cache miss for a task ⇒ `GateVerdict{ALLOW}` + `Dropped{gate_timeout}` accounting (`M1E-5001`). A verdict subsystem failure can never block a developer.

### 2.4 `spool` — the single writer

Binary layout, ledger format, bounds, and the six-step unclean-shutdown recovery are **07 §6**, cited not restated. This section fixes the Go internals around those bytes.

```go
package spool

// New is called exactly once, in cmd/main.go, and the returned writer handle
// is moved into capture.Admitter. That is the single-writer discipline: not a
// convention, a possession. The reader side (uplink) gets a separate
// read-only handle over sealed bytes.
func New(dir string, caps Caps) (w *Writer, r *Reader, err error)

type Writer struct { /* owned by exactly one goroutine; in via bounded chan */ }
type Class uint8   // Billing = 1, Diagnostic = 2 — mirrors record_id[16] (07 §6)

// Append semantics by class:
//   Billing:    blocks when the spool is at cap — backpressure, never shed.
//   Diagnostic: returns ErrFull when at cap — caller sheds, Dropped{SPOOL_SHED}.
func (w *Writer) Append(rec Record) error

type Reader struct { /* ack cursor advance; whole-file ack-then-delete */ }
func (r *Reader) Next(max int, maxBytes int64) (BatchView, error) // zero-copy view over mmap'd segments
func (r *Reader) Ack(through Cursor) error                        // advances ledger ack slot; deletes fully-acked segments
```

- **Single-writer goroutine** consumes the capture channel, appends, and runs the adaptive fsync loop (250 ms with billing-grade pending, 500 ms diagnostics-only — 07 §6). Group commit: many appends per fsync; the fsync is off the admission path, which is what keeps `Admit` cheap.
- **`Dropped{}` accounting** is an atomic counter table keyed `(reason, category)` in this package, incremented by every shed, CRC loss, and local quarantine anywhere in `mark1d`; `uplink` drains it into each batch's `dropped[]` (07 §2 `Batch.dropped`). Silence is the one failure the ledger can't price, so the counters have no reset path except a successful drain.
- **Caps:** ~2 GiB spool, 95%-disk hard stop @ a pre-append statfs check; at the hard stop capture degrades and `CoverageTransition{BYPASS, reason_code:"disk_hard_stop"}` is emitted (07 §6). Mark 1 never gets to be why a laptop's disk fills.
- **Drain barriers:** `SessionEnd` and daemon shutdown force fsync + upload attempt (`Flush{}`/`FlushAck` on the fabric, 08 §4.2), regardless of cadence.

### 2.5 `uplink` — batching, zstd, the retry automaton

```go
package uplink

// Batcher composes batches from the spool read cursor: ≤32 MiB decoded
// (08 §2.1), zstd level 3, per-category composition respecting the last
// M1P-Rate-Limits header. The spool IS the queue — no second in-memory copy.
type Batcher struct{ /* ... */ }

// Sender runs the 08 §2.5 automaton per batch. States:
//   IDLE → SENDING → (2xx) ACK → spool.Ack
//                  → (net/5xx/429) BACKOFF(n) → SENDING   n ≤ ~10
//                  → (exhausted)   PARKED                  re-queued on restart,
//                                                          network-change, every 6 h
//                  → (4xx, except 401-with-refresh) QUARANTINED
type Sender struct{ /* ... */ }
```

Behavior is 08 §2.4/§2.5 verbatim; the edge-side specifics worth fixing:

- **Park** leaves bytes in the spool (they are already durable there); PARKED is uploader state, not data state. Billing-grade classes therefore survive arbitrarily long outages at the cost of spool space, and the block-on-full policy converts a *very* long outage into visible backpressure rather than loss.
- **Quarantine** moves the batch out of the spool to `~/.omium/mark1/quarantine/` (0600, encrypted with the device spill key §5.4), emits `Dropped{reason: quarantined}` in the next successful batch, surfaces in `mark1 status`, and is never auto-retried. WHY out of the spool: a poison batch must not head-of-line-block billing-grade drainage.
- **401** triggers `identity.Refresh()` then one re-send (the sole retryable 4xx); **413** splits deterministically and re-sends halves; **409** quarantines with a spool-corruption warning (`M1E-2003`).
- The sender is one goroutine; batching is one goroutine. Upload order follows spool order (billing-grade never overtaken by diagnostics from a later segment; within a segment, record order).

### 2.6 `policy` — the Go parallel decoder, fail-static

```go
package policy

// Client: jittered 5-min ETag poll (correctness path) + SSE listener
// (advisory latency path, 08 §3.2). A dead stream degrades latency, never
// correctness.
type Client struct{ /* ... */ }

// Decode is the Go PARALLEL decoder of PolicyBundle v1, validated
// bit-identical in verdict against the Rust mark1-policy crate by shared
// conformance vectors in CI (a Go/Rust disagreement on any vector fails the
// build). Verification order: section-split signatures → monotonic seq →
// transparency-log inclusion proof → schema decode. ANY command string in
// verify ⇒ the whole bundle rejects (M1E-3005) — invalid is a security event,
// unknown is a compatibility event (08 §10.3 ladder, applied per section).
func Decode(raw []byte, keys KeyManifest, lastSeq uint64) (*Bundle, RejectCode)

// Current is the read side: an atomic.Pointer[Bundle] swap on apply.
// Consumers (verdict, anchors, adapters/agent_maps, gates) load it lock-free;
// no consumer ever blocks on a policy fetch.
func Current() *Bundle
```

- **Fail-static:** last-known-good persisted at `~/.omium/mark1/bundle/` (bytes + seq + applied-at); control plane gone ⇒ run it indefinitely. Past `max_age` ⇒ conservative built-ins compiled into the binary (single-rung ladder, knee=1, detect-only redaction, gates open, verdicts flagged `stale_cert`) — `M1E-3006`, surfaced as `stale: true` in `mark1 status`.
- **ACK** per 08 §3.2, including `sections_skipped` for the skip-and-retain ladder; rollback is previous content under a higher seq, so no seq exception exists.
- **Gate-direction constraint** enforced at decode: a `gates` section may downgrade closed→open only; any fail-closed tightening requires the local on-disk tenant opt-in artifact, else the section is rejected.

### 2.7 `coverage` — attributable windows

```go
package coverage

// Transition is the SINGLE chokepoint: any state change anywhere in mark1d
// that reduces or restores capture MUST route through it. That is the whole
// design — coverage integrity is a property of having exactly one door.
func Transition(kind m1pv1.CoverageKind, workspaceID []byte, reason string) error

// Tracker holds open windows (start, kind, reason); Close stamps duration_ms.
// Open windows survive restart (persisted 0600 JSON) so a crash inside a
// bypass window still closes it attributably on the next boot.
type Tracker struct{ /* ... */ }
```

Callers and their reason codes: `mark1 enable`/`off` (`"user_enable"`, `"mark1_off"`), spool hard stop (`"disk_hard_stop"`), proxy auto-bypass and supervision failure (`"proxy_bypass"`, `"proxy_failed"`), adapter version drop (`"unsupported_agent_version"`), tailer retention gap (`"transcript_retention_gap"`), and the desktop per-agent pause/resume (`"agent_pause"`, `"agent_resume"` — `POST /v1/agents/{name}/pause|resume`; the wire carries no agent field, so the agent name lives in the local journal line and the transition lands device-wide, exactly as `mark1 off --all` does). Nine codes; `m1_043.reason` mirrors them verbatim without a CHECK so a tenth is a doc change, not a migration. Every transition is a per-event-receipted `CoverageTransition` (contract C13) — that receipting is what lets TVO reports carry an honest coverage band and refuse guarantee-grade issuance below the floor (`M1E-5004`). The edge's duty is narrow and total: **no capture-affecting state change without a transition event.** The band itself is computed server-side.

### 2.8 `supervise` — children (§1.2 fixed here as API)

```go
package supervise

type Child struct {
    Name     string
    Start    func(ctx context.Context) (*exec.Cmd, error)
    Backoff  Backoff        // base 500 ms, ×2, cap 60 s, decorrelated jitter
    Breaker  Breaker        // >5 restarts / 60 s ⇒ FAILED
    OnFailed func()         // e.g. proxy: revert base-URL fragment + coverage.Transition
    Adopt    AdoptSpec      // pidfile path + expected binary BLAKE3 — restart-survivable
}

type Supervisor struct{ /* one goroutine per child; owns child state exclusively */ }
```

Adoption on `mark1d` restart: read pidfile, verify the process's binary hash and start time; match ⇒ adopt (cortexd keeps its warm index), mismatch ⇒ kill and respawn. `OnFailed` is where crash isolation becomes user-visible truth: a FAILED proxy reverts the agent's base-URL fragment (agent talks direct — developer unblocked) and receipts the bypass; a FAILED cortexd only flips MCP to refusals and marks anchor integrity incomplete.

### 2.9 `identity` — key custody, tokens, revocation

```go
package identity

// DeviceKey: Ed25519 origin-signing key. Custody ladder, best first:
//   macOS Keychain → Windows TPM via CNG KSP (DPAPI fallback) →
//   Linux secret-service/TPM2 where present → 0600 file under
//   ~/.omium/mark1/ (the floor, never skipped-below).
// The private key never leaves custody; Sign() is the only operation.
type DeviceKey interface {
    Sign(domainPrefixed []byte) ([]byte, error) // "mark1-label-v1\0" prefix applied by caller (mark1-receipt discipline)
    KeyID() string                              // "ed25519:" + sha256(pub)[:16]
}

// TokenSource: device token (≤24 h), refreshed at 80% of expires_in with
// jitter via the proof-of-possession flow (08 §3.1). Refresh failure NEVER
// stops capture — tokens gate egress only. 30 d of failures ⇒ DORMANT
// (bookkeeping); success resumes ACTIVE.
type TokenSource interface{ Token(ctx context.Context) (string, error) }

// Revocation handling — the fail-closed class. On any M1E-1003:
//   1. uplink stops (egress closed), spool retained (data outlives identity;
//      the old chain stays attributable to the old device_id),
//   2. the synced memory-artifact cache is PURGED (secret-bearing delivery is
//      fail-closed on revocation, spec §6.3),
//   3. capture continues local-only; `mark1 status` surfaces re-enrollment.
func OnRevoked()
```

Also here: the per-tenant HMAC key material for digests/`idem_key` (delivered at enrollment as 08 §3.1's `tenant_root_hex` on the ACTIVE poll body and every PoP refresh; `mark1 enroll` persists it with the device identity in `<state>/enrollment.json` (08 §7.1), which `mark1d` reads at boot — the `--tenant-salt`, `--device-token`, `--tenant-id`, `--device-id`, `--ingest-url` flags are dev-seam overrides of that document, and a daemon with neither refuses to start naming `mark1 enroll`; custody same ladder) and the X25519 device spill keypair (§5.4) — the private half exists only inside `mark1d`, which is why the shim and proxy can encrypt spill they cannot read back.

### 2.10 `adapters/*` — seven agents, one interface

```go
package adapters

type Adapter interface {
    Name() string                       // "claudecode" | "codex" | ...
    Detect() (Detection, error)         // installed? version? regime?
    Provision(ws Workspace, m agentmaps.Maps) error // via 08 §8 fragments ONLY
    Surfaces() []CaptureSurface         // hook registration, transcript globs, artifact dirs
}

type Detection struct {
    Installed bool
    Version   string // runtime-sniffed; selects the agent_maps field map
    Regime    Regime // Subscription | APIKey — drives proxy eligibility (the guard's Detect()==apikey input)
}
```

Rules, all from 08 §5 and binding on every adapter: field maps live in `agent_maps` bundle data, never code; a sniffed version with no map ⇒ the adapter goes inert and emits `Dropped{UNSUPPORTED_AGENT_VERSION}` + a coverage bypass — it never guesses a field; an adapter slot opens only when its go/no-go spike fixture lands in `conformance/`. Phase order: claudecode (1), codex (2), gemini (3), opencode (4), copilot + cursor (5), crush (roadmap). Only `claudecode` contains real logic at Phase 1 — including the transcript-tail contract of 08 §5.1 wired into `tailers`.

### 2.11 `obs` — self-observation without OTel

Estate-convention `obs` package: `slog` structured logging to a rotating local file (0600), atomic counter/gauge tables read by `mark1 status --json`, and nothing exported over the network as telemetry — the product's operational signals travel as `Dropped{}` events and `CoverageTransition`s in the ledger itself (11 owns the catalog). No Prometheus endpoint on the edge: a laptop daemon exposing a metrics port is attack surface with no scraper.

---

## 3. `mark1-proxy` (Rust) — built in Phase 3; gateway mode in Phase 5

tokio + hyper 1 + tower + rustls. API-key traffic **only** — the subscription regime never touches this binary; the guard is what makes that structural.

```
rust/mark1-proxy/src/
├── main.rs          # runtime init; RLIMIT_CORE=0 + PR_SET_DUMPABLE=0 set BEFORE any
│                    # credential can be loaded; mode select (sidecar|gateway)
├── guard/
│   └── provenance.rs  # the OAuth non-interception control — §3.1, in full
├── router/          # listener setup; sidecar loopback rules vs gateway mTLS
├── request/         # header handling, M1-Cred-Ref extraction, redact-in-transit
│                    # (default off), model rewrite (RouteDecision, WIRE_ENFORCED)
├── upstream/        # pools keyed (upstream, credential-identity); rustls; hostname allow-list
├── response/        # bytes-forward return path; subscription-marker tripwire scan
└── tee/             # explicit-field-allow-list observation → mark1-frames → fabric; spill ring
```

### 3.1 The provenance guard, in full

The request path, in order, before a single byte goes upstream:

1. **Off-check.** `MARK1_DISABLE=1` / off-marker ⇒ the proxy is a pure pass-through this request… except it is not even that: `mark1 off` detaches the proxy (reverts the base-URL fragment), so in practice traffic no longer arrives. The in-binary check exists for the race window.
2. **Enrollment naming.** A request names its enrollment either by `M1-Cred-Ref: <ref-id>` (injected by the provisioned agent config fragment) or — for agents with no custom-header surface, e.g. Copilot BYOK (D-EI, 2026-09-16) — by the HMAC fingerprint of the credential it carries, computed only after the shape gate and compared constant-time against every enrollment (lowest matching ref binds, deterministically). A header naming an unknown ref, or a header-free credential matching no enrollment ⇒ `403 M1E-8001`. Only a credential `mark1d` provisioned **after `Detect()==apikey`** can match.
3. **HMAC fingerprint match to enrollment.** The guard holds a registry `ref-id → HMAC-SHA256 fingerprint` recorded at provisioning. It extracts the actual credential from the request (`x-api-key` / `Authorization`), computes the HMAC under the device-local guard key, and compares constant-time to the enrollment fingerprint. Unknown ref, mismatch, or any parse ambiguity ⇒ **`403 M1E-8001`**, and a `GuardDecision{REFUSED, reason_code:"unprovisioned_cred"}` is emitted with its `sample_rate` — refusal is provable, not asserted.

    > **DECISION D-AJ (lead, binding, 2026-08-30) — refusals are never sampled; `sample_rate = 1.0` on the REFUSED arm, always.** No document stated a rate for either arm, and "sampled" appeared here unqualified. The asymmetry is not a tuning preference: **the refusal record IS the evidence for the legal claim.** A guard that refuses OAuth traffic 100% of the time but records 1% of those refusals can demonstrate a *policy* and never a *practice* — and the one refusal that matters in a dispute is precisely the one sampling dropped. Volume is not an argument here either, because a refusal is by construction rare: the provisioned agent config always carries a valid `M1-Cred-Ref`, so a refusal means something is already wrong. The FORWARD arm is the high-volume one and stays sampled — bundle-tunable, default `0.01` — because it is ordinary product telemetry rather than proof of a promise. The bundle may raise the forward rate and **may not lower the refusal rate**; a `verify` section that tries fails decode, the same way it cannot name a command string.
4. **No override path is compiled into the binary.** There is no env var, config key, CLI flag, bundle section, or debug build feature that causes forwarding of an unprovisioned credential. The negative test in 12 proves no code path forwards one; a grep gate rejects any `cfg`/flag whose name matches an override pattern in this crate. WHY this severity: the alternative — an "operator escape hatch" — converts a legal guarantee into a policy, and policies get overridden under deadline pressure.
5. **Shape-inspection tripwire (secondary signal).** A classifier over credential shape (API-key grammar vs OAuth token grammar). A provisioned credential that classifies OAuth-shaped ⇒ refuse + P1 (the provisioning path has a bug). The weekly token-shape canary in CI fails on any classifier miss — the classifier is allowed to age only loudly.
6. **Upstream-subscription-marker kill path (tertiary, on the response).** `response/` scans upstream response headers/shape for subscription-billing markers. A hit means an OAuth credential got through everything — the P0 case — and triggers, in order: **session kill** (client connection closed, all further requests for that session refused), **config rollback** (`mark1d` instructed over the fabric to revert the base-URL fragment immediately, so the very next agent request bypasses the proxy entirely), and a **per-event-receipted `oauth_contamination` event** (`M1E-8002`, one of C13's per-event receipt kinds). Nothing about this path is rate-limited or sampled.

> **DECISION D-AI (lead, binding, 2026-08-30) — the P0 kill path had no wire, and gets `ContaminationAlert = 10`.** Step 6 and §9.4's state machine both say `mark1d` is "instructed over the fabric" to revert the base-URL fragment. `FabricFrame` (`proto/m1p/v1/fabric.proto`) has exactly seven arms — Event, Hello, HelloAck, GateQuery, GateVerdict, Flush, FlushAck — and `internal/fabric/session.go` hard-codes that set, rejecting anything else. **The single most severe action the proxy can take is the one action it has no way to express.** This is the D-N hole class a third time: a behaviour named in prose by two documents and carried by no frozen surface.
>
> The arm is **one-way, and the proxy never awaits a reply.** A P0 kill that blocks on a daemon round-trip is a P0 kill that a hung daemon can veto. The proxy closes the session and refuses every subsequent request for it on its own authority; the frame is notification, not permission. If `mark1d` is unreachable the fragment stays pointed at the proxy — which now refuses everything for that session, so the failure direction is closed, and the `oauth_contamination` receipt spills locally for the next drain rather than being lost.
>
> **Oneof tag allocation, recorded here once so two build rows cannot collide:** `8 = ContextQuery`, `9 = ContextReply` (D-AE), `10 = ContaminationAlert` (this ruling). All three are additive and land in a single regen when the Phase 3/4 rows build — no mid-wave proto edit.
>
> **Refuted, so it is not raised a fourth time:** `Hello.component` being a free `string` rather than an enum is **not** an oversight. `fabric.proto` states the reason in place — "Free text, not an enum: a new writer must be able to introduce itself before the daemon's release knows its name." `"mark1-proxy"` is accepted by decision, not by omission.

### 3.2 Hot path and the tee

**Bytes-forward:** the client's request body and the upstream's response body are streamed chunk-by-chunk with no full-message buffering; header edits are the minimum set (Host, credential pass-through, `M1-Cred-Ref` stripped before upstream). Model rewrite (the one legitimate mutation, producing `RouteDecision{WIRE_ENFORCED}`) parses only the JSON prefix needed to rewrite `"model"`, streams the rest.

**Tee-on-clone, from an explicit field allow-list:** the tee task is handed a struct built field-by-field — method, path, requested/served model, byte counts, timings, status — plus response chunks via a bounded channel for `mark1-frames` parsing. **Never a request clone**: `Request::clone()` (or any wholesale copy) would carry headers, and headers carry credentials; the allow-list is the compile-visible proof that the tee cannot see a secret.

**The tee provably cannot hold a client write:** the client-facing forward loop `try_send`s chunks to the tee channel and **never awaits it**. Channel full ⇒ the chunk is not teed, parsing degrades for that stream (`mark1-frames` reports `ParseDegraded`), transport-level `ModelRequest/Response` counters still emit, and the client byte stream proceeds untouched. The 12 chaos suite (upstream stall, mid-stream reset, slow client) asserts zero client-visible deltas with the tee saturated.

> **DECISION D-AH (lead, binding, 2026-08-30) — the tee channel is bounded in BYTES, not in slots.** This paragraph and §9's backpressure table both read "cap 1024 × 64 KiB", which is **64 MiB against this component's ≤35 MB RSS budget** (§3.4). The two numbers cannot both be honoured, and the slot-denominated one is the wrong shape regardless.
>
> Note what does *not* fix it: making the channel carry refcounted `Bytes` handles instead of copies. Handles are O(1) to clone and cost ~16 bytes each, so the slot array becomes free — but the handles keep the underlying buffers **alive**, and the retained bytes were always the budget, never the slot array. Zero-copy removes a duplicate; it does not remove retention. A stalled tee holding 1024 handles to 64 KiB chunks pins 64 MiB just as surely as a copying one.
>
> **The bound is therefore `TEE_INFLIGHT_MAX = 8 MiB` of retained chunk bytes, admission-tested per chunk: `try_send` fails when the chunk would carry in-flight bytes past the ceiling, and the chunk is dropped exactly as an over-capacity slot would be.** Chunk *count* becomes irrelevant, which is the point — an upstream that emits many small SSE frames and one that emits few large ones now cost the same ceiling instead of differing by three orders of magnitude. 8 MiB against 35 MB leaves the remainder for rustls buffers, pools and parser state, and it makes `bench_proxy_latency_rss` a check of an arithmetic claim rather than a hope.
>
> WHY this is a ruling and not an implementation note: a bound stated in slots is only a memory bound if every slot has a known maximum size, and nothing in the frozen docs bounds an upstream chunk. The slot form silently delegates the RSS budget to the upstream's framing choices.

### 3.3 Credential custody in the binary

- `Secret<T>` newtype: no `Debug`/`Display`/`Serialize` impls exist (compile-time — the CI grep gate rejects any derive or manual impl on it), zeroize-on-drop.
- `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0` in `main` before credential load (platform equivalents in §11.6).
- Gateway mode: credentials are **referenced from the customer's secret manager per request** — fetched, used, zeroized; never persisted, never cached beyond request scope, never written to the spill ring (the tee's allow-list already excludes them).

### 3.4 Pools, budgets, modes

- **Connection pools keyed `(upstream, credential-identity)`; no multiplexing, no identity masking.** Requests under different credentials never share a connection (not even h2 streams), so the upstream always sees the true caller identity — this is what satisfies OpenAI/Google/GitHub terms simultaneously.
- **Budgets:** `≤1 ms median added latency @ per-request self-timer (t_client_byte_in → t_upstream_byte_out), enforced as a CI bench threshold (12)`; `≤35 MB RSS @ supervise poll + CI bench`. linkerd2-proxy is the existence proof the budget is honest.
- **Sidecar vs gateway:** sidecar binds `127.0.0.1:<random high port>` with a per-boot loopback token, rejects any `Origin`, and pins upstreams to the bundle-declared hostname allow-list; gateway binds an mTLS listener on customer infra, takes fleet policy via `mark1d --fleet`, and unlocks E2 evidence. Same binary, config not code.
- **Bedrock stays observe-only until customer-held re-signing hardens:** SigV4 signs the request body, so any mutation (model rewrite, redact-in-transit) invalidates the signature; re-signing requires the customer's AWS credentials at the proxy, a custody expansion that is not taken casually. Until then: forward untouched, tee/observe only, `RouteDecision` on Bedrock is never `WIRE_ENFORCED`.

### 3.5 Failure postures

| Failure | Posture |
|---|---|
| Guard cannot verify (registry unreadable, HMAC key missing) | **fail-closed** — refuse the request; legality beats availability here and only here |
| Tee/frames/spill failure | fail-open — client stream unaffected; parse degrades; `Dropped{}` accounting |
| Upstream connect failure | pass the error to the client verbatim; the proxy adds no retry (the agent owns retries) |
| Proxy crash | fail-open at the topology level — supervision reverts the fragment, traffic flows direct, `CoverageTransition{BYPASS}` receipted (§1.2) |

---

## 4. `mark1-frames` (Rust) — dialect parsers, proxy-internal

Not one of the four client crates; a proxy-internal crate, listed separately in the registry. Five dialects, **independently versioned** (each module carries its own `DIALECT_REV`, bumped on any vendor grammar change, so a Gemini format churn never forces an Anthropic parser release):

```
rust/mark1-frames/src/
├── lib.rs                     # DialectParser trait + registry
├── anthropic_sse/             # message_start/delta/stop; usage blocks incl. cache fields
├── openai_responses/
├── openai_chat/
├── gemini/
└── bedrock_eventstream/       # AWS event-stream binary framing (observe-only upstream, §3.4)
```

```rust
pub trait DialectParser {
    /// Feed a teed chunk. Returns zero or more typed wire observations
    /// (ModelRequest/ModelResponse/Usage inputs). NEVER sees the client
    /// stream — only the tee's clone.
    fn feed(&mut self, chunk: &[u8]) -> Result<Vec<WireObservation>, ParseDegraded>;
    fn finish(&mut self) -> Result<Vec<WireObservation>, ParseDegraded>;
    fn dialect_rev(&self) -> &'static str;
}

/// ParseDegraded is NOT an error the request path can see.
pub struct ParseDegraded { pub at_byte: u64, pub reason: DegradeReason }
```

**The parse-tee contract:** parsers consume only the tee clone (§3.2); a parse failure degrades that stream to opaque passthrough — the client's bytes were never dependent on the parser, so "degrades" means *observation* narrows to transport-level counters (`ModelRequest`/`ModelResponse` still emit with sizes/timings/status; wire `Usage` for that response is lost and accounted via `Dropped{}`). In the common deployment the transcript tailer still captures usage — `idem_key` collapses the overlap, so the fallback can never double-bill (07 §7). **A parse failure never affects the client** is a theorem of the topology, not a promise of the parser.

**Golden-transcript conformance obligation:** every dialect ships recorded transcripts in `conformance/` per pinned vendor version; CI asserts (a) byte-exact passthrough — output bytes ≡ input bytes for the forwarded stream, and (b) parsed-observation snapshots match. A vendor format change is detected as a fixture failure, answered by a `DIALECT_REV` bump + new fixture — and until that ships, production behavior is the safe one: degrade to passthrough, count the loss.

---

## 5. `mark1-hookshim` (Rust) — one static binary, per-agent maps as data

One self-contained binary (no runtime deps) registered into every agent's hook config by the 08 §8 provisioning path. It is exec'd per hook event and must be *boring*: read stdin, map, hand off, exit 0.

```
rust/mark1-hookshim/src/
├── main.rs        # off-check FIRST; then stdin read, map, dispatch; total-deadline timer
├── maps.rs        # per-agent field maps: loaded from the daemon-materialized cache of
│                  # the bundle's agent_maps section (~/.omium/mark1/maps/<agent>.bin,
│                  # pre-compiled by mark1d so the shim parses no CBOR on the hot path)
├── emit.rs        # m1p.v1 Event construction; event_id (UUIDv7) stamped here; seq is NOT (R-4)
├── fabric.rs      # M1PL client: 100 ms connect, 250 ms write deadline (08 §4.4)
├── gate.rs        # GateQuery/GateVerdict; deadline = agent hook budget − 10 ms
└── spill.rs       # sanitized emergency spill ring — links mark1-redact
```

**Execution order, every invocation:**

1. **Off-check before everything** (`MARK1_DISABLE=1`, off-marker file): if off, exit 0 with no output and no I/O beyond the marker stat — invariant 2.
2. Read stdin JSON; select the field map for `(agent, sniffed version)`. No map ⇒ emit nothing speculative; write a `Dropped{UNSUPPORTED_AGENT_VERSION}` marker via the fabric if reachable, exit 0.
3. Map to an `m1p.v1.Event`; stamp `event_id`.
4. **Observer events (the 50 ms fire-and-forget path):** connect (≤100 ms), write frame (≤250 ms deadline), exit 0. Any failure ⇒ spill (§5.4) and exit 0. Total wall budget **≤50 ms @ the shim's own deadline timer** — the timer, not hope, is what bounds it: at 45 ms the shim abandons the fabric attempt and spills.
5. **Gate events (bounded deadlines):** send `GateQuery{deadline_ms}` where `deadline_ms` = the map's `gate.budget_ms` − `SHIM_MARGIN_MS`, i.e. **250 − 10 = 240 ms** (the shim, not the daemon, owns the agent-facing deadline — 08 §4.4). The budget is *not* the agent's configured hook timeout, which 08 §4.4 bounds only from above: a wedged daemon held to the vendor timeout costs 31.4 s per turn against 217 ms for an *absent* one, so the failure mode that matters — half-dead Mark 1, 145× worse than no Mark 1, on the hook that fires at every turn end — is created by spending the whole ceiling. 250 ms is fifty times the ≤5 ms cache read §2.3 specifies this gate to be (D-AU). Reply → the vendor-schema response (e.g. Claude Code `{"decision":"block", …}`, 08 §5.1). Timeout/unreachable ⇒ **return allow** (fail-open, `M1E-5001`) and record `Dropped{gate_timeout}` via spill.

**Cold-start budget:** ≤10 ms to first syscall-after-setup @ measured in the 12 bench — achieved by being static (no dynamic linker surprises), parsing no config (maps are pre-compiled binary, mmap-read), and initializing no runtime (no tokio; the shim is synchronous — an async runtime is startup cost with zero concurrency to spend it on).

**Daemon-unreachable: the event is not lost.** The shim appends to its **sanitized spill ring** and exits 0; `mark1d` drains the ring on the shim's next successful connect (the `Hello` handshake advertises ring non-emptiness) or on its own restart scan, admits the events through the normal capture pipeline, then truncates the ring.

### 5.4 The sanitized spill ring (shared design with the proxy's tee spill)

- Path `~/.omium/mark1/spill/hookshim.ring`, 0600, append-only ring, ≤24 h TTL with receipted expiry.
- **Sanitized:** the shim links `mark1-redact` and runs the **admit-to-upload axis in-process before any byte hits the ring** — no pre-redaction plaintext persistence exists, even in the emergency path (invariant 5). Scanner failure ⇒ the event is dropped and counted, never spilled raw.
- **Encrypted such that the writer cannot read it back:** sealed to the device X25519 spill public key; the private half lives only in `mark1d.identity` (§2.9). A compromised or debugged shim process can therefore leak at most the single in-flight event it was handed, never the ring's history.
- Ring overflow (daemon down for a very long time): v1 behavior is **stop-appending at the cap with a counted shed** — the shim appends one byte per refused entry to a `.shed` sidecar (O_APPEND, concurrent-shim safe) and the daemon's drain converts the count to `Dropped{RING_EVICTED}`, so overflow loss is accounted, never vanished. This clause originally promised oldest-diagnostic-first eviction; drop-newest-with-accounting shipped instead because in-place eviction inside a sealed append-only ring means rewriting frames the crash model assumes immutable, and the loss ledger — not the eviction order — is what the guarantee rests on. Oldest-first eviction remains the upgrade path if replay value at the tail ever proves to matter; billing-grade hook events are tiny and effectively never hit the cap inside the TTL either way.

**Per-agent JSON field maps loaded from bundle data** is the load-bearing distribution decision: when a vendor renames a hook field, the fix is an `agent_maps` bundle push reaching the fleet in minutes — not a shim release reaching it in weeks. The shim binary changes only when *semantics* change (a new gate type, a new spill rule), which is exactly the cadence a signed, SLSA-attested binary can afford.

---

## 6. `cortexd` (Rust) — per-workspace repo intelligence

```
rust/cortexd/src/
├── main.rs         # workspace root bind; session/loopback token setup
├── l0_merkle/      # notify watcher + BLAKE3 file-plane merkle tree
├── l1_tags/        # vendored tree-sitter grammars + tags queries (per-language)
├── l2_graph/       # petgraph symbol graph + personalized PageRank
├── l3_scip/        # opportunistic SCIP precision (strictly best-effort)
├── cas/            # SQLite content-addressed store of derived artifacts
├── shards/         # redb graph shards
├── map/            # budgeted ranked map assembly (budget binary search, 1–8k tokens)
├── mcp/            # MCP server over the loopback rules (08 §4.5 + §6)
├── fabric/         # M1PL client → mark1d: CortexInjection events + L0 root pushes
└── session/        # session scoping, index_clock, memory-artifact recall cache
```

### 6.1 The four layers and the incremental update path

```
notify event ──debounce 50 ms──▶ L0: BLAKE3 rehash changed files, merkle path
                                  update, root recompute            (µs–ms)
        │ changed set
        ▼
L1: re-run tree-sitter tags on changed files ONLY — CAS hit skips the parse
        │ tag deltas
        ▼
L2: petgraph delta — remove the file's nodes/edges, insert new; PPR is NOT
    eagerly recomputed: it is evaluated lazily at query time, seeded per
    query, memoized per (seed-set, index_clock)
        │
        ▼
L3: SCIP indexer scheduled opportunistically (idle, budget available); its
    output upgrades edge confidence from "tags" to "scip" (08 §6.2) and is
    always SKIPPABLE — no answer ever waits on L3
        │
        ▼
index_clock += 1; L0 root pushed to mark1d over the fabric
```

**CAS key `(path, content_hash, grammar_rev, query_rev, indexer_rev)`** — the full provenance of a derived artifact. Bumping a grammar, a tags query, or the SCIP indexer invalidates exactly the derived layers, never the content hashes; an unchanged file after a grammar bump costs one CAS probe + one re-parse, not a merkle recompute.

### 6.2 Storage layout

`~/.omium/mark1/cortex/<workspace_id>/`: `cas.sqlite` (derived artifacts, keyed as above), `graph/` redb shards, `l0.merkle` (persisted tree for warm restart). **Shards are keyed by top-level directory hash**, bounding the blast radius of one corrupt shard to one subtree — a corrupt shard is deleted and reindexed (refusals `M1E-6404` until rebuilt), never repaired in place. redb gives MVCC read transactions, so queries read a consistent snapshot while the single writer task advances.

### 6.3 Concurrency model

One **writer task** owns all index mutation (L0→L2 pipeline above) — the single-writer discipline again, chosen for the same reason as the spool: one owner means torn state is impossible by construction. MCP query tasks and the map assembler read redb snapshots + the atomic `index_clock`. A query whose snapshot clock lags the live clock beyond tolerance refuses (`M1E-6401`, `retry_after_ms`) — **refusal beats fabrication**, the estate's probe-registry rule applied to code intelligence.

### 6.4 The budgeted session-start map

Precomputed at index settle (not at query time): PPR over L2 seeded by the live recent-edit set, files ranked, per-file symbol signatures emitted richest-first, then **binary search over inclusion depth** until the rendering fits the token budget (default 2k, ceiling 8k, bundle-tunable via the `cortex` section) — but see **D-AF** (08 §5.1): on the claudecode hook surface the vendor's 10,000-character `additionalContext` cap binds first, making the effective ceiling **2,500 tokens** there and the fit predicate a conjunction of both limits. The 8k ceiling is reachable only on a surface whose delivery channel is not character-capped. Served on `SessionStart` as a read (10 s hook deadline is comfortable because assembly already happened). Every serve emits `CortexInjection{root_hash, index_clock, token_budget, tokens_used}`.

> **DECISION D-AE (lead, binding, 2026-08-30) — the `mark1d → shim` transport is a PULL on the
> existing fabric socket.** Two reconciliation passes recorded this as an honest BLOCKED: this
> section and 08 §5.1 both promise the map on `SessionStart`, and no document named the channel.
> It is named here.
>
> **The map is pulled by the shim, never pushed to it.** §6.7 has cortexd *pushing* the L0 root to
> mark1d, and `Hello.component` already enumerates `cortexd` with an empty `session_id` for exactly
> that ("session-less writers (cortexd push maps)"). The symmetric push onward to the shim is not
> merely unspecified, it is impossible: **the shim is a per-exec hook process that does not exist
> until the hook fires.** There is nothing to push to. cortexd pushes to mark1d because mark1d is
> long-lived; the shim pulls from mark1d because it is not.
>
> The channel is therefore the M1PL fabric socket the shim already opens, with two new
> `FabricFrame` arms — `ContextQuery = 8` / `ContextReply = 9` — symmetric in every respect with
> `GateQuery`/`GateVerdict`. That reuse is the whole point: one socket, one Hello handshake, one
> framing, one fail-open posture, one place where a session is bound to a connection.
>
> Four binding properties:
>
> 1. **mark1d stores, it does not assemble.** It holds the latest `MapRender` per workspace,
>    replaced on each cortexd push, and serves the bytes. The same discipline the gate has (04
>    §2.3: a cache READ, never a computation) — cortexd owns the budget binary search and is the
>    only process that may run it.
> 2. **`ContextQuery` carries no session id and no workspace id.** D-AA (§9.2) governs: the
>    connection's `Hello` bound the session, and the session determines the workspace. A shim
>    cannot ask for another session's map because it has no field in which to ask.
> 3. **Every failure is an empty injection.** Cold index, no map yet, cortexd down, deadline
>    expired, malformed reply ⇒ the shim exits 0 with no output — byte-identical to Mark 1 being
>    absent, which is the same promise the gate makes. A session start is never delayed and never
>    fails because Mark 1 has nothing to say. Accounted `Dropped{fabric_unavailable, DIAGNOSTIC}`
>    per §6.6, because an uncounted silent degradation is indistinguishable from a product that
>    does nothing.
> 4. **The 10 s hook deadline is not the fabric deadline.** The shim states its own budget the same
>    way it does for the gate (08 §4.4: the hook budget minus the 10 ms margin), and D-Y(c) applies
>    unchanged — 0 means unspecified, never expired.
>
> Implementation is a Phase 4 build row, not a mid-wave edit: the two oneof arms are an additive
> change to frozen `fabric.proto` requiring a regen, and the regen lane is already red pending the
> D-T/D-U commit. The contract is settled here so the row can be built without re-litigating it.

### 6.5 MCP surface

Cite 08 §6 for the schemas and the scoping/refusal/budget rules: `repo_map / find_definition / find_references / deps / ranked_files / memory_recall`, loopback transport with per-session bearer token, literal-loopback `Host`, `Origin` rejection, path canonicalization inside the session's workspace root (`M1E-6402` refusal on anything else). **Reconciliation note R-3 applies:** the spec's C6 row names `expand` and omits `ranked_files`/`memory_recall`; this document and the wire contract follow 08. `memory_recall` serves from the locally-synced tenant artifact cache (`session/`), which is purged on revocation (§2.9).

### 6.6 Backpressure under a large monorepo

- Full-index passes run at idle priority (`nice 19` + `IOPRIO_CLASS_IDLE` on Linux; `QOS_CLASS_BACKGROUND` on macOS; `IDLE_PRIORITY_CLASS` on Windows) and are chunked so a foreground query is never starved.
- The notify→writer queue is bounded; **watcher overflow** (inotify queue overflow, FSEvents coalescing, RDCW buffer overrun) is handled identically everywhere: schedule a full rescan, serve refusals (`M1E-6401`) for stale-affected queries until caught up. Never guess which events were lost.
- Memory ceiling ladder (§1.3): shed L3 first, then coarsen L2 (drop per-symbol edges for vendor/generated trees), then refuse. `.mark1ignore` and vendor-dir heuristics keep the default graph tractable.
- Fabric pushes (map refreshes, root updates) are droppable: recomputable, `Dropped{fabric_unavailable, DIAGNOSTIC}` (08 §4.4).

### 6.7 The L0 root double-serve — anti-tamper anchor

The same L0 merkle table serves (a) cortex provenance — every map/tool answer carries `root_hash` so ledger joins know exactly what tree the answer described — and (b) the anchors' anti-tamper envelope: cortexd pushes the root to `mark1d` on every index-clock bump; `mark1d.anchors` stamps the latest root into `AnchorIntegrity.worktree_merkle_root` (§2.2). One hash table, two consumers, zero duplicate hashing — and a mismatch between the root an anchor ran under and the root the verdict was later evaluated against is a `tamper` signal. cortexd down ⇒ envelope incomplete ⇒ votes never certify (§2.2); capture continues.

---

## 7. The four client crates

All four live in the virtual Cargo workspace, versions pinned in `[workspace.dependencies]`, committed codegen, no `build.rs` (07 §1).

### 7.1 `mark1-redact` — the two-axis scanner

```rust
/// Compiled ruleset: teddy/aho-corasick prefilter → regex confirm →
/// randomness (entropy) test. Streaming with a carry-over window of
/// max_pattern_len − 1 bytes so a secret split across chunks is still caught.
pub struct Scanner { /* ... */ }

pub enum SecretClass { ApiKey, OauthToken, PrivateKey, Password, HighEntropy /* … */ }
pub struct Finding { pub class: SecretClass, pub span: Range<usize>, pub confidence: Confidence }

impl Scanner {
    /// DETECT axis (mutate-in-transit; default OFF, bundle-enableable).
    pub fn scan(&self, chunk: &[u8], carry: &mut Carry) -> Vec<Finding>;

    /// ADMIT-TO-UPLOAD axis — fail-closed, NO OFF SWITCH. There is no config
    /// field, feature flag, or parameter that bypasses it: the absence of an
    /// off switch is an API property, not a policy. Flagged spans are
    /// replaced IN PLACE with ⟨redacted:class:hash⟩ (hash = per-tenant HMAC
    /// of the span — equal secrets correlate within a tenant, reveal nothing)
    /// BEFORE spool admission; the pre-image is never persisted anywhere.
    pub fn admit(&self, event_bytes: &mut Vec<u8>) -> AdmitOutcome;
}

pub enum AdmitOutcome {
    Clean,
    Redacted { substitutions: u32 },
    /// Any internal failure (ruleset load, regex engine, panic-caught) lands
    /// here: the event is quarantined locally, never admitted raw.
    Quarantine,
}
```

Linked by the proxy (both axes) and the shim (admit axis, §5.4); `mark1d` carries the conformance-vector-validated Go admit implementation (§2.0). **Budget: ~100 MB/s worst case @ CI bench (12)** — rust/regex's worst-case throughput, giving ~100× headroom over any single edge stream; the headroom is the design margin that lets the admit axis sit synchronously on every path with no bypass lane "for performance".

### 7.2 `mark1-receipt` — chain primitives

```rust
pub const DOMAIN_PREFIX: &[u8] = b"mark1-label-v1\0";

/// canonical.py vendored discipline: sort_keys, compact separators, ascii —
/// byte-stable across languages, verified by shared vectors.
pub fn canonical_bytes(payload: &serde_json::Value) -> Vec<u8>;
pub fn receipt_hash(prev_hash: &[u8; 32], canonical_payload: &[u8]) -> [u8; 32];

pub trait Signer {                       // the keys.py Protocol, in Rust
    fn sign(&self, msg: &[u8]) -> [u8; 64];
    fn key_id(&self) -> String;          // "ed25519:" + sha256(pub)[:16]
}

/// Checkpoint model (C13): N events / T seconds → BLAKE3 Merkle root over
/// event_id leaves → chained, dual-signed receipt.
pub fn merkle_root(leaves: &[[u8; 16]]) -> [u8; 32];
pub fn inclusion_path(leaves: &[[u8; 16]], index: usize) -> Vec<[u8; 32]>;

/// KeyRing: key_id → pubkey with not_before/not_after and cross-signatures;
/// rotation verification is here so mark1d, the proxy, and tools/verifier
/// share one implementation of "is this signature from a then-valid key".
pub struct KeyRing { /* ... */ }
```

One signing discipline product-wide: `mark1d.identity` uses this crate's semantics (via the Go mirror, conformance-vector-validated) for origin signatures; `tools/verifier` consumes the same primitives so "verify offline" and "sign at origin" cannot drift.

### 7.3 `mark1-policy` — bundle verify + decode to typed eval structs

```rust
/// Full verification order: section-split signatures (against KeyRing) →
/// monotonic seq per (tenant, channel) → transparency-log inclusion proof →
/// canonical-CBOR schema decode. Returns typed, allocation-final structs
/// designed for nanosecond evaluation — no map lookups or string compares on
/// the gate/route path after decode.
pub fn verify_and_decode(
    raw: &[u8], keys: &SectionKeys, last_applied_seq: Option<u64>,
    tlog_head: Option<&TlogHead>,
) -> Result<Bundle, Reject>;   // Reject carries M1E-3001/3002/3003/3005
// SectionKeys, not a single KeyRing: 05 §4.5 splits signing across SIX section
// key classes, while mark1-receipt's KeyRole is two-valued. SectionKeys is six
// reused KeyRings — ring membership IS the role, so a `route` key cannot sign
// `verify` (the key-ROLE binding lesson, applied to bundles).
// Option<u64>, not u64: D-P makes seq 0 a legal bundle, so a bare u64 cannot
// express "nothing applied yet" without stealing a legal sequence number.
// None = boot / no last-known-good.
//
// DECISION D-S (lead, binding). `tlog_head` is REQUIRED for seq > 0 and a
// `None` head at seq > 0 is an M1E-3003 refusal. Without it the inclusion
// proof verified the audit path against a `root` read from the bundle's OWN
// `inclusion` map — a self-consistency check, not evidence. Adversarial review
// tampered a signed bundle's body, recomputed a proof over the tampered leaf,
// wrote the resulting root into the bundle, and it was ACCEPTED with no
// signing key involved. 05 §4.4 always said "against the PINNED log head";
// this signature is what makes that sentence executable. Refusing on a missing
// head is the correct fail-static behaviour, not an availability risk: an edge
// with no fresh head keeps its last-known-good bundle rather than accepting an
// unwitnessed new one. At `seq == 0` the D-P bundle-zero waiver is unchanged —
// no proof, no head, structurally.

pub struct Bundle {
    pub seq: u64, pub max_age: Duration, pub prev_hash: [u8; 32],
    pub verify: VerifySection,   // confusion matrices, priors, correlation groups,
                                 // abstention models, anchor ENABLES BY CATALOG ID
    pub route: RouteSection,     // CPVS tables, ladders, knee tables, cost_basis
    pub memory: MemorySection, pub cortex: CortexSection,
    pub gates: GatesSection,     // may downgrade closed→open ONLY
    pub agent_maps: AgentMaps,   // hookshim field maps, tailer parser rules
}
```

**Any command string fails decode:** the `verify` section's schema has no field where an executable string can live — anchor references are catalog IDs validated against the grammar `[a-z0-9_.-]{1,64}` (normative in 07's CDDL — this doc previously carried a mutually exclusive `@cat-N` form, which no implementation ever spoke); a token containing whitespace, a path separator, or a shell metacharacter fails the grammar and rejects the **whole bundle** (`M1E-3005` — invalid is a security event, never applied piecewise). Fail-static behavior is **split**, and the split is deliberate: the crate owns only the pure part — evaluating a decoded bundle's age against `max_age` and reporting `Fresh | Stale` so a caller past the horizon falls to conservative built-ins. Last-known-good **persistence** is each consumer's, because the store differs per process (cortexd's redb, the proxy's memory-only cache, `mark1d`'s spool-adjacent state) and a crate that opened files would force all three onto one. A single staleness function with no I/O is the part that must not be reimplemented three times; the storage around it is not.

> **Go decoder status (lead, 2026-08-29): NOT BUILT.** Earlier text here claimed this crate was "consumed by … the conformance-vector-validated Go decoder"; no such decoder exists anywhere in `go/`. The bundle vector family has **zero** Go coverage, and `tools/ci/conformance_crosslang.sh` does not catch this because it asserts only a global `GO_N > 0`, which the receipt, redact and TVO-band families already satisfy. Until the Go twin lands (Phase 2 Wave B), `mark1d` consumes policy **through `mark1-policy` only**, and the cross-language guarantee this doc offers for bundles is a guarantee about one implementation, not two. Stated here rather than quietly corrected: a conformance claim that names a second implementation is exactly the kind of decorative control this repo exists not to repeat.
>
> **Superseded 2026-08-30 (Wave B): BUILT.** `go/mark1d/internal/policy` is the Go twin — hand-rolled canonical CBOR, all frozen bundle vectors passing, `GO_PENDING` in `conformance_crosslang.sh` now empty and the per-family assertion hard-failing. The paragraph above stands as the record of what an unqualified conformance claim was covering before it.
>
> **DECISION D-AD (lead, binding) — a decoder may not reject a key the frozen CDDL permits.** Both twins agreed with each other and disagreed with the schema: `decode.go`'s and `decode.rs`'s `strictKeys`/`strict_keys` for a knee row list `["n","c_n"]` with an EMPTY optional set, so the `? p_lcb` that 07 §7 declares (D-Z) is refused as an unknown key. Consequences, in order of severity: a bundle authored to the frozen CDDL is structurally rejected with `M1E-3005` and the daemon falls back to `Builtins()` with `Stale=true`; no bundle can therefore carry `p_lcb`; `FromBundle` leaves `PLCB` permanently nil; and `kneeFor` can only ever return `Stop=false` — **the knee governor cannot fire in production at all**, so 04 §2.3's at-the-knee ALLOW is unreachable code. `p_lcb` joins the optional-key set in both decoders, and a new bundle vector carrying it joins the frozen family so the gap cannot reopen. The general rule this instance illustrates: *two implementations agreeing is not evidence they are right* — it is exactly the failure mode a cross-language conformance gate is structurally unable to see, and it is why the vector families must be generated from the schema rather than captured from whichever twin ran first.

### 7.4 `m1p-wire` — codegen + M1PL framing

```rust
pub mod pb { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/gen/m1p.v1.rs")); } // committed, no build.rs

pub fn encode_frame(ev: &pb::Event, out: &mut Vec<u8>) -> Result<(), FrameError>;

/// Incremental, bound-enforcing decoder. Bounds per 07 §5: `0 < len ≤ 4 MiB`,
/// checked from the 9-byte header BEFORE any allocation (R-1, resolved — 08
/// §4.2 now names the same constant).
/// The maximum allocation reachable from any hostile length prefix is the
/// bound, which is what makes the fuzz target meaningful memory-safety
/// evidence rather than an OOM lottery.
pub struct FrameDecoder { /* ... */ }
impl FrameDecoder {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<pb::Event>, FrameError>;
}
```

Fuzz target `fuzz_targets/frame_decode.rs` runs in CI; the same corpus doubles as the shared conformance vectors against the Go decoder in `mark1d.fabric` — a Go/Rust disagreement on any vector fails the build (08 §4.2).

---

## 8. Concurrency, ownership and backpressure — the edge-wide model

### 8.1 State ownership (exclusive owner; everyone else reads snapshots)

| State | Exclusive owner | Access for everyone else |
|---|---|---|
| Spool segments + ledger | `mark1d.spool` writer goroutine | `uplink` via the read handle over sealed bytes; nobody else touches the files |
| Verdict cache + knee state | `mark1d.verdict` recompute goroutine | lock-free `atomic.Pointer` snapshot via `verdict.Reader` |
| Applied policy bundle | `mark1d.policy` apply path | `atomic.Pointer[Bundle]` load; consumers never block on a fetch |
| Tailer cursors + pending Usage maps | each tailer goroutine, its own | persisted files; nobody reads another tailer's state |
| `Dropped{}` counter table | atomic adds from anywhere | drained (read-and-reset) only by `uplink` at batch composition |
| Child process states | `mark1d.supervise`, one goroutine per child | status snapshots for `mark1 status` |
| Device/HMAC/spill keys | `mark1d.identity` | `Sign()`/`Seal()` operations only; key bytes never cross a package boundary |
| Guard credential registry | proxy `guard`, `ArcSwap` on provisioning updates | per-request lock-free load |
| cortexd index (L0–L3, shards, CAS) | the single writer task | redb MVCC read snapshots + atomic `index_clock` |
| Coverage open-window table | `mark1d.coverage` | via `Transition()` only — the single door |

The pattern is uniform and deliberate: **every mutable thing has exactly one writer; readers get immutable snapshots.** Locks that remain are read-mostly and never held across I/O.

### 8.2 Bounded channels and what happens at full

| Channel | Bound | At full |
|---|---|---|
| fabric connection read → capture | 4 MiB buffered per connection (08 §4.4) | stop reading the socket — TCP-style backpressure to the writer (which spills per its §4.4 rules) |
| capture → spool writer | 1024 events | billing-grade: sender **blocks** (backpressure chain: spool full → capture → fabric read stop → writer spill). diagnostics: shed + `Dropped{SPOOL_SHED}` |
| anchor work queue | 16 | coalesce per `(task, anchor)` — only the newest request matters; nothing queues twice |
| verdict recompute trigger | 1 (latest-wins) | debounce by design; fusion over stale votes is corrected by the next trigger |
| proxy tee channel | 8 MiB retained chunk bytes (D-AH — bytes, never slots) | `try_send` drop — parse degrades, client stream untouched (§3.2) |
| cortexd notify → writer | 4096 fs events | overflow ⇒ full-rescan scheduled + stale refusals (§6.6) |
| shim → fabric | n/a (one frame per exec) | deadline ⇒ spill ring (§5.4) |

The chain to internalize: **spool-full for billing-grade data propagates backpressure all the way to the producer's spill ring; nothing billing-grade is ever silently shed anywhere on the edge.** Diagnostics shed early and loudly (`Dropped{}`). This is the per-class durability policy made into a topology.

### 8.3 The no-network-on-hot-paths rule

Paths that must never block on the network, and what they touch instead:

- **Gate path** (shim → fabric → `verdict.Reader` → reply): memory only. Budget ≤5 ms; the off-check is a file `stat` (cached 1 s).
- **Proxy client path**: client socket + upstream socket only — no fabric await (tee is `try_send`), no policy fetch (bundle is a loaded pointer), no guard network call (registry is local).
- **Capture admission**: memory + eventual spool append; fsync is group-committed off-path; redaction is in-process (~100 MB/s, §7.1).
- **MCP answers**: redb snapshot reads; index staleness refuses rather than waiting on the writer.

Network I/O exists in exactly three places on the edge — `uplink`, `policy.Client`, `identity` refresh — and all three are retry-automaton background loops whose failure degrades to park/fail-static/local-only respectively. WHY this rule is absolute: every SLO the edge owes the developer (hook deadline, gate deadline, proxy latency) is a local-time promise, and a promise that transitively awaits a WAN is a lie waiting for a bad Tuesday.

---

## 9. State machines

Every transition labeled `trigger / action`. Terminal states are double-circled by Mermaid's `[*]` convention.

### 9.1 Session lifecycle (owned by the active adapter + `capture`)

```mermaid
stateDiagram-v2
    [*] --> DISCOVERED : SessionStart hook OR transcript file appears / emit SessionStart, start tailers, serve cortex map
    DISCOVERED --> ACTIVE : first event admitted / open task_seg context
    ACTIVE --> ACTIVE : hooks, tool events, Usage lines / capture; fast-anchor debounce
    ACTIVE --> DRAINING : SessionEnd hook / Flush{} barrier, close open tasks as UNRESOLVED, emit SessionEnd{EXIT, drained}
    ACTIVE --> DRAINING : idle timeout (no events, 2 h) / same, EndReason IDLE_TIMEOUT
    ACTIVE --> DRAINING : tailer sees session die without exit / EndReason CRASH_DETECTED
    DRAINING --> CLOSED : FlushAck received / mandatory spool drain + upload attempt
    DRAINING --> CLOSED : drain deadline (30 s) exceeded / SessionEnd{drained:false} — next boot replays (07 §6)
    CLOSED --> [*]
```

### 9.2 Task lifecycle (`task_seg.v1`; the TVO denominator, contract C1)

```mermaid
stateDiagram-v2
    [*] --> OPEN : task_seg.v1 mints task_id / emit TaskOpen{task_seg_version, prompt_digest, file_set_digest}
    OPEN --> ACTIVE : first tool/turn event under the task
    ACTIVE --> ACTIVE : anchor votes / fusion recompute, cache PROVISIONAL verdict
    ACTIVE --> CLOSED_VERDICT : closing VerdictEvent / emit TaskClose{RESOLUTION_VERDICT, final_verdict_id}
    ACTIVE --> MERGED_FORWARD : follow-up ≤ N turns touching same files / emit TaskClose{RESOLUTION_MERGED_FORWARD}; successor carries parent_task_id
    ACTIVE --> CLOSED_UNRESOLVED : session end without verdict / emit TaskClose{RESOLUTION_UNRESOLVED_SESSION_END} — a first-class denominator class, never excluded
    MERGED_FORWARD --> [*]
    CLOSED_VERDICT --> [*]
    CLOSED_UNRESOLVED --> [*]
```

> **DECISION D-AA (lead, binding) — how a gate query acquires its task id, and why `TaskID{}` is a sentinel and never an address.**
>
> The state machine above says `task_seg.v1` mints `task_id` **in the daemon**, and R-4 keeps it off the client wire, so the hookshim — a fresh per-exec process — cannot know it. It therefore sends `GateQuery.task_id` empty, correctly refusing to fabricate one. No document said what the daemon does with that, and the built daemon did the one unsafe thing: `copy(task[:], q.GetTaskId())` over an empty slice yields the all-zero `TaskID`, which was then used as a real map key for the verdict cache, the consecutive-block streak and the hourly ceiling. Every session on the machine collapsed into that one bucket. Demonstrated against the assembled daemon: session A votes VIOLATED; session B — separate connection, separate session id, **zero votes of its own** — is answered `BLOCK / VERDICT_VIOLATED` carrying A's posterior and A's evidence. One developer's failing task blocks a different developer's unrelated one, and D-Y's "streak resets on any publish *for the task*" resets it for everyone.
>
> The binding rule, in three parts:
>
> 1. **An all-zero `TaskID` is a sentinel meaning "unresolved", never an address.** No cache entry, no streak counter and no ceiling counter may ever be stored under it, in any language. A lookup that arrives at the sentinel is a **miss** — which is `M1E-5001` and therefore ALLOW, the correct fail-open direction.
> 2. **An empty `GateQuery.task_id` resolves through the connection's session.** The M1PL connection is session-scoped and its session id is authenticated in the `Hello` handshake (08 §4.3), so the daemon — which is the party that mints task ids — resolves *the currently open task of that session* and answers under it. If the session has no open task, part 1 applies and the answer is ALLOW.
> 3. **A non-empty `task_id` is honoured as sent, but only within its session.** A writer may name a task explicitly; it may not name another session's task. Cross-session naming is a miss, not a lookup.
>
> This is a missing cross-document contract being written down, not a policy invention: 04 §9.2 and 08 §5.1 both promise the daemon mints the id, and neither named the channel by which a per-exec hook process reaches it. The channel is the session, and it was already on the wire.

> **DECISION D-AL (lead, binding, 2026-08-30) — the all-zero SESSION id is a sentinel too. D-AA, one axis over.**
> D-AA closed the all-zero *task* id and the code says so in a comment — "the all-zero value is D-AA's 'unresolved' sentinel and is never a key here." It is never a **task** key. It is, today, a live **session** key. `Hello.session_id` is optional (08 §4.3 writes it `session_id?`, and cortexd legitimately sends none), `internal/fabric/session.go` accepts the handshake and leaves the session id all-zero, and `taskseg`'s `Observe`/`TaskFor` guard only the *length*. Every session-less connection therefore shares one bucket with a real, addressable open task. A pre-release probe drove three raw connections against the assembled daemon: connection B, whose `Hello` carried no `session_id` and which had cast no vote at all, was **BLOCKed on connection A's evidence**. The gate blocked a developer on a stranger's verdict.
>
> **Binding, both axes, both languages: a session id of all zeros is "no authenticated session", never an address.** `Observe` returns without segmenting; `TaskFor` misses ⇒ `M1E-5001` ⇒ ALLOW. The same holds for `capture`'s per-session sequence counter. The general rule, stated once because this is the third instance: *an identifier that has a legal "absent" encoding must be rejected as a map key at every level it appears, not only at the level where it was first noticed.* A sentinel closed on one axis is not closed.

> **DECISION D-AM (lead, binding, 2026-08-30) — `ToolUse` gains path digests, and this is a frozen-proto change made deliberately, because without it the product's headline metric cannot work.**
> ADR-0002 R2 requires a MERGE to satisfy BOTH proximity (≤3 assistant turns) AND ≥1 overlapping HMAC-salted path digest. `proto/m1p/v1/events.proto`'s `ToolUse` carries exactly `tool_name`, `tool_use_id`, `duration_ms`, `status` — **no path of any kind**. The overlap predicate can therefore never be satisfied, R2 MERGE can never fire, and every user prompt opens a fresh denominator entry. Measured on one realistic session: two `TaskOpen`, two `TaskClose`, both `RESOLUTION_UNRESOLVED_SESSION_END`, zero verified outcomes — **100% of the TVO denominator is `unresolved`**, while the gate was simultaneously serving a fused VIOLATED verdict off the cache. This is precisely the "retry loop counted as three cheap outcomes" the ADR exists to prevent, and it means every TVO number we could quote today is computed over a denominator that never merges.
>
> `repeated bytes path_digests = 5` is added to `ToolUse` — **digests, never paths**, HMAC-salted per tenant exactly as C4's evidence rule requires, so this expands no privacy surface. The change is additive and `buf breaking` at WIRE_JSON permits it. Landing it is a build row with its regen, not a mid-wave edit.
>
> **R3's half needs no proto change and is the cheaper cut:** the fused `VerdictEvent` is produced and cached but never admitted as an `Event`, so `taskseg`'s only path to `RESOLUTION_VERDICT` has no producer at all. Emitting it at publish time closes that half on its own.
>
> Related, and an S1 the moment R3 is wired: the segmenter's verdict arm ignores `ev.GetTaskId()` and closes `ss.cur`, having possibly just minted a fresh empty task — so the task that did the work is laundered into `unresolved` and the credit lands on an empty one. The verdict must resolve its target from its own `task_id` within the session's tasks.

> **DECISION D-AN (lead, binding, 2026-08-30) — three gate-scoping corrections.**
> **(a) The hourly block ceiling is PER SESSION.** It is currently a bare `uint32` with no key at all, so one session burning 30 blocks silently disables gating for every other session on the machine for the rest of the hour. The fail direction is ALLOW so no developer is harmed, which is exactly why it would have survived indefinitely — a control that degrades to decorative without ever failing loudly. The docs say "an hourly block ceiling" without a scope; the scope is now stated.
> **(b) `RLIMIT_AS` is the wrong knob for the anchor sandbox, and this is a field defect, not a test defect.** 512 MiB of *address space* is not 512 MiB of memory: thread-per-core allocators reserve address space proportional to core count, so on a 16-core host `ruff` is SIGKILLed and the anchor returns `VERDICT_ERROR`. The verify plane is therefore inert on exactly the hardware developers use, and the only reason we know is that the Phase 2 milestone test refused to run and said why. The cap moves to `RLIMIT_DATA`/cgroup `memory.max` as the sandbox's own doc comment already intended.
> **(c) A BLOCK reason may not state an inequality that was never evaluated.** The reason string is a template — `"p̂_LCB %.3f · V %.2f > c(n) %.2f"` — emitted on the `VIOLATED && !Stop` branch, but `Stop` is false in three cases that are *not* "the inequality holds": `p_lcb` absent (D-Z), `n` below the first knee row (D-Y(b)), and an empty knee table. In all three it prints `0.000 · 10.00 > 0.50`, which is arithmetically false, and it reintroduces the exact "absent collapses to certainly-hopeless" reading that `frombundle.go` is explicit it must never take. When the knee is not evaluable the reason says so and carries no numbers.

> **DECISION D-AR (lead, binding, 2026-08-30) — LEDGER CLOSURE IS NOT GATE LIFETIME, and conflating them is what D-AM broke.** Wiring R3 made the gate stop working. The chain, observed on a real session over the real fabric socket: a slow anchor publishes `REVISED VIOLATED` → the emitted `VerdictEvent` reaches the segmenter → the task closes with `RESOLUTION_VERDICT` and is marked not-live → the shim's gate query carries an empty `task_id` by design (D-AA) → `TaskFor` requires a *live* `ss.cur` → miss → `M1E-5001 no open task`, ALLOW. The daemon never BLOCKed once, with a `VERDICT_VIOLATED` sitting in the cache for the whole run. **D-AM traded the stop-gate's ability to act on the strongest evidence class we have — build, vet, test — for the denominator, and it fails toward allow, so nothing complained.**
>
> The fix is to stop treating one event as two things. **A verdict RESOLVES a task for the ledger and leaves it ADDRESSABLE for the gate** until the session ends or a new task opens. These are different lifetimes and always were; `live` was doing double duty. `TaskFor`'s sentinel path falls back to `ss.cur` whenever one exists, verdicted or not — closure is performed by `closeTask`, so the denominator is untouched.
>
> This also settles what `CLOSED_VERDICT` means, which the review correctly flagged as a decision and not a bug: it means *the ledger has its answer*, *never* "the agent may now stop." Reading it the other way makes the product's central claim false by design — and note that the gate wants the verdict for precisely the reason the segmenter wants it. Both consumers were right; the state was overloaded.
>
> Consequence, and it must land in the same change: because R3 reopens a task under the same `task_id`, a reopened task inherits its pre-close consecutive-block streak, and a streak already at the cap short-circuits the next gate query to ALLOW at step 3 — *before* the cache read — so the new attempt runs entirely ungated on stale state. `ResetTask` is documented to reset "on any cache publish **and on task close**" and has exactly one caller, the publish. Close must call it.

> **DECISION D-AS (lead, binding, 2026-08-30) — `unresolved` means NO VERDICT, never "no slow anchor ran".** `VERDICT_STAGE_CERTIFIED` has two consumers and zero producers anywhere in the tree, and `REVISED` is reachable only from a consented *slow* anchor. So on any install where the user has not run consent, or any workspace where `Derive` finds no slow anchor, the denominator is still 100% `RESOLUTION_UNRESOLVED_SESSION_END` — D-AM's attribution is correct and its *reachability* was the defect. Verified: with a slow anchor the spool shows `final_verdict_id` matching the `VerdictEvent`'s `event_id`, credited to the task that did the work; without one, nothing resolves.
>
> At task close, a verdict present in the cache at **any** stage closes the task with `RESOLUTION_VERDICT`, and the stage is recorded alongside it. A `ruff`-only `PROVISIONAL` is a weak verified outcome, not a non-outcome, and the instrument that reports its weakness already exists — the D-X/D-AB coverage band, which the estate's standing discipline requires on every number we quote. Suppressing the measurement instead of banding it loses the observation and reports the loss as `unresolved`, which is the one value that cannot be distinguished from "we were not there."
>
> The phantom `CERTIFIED` branch is deleted rather than left as a to-do: two consumers and no producer make the code read as though it has two adjudicated paths when it has one, and every future reader pays for that.

> **DECISION D-AT (lead, binding, 2026-08-30) — the handshake may not accept a session it will then discard.** D-AL closed the all-zero session at every *consumer* — capture quarantines, `Observe` segments nothing, `TaskFor` misses, `Gate.resolve` rejects before any counter is keyed — and a review confirmed each one genuinely closed rather than decoratively. What is not closed is *entry*: a `Hello` whose `session_id` is missing, wrong-length, or explicitly sixteen zero bytes still receives `HelloAck{Accepted: true}`, after which everything it sends is silently dropped. Defence in depth is intact; the handshake is lying. Reject at `Hello` with the handshake error code, citing 08 §4.3. **Fourth appearance of one disease: the sentinel is now closed on the producer axis as well as every consumer axis, which is the shape D-AL's own rule asked for and did not get.**

> **DECISION D-AU (lead, binding, 2026-08-30) — the shim gate budget is 250 ms; the doc and the e2e guard move to meet it.** Three artefacts disagreed: the shipped map says 250, the Go e2e test hardcodes 29,990, and 04 §2.3's prose still says "the agent's configured hook timeout − 10 ms". The Rust rationale wins on the merits — a wedged daemon at the vendor's hook timeout costs 31.4 s per turn against 217 ms for an *absent* one, so a half-dead Mark 1 would be 145× worse than no Mark 1, on the hook that fires at every turn end. 250 ms is fifty times the ≤5 ms cache read this gate is specified to be, which is slack enough. **The hardcoded Go constant is not the defect and does not go away** — it exists so a silent map edit cannot move the number, and it did its job: it caught this one. It is re-pinned at 250 and stays hardcoded.

### 9.3 Enrollment — the edge-local view (server machine is 08 §3.1; not restated)

```mermaid
stateDiagram-v2
    [*] --> UNENROLLED
    UNENROLLED --> PENDING : mark1 enroll / generate device key in custody ladder (§2.9), POST enroll/start, print user_code
    PENDING --> ACTIVE_LOCAL : poll returns active / persist enrollment doc 0600, install supervisor unit, start mark1d
    PENDING --> UNENROLLED : device_code expires (M1E-1004) OR IdP denial (M1E-1005) / report; rerun to retry
    ACTIVE_LOCAL --> ACTIVE_LOCAL : token 80% of expires_in / proof-of-possession refresh (§2.9); failure parks uploads, capture unaffected
    ACTIVE_LOCAL --> REVOKED_LOCAL : any M1E-1003 / OnRevoked() — stop uplink, PURGE memory-artifact cache, capture local-only, surface re-enroll
    REVOKED_LOCAL --> [*] : re-enroll creates a NEW device_id + key; old chain stays attributable to the old identity
```

### 9.4 Policy-bundle application (`mark1d.policy` + `mark1-policy`)

```mermaid
stateDiagram-v2
    [*] --> RUNNING_LKG : boot / load persisted last-known-good (or built-ins if none)
    RUNNING_LKG --> FETCHED : ETag poll 200 OR SSE hint→GET / bytes in hand
    FETCHED --> RUNNING_NEW : verify sigs + monotonic seq + tlog proof + decode OK / atomic.Pointer swap, persist LKG, ACK applied
    FETCHED --> RUNNING_LKG : M1E-3001|3002|3003 / keep LKG, ACK rejected(code), report via doctor
    FETCHED --> RUNNING_LKG : command string anywhere (M1E-3005) / reject WHOLE bundle, ACK rejected — security event, compiler bug is P1
    FETCHED --> RUNNING_PARTIAL : unknown section version / skip-and-retain per 08 §10.3, ACK applied + sections_skipped
    RUNNING_NEW --> RUNNING_LKG : note — RUNNING_NEW simply becomes the new LKG
    RUNNING_LKG --> BUILTINS : max_age exceeded, control plane unreachable (M1E-3006) / conservative built-ins; verdicts flagged stale_cert; status shows stale true
    BUILTINS --> RUNNING_LKG : any valid bundle fetched / normal apply path
```

### 9.5 Spool segment lifecycle (bytes per 07 §6)

```mermaid
stateDiagram-v2
    [*] --> ACTIVE : segment created / header written, records append
    ACTIVE --> ACTIVE : append / group-committed fsync 250–500 ms adaptive
    ACTIVE --> SEALED : next record would overflow 64 MiB OR drain barrier / final fsync, rotate to new ACTIVE
    SEALED --> UPLOADING : uplink cursor reaches segment / batches composed ≤32 MiB decoded
    UPLOADING --> ACKED : 200/202 for all records / ledger ack slot advanced
    UPLOADING --> UPLOADING : net/5xx/429 / 08 §2.5 backoff; PARKED leaves the segment in place
    UPLOADING --> QUARANTINED_PART : non-retryable 4xx / offending batch moved to quarantine dir, Dropped{} accounting, rest continues
    ACKED --> [*] : whole file acked / DELETE segment (whole-file ack-then-delete)
    ACTIVE --> TRUNCATED_TAIL : unclean shutdown, torn final record / recovery scan truncates to last good boundary, Dropped{CRC_LOSS} in first batch
    TRUNCATED_TAIL --> ACTIVE : recovery complete / appends resume
```

### 9.6 Guard decision path (proxy, per request — §3.1 as a machine)

```mermaid
stateDiagram-v2
    [*] --> RECEIVED : client request arrives
    RECEIVED --> REFUSED : no M1-Cred-Ref (M1E-8001) / 403; sampled GuardDecision{REFUSED}
    RECEIVED --> FP_CHECK : M1-Cred-Ref present
    FP_CHECK --> REFUSED : unknown ref OR HMAC mismatch (M1E-8001) / 403; sampled receipt — NO override path exists
    FP_CHECK --> TRIPWIRE : fingerprint matches enrollment
    TRIPWIRE --> REFUSED : credential shape classifies OAuth / 403 + P1 (provisioning bug); canary CI guards the classifier
    TRIPWIRE --> FORWARDING : shape consistent with apikey / bytes-forward; tee try_send; pool (upstream, credential-identity)
    TRIPWIRE --> NOOP_FORWARD : shape ok AND off-marker present / same ticket with observe=false; race window only, off normally detaches the proxy
    FORWARDING --> MARKER_SCAN : upstream response streaming / response/ scans for subscription markers
    MARKER_SCAN --> DONE : no marker / GuardDecision{FORWARDED} (sampled)
    MARKER_SCAN --> CONTAMINATION : subscription marker (M1E-8002) / KILL session + ROLLBACK base-URL fragment via fabric + per-event-receipted oauth_contamination P0
    REFUSED --> [*]
    DONE --> [*]
    CONTAMINATION --> [*]
```

**`off` does not short-circuit the guard, and the diagram used to say it did** (D-BE). The edge into `NOOP_FORWARD` hangs off `TRIPWIRE`, not `RECEIVED`: `Guard::decide` threads `off` all the way to the last statement, so an unverifiable guard, a missing `M1-Cred-Ref`, an unknown ref, an ambiguous credential, a fingerprint mismatch and an OAuth-shaped credential all still **refuse** with the off-marker set. That is a stronger property than the old edge described — `mark1 off` cannot be used as a guard bypass — and it is asserted directly (`provenance.rs`: `assert_refused(&g, &wrong, Cause::FingerprintMismatch, /*off=*/true)`). `NOOP_FORWARD` reaches the same `ForwardTicket` as `FORWARDING` with `observe = false`; whether the state survives at all is SEC-01, a founder decision.

---

## 10. Failure-mode catalog

The point of this document. Posture column uses the frozen matrix (open = availability, static = policy, closed = legality/secrets). The final column names the proving test with a stable slug for `12-testing-and-quality.md` to adopt; 12 owns the test definitions.

| # | Failure | Detection | Posture | User-visible effect | Recovery | Test in 12 |
|---|---|---|---|---|---|---|
| F-01 | `mark1d` SIGKILL / crash | OS supervisor; shim connect failure | open | none (agent unaffected); capture delayed | supervisor restart; spool recovery 07 §6; spill rings drained; children adopted | `12/chaos-daemon-kill9` |
| F-02 | `mark1d` crash-loop | supervisor restart counter | open | `mark1 status` degraded; capture gap | supervisor backoff; gap is a coverage window once daemon returns | `12/chaos-daemon-crashloop` |
| F-03 | cortexd panic / OOM | `supervise` breaker | open | MCP tools refuse (`M1E-6404`); maps stale; anchors' integrity incomplete | backoff restart; warm index from CAS/redb; reindex if corrupt | `12/chaos-cortexd-kill` |
| F-04 | cortexd shard/CAS corruption | redb/SQLite open error, checksum | open (refusal) | refusals until rebuilt | delete shard, reindex subtree | `12/cortex-shard-corrupt` |
| F-05 | proxy crash mid-stream | client conn reset; `supervise` | open | one failed request (agent retries); then direct-to-vendor traffic | fragment reverted; `CoverageTransition{BYPASS,"proxy_failed"}` receipted | `12/chaos-proxy-kill-midstream` |
| F-06 | proxy over latency/RSS budget | self-timer histogram; supervise RSS poll | open | none (budget breach ≠ outage) | CI bench blocks release; runtime breach alarms via status | `12/bench-proxy-latency-rss` |
| F-07 | upstream stall / mid-stream reset / slow client | chaos conditions on the wire | open | exactly what the vendor would show without Mark 1 — zero added regression | passthrough semantics; tee degrades independently | `12/chaos-proxy-stream-suite` |
| F-08 | tee channel saturated | `try_send` failure count | open | none | parse degrades; transport counters still emit; `Dropped{}` | `12/proxy-tee-saturation` |
| F-09 | `mark1-frames` parse failure (vendor drift) | golden fixture failure in CI; `ParseDegraded` in prod | open | none | opaque passthrough; wire Usage lost → transcript fallback; `DIALECT_REV` bump + fixture | `12/frames-golden-per-dialect` |
| F-10 | shim: daemon unreachable (event path) | connect timeout 100 ms | open | none (exit 0 within budget) | sanitized encrypted spill ring; drained on next connect | `12/shim-spill-replay` |
| F-11 | shim: gate query timeout | `GateQuery` deadline | **open — allow** | agent proceeds; no gating this turn | `Dropped{gate_timeout}` (`M1E-5001`); cache warms on next debounce | `12/gate-timeout-allows` |
| F-12 | shim: unknown hook payload shape | field-map miss for sniffed version | open | adapter inert; `mark1 status` shows `dropped:unsupported_agent_version` | `Dropped{UNSUPPORTED_AGENT_VERSION}` + coverage bypass; `agent_maps` bundle push | `12/adapter-version-sniff-drop` |
| F-13 | transcript rotation | `FileID` change at path | open | none | drain old handle to EOF, switch | `12/tailer-rotation` |
| F-14 | transcript truncation | size < cursor offset, same `FileID` | open | none | rescan from 0; `idem_key` collapses replays | `12/tailer-truncation-replay` |
| F-15 | tailer cursor lost/stale | cursor-file corrupt or `FileID` mismatch | open | none | full rescan; dedupe absorbs | `12/tailer-cursor-loss` |
| F-16 | transcript deleted by vendor retention before tail | file missing on resume | open | coverage gap in reports | `CoverageTransition{BYPASS,"transcript_retention_gap"}` — attributable, never silent | `12/tailer-retention-gap` |
| F-17 | spool full — billing-grade class | `Append` blocks | open (backpressure, **never shed**) | writers stall → spill rings absorb; status shows depth | uplink drains; block releases | `12/spool-billing-blocks-on-full` |
| F-18 | spool full — diagnostics | `ErrFull` | open | none | drop-newest + `Dropped{SPOOL_SHED}` | `12/spool-diag-shed-accounted` |
| F-19 | disk 95% hard stop | pre-append statfs | open | capture degrades; status warns | `CoverageTransition{BYPASS,"disk_hard_stop"}`; resumes when space returns | `12/spool-disk-hardstop` |
| F-20 | torn spool tail after `kill -9` | CRC/bounds fail on recovery scan | open | none | truncate to last good record; `Dropped{CRC_LOSS}`; loss bounded by fsync cadence | `12/spool-kill9-taillos-accounted` |
| F-21 | mid-file spool corruption | CRC fail on read during upload | open | none | record skipped + `Dropped{CRC_LOSS}`; segment still drains around it | `12/spool-midfile-crc` |
| F-22 | network down (uplink) | send errors | open | status shows parked | 08 §2.5 automaton → PARKED; re-queue on restart/network-change/6 h | `12/uplink-park-requeue` |
| F-23 | non-retryable 4xx from ingest | status code | open | status shows quarantined | quarantine dir, `Dropped{quarantined}`, never auto-retried | `12/uplink-4xx-quarantine` |
| F-24 | 409 batch divergence (`M1E-2003`) | ingest response | open | spool-corruption warning | quarantine; never overwrite a landed batch | `12/uplink-409-divergence` |
| F-25 | token expired / refresh failing | 401; refresh errors | open (capture) / closed (egress) | none until 30 d (then DORMANT note) | re-auth once per 401; park otherwise; capture never stops | `12/identity-refresh-outage` |
| F-26 | device revoked (`M1E-1003`) | 403 on any endpoint | **closed** | uplink stops; re-enroll prompt | `OnRevoked()`: purge memory-artifact cache, local-only capture, new identity on re-enroll | `12/identity-revoked-purge` |
| F-27 | bundle sig/seq/proof invalid (`M1E-3001/2/3`) | `verify_and_decode` | **static** | doctor note | keep last-known-good; ACK rejected | `12/bundle-invalid-keeps-lkg` |
| F-28 | command string in bundle (`M1E-3005`) | decode-time grammar | **static** (+ security event) | doctor + ACK rejected | whole-bundle reject; compiler bug escalated P1 | `12/bundle-command-string-rejects` |
| F-29 | bundle past `max_age`, control plane gone (`M1E-3006`) | age timer | **static → built-ins** | status `stale: true`; verdicts flagged `stale_cert` | conservative built-ins until any valid bundle | `12/bundle-maxage-builtins` |
| F-30 | unknown bundle section version | decode | static (per section) | ACK `sections_skipped` | skip-and-retain; LKG section keeps running | `12/bundle-skip-and-retain` |
| F-31 | anchor crash / timeout / sandbox-setup failure | runner result; sandbox error | open | none | `AnchorVote{VERDICT_ERROR}` — never `violated`; schedule continues | `12/anchor-error-not-violated` |
| F-32 | PATH shim / swapped binary | `resolved_binary_hashes` mismatch vs consent | closed (integrity: the vote carries `tamper`) | none visible; vote flagged | `tamper: true` — vote never certifies; doctor surfaces | `12/antitamper-path-shim` |
| F-33 | worktree mutated around anchor / suppression-directive spike | merkle root mismatch; `suppression_directive_delta` | closed (integrity: the vote carries `tamper`) | none | tamper flag; anchor-vs-T3 divergence feeds the adversarial-ML metric | `12/antitamper-worktree-suppression` |
| F-34 | cortexd absent when anchor runs | no fresh L0 root in cache | open | none | integrity-incomplete vote; never certifies | `12/anchor-integrity-incomplete` |
| F-35 | redact scanner internal failure | `AdmitOutcome::Quarantine` | **closed** | none | event locally quarantined + `Dropped{LOCAL_QUARANTINE}`; never admitted raw | `12/redact-fails-closed` |
| F-36 | secret detected in event | admit axis hit | **closed, no off switch** | none | span → `⟨redacted:class:hash⟩` before spool admission | `12/redact-substitution-pre-spool` |
| F-37 | unprovisioned credential at proxy (`M1E-8001`) | guard steps 2–3 | **closed** | agent request 403s | sampled receipted refusal; NO override path — negative test proves it | `12/guard-no-forward-path` |
| F-38 | OAuth marker in upstream response (`M1E-8002`) | response marker scan | **closed** | session killed; traffic reverts to direct | config rollback + per-event-receipted `oauth_contamination` P0 | `12/guard-contamination-killpath` |
| F-39 | loopback bad `Host` / `Origin` present (`M1E-4004/5`) | listener validation | **closed** | caller 403s | security event; DNS-rebinding structurally inert | `12/loopback-host-origin` |
| F-40 | fabric socket path is a symlink / bad perms (`M1E-4001`) | startup check | **closed** (start refusal) | daemon refuses to start; doctor explains | operator fixes path; refusal beats a hijackable socket | `12/fabric-symlink-refusal` |
| F-41 | oversized/garbage M1PL frame (`M1E-4002/3`) | bounds/handshake check | open | none | connection closed; writer spills; fuzz corpus grows | `12/fuzz-m1pl-frames` |
| F-42 | keychain/TPM unavailable at runtime | custody API errors | closed (secrets) | enroll fails loudly, or falls to 0600 file floor with doctor warning | never silently downgrade below the floor | `12/custody-floor` |
| F-43 | machine sleep/wake | monotonic clock; network-change signal | open | none | §1.4: cursors re-stat, parks re-queue, slow anchors deferred | `12/chaos-sleep-wake` |
| F-44 | clock skew | server computes from `sent_at` | open | none | the pair `(session_epoch, seq)` carries causal order; wall time is display-only (07 §2) | `12/skew-ordering-invariance` |
| F-45 | user edits inside a managed fragment (`M1E-7102`) | fence checksum mismatch | closed (refusal: nothing is rewritten) | doctor shows FRAGMENT-DAMAGED | repair only via explicit `doctor --fix` (08 §8.3) | `12/fragment-user-edit-refusal` |
| F-46 | `mark1 off` under any of the above | off-marker check precedes every gate | open (the off-marker outranks every posture above) | everything stops gating; byte-equality revert | `CoverageTransition{disable}` receipted; snapshot test | `12/off-byte-equality` |

Reading rule: every fail-**closed** row protects legality or secrets and is allowed to cost availability; no fail-**open** row is allowed to lose billing-grade data (it parks, blocks, or spills instead); every gap any row creates must surface as `Dropped{}` or a `CoverageTransition` — the two accounting channels are the difference between a failure and a lie.

---

## 11. Cross-platform notes (macOS / Linux / Windows differences that change the design)

CI runs on all three from day one (frozen plan §Deployment); these are the places where "the same design" needs different mechanics — or honestly weaker guarantees, stated as such.

### 11.1 Local fabric

| | Linux | macOS | Windows |
|---|---|---|---|
| Endpoint | UDS per 07 §5 (see flag R-2) | UDS, same | named pipe `\\.\pipe\omium-mark1-<user-SID>` — SID in the name prevents squatting; the DACL (owner SID only) is the actual boundary |
| Peer verification | `SO_PEERCRED` UID == daemon UID | `LOCAL_PEERCRED` | `GetNamedPipeClientProcessId` + client token SID check |
| Perms | socket 0600, parent 0700 | same | DACL: current user only; no Everyone, no NETWORK |

### 11.2 Key custody (the §2.9 ladder, per platform)

- **macOS:** Keychain (`kSecAttrAccessibleAfterFirstUnlock`, non-synchronizable — device keys must never ride iCloud Keychain to another machine: the key *is* the device identity).
- **Windows:** CNG with the Platform (TPM) KSP where present; DPAPI-protected file otherwise.
- **Linux:** secret-service (GNOME Keyring/KWallet) where a session bus exists; TPM2 via tpm2-tss on capable headless machines; else the 0600 file floor. The floor is universal and never skipped-below (F-42).

### 11.3 File watching

`notify`-crate/fsnotify abstractions with one shared overflow contract (§6.6): **FSEvents** (macOS) coalesces to directory granularity — treat every callback as "rescan this dir"; **inotify** (Linux) has a finite queue — `IN_Q_OVERFLOW` ⇒ full rescan; **ReadDirectoryChangesW** (Windows) has a finite buffer — `ERROR_NOTIFY_ENUM_DIR` ⇒ full rescan. The design consequence: nothing on the edge is allowed to *require* per-event watch fidelity; every watcher consumer (tailers, cortexd L0) must be rescan-correct, which they are because content hashing and idempotency make rescans cheap and safe.

### 11.4 Process supervision and sleep

- **Linux:** systemd user unit (`Restart=on-failure`); survives sleep; lingering enabled so the daemon runs without an open session where the distro allows.
- **macOS:** launchd LaunchAgent (`KeepAlive`); launchd may kill during sleep/pressure — handled as SIGKILL (§1.4), which is why the spool recovery path is not an edge case but a routine.
- **Windows:** per-user service (or Task Scheduler logon task where service install is not permitted); Fast Startup/hibernate resume re-triggers the network-change re-queue.

### 11.5 Anchor sandbox — the honest asymmetry

- **Linux (strongest):** namespaces (net/mount) + cgroup v2 (`cpu.max`, `memory.max`, `pids.max`) + seccomp; read-only outside the worktree via mount namespace.
- **macOS:** `sandbox-exec` profile (network deny, FS read-only outside worktree) + `setrlimit`; deprecated-but-functional, re-validated per OS release in CI.
- **Windows (weakest):** job objects (memory/CPU/process caps, kill-on-close) + restricted token + WFP network block — no mount-namespace equivalent, so "read-only outside the worktree" is best-effort. **Design consequence, recorded as a decision:** on Windows, test-class anchors are disabled by default until sandbox parity; static-analysis anchors (side-effect-free by nature) run under the job-object caps. Weaker isolation gets a smaller privilege, not a waiver.

### 11.6 Core-dump / memory-disclosure suppression (proxy §3.3)

Linux: `RLIMIT_CORE=0` + `prctl(PR_SET_DUMPABLE, 0)`. macOS: `RLIMIT_CORE=0` (dumpable flag n/a). Windows: `WerAddExcludedApplication` + no unhandled-exception minidump handler; DPAPI-scoped secrets reduce exposure of anything that leaks anyway.

### 11.7 Path handling

All allow-list and `.mark1ignore` comparisons run on **canonicalized** paths (symlinks resolved, then compared) — the same canonicalize-then-check discipline as the MCP scope rule (08 §6). macOS and Windows default volumes are case-insensitive: comparisons are case-normalized per volume probe, not per OS assumption. Windows: long-path (`\\?\`) prefixing for spool/CAS files; UNC paths are refused for workspace roots in v1 (a watched, tailed, sandboxed workspace on a network share breaks three subsystems' assumptions — refuse loudly rather than degrade quietly). The transcript `<munged-cwd>` derivation is vendor-defined per agent and lives in `agent_maps`, not in code (08 §5.1).

---

*End of 04 — Low-Level Design: The Edge. Cloud internals: 05. Intelligence services: 06. Bytes and schemas: 07. Contracts and error codes: 08. Tests named here: 12.*
