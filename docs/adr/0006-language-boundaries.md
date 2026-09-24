# ADR-0006 — Language boundaries: Rust on the hot path, Go for daemons, Python for statistics

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** expensive — each component's language is baked into its build, packaging, CI matrix, and (for the crates) its linkage into sibling binaries; rewriting any one component is weeks, and the cross-language conformance obligations exist precisely because no rewrite is planned
- **Blocks:** nothing new — the frozen plan's component registry already assigns every component; this ADR records the *reasoning* and the rule for new components so the decision generalizes instead of being relitigated per component

## Context

The plan's directive is "Rust + Go + Python with each language where it provably wins." The component registry assigns:

- **Rust:** `mark1-proxy`, `mark1-hookshim`, `cortexd`, and the four crates (`mark1-redact`, `mark1-receipt`, `mark1-policy`, `m1p-wire`, plus proxy-internal `mark1-frames`)
- **Go:** `mark1d`, `controld`, the `mark1` CLI
- **Python:** `adjudicator-svc`, `mark1-intel`

Three toolchains is a real cost and deserves a recorded defense. The estate context matters: Go services already exist in the platform (`checkpoint-manager`, `policy-engine` — go 1.25, `cmd/main.go` + `internal/`, an `obs` package), the Rust build conventions are established (virtual workspace, distroless-cc, `clippy -D warnings`), and the Python service skeleton (FastAPI/pydantic/asyncpg) is the house template. None of the three languages is new to the estate.

## Decision

Ratify the registry's assignments, for these reasons per boundary:

**Rust where a budget or a linkage forces it.**
- `mark1-proxy` sits on the customer's model-request hot path with a hard budget: **≤1 ms median added latency, 15–30 MB RSS** (CI-enforced). linkerd2-proxy is the existence proof that tokio + hyper1 + tower + rustls meets exactly this envelope; no GC runtime has shipped a comparable proxy inside it. The proxy also carries `Secret<T>` credential custody, where "no Display/Serialize impl exists" is a compile-time property only Rust's trait system gives us.
- `mark1-hookshim` is exec'd by agents per hook invocation under a 50 ms fire-and-forget deadline — it needs microsecond start-up, a small static binary, and zero runtime. It also must link `mark1-redact` in-process so even emergency spill is sanitized.
- The crates (`mark1-redact`, `mark1-receipt`, `mark1-policy`, `m1p-wire`) exist to be **linked into both the proxy and the shim** — one implementation of redaction, signing, bundle verification, and framing, memory-safe, on the most trust-critical paths. rust/regex's ~100 MB/s worst case gives 100× stream headroom for redaction.
- `cortexd` parses hostile input (arbitrary repo content through tree-sitter) and runs graph algorithms (petgraph PPR) under per-workspace isolation — memory safety against malicious files plus native performance for the merkle/graph work.

**Go where the work is supervision, tailing, adapters, and distribution.**
- `mark1d` is the shape of work Go demonstrably wins: a long-lived daemon doing file tailing, process supervision, seven per-agent adapters with high format churn, an uploader, and a policy client — Tailscale and lefthook are the existence proofs the plan cites. Critically, **the spool lives in `mark1d` because it is the single writer** — putting the spool in a Rust crate would force every Go call through cgo, and the cgo distribution tax (per-OS/per-arch linkage pain, crossed build matrices, debugger opacity) is exactly what the plan's "kills the cgo distribution tax" line refuses. Verdict fusion (log-space naive Bayes) is cheap math and belongs where the gates fire.
- `controld` is a one-binary cloud service — ingest, enroll, policy-dist, dp-release, query-choke — which is the estate's existing Go service shape, and its DP dependency (`google/differential-privacy` Go integer mechanisms) is Go-native.
- The `mark1` CLI ships as a single static binary on three OSes; Go's distribution story here is the industry default for a reason.

**Python where the work is numpy-shaped.**
- `adjudicator-svc` (spectral Dawid–Skene, ~500 LoC of numpy, with crowd-kit as a test oracle that only exists in Python) and `mark1-intel` (OPE estimators, DP release math adjacency, DuckDB batch analytics, policy compilation) are statistical/research-adjacent workloads. Reimplementing spectral methods, shrinkage estimators, and DR/SNIPS outside the scipy ecosystem is a research tax: every algorithm change costs a hand-rolled numerical kernel instead of a library call, and the papers' reference implementations stop being executable documentation.

**The rule for a new component** (so this ADR generalizes):

1. Does it have a hard latency/RSS budget, parse hostile input, hold credentials, or need to be linked into an existing Rust binary? → **Rust.**
2. Is it a long-lived daemon, adapter, supervisor, CLI, or cloud service module? → **Go**, and it should be a module inside `mark1d`/`controld` rather than a new deployable unless the registry itself changes.
3. Is it statistics, ML evaluation, or research-adjacent batch work behind a service contract? → **Python.**
4. Ties break toward **the binary it ships inside of** — extending an existing deployable beats creating a new one in a "better" language, because the deployable count (9) is a plan-level commitment.

**The obligations that keep three languages honest** (accepted as part of this decision, not negotiable per component):
- One proto source (`proto/m1p/v1/`) with committed, pinned-plugin codegen for all three languages; `buf breaking` at WIRE_JSON in CI; a message must round-trip identically across prost, protoc-gen-go, and the Python plugin.
- **Shared conformance vectors** wherever two languages implement one behavior: Go's parallel M1P decoder validated against `m1p-wire`; `mark1d`'s Go redaction admit axis validated **bit-identical** against the Rust `mark1-redact` (a disagreement on any vector fails the build); `KeyRing` signature verification vectors across Rust, Go, and the offline verifier.
- Three dependency-audit surfaces, each gated: `cargo-deny` + `cargo-vet`, `govulncheck`, `pip-audit` + uv lockfile audit (per `12`/`13`; new gates in this repo's CI).

## Alternatives considered

### All Rust

The strongest case: one toolchain, one CI matrix, one audit surface, memory safety everywhere, and — the sharpest point — **the conformance-vector obligation largely disappears**, because there is one redaction implementation, one wire decoder, one signing library, all just linked. Async Rust is fully capable of daemon work (tokio powers plenty of long-lived services), and the team already maintains Rust planes in the estate. The spool-in-Go/cgo argument inverts: if `mark1d` were Rust, the spool crate links natively and the "single writer" and "no cgo" goals are both met with zero duplication.

Why it loses: it optimizes the wrong loop. `mark1d`'s adapter surface — seven agents' hook vocabularies, transcript formats, and config surfaces, all of which churn with vendor releases — is the highest-iteration-rate code in the product, and Rust's edit-compile-borrow-check loop is a real tax on exactly that work, paid weekly forever. The estate's Go precedent (two production services, established layout, an `obs` package) is leverage all-Rust discards. And `adjudicator`/`intel` in Rust means hand-rolling spectral estimators and losing crowd-kit as a test oracle — the research tax lands on the components where correctness against the papers matters most. The conformance vectors are a cheaper price than all three of those, because vectors are written once per behavior and run mechanically.

### All Go

The strongest case: one toolchain with the best build/distribution story of the three, first-class daemons and CLIs, gofmt-culture uniformity, the fastest onboarding for generalist hires, and the estate's cloud services are already Go. The spool, the daemon, the CLI, and `controld` are all already Go in the plan — this alternative just annexes the rest.

Why it loses, concretely per annexed component: the **proxy** cannot make its budget-with-guarantees — a GC runtime on a sub-millisecond credential-bearing hot path means tail-latency stalls we cannot compile away and secret custody enforced by convention rather than by the type system (no `Secret<T>` equivalent: nothing in Go *prevents* a credential reaching `fmt.Sprintf`); linkerd's own history — linkerd1 on a managed runtime, rewritten as linkerd2-proxy in Rust to hit this exact envelope — is the counter-existence-proof. The **hookshim** would pay Go's multi-megabyte static binary and runtime start-up on every hook exec under a 50 ms deadline. **cortexd** would parse hostile repo bytes through cgo tree-sitter bindings — cgo *and* a memory-unsafe FFI surface on untrusted input, the worst of both. And Python's statistics case is unchanged. All-Go concentrates its losses on precisely the components where the plan's budgets and threat model are strictest.

### Two languages (Rust + Python, dropping Go)

Worth a line because it is the obvious compromise: Rust absorbs `mark1d`/`controld`/CLI, Python keeps the statistics. It inherits all-Rust's adapter-churn tax and discards the estate's Go conventions, while still paying a second language's audit surface — the costs of both prior alternatives with the savings of neither. The three-way split is not an accident of indecision; each pairwise merge has a named loser.

## Consequences

### What this makes easy
- Every component sits in the language where its dominant constraint is cheapest: budgets provable in Rust, churn absorbed in Go, research executable in Python.
- Hiring and estate reuse: each language's conventions, CI patterns, and deployment shapes already exist in the workspace.
- The new-component rule ends per-component language debates — the registry plus this ADR is the answer.

### What this makes hard
- **Three toolchains, three dependency-audit surfaces, three CI matrices** — multiplied by three OSes for the edge. CI wall-time and release engineering are permanently more expensive than a monoglot repo.
- The protobuf contract must round-trip identically across three code generators, forever, with `buf breaking` and freshness gates as the only guardrails.
- Every dual-implemented behavior (redaction admit, wire decode, signature verify) carries a conformance-vector suite that must grow with the behavior — forgetting to extend vectors is the new class of cross-language bug.

### What we accept
- That some engineers will work across all three languages, and context-switching is a real cognitive cost.
- That the conformance-vector discipline is load-bearing: if it rots, the Go/Rust redaction implementations *will* diverge silently, and the build-failure-on-any-vector rule is the only thing standing in the way.

## How we would know we were wrong

**Leading indicators, measurable:**
1. **Conformance-vector escape:** any cross-language behavioral divergence that reaches production despite the vector suites (i.e., the vectors existed but did not cover the divergence) — one such incident is a yellow flag; two in a year means the dual-implementation cost is being paid without buying the protection.
2. **Toolchain tax dominance:** release engineering + CI maintenance + codegen wrangling exceeding ~20% of engineering time over a quarter (observable from where PRs land: if one PR in five is build-system, the tri-language machine is eating the product).
3. **The Python seam leaking:** if `adjudicator`/`intel` latency or deployment weight forces their logic to be re-implemented at the edge or in `controld` anyway, the Python tier is a staging area, not a home.

**Migration path and cost:** consolidation proceeds from the cheapest boundary inward. Python → Go/Rust is the cheapest reversal (both services are batch/request workloads behind service contracts; cost: reimplementing spectral D-S and OPE against the papers with a numeric library, keeping crowd-kit as an offline oracle — weeks, no wire change). The Go ↔ Rust boundary is the expensive one: moving `mark1d` to Rust is a rewrite of the highest-churn component plus repackaging on three OSes (months), and moving the proxy to Go is foreclosed by its budget. Accordingly the decision is structured so the expensive boundary should never need to move: the components on each side were chosen by constraints (budgets, linkage, churn) that do not drift with fashion.

## References
- `docs/spec/execution-plan-v2.md` — component registry "Why this choice" column (linkerd2-proxy existence proof; cgo distribution tax; Tailscale/lefthook-shaped work; ~500 LoC numpy with crowd-kit as test oracle); repo layout; grounding facts (existing Go services `checkpoint-manager`/`policy-engine`; Rust build conventions; committed codegen with pinned buf plugins)
- `docs/design/04-lld-edge.md` — hot-path budgets, `Secret<T>` custody, shim deadlines
- `docs/design/12-testing-and-quality.md`, `docs/design/13-repo-scaffold.md` — the three CI matrices and the new audit gates (`cargo-deny`, `cargo-vet`, `govulncheck`)
- ADR-0005 — the M1P conformance-vector obligation this ADR's Go/Rust dual decoders inherit
