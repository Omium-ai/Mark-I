# ADR-0002 — `task_seg.v1` merge rules: the TVO denominator

- **Status:** Accepted — signed by Anurag Upadhyay (founder) 2026-09-16, as recommended by the lead; the ruling is recorded in docs/RECONCILIATION.md (D-EI). Rule changes become `task_seg.v2` on new events only; v1 rows are never re-segmented.
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap to *evolve*, expensive to *restate* — and the design makes restatement structurally impossible by accident. Changing the rules is a version bump (`task_seg.v2`) that applies only to new `TaskOpen` events; old events are never re-stamped, so shipping v2 costs one bundle push plus a new rollup series. Restating *history* under new rules is an explicit, per-tenant, receipted re-segmentation job into a new rollup keyed `v2-restated` — the old numbers and their receipts remain valid forever. What can never be reversed: a number already quoted to a customer under v1. That is the point.
- **Blocks:** the TVO engine (`python/intel/tvo/`, Phase 1 critical file 9); the segmenter in `mark1d`; every customer-facing TVO number; the `tvo_task` and `tvo_tenant_day` rollups (keyed by `task_seg_version`). The plan: "An ADR precedes the code."

## Context

TVO — tokens per verified outcome — is the product's headline number, and its denominator is "verified outcomes", which requires deciding *what counts as one task*. Segment too coarsely and TVO flatters us (few, fat outcomes); too finely and it flatters the baseline (retry loops counted as three cheap outcomes instead of one expensive one). Every number Mark 1 will ever quote to a customer, put in a report, or attach a coverage band to divides by this algorithm's output.

Two constraints shape the design:

1. **The denominator must be an algorithm, not a heuristic** — specified to the point where two independent implementations segment identical sessions identically. It runs in `mark1d` at the edge, because the merge rules reference files and file paths exist only at the edge; only the resulting `task_id` and `task_seg_version` ever leave the machine.
2. **A quoted number must stay auditable forever.** A customer holding a Q3 report must be able to verify its numbers against the ledger in Q4, even if the segmentation rules have since improved. This forces version stamping and forbids silent restatement.

## Decision

Adopt `task_seg.v1` as six normative rules, in evaluation order:

```
R1  A task opens at the first user prompt of a session, and at every user
    prompt that R2 does not merge into an open task.
R2  MERGE rule: a user prompt within N = 3 assistant turns of the previous
    task's last activity, whose subsequent tool activity touches ≥ 1 file
    (by per-tenant HMAC-salted path digest) already touched by that task,
    is the SAME task. Both conditions required: proximity alone merges
    nothing; file overlap alone merges nothing.
R3  A certified or revised verdict CLOSES the task. A follow-up prompt that
    R2-matches a CLOSED task within N turns REOPENS it (same task_id, new
    attempt) — this is what makes retry loops one denominator entry, not
    several.
R4  Merges never cross a session boundary. SessionEnd force-closes every
    open task with close_reason = 'session_end_no_verdict' → the task
    enters the `unresolved` denominator class.
R5  `unresolved` tasks are their own reporting class: their tokens appear
    in the numerator report, they never count as verified outcomes, and
    they are never silently dropped. A later session touching the same
    files is a NEW task (R4), even if it "finishes the same work".
R6  N = 3 and the file-overlap predicate are PART OF the version. Changing
    either — or anything above — is a version bump, never an edit.
```

**Version stamping.** Every `TaskOpen` event carries `task_seg_version` (the M1P field exists exactly for this), and every rollup row is keyed by it. The version string `task_seg.v1` is opaque — compared by equality, never parsed.

**Version bumps without restating history.** When `task_seg.v2` ships: (1) edges stamp `v2` on new `TaskOpen`s from their bundle-directed activation date — old events are never re-stamped; (2) rollups naturally partition by version, so a report period spanning the cutover shows two labeled series, never one silently-blended number; (3) restating a tenant's history under v2 is an explicit re-segmentation job: replay the tenant's ledger through the v2 segmenter into a *new* rollup keyed `v2-restated`, covered by its own receipt (the same per-event receipt class as corpus exports), leaving v1 rollups untouched and the original receipts valid. History is append-only; reinterpretation is a new, receipted artifact.

**Worked examples — the three ambiguous sessions, resolved:**

1. *Same window, different files.* "fix the auth timeout bug" → agent edits `auth/session.go`, certified `satisfied`. Two turns later: "also update the changelog" → agent edits `CHANGELOG.md`. **Two tasks.** R2's proximity condition holds (2 ≤ N) but file overlap fails — `CHANGELOG.md` was never touched by task 1. TVO counts two verified outcomes; merging them would deflate the denominator and flatter nobody honestly.
2. *The retry rephrase.* "fix the flaky test" → agent edits `tests/test_sync.py`, fused verdict `violated`. One turn later: "no — the race is in the fixture, look at conftest" → agent edits `tests/conftest.py` *and* `tests/test_sync.py` again. **One task, second attempt.** R3 reopens: proximity holds and `test_sync.py` overlaps. The second attempt's tokens land in `retry_loop_tokens`. This is the rule doing its real job: a retry loop is one outcome bought expensively, not three outcomes bought cheaply.
3. *The overnight orphan.* Refactor requested at 18:40, agent works across `pkg/router/*.go`, laptop closes mid-run — no verdict fires. SessionEnd (R4) closes the task `unresolved`. Next morning a new session finishes the refactor on the same files and certifies `satisfied`. **Two tasks:** yesterday's is permanently `unresolved` (tokens reported in that class), today's is one verified outcome. R4 is deliberately blunt: a cross-session merge rule would need to bound how far back to look, turning the denominator into a function of retention windows and making TVO drift as old data ages out. Blunt and stable beats clever and unreproducible.

## Alternatives considered

### Per-session denominators (task = session)

**Strongest case:** zero ambiguity and zero implementation risk — session boundaries are hard events the capture layer already emits, no merge heuristics, no N to tune, trivially reproducible by any auditor, and it needs no file information so it could run entirely server-side. Most published agent-cost figures are per-session, so comparisons come free.

**Why it lost:** it destroys the metric's meaning at both ends. A session with five unrelated fixes becomes one "outcome" (TVO flattered ~5×); a five-session slog on one bug becomes five outcomes (TVO flattered the other way — and worse, four of those sessions have *no* verified outcome, forcing either a zero denominator or silent exclusion). The metric would measure how users batch their work, not what the work costs. Paper I's TVO axioms require verified-outcome denominators precisely because session-grain accounting is what current leaderboards already get wrong.

### Per-commit denominators (task = VCS commit)

**Strongest case:** commits are the developer's *own* declaration of a completed unit of work — ground truth from the user, not inference by us. They come with stable identifiers, diffs for free, and an audit trail the customer already trusts. For the subset of work that lands as clean, atomic commits, this is a better task boundary than anything we can infer.

**Why it lost:** coverage and coupling. Much of what agents do never becomes a commit (exploration, answered questions, abandoned attempts, work squashed away) — those tokens would have no denominator entry and would either vanish or pile into an "uncommitted" bucket that dwarfs the signal. Commit discipline varies wildly across users and teams, so the denominator would measure git hygiene as much as outcomes. And it binds the metric to VCS state the capture layer otherwise never needs to read — a privacy-surface expansion (commit metadata, branch names) for a boundary that only sometimes exists. Commits remain useful as *corroborating evidence* for verdicts; they are the wrong denominator.

### Human-labeled task boundaries

**Strongest case:** it is the accuracy gold standard — humans resolve every ambiguous case correctly, including the intent-level merges no file-overlap rule can see ("refactor the router" and "now update its docs" are one task to a human). And a gold set of human labels is genuinely valuable for *validating* any algorithmic segmenter.

**Why it lost:** it cannot be the production denominator. It does not scale (every session of every tenant, forever), it violates the privacy posture (labelers reading customer prompts and file paths, when the design guarantees paths never leave the edge), it is irreproducible (two labelers disagree; the customer's auditor cannot re-run a human), and it makes the headline number a function of labeling-vendor quality. Its correct role is exactly the one it keeps: a small consented gold set to measure the algorithmic segmenter's agreement rate — the validation instrument, not the instrument.

## Consequences

### What this makes easy

- **Defensible numbers.** Any TVO figure ever issued names its `task_seg_version`; the customer can replay their ledger through the pinned rules and reproduce the number exactly. Two independent implementations (the Go segmenter in `mark1d`, a reference implementation in the verifier tooling) can be conformance-tested against shared fixtures.
- **Honest retry accounting.** R3 makes retry loops one expensive outcome, which is what makes `retry_loop_tokens` (the waste taxonomy's largest column) pure ledger arithmetic.
- **Honest incompleteness.** R4+R5's `unresolved` class means abandoned work is reported, never laundered into either side of the ratio — folding it into the denominator would flatter TVO with unverified work; dropping its tokens would hide real spend.
- **Improvement without betrayal.** R6 plus version-keyed rollups means the algorithm can get better forever without ever invalidating a previously-issued report.

### What this makes hard

- **Cross-version comparisons.** A report period spanning a version cutover shows two labeled series; sales and dashboards must present that honestly rather than blending. This is deliberate friction.
- **Intent-level merges are invisible.** Work continued on *different* files with the same intent (example 1's inverse: "now do the same fix in the other service") counts as a new task. v1 accepts under-merging as the safe failure direction — under-merging inflates the denominator and *understates* our savings claim, which is the direction we can live with in front of a customer.
- **Edge-resident complexity.** The segmenter must run in `mark1d` (file digests exist only there), so it ships in Go inside the capture daemon, with conformance fixtures, rather than as a tidy server-side batch job.

### What we accept

- **N = 3 is a judgment call, frozen.** It was not fit to data (there is none yet); it is a prior. R6 exists because we expect dogfooding to revise it — as a v2, with its own series.
- **Path digests are the overlap predicate.** A renamed file breaks overlap (different digest), splitting what a human would call one task. Accepted: rename-tracking would drag VCS awareness into the edge for a rare case, and the failure direction is again under-merging.
- **A wrong denominator is a wrong customer claim.** If v1 systematically over-merges, quoted TVO is better than reality and a customer audit could find it. The mitigations are the safe-direction bias above, the version stamp that scopes any error to its version, and the gold-set agreement measurement below. What the versioning rule buys is that even a *wrong* v1 number remains an honest, reproducible statement of "TVO under task_seg.v1" — the claim survives its algorithm's revision.

## How we would know we were wrong

**Leading indicators, all measurable from the ledger:**

1. **Unresolved share.** If the `unresolved` class exceeds ~25% of denominator entries for a tenant over a trailing month, R4 is too blunt for real usage patterns (people genuinely resume work across sessions) and the denominator is discarding too much signal.
2. **Reopen distance clipping.** If the distribution of R2/R3 matches shows heavy mass exactly at N = 3 turns (matches at distance 3 ≫ distance 2), real follow-ups are being cut off just past the window and N is too small. Mass concentrated at distance 1 with near-none at 3 means N could tighten.
3. **Gold-set disagreement.** A small consented gold set (our own dogfood sessions, human-labeled) measures segmenter agreement. Below ~90% task-boundary agreement on dogfood data, v1's rules are missing how work actually clusters.

**Migration path and cost:** write `task_seg.v2` with the revised rules; ship it as a bundle-directed activation date (a bundle push, not a release, since the version is stamped per `TaskOpen`); rollups fork into a `v2` series automatically. Cost: the segmenter change itself, new conformance fixtures, and — only if a tenant wants history restated — a per-tenant re-segmentation job producing a receipted `v2-restated` rollup (compute cost: one replay of that tenant's ledger through the segmenter; no re-ingest, no schema change). Previously-issued v1 reports remain verifiable forever. The one thing no migration can do is silently change a number already quoted — by design.

## References

- `/home/anurag/workspace/Omium/omium-mark1/docs/spec/execution-plan-v2.md` — contract C1 (`task_seg.v1`); "Decisions to make before code" item 2; TVO engine as Phase 1 critical file 9.
- `/home/anurag/workspace/Omium/omium-mark1/docs/.parts/07-part3-analytics.md` — §`task_seg.v1` (the normative rules, version-bump mechanics, and worked examples this record formalizes); `tvo_tenant_day.task_seg_version` rollup keying; the TVO read-time arithmetic and `unresolved` handling.
- `/home/anurag/workspace/Omium/mark1-research/README.md` — Paper I: TVO metric, the four axioms (Prop 3.2), Thm 6.1 (non-recoverability of TVO from pass@k + mean cost — why session/leaderboard grains fail), TVO-Bench rules R1–R6 (verified denominators, full-session accounting, gaming resistance).
