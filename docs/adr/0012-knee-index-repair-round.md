# ADR-0012 — The knee index is the repair round, not the attempt count

- **Status:** Accepted — approved by Anurag Upadhyay (founder) 2026-09-26 as part of `docs/design/16-release-savings-rm.md` (lane L2, Phase 2)
- **Date:** 2026-09-26
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap — edge-only arithmetic plus two additive proto fields; the ledger's `attempt` keeps its meaning, so no stored row changes interpretation
- **Blocks:** trusting any knee arrest as "the agent stopped making progress"; the anchor-grounded knee fit, which fits p(r) on the same index (ADR-0013 carries its `anchor_grounded` basis on the bundle; the fit itself is still owed)

## Context

04 §2.3 evaluates the knee governor at "attempt n": stop when p̂_LCB(n)·V(task) ≤ c(n). The edge's operational n (`anchors/votes.go`) counts **new states of the tree** — every re-vote whose evidence changed opens the next attempt. That is the right count for the ledger (how many tries this task took) and the wrong index for the knee:

- An agent that fixes a lint error, then hits an unrelated type error, then a failing test is making progress — three different defects, each repaired — but n reaches 3 and the bootstrap table (first stop at n = 3, `policydist/bootstrap.go`) arrests it.
- Paper I's model p(n) = p₁·γ^(n−1) is a *repair* curve: the probability the next try fixes **this** failure decays because the agent keeps failing on it. A fresh failure starts a fresh repair.

The research pass (`scratch/release-research/README.md`, "Real savings number") named this the over-arrest risk: the knee **can** fire in bootstrap, and when it does it may fire on progress.

## Decision

1. **Failure signature.** An attempt's signature is the set of `tool:diagnostic_code` over every untampered VIOLATED anchor vote in the task's current vote set (the anchor id when a vote carried no `EvidenceRecord`). Empty ⇔ nothing failing. The typed EvidenceRecord vocabulary only — never a path or excerpt (CON-004).
2. **Repair round r.** A failing attempt whose signature overlaps the previous attempt's is round `r_prev + 1`; a failing attempt sharing nothing with the previous one restarts at `r = 1`; a passing attempt (empty signature) is `r = 0`. Computed edge-side in `anchors.Votes.record` at vote time, where the evidence still exists (the fusion tee strips it). "VIOLATED attempt" is read off the votes, not the fused verdict, which does not exist yet at vote time; a fused non-VIOLATED verdict never reaches the knee anyway (the gate blocks or arrests only on VIOLATED).
3. **The knee reads r.** `verdict.Engine` evaluates `kneeFor(bundle, r)`; the table's `n` column is read as a round index. D-Y(b) and D-Z are unchanged: r below the first row (r = 0 included) is not evaluable and never stops.
4. **n stays for the ledger.** `KneeState.N`, `GuardDecision.attempt` and the app's "attempt" all remain the attempt count. `KneeState.R` carries r; the gate's reasons name both ("attempt 5, repair round 3").
5. **Say where p came from.** `GuardDecision.knee_basis` (proto field 8) is `prior` | `anchor_grounded` | `certified`. The edge infers it from the applied bundle until the bundle carries it (ADR-0013): the compiler fits knee rows on certified attempts only (06 §10.3) and certification needs at least three independent correlation groups, so a verify section with fewer — the bootstrap bundle has one — carries the **prior**. Every surface words a prior as "prior p(r)", never p̂_LCB: a Paper I prior is not a measured lower bound.
6. **`bundle_seq` is recorded and projected.** `GuardDecision.bundle_seq` (proto field 9) is the applied bundle's seq; `chproj` projects it into `m1p_events.bundle_seq`, which the interventions read already selected and always found 0.

## Consequences

- An agent repairing a sequence of different defects is not arrested for it; one stuck on the same defect is arrested at the same round the old rule would have used for a pure loop.
- The consecutive-block cap (≤ 3, FR-VERIFY-010) is untouched and still ends a loop whose knee is not evaluable or whose rounds keep restarting (`block_cap`).
- 04 §2.3 is amended (repair round, reason wording); 07's GuardDecision gains fields 8 and 9. Additive proto: old edges send neither, old controld ignores both.
- The arrest SSE row gains `round`, `knee_basis` and the `tokens_saved_estimate` the ledger records for the same arrest.
- Rejected: resetting n itself (loses the attempt count the ledger and the TVO waste taxonomy read); overlap on the full evidence fingerprint (counts change as the agent fixes part of a defect, which is progress on the same failure, not a new one); computing r in the Engine from the fused verdict (the Engine never sees evidence).
