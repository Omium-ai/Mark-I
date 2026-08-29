# ADR-0003 — The Shapley waste-attribution game: players and v(S)

- **Status:** Proposed — **deferred**, awaiting founder sign-off on the deferral and its trigger. No Shapley code may be written until this ADR is superseded by one that defines the game; the deterministic waste taxonomy ships in Phase 1 regardless and remains the audit-grade floor forever.
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap — deferral costs nothing to reverse. Shapley attribution, when it comes, is presentation on top of the deterministic taxonomy's columns, never a replacement for them; un-deferring is a new ADR plus an intel-job module, with no schema change and no restatement of any shipped number. The asymmetric risk is all on the other side: shipping a Shapley number *before* the game is well-defined bakes an indefensible attribution into customer reports, and a retracted headline number is the one thing this product cannot afford.
- **Blocks:** any Shapley implementation in `mark1-intel.tvo-engine`; any customer-facing "savings attributed to plane X" claim beyond the deterministic columns. Does **not** block Phase 1 — the deterministic taxonomy is unblocked and specified.

## Context

Paper I, Theorem 7.1, gives an exact, order-independent Shapley decomposition of session waste into four channels — **iteration, exploration, misallocation, context**. The theorem is real and the eventual product story ("your waste splits X% retry loops, Y% re-exploration, …, and Mark 1's planes each saved you $Z") is the natural presentation layer over it. The plan is equally explicit that the theorem does not license code: *"Shapley requires a game-definition ADR before any Shapley code is written"*, because a Shapley value is only as meaningful as the cooperative game `(N, v)` it is computed over, and three distinct games are candidates here.

Meanwhile the deterministic taxonomy already ships in Phase 1 and answers most of the customer question without any game theory:

- `retry_loop_tokens` — tokens of attempt *n* ≥ 2 where attempt *n−1*'s fused verdict was `violated`. Pure ledger arithmetic.
- `reexploration_tokens` — read/grep/list/glob tokens whose target digest was already in the session's `CortexInjection` served-set. Claimable only where an injection event actually exists — no counterfactual model.
- `over_model_tokens` — for certified-`satisfied` tasks, the token excess over the cheapest ladder rung *with an actual passing signal on the same task*; contributes zero where no cheaper rung was exercised. The taxonomy refuses to guess what a cheaper model would have done.

The gap Shapley would fill: the deterministic columns can overlap (a retry attempt can also contain re-exploration) and they attribute waste to *phenomena*, not to *Mark 1's interventions*. A fair, order-independent split of "tokens Mark 1 saved you" across verify/cortex/memory/route needs a game.

**The three candidate games, argued:**

1. **Players = the four waste channels** (Thm 7.1's frame: iteration, exploration, misallocation, context). Here `v(S)` = total session waste jointly explainable by the channels in S, and Shapley resolves the overlap between channels — the interaction terms the deterministic columns double-count. This game is *fully observable from the ledger*: no counterfactual needed, because it decomposes waste that already happened. Its limitation: it attributes waste to its causes, not savings to our interventions — it sharpens the diagnosis, not the invoice.
2. **Players = Mark 1's interventions** (stop-gate, cortex injection, memory injection, route decision). Here `v(S)` = tokens saved when exactly the interventions in S are active, relative to none. This is the game the sales claim wants — and it is the one with the honesty problem: `v(S)` for coalitions we never ran is a counterfactual. "Tokens Cortex would have saved" is not directly observable; estimating it requires either randomized holdouts (ε > 0 exploration, which defaults to 0 and is a per-tenant contractual opt-in) or an outcome model, which would put a modeled number inside a product whose entire identity is "every number traces to a ledger query".
3. **Players = system components** (the deployables). Rejected outright: component boundaries are engineering facts, not economic ones — `mark1d` hosting the fusion math does not make it the *cause* of the saved tokens — and the resulting split would be an artifact of the repo layout.

**Computational cost, honestly assessed:** with 4 players, exact Shapley is 2⁴ = 16 coalition values and a 24-permutation average — computationally trivial; sampling approximations are irrelevant at this player count. The real cost was never the sum. It is *estimating the 16 values of `v(S)`*: in game 2, at least the 14 non-trivial coalitions are counterfactual configurations, each needing either an experimental arm (14 arms × enough tasks per arm for a confidence interval — a randomization budget no pilot tenant has consented to) or a model. The computation is free; the measurement is the entire problem.

## Decision

**Defer.** Specifically:

1. **The deterministic waste taxonomy ships first and stays forever** as the audit-grade floor. Every deterministic column is claimable only where its evidence event exists, contributes zero where it would have to guess, and is reproducible by the customer from their own ledger.
2. **No Shapley code is written** — not the sum, not the sampling scaffolding, not a `shapley` module stub — until a superseding ADR defines the game. A stub invites someone to fill it before the definition exists.
3. **The deferral has a named trigger** (below). When it fires, the superseding ADR's default candidate is **game 1 (the four channels of Thm 7.1)** with `v(S)` = jointly-explainable session waste in tokens, because it is the only candidate computable from observed ledger data alone — game 2 remains out of reach until real experimental coalitions exist.
4. Until then, any customer-facing attribution claim uses the deterministic columns verbatim, labeled as such, with their coverage band.

**The trigger — un-defer when either fires:**

- **T-A (overlap materiality):** dogfood or tenant ledgers show the deterministic columns overlapping materially — concretely, tokens counted in ≥ 2 columns exceed **10% of total attributed waste** over a trailing month. At that point the columns' sum overstates total waste, the double-count needs a principled resolution, and game 1 is exactly the instrument that resolves it from observed data.
- **T-B (contractual demand for intervention attribution):** a signed customer requirement to split *savings* across Mark 1's planes (pricing, chargeback, or renewal justification) **and** that tenant's contractual ε > 0 exploration opt-in — because game 2's `v(S)` is only honestly estimable from randomized coalition data, and `RouteDecision.propensity`/`fidelity` (contract C9) plus stop-gate holdouts are precisely the logging that makes DR/SNIPS-style off-policy estimates of coalition values legitimate. Demand without the opt-in gets the deterministic columns and this ADR as the explanation.

## Alternatives considered

### Define game 1 now (players = the four channels, v(S) = jointly-explainable waste)

**Strongest case:** it is Thm 7.1's own frame, fully observable, computationally trivial, and defining it now would let the overlap-resolution machinery ship alongside the taxonomy instead of after it. The theorem's order-independence is exactly the property that makes the split defensible; waiting gains no information that the ledger will not also provide later.

**Why it lost:** it *does* gain information by waiting — T-A is the empirical test of whether the overlap is material at all. If the deterministic columns overlap by 2%, Shapley resolves a rounding error at the cost of explaining a cooperative game to every customer who asks what the number means. Defining `v(S)`'s "jointly explainable" predicate also has real freedom in it (is a retried re-exploration iteration waste, exploration waste, or their interaction?) and fixing that predicate before seeing real overlap data means fixing it blind. The game is cheap to define later and wrong to define blind now.

### Define game 2 now (players = interventions), with modeled counterfactuals

**Strongest case:** it is the game the product story actually needs — customers buy interventions, not diagnoses, and a savings-per-plane number is the renewal slide. Off-policy estimation is a mature field; propensity logging is already contract C9; and shipping the definition early would shape the logging (holdout windows, shadow runs) so the data needed later gets captured from day one.

**Why it lost:** with ε defaulting to 0 and exploration a per-tenant contractual opt-in, propensities are 1.0 and there is *no* off-policy signal — every DR/SNIPS estimate degenerates to a model's opinion. A modeled counterfactual inside the headline attribution breaks the product's core claim that every number traces to a ledger query, and it does so at the exact surface a procurement auditor will probe. The one piece worth keeping — shaping the logging — is already secured by C9 without this ADR. When T-B fires, this game becomes definable on honest data; that is the migration path, not the starting point.

### Skip Shapley permanently (the taxonomy is enough)

**Strongest case:** the deterministic columns already answer "where did my tokens go" with audit-grade provenance; Shapley adds a fairness axiom customers never asked for; and every avoided estimator is an avoided dispute. YAGNI, applied to game theory.

**Why it lost — narrowly:** as a permanent posture it forfeits Thm 7.1, which is published, differentiating IP that only a deployed Mark 1 can operationalize (the papers' defensibility argument rests on exactly this: reading the theorem does not confer the production data to run it). It also leaves the double-count problem (T-A) with no principled resolution if it turns out material. The deferral adopted here is this alternative *bounded by a trigger* — we get its discipline without its foreclosure.

## Consequences

### What this makes easy

- Phase 1 ships with zero game-theory dependencies; the TVO engine is pure ledger arithmetic, reproducible by the customer's own offline tooling.
- Every attribution number issued in the deferral window is deterministic, evidence-gated, and immune to the "your counterfactual is a guess" attack.
- The eventual Shapley ADR gets decided on data: observed overlap rates (T-A) or a real randomization budget (T-B), instead of priors.

### What this makes hard

- Sales cannot quote a per-plane savings split; the pitch leans on total TVO delta and the deterministic columns. If a competitor ships a (modeled, indefensible) per-plane number first, we concede that slide on purpose.
- The deterministic columns may double-count overlapping waste until T-A forces resolution; reports must present them as independently-evidenced *categories*, never summed into a single "total waste" figure without a disclosed overlap caveat.

### What we accept

- Thm 7.1 stays shelf IP for now — published, cited in the papers, unexecuted in the product. Accepted because executing it badly (blind `v(S)`, modeled counterfactuals) would spend its credibility rather than bank it.
- "Tokens Cortex would have saved" remains claimable only in its narrow deterministic form (re-reads of already-served digests), which understates Cortex's true value. Understatement is the survivable direction.

## How we would know we were wrong

**Leading indicator that deferral itself was the wrong call:** the overlap metric (T-A) or the contractual demand (T-B) firing — both are defined above with thresholds precisely so this ADR self-expires rather than lingering. Additionally: if two consecutive customer renewals stall specifically on "we can't tell which plane earned its keep" (named objection, not inferred), T-B's demand condition is met in substance even without the exploration opt-in, and the superseding ADR must confront game 2's estimation problem head-on rather than waiting for ε > 0.

**Migration path and cost when a trigger fires:** write ADR-0003-superseding defining `(N, v)` — default game 1 per Decision item 3; implement as a batch module in `mark1-intel.tvo-engine` over the existing rollup columns (game 1 needs no new capture, no schema change: 16 coalition values from ledger queries, exact Shapley in microseconds); present as a new labeled report series alongside — never replacing — the deterministic columns. Estimated cost: the ADR, ~a week of intel-job work, and report-surface changes. Game 2, if T-B: additionally an estimation design (holdout windows, DR/SNIPS over `WIRE_ENFORCED` decisions per C9) reviewed against the same standard as noise certificates — a modeled number ships only with its uncertainty attached.

## References

- `/home/anurag/workspace/Omium/mark1-research/README.md` — Paper I Thm 7.1 (exact, order-independent Shapley decomposition of session waste into iteration / exploration / misallocation / context channels); the defensibility argument (theorems are public; the production trajectory data to run them is not).
- `/home/anurag/workspace/Omium/omium-mark1/docs/spec/execution-plan-v2.md` — Data stores section ("Shapley requires a game-definition ADR before any Shapley code is written"; deterministic taxonomy ships first); contract C9 (propensity + fidelity logging, ε defaults to 0, exploration is per-tenant contractual opt-in); "Decisions to make before code" item 3.
- `/home/anurag/workspace/Omium/omium-mark1/docs/.parts/07-part3-analytics.md` — the deterministic waste-taxonomy formulas (`retry_loop_tokens`, `reexploration_tokens`, `over_model_tokens`) and the standing note "Shapley attribution is deliberately absent … presentation on top of these columns, never a replacement for them".
