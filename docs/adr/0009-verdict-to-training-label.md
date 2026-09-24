# ADR-0009 — Mapping the four-verdict vocabulary onto the trainer's binary KTO label

- **Status:** Accepted — signed by Anurag Upadhyay (founder) 2026-09-16, as recommended by the lead; the ruling is recorded in docs/history/RECONCILIATION.md (D-EI).
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap for future exports, impossible for past training runs — corpus exports are immutable and receipted (a corrected export is a new `export_id`, never a rewrite), so changing the mapping is a new exporter release producing new exports under the new rule; nothing historical is restated and every old export's receipt stays valid. What cannot be reversed: gradient updates already taken from a corpus built under the old mapping. A model trained on a mis-mapped corpus is retrained from checkpoints, at GPU cost, not patched.
- **Blocks:** `mark1-intel.corpus-exporter` (the KTO JSONL emission path); the Phase 5 gate artifact (first corpus export consumed by `data-refinery`/the trainer); any LEARN-plane work that consumes Mark 1 rows. This is reconciliation finding **R-02** — the decision was made in-document by `07`'s author and needs a founder-signed record.

## Context

Mark 1's verdict vocabulary is four-valued and frozen at the type level: `satisfied | violated | refused | error` (adopted verbatim from platform migration `008`; Paper II Thm 5.1–5.2 proves the four-verdict scheme Bayes-optimal). The trainer's wire shape, `KtoRow` (`training-jobs/src/training_jobs/rows.py`), is binary: `label ∈ {desirable, undesirable}` with `reward ∈ {1, 0}`, and the trainer *drops* any row whose reward and label disagree (`reward_label_mismatch`, counted). Two verdict values therefore have no defined image, and — as R-02 records — neither the plan nor the spec says what happens to `refused` and `error` at export. `07` §7 (corpus schemas) resolved it in-document; this ADR is that resolution made a recorded, signed decision.

The semantic content of the two orphan verdicts matters:

- `refused` — the adjudicator abstained: the evidence did not support any confident verdict. Paper II Thm 5.1 proves the abstaining rule strictly dominates every binary verifier (the Chow band); refusal is frequently the *correct* output.
- `error` — the verification infrastructure itself failed (toolchain broken, anchor crashed, sandbox unavailable). Paper II Thm 5.2 proves that conflating infrastructure failure with `violated` incurs unavoidable excess risk: an `error` carries no information about the *completion's* quality, only about the environment's ability to measure it.

## Decision

The corpus exporter maps verdicts to KTO rows as follows, for certified/revised verdicts only (provisional rows never export):

| Verdict | KTO export |
|---|---|
| `satisfied` (certified) | `label = desirable`, `reward = 1` |
| `violated` (certified) | `label = undesirable`, `reward = 0` |
| `refused` | **not exported to KTO** |
| `error` | **not exported to KTO** |

Exclusion is total for the KTO pair (`rows.jsonl` + `manifest.json`). The **Parquet analytics mirror keeps all four verdicts** with full posteriors — exclusion is a training-signal decision, not a data-retention decision, and the excluded population stays measurable forever.

Two accounting requirements make the exclusion honest rather than silent:

1. **Counted, not vanished.** The export receipt records the number of certified tasks excluded per verdict class alongside the row count, so every export states what it left out.
2. **The exclusion rate is a product metric.** `excluded_fraction = (refused + error) / certified_total` per tenant per export is computed by the exporter and lands in the corpus telemetry — it is the leading indicator below.

**The second-order effect, stated plainly.** Excluding `error` rows biases the corpus toward environments where the toolchain works — which is exactly the population where verification is cheapest and Mark 1's marginal value is lowest. The customers with flaky sandboxes, broken CI, and test-poor repos are the ones with the most waste to save *and* the highest `error` rates; under this mapping they contribute the least training signal per session. What that costs: models trained on this corpus will be best-adapted to the environments that need them least, and per-tenant fine-tunes for exactly the highest-value tenants will be data-starved relative to their session volume. We accept this now because a biased-but-clean preference signal beats a complete-but-poisoned one (Thm 5.2's excess risk is *unavoidable*, not merely undesirable), and because every later remedy — a third label class, a separate abstention/error head, reward shaping over `label_confidence`, or propensity reweighting by inclusion probability — requires trainer-side changes that violate the standing no-cross-repo constraint today (see R-03 for how contested even a one-field trainer change is). The exclusion counters in requirement 2 are precisely the data those remedies would need, so deferring the fix does not defer the measurement.

## Alternatives considered

### Map `refused` → `undesirable` (reward 0)

**Strongest case:** from the *user's* seat, a session that ends in adjudicator abstention delivered no verified outcome — they paid tokens and got no certified result. If the trainer's job is to increase verified outcomes per token, then everything that is not `satisfied` is, economically, a failure to produce one, and training against it pushes the policy toward completions that verify cleanly.

**Why it lost:** it punishes the measurement for the measurand. `refused` means *our evidence was insufficient*, not *the completion was bad* — a correct fix in a repo with no anchors coverage earns `refused` through no fault of the completion. Labeling it `undesirable` teaches the policy to avoid *hard-to-verify* work, not bad work — an incentive directly against the product's expansion into test-poor environments, and against Paper II's central result that abstention is the optimal action in the Chow band. It would also poison the corpus with false negatives at a rate set by anchor coverage, which varies by tenant — making label quality a function of who bought which anchors.

### Map `error` → `undesirable` (reward 0)

**Strongest case:** empirically, sessions that end in infrastructure errors are not a random sample — agents that wedge toolchains, write pathological tests, or trash their sandbox generate more `error` verdicts, so the verdict plausibly carries *some* signal about undesirable agent behavior. Excluding it discards that correlation, and the binary trainer has no other channel to receive it.

**Why it lost:** Paper II Thm 5.2 is directly on point — conflating infrastructure failure with `violated` incurs unavoidable excess risk, and reward 0 *is* that conflation in the trainer's loss. The correlation in the steelman is real but confounded: `error` rates are dominated by environment quality (the tenant's toolchain), not completion quality, so the label would mostly teach the model which *tenants* have broken CI. Where agent behavior genuinely causes the error, the causal event is usually visible as a prior `violated` or in the deterministic waste columns — channels that carry the signal without the confound.

### Keep both, with reward 0.5

**Strongest case:** a middle reward preserves corpus coverage — no environment's sessions vanish — and gradient-based preference methods can in principle exploit a soft target as an uncertainty encoding, sidestepping the false-negative problem of the reward-0 mappings.

**Why it lost:** it is unimplementable against the actual contract and wrong even if it weren't. `KtoRow.reward` is an **int constrained to 1|0 that MUST match the label** — a 0.5 row is `reward_label_mismatch`, dropped and counted; KTO itself is a binary-preference objective with no defined semantics for a half-desirable example. Honoring this alternative would mean changing the trainer's wire contract and loss (a cross-repo change far larger than R-03's contested one field) to encode a signal — "we don't know" — that is more faithfully encoded by absence. An excluded row *is* the honest 0.5.

### Train a separate abstention model

**Strongest case:** the principled endgame. `refused`/`error` are a rich signal about *when verification will fail* — a model predicting abstention/error from context could route verification spend, pre-warn on flaky environments, and eventually feed a three-headed objective that uses all four verdicts losslessly. Paper II's machinery (abstention models per verifier, `P(abstain | true verdict)`) already treats silence as information in the fusion layer; extending that to the learned tier is coherent, not speculative.

**Why it lost — as a *now*:** there is no trainer for it. The existing KTO/QLoRA pipeline is the only training path in the estate, it is binary, and standing up a second objective head is Phase 6 LEARN-plane work gated behind probation → shadow → LCB promotion. Building it today would be scope returning through the corpus door. It loses as a present decision and is explicitly named as the preferred future remedy: the exclusion counters and the Parquet mirror (which retains all four verdicts with posteriors) preserve every byte it will need.

## Consequences

### What this makes easy

- The exporter is a pure function of certified verdicts with no trainer-side changes — the Phase 5 seam stays additive (the R-03 one-field question is unaffected either way).
- Corpus label quality inherits Paper II's guarantees: every exported label is a certified, noise-certificated preference signal; no label encodes environment health.
- The trainer's existing drop taxonomy and `assert_trainable` invariants hold without modification; `reward` and `label` are consistent by construction.

### What this makes hard

- Per-tenant fine-tuning for high-`error` tenants (the highest-value population) is data-starved relative to their volume; corpus growth curves will understate flywheel progress for exactly the tenants the sales narrative features.
- Any future model claiming competence in test-poor environments must confront the fact that its training distribution under-represents them — the claim needs the coverage caveat until a remedy ships.

### What we accept

- A corpus population bias we can measure but not yet correct, in exchange for label cleanliness we cannot later retrofit (a poisoned label, once trained on, costs a retrain; a missing row costs nothing but time).
- That `refused` — often the *correct* system output — generates zero training reward, so the trainer never directly learns to value calibrated abstention. That signal waits for the separate-head future.

## How we would know we were wrong

**Leading indicator:** the per-tenant `excluded_fraction` from requirement 2. Concretely: if the median tenant's excluded fraction exceeds **25%**, or any *paying* tenant's exceeds **50%**, over a trailing month of exports, the corpus is unrepresentative of the population we sell to and the exclusion policy is costing more signal than the poisoning it prevents. Secondary indicator, once models train: holdout evaluation stratified by environment `error`-rate quartile — if the trained model's uplift in the top-quartile (flakiest) environments is statistically indistinguishable from zero while bottom-quartile uplift is strong, the bias has propagated into capability and the remedy can no longer wait.

**Migration path and cost:** the remedies, in ascending order of trainer intrusion — (1) **propensity reweighting:** export an inclusion-probability column and reweight the KTO loss per row; needs one optional field and a loss-weighting change in the trainer. (2) **Reward shaping over `label_confidence`:** already an exported Parquet column; needs the trainer to accept a float target — a larger objective change. (3) **Third label class / separate abstention-error head:** the principled fix, Phase 6 LEARN-plane scope, entering via the standard probation → shadow → LCB promotion path. All three are *new exports under a new exporter version* consumed by a *new training run* — no historical export is restated (immutable-export rule), and any model trained under the old mapping is superseded through the promotion pipeline, not patched. Cost: exporter release + trainer change (founder authorization required per the cross-repo constraint) + one retrain cycle on the GPU pool.

## References

- `/home/anurag/workspace/Omium/omium-mark1/docs/history/RECONCILIATION.md` — **R-02** (the finding this ADR resolves: the mapping existed nowhere; `07` decided it in-document; the second-order bias note originates here). Related: R-03 (the `completion` field cross-repo question), R-19 (`filter_by_sigs` drops unsigned rows — correct for Mark 1).
- `/home/anurag/workspace/Omium/omium-mark1/docs/.parts/07-part3-analytics.md` — §Corpus schemas: the `KtoRow` wire mirror (label/reward constraints, drop taxonomy `malformed / empty / non_train_split / reward_label_mismatch`), the in-document resolution ("`refused` and `error` rows are not exported to KTO at all (Paper II: infrastructure failure is not a preference signal)"), the Parquet mirror retaining all four verdicts with posteriors and `label_confidence`, and the immutable-export / one-receipt-covers-the-pair rule.
- `/home/anurag/workspace/Omium/mark1-research/README.md` — Paper II Thm 5.1 (abstaining rule strictly dominates every binary verifier; the Chow band) and Thm 5.2 (conflating infrastructure failure with `violated` incurs unavoidable excess risk; the four-verdict vocabulary proved Bayes-optimal).
- `/home/anurag/workspace/Omium/omium-mark1/docs/spec/execution-plan-v2.md` — the four-verdict vocabulary adopted verbatim from platform migration `008`; Appendix A delta 1 (the trainer reads `manifest.json` + `rows.jsonl`, not Parquet; Arrow shards carry no label column).
