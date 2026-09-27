# ADR-0014 — Non-serving members enter estimation, not fusion; promotion is tethered to gold

- **Status:** Accepted — approved by Anurag Upadhyay (founder) 2026-09-26 as part of `docs/design/16-release-savings-rm.md` (lane L6, "shadow members enter estimation, not fusion (amends 06 §4.4)")
- **Date:** 2026-09-26
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap — a filter in `nightly.vote_matrix` and a measurement source in `promotion.step`; no stored row changes meaning, and m1_098's gold path only relaxes a CHECK
- **Blocks:** certifying anything with the T2 reward models; promoting the third clique at all

## Context

06 §4.4 said a `probation` verifier shadow-votes with no fusion weight until it has ≥ 500 votes measured against the ensemble's **certified** verdicts, and only then enters estimation. Certification (06 §5.3) needs the identifiability gate, which needs three independent correlation groups (Paper II Thm 4.1). With the E0 judge reclassified as a derived view of the anchors (16 §Independence rules), the ensemble without the RM has two groups at most — so nothing is ever certified, so no RM is ever measured, so no third group ever enters estimation. The spec was circular for exactly the member it exists to admit (rm-design §4.4, D-RM3).

## Decision

1. **Estimation reads every member's votes; fusion reads only serving ones.** A non-`active` member's column is in the spectral vote matrix from its first vote and gets a law; `split_shadow` keeps its votes out of every `adjudicate` call (a canary member is fused only on its hashed ~10% slice). Estimation weight is not fusion weight: a shadow member can change the *laws* the estimator reports, never a verdict.
2. **The tether is the human/T3 gold set.** A candidate's pairs are its vote against the gold label where the task has one (`label_source IN ('t3','human')`), else — for a member not yet serving — against the task's certified ledger verdict under a live cert. Never escalations (ambiguity-selected, so a biased sample) and never `batch-readjudication` gold (the ensemble grading itself).
3. **Promotion may rest on gold.** ≥ 500 member votes and either ≥ 500 certified pairs or ≥ 200 gold overlaps (D15); m1_098 lets `lcb_promoted` carry `cert_id IS NULL` when `gold_n ≥ 200`, and still asserts the cert live when one is named.
4. **The estimator's own claim is checked against gold.** Because a shadow member now shapes the laws, every passed spectral run persists its Thm 6.1 predicted noise; a prediction outside the gold interval is a structural violation that holds the certificate at `bootstrapping` (06 §4.3).

## Consequences

- The third clique is measurable the night it starts voting, and certifiable once G1–G6 pass *and* its predicted noise agrees with gold.
- A correlated or derived member can no longer buy a certificate by making the ensemble look stronger: identifiability passes, the structural check does not.
- Rejected: exempting learned members from the certified-verdict rule only (keeps the circularity for any future third view); promoting on the spectral estimate alone (the member would grade itself); zero-weight estimation columns (a column the estimator ignores is not measured).
