# ADR-0008 — Judges run client-side first, through the customer's own key; free-form LLM judging is banned

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** expensive — the default is wired into the consent model, the subprocessor register, the evidence-tier contract (C4), every enterprise conversation, and the tenant-facing privacy language; flipping the default later is a config change technically and a trust-posture reversal commercially
- **Blocks:** nothing before Phase 4 (T1 judges); recorded now because C4 and the threat model already assume it and the adjudicator design consumes it

## Context

Judges are the T1 ensemble members of the VERIFY plane: model-scored evaluations that join deterministic anchors and (opt-in) tests in verdict fusion. Two questions define their design: **where do they run** (whose machine sees the evidence, whose key pays the tokens) and **what are they allowed to be** (grounded rubric scorers vs. free-form "rate this code" judging).

Contract C4 fixes the evidence tiers:
- **E0 (default):** typed `EvidenceRecord` only — tool, diagnostic code, category, counts, path role, output HMAC; no paths, no excerpts, no free text. An E0 judge is modeled as a **low-power ensemble member**: little to see, honestly weighted as such by its measured confusion matrix.
- **E1 (per-tenant opt-in):** sanitized diff hunks, every upload redaction-receipted.
- **E2 (full diff):** VPC or self-host only — the evidence's destination is the customer's own infrastructure, never Omium cloud.

The load-bearing citation for the second question is **Paper I, Corollary 4.3** (`mark1-research/`): Theorem 4.2 gives the verifier break-even `v* = (1−p)·D·(α−β) − c(1−α)` — verification pays iff its Youden discrimination clears an explicit economic threshold — and Cor 4.3 converts it to a necessary AUC condition: **grounded rubric verification (AUC 0.886) clears break-even at roughly 2×, while free-form LLM-judge verification (AUROC ≤ 0.65) fails it economically.** A free-form judge is not merely a weaker ensemble member; at literature-calibrated discrimination it is a verifier whose tokens cost more than its verdicts are worth. That is a design rule, not a preference.

## Decision

1. **Judges default to running client-side, on the customer's machine, through the customer's own model key.** Evidence never leaves the machine on the default path — the strongest privacy control in the verify plane is that the evidence-egress question usually never arises.
2. **Cloud judges are a per-tenant opt-in requiring all three of:** tenant consent flag, a subprocessor-register entry (who processes what, under which DPA), and region pinning for all judge-bound evidence. Each is receipted; absence of any one refuses the cloud path (`12/judge-cloud-path-requires-consent`).
3. **Evidence tiers per C4:** E0 by default everywhere; E1 by tenant opt-in with per-upload redaction receipts; E2 only where the customer's own VPC or self-host deployment is the destination.
4. **Free-form LLM judging is banned — not discouraged, banned.** Every judge is a grounded rubric scorer: it receives typed evidence (plus tier-appropriate hunks), scores against an explicit rubric with a constrained output schema, and emits a `JudgeVote` whose confusion matrix is measured by the same Dawid–Skene machinery that certifies everything. A free-form "is this good code?" judge cannot clear `v*` at its published discrimination (Cor 4.3), so admitting one would knowingly ship a component that destroys TVO while claiming to improve it. The adjudicator's judge registry rejects unrubriced judge definitions at registration, the same way bundles reject command strings — invalid by construction, not by review.
5. Judge prompts/rubrics distribute as bundle data (versioned, signed); judge identity and rubric version travel on every `JudgeVote`, so fleet skew is measurable rather than mysterious.

## Alternatives considered

### Cloud-side judging by default, with an opt-out

The strongest case — and it deserves its full weight, because operationally it is the *better* engineering position on almost every axis: **uniform judge versions** (one prompt, one model snapshot, no fleet skew), **observable failures** (a misbehaving judge is in our logs, reproducible on our infrastructure, fixable in one deploy), **centralized rubric iteration** (A/B a rubric change against the gold set in an afternoon instead of shipping a bundle and waiting for fleet convergence), **cheaper tokens** (Batch API discounts, prompt caching across tenants' structurally similar evidence), and **a cleaner TVO story for the customer** — the judge spend lands on Omium's bill, so the numerator the customer sees shrinks by exactly the judging cost. Every ML-evaluation platform in the industry runs this way, for these reasons.

Why it loses anyway: the default direction of evidence flow is the product's privacy architecture. "Raw sessions and code stay client-side" is a hard constraint of the frozen plan, made physical by E0-typed capture, edge-held raw evidence, and client-side judging — reverse the judge default and evidence egress becomes the *normal case*, which (a) converts every enterprise procurement from "nothing leaves by default, here is the receipt system that proves it" into a DPA negotiation about code egress with a subprocessor attached for every tenant rather than for consenting ones; (b) re-opens the correlated-leak blast radius the design closed everywhere else — Omium cloud holding a stream of E1 hunks for all tenants is a target the current design simply does not contain; and (c) inverts the consent model the receipts assume: opt-*out* consent for evidence egress is exactly the posture the threat model's hostile auditor is paid to find. The operational wins are real and are partially recoverable inside the chosen default (versioned rubric bundles, judge-version stamping, gold-set-anchored calibration); the trust reversal is not recoverable once the default has shipped.

### Hybrid default by tier: E0 to the cloud, E1+ client-side

The strongest case: E0 is *typed counts and HMACs* — it discloses no code, so cloud-judging it by default costs little privacy while restoring uniform versions for the lowest-power member; the sensitive tiers stay client-side. Why it loses: it splits the judge fleet across two execution environments for the *least valuable* member (E0 judges are honestly weak — that is what "low-power ensemble member" means), buying uniformity where it matters least while doubling the operational surface (two judge runtimes, two failure stories, two calibration populations for D-S). And it muddies the sales sentence: "evidence never leaves by default" becomes "evidence that we consider non-sensitive leaves by default," which is a lawyer's sentence, not a seller's. The simplification is worth more than the E0 uniformity.

### Allowing free-form judges as "advisory-only" ensemble members

The strongest case: free-form judges are cheap to build, cover failure modes rubrics haven't anticipated, and D-S calibration would honestly down-weight them — the machinery is designed to absorb weak members, so why ban rather than let the confusion matrix speak? Why it loses: Cor 4.3 says the problem is not the verdict quality (fusion does absorb that) but the *economics* — the customer pays real tokens for a member whose discrimination cannot clear its own cost at published AUROC. An advisory member that can never pay for itself is a permanent tax dressed as coverage, and "advisory-only" designations erode under exactly the pressure that made the plan delete the `wasm_module` field rather than mitigate it. Banned means the temptation has no API to land on.

## Consequences

### What this makes easy
- **The enterprise-procurement conversation.** The default answer to "what code leaves the developer's machine?" is *none* — no DPA rider, no subprocessor for non-consenting tenants, region pinning and consent receipts for those who opt in. This is the cheapest security-review posture available to a product in this category.
- The privacy architecture stays one story: E0-typed capture, client-held raw evidence, client-side judging, and salt-scoped digests all point the same direction; there is no "except judges" footnote.
- The ban gives the adjudicator a crisp admission rule (rubric + schema or rejected), and Paper I gives every judge a standing economic test: a judge class whose measured discrimination stops clearing `v*` is retired by the same arithmetic that admitted it.

### What this makes hard
- **The customer pays the judge tokens, inside the numerator we are selling a reduction of.** Be honest about this tension: Mark 1's pitch is fewer tokens per verified outcome, and client-side judging *adds* token spend on the customer's own key. The defense is not hand-waving, it is Theorem 4.2 — judging is admitted only where its discrimination makes the TVO *net* lower (break-even cleared ~2× at rubric-grade AUC), and the ledger shows the customer both sides of that arithmetic per report. But the optics are real: the invoice line the customer sees grows before the outcome line shrinks, and the TVO story must be told with the closed form, not with vibes.
- **Debugging judges on machines we cannot see.** A judge misfiring in a customer's environment reproduces only from typed `JudgeVote` diagnostics, rubric/version stamps, and receipts — no logs, no REPL. Mitigations: conformance fixtures per rubric version, `mark1 doctor` surfacing the local judge configuration, and D-S drift detection flagging device populations whose judge error rates diverge. It is still strictly harder than tailing our own service logs.
- Fleet skew is a permanent calibration concern: judge model versions ride the customer's key and the customer's model access, so the "same" judge is not byte-identical across the fleet — the noise-certificate machinery must treat judge version as a first-class stratum.

### What we accept
- Slower rubric iteration (bundle-push cadence rather than server deploy cadence).
- That E0-default judges are weak, and reports over E0-only tenants will honestly carry wider bands — the alternative (pressuring evidence opt-in to improve our own numbers) is the incentive this design deliberately refuses.
- Forgoing cross-tenant prompt-cache economics on judge traffic.

## How we would know we were wrong

**Leading indicators, measurable:**
1. **Certification degradation attributable to fleet skew:** the share of tenants stuck in `uncertified/bootstrapping` status, or D-S-measured judge error-rate variance across devices *within* a rubric version, trending materially above the same rubric's gold-set-measured rates — the signal that client-side execution variance (model versions, truncation, local failure modes) is costing more verdict quality than evidence egress would have.
2. **The economics inverting:** ledger-measured judge token spend per verified outcome exceeding the `v*` bound for a judge class across a quarter — Paper I's own arithmetic saying that class no longer pays at fleet-realized (not literature) discrimination.
3. **The market not caring:** if a majority of enterprise tenants opt into the cloud path unprompted within their first quarter, the privacy default is protecting a preference customers do not hold, and the operational costs are being paid for nothing.

**Migration path and cost:** the machinery for cloud judging already exists (it is the opt-in path — consent flag, subprocessor register, region pinning, receipts), so "flipping the default" is technically a bundle/config change plus consent-flow inversion: weeks of engineering. The real cost is commercial and irreversible in the way trust changes are: every security review that was answered with "nothing leaves by default" has to be re-answered, and the tenant-facing privacy language must be re-consented, not silently amended. That asymmetry — cheap to loosen technically, expensive to loosen reputationally, nearly free to have started strict — is precisely why the strict default is the right opening position. The free-form ban has a separate, simpler wrongness test: a published, adversarially credible free-form judging method clearing AUC ≈ 0.89-grade discrimination at rubric-grade cost would void Cor 4.3's premise; the ban is repealed by updating the same arithmetic that imposed it, and the registry admits the newly economic judge class with a measured confusion matrix like any other member.

## References
- `docs/spec/execution-plan-v2.md` — contract C4 (evidence tiers, client-side default), C5 (noise certificates), Phase 4 gate; "raw sessions and code stay client-side made physical"
- `/home/anurag/workspace/Omium/mark1-research/README.md` — Paper I Thm 4.2 (`v*` break-even) and **Cor 4.3** (grounded rubric AUC 0.886 clears break-even 2×; LLM-judge AUROC ≤ 0.65 fails economically) — the load-bearing citation; Paper II (four-verdict optimality, self-certifying labels)
- `docs/10-security-threat-model.md` — §10.4 (what each tier actually discloses; subprocessor register; region pinning), §2.4 B-V row on cloud-judge consent, §11.3 (learned-member reward hacking, the adjacent arms race)
- `docs/06-lld-intelligence.md` — adjudicator judge orchestration, gold-set lifecycle, D-S calibration
