# Fusion conformance vectors — the cross-language ADJUDICATE lock

`manifest.json` + the `.json` vector files freeze the ADJUDICATE contract (06 §3.1)
that its **two** implementations must reproduce identically:

- edge — `go/mark1d/internal/verdict` (`Fuser.Fuse`), the hot path;
- cloud — `python/adjudicator/app/adjudicate` (`adjudicate`), the reference.

06 §3 is explicit that this is one algorithm at two deployment points and that
"divergence between them is a CI failure, not a runtime surprise". Until this family
existed, nothing enforced that sentence, and the two had silently drifted in seven
places (absent-member synthesis, accept-branch tie direction, unknown voters, negative
likelihoods, group iteration order, …). Every vector below is one of those divergences
nailed down, or a boundary that would have hidden the next one.

Regenerate with `python3 conformance/vectors/fusion/gen_fusion_vectors.py` (stdlib
only). The committed files are the frozen contract: if regeneration ever changes a
byte, that is a finding against the generator, never a licence to re-freeze.
`selfcheck.py` (stdlib-only) audits manifest/disk consistency without re-deriving any
fusion behavior.

This README is normative where the docs delegate a construction detail (12 §3.4: the
vector commit fixes what the prose left open). Everything else restates 06 §3.1/§3.2,
04 §2.3 and the lead rulings D-V, D-W, D-X, D-AB, D-AK, D-AO, D-AP, D-AQ.

## Where the expectations come from

There is no Rust twin of ADJUDICATE, so the reference cannot be a third codebase. It is
arithmetic instead: `gen_fusion_vectors.py` re-derives every posterior in **exact
rational arithmetic** — `fractions.Fraction` over the parsed float64 inputs, priors
times one collapsed likelihood per clique, normalized, rounded to float64 exactly once
at the end. No logs, no `exp`, no floating addition, and no execution of either
implementation under test. An expectation copied from whichever side ran first would
freeze that side's bug into the referee; this cannot.

**D-AK (lead, binding) — bit-identity is restored by deleting its cause, and D-AC's
1e-12 quantisation is WITHDRAWN.** Nothing in this derivation rounds any more.

IEEE-754 mandates correctly-rounded results for `+ - * /` and `sqrt`; it mandates
*nothing* for `exp`/`log`. Go's pure-Go `math` and CPython's platform libm were
therefore free to land the same fusion one ulp apart, and the Chow rule compares
against exactly `A/R = 1/3` — so that ulp decided whether the edge BLOCKED a developer
the cloud refused to block. D-AC tried to absorb it by rounding the posterior to 1e-12
before the comparison; a review swept 27 constructions sitting on that grid line and
**8 flipped verdict across the two languages, in both directions**. Rounding cannot fix
it: the rounded value is still derived from the transcendental, so every "round, then
compare" variant only relocates the straddle set. All 21 frozen vectors sat off that
set, which is why the family was green throughout and the backstop could not see the
failure it was posted to catch.

So the transcendentals are gone from the verdict path, in both languages:

1. Fuse by **direct multiplication** of likelihoods — no `log`, no `exp`.
2. Prevent underflow **exactly**: rescale the mass vector by a **power of two**
   (`frexp`/`ldexp`, so `max` sits in `[0.5, 1)`) before each clique's multiply. A
   power of two shifts the exponent and touches no mantissa bit, and a common factor
   cancels in the normalisation and in the comparison alike — zero error introduced.
   This is what log-space was actually protecting; it buys nothing else here.
3. Compare by **cross-multiplication**: `u_S·R ≤ A·total` and `u_S·D ≥ (D−A)·total`, on
   the UNNORMALISED mass.

   **D-AO(c) corrects an overstatement here.** This is NOT because division is inexact
   or non-deterministic — IEEE-754 mandates correct rounding for `/` exactly as for `*`,
   so both forms are bit-portable and `u_S·R` rounds like anything else. Division was
   never the portability hazard the transcendentals were. Cross-multiplication is chosen
   on **accuracy**: it needs no derived constant (the divided form must first round
   `1 − A/D`, and A/D is not representable, putting a second rounding on the threshold
   itself) and it is scale-invariant under the frexp/ldexp rescale. The trade runs both
   ways, and Wave D measured it over 300k constructions: at the SATISFIED threshold
   cross-multiplication is wrong 35,616 times against division's 57,384; at the VIOLATED
   threshold under D4 costs division is wrong 0 times and cross-multiplication 22,682.
   It is chosen for the threshold carrying the false-accept cost (D = 9).
4. There is consequently no separate "comparison" copy of the posterior distinct from
   the wire copy.
5. **D-AO(a): no library reduction on either leg, ever.** IEEE-754 pins BINARY `+`; it
   says nothing about an n-ary reduction, and a standard library is free to compensate —
   CPython's built-in `sum()` over floats has used Neumaier summation **since 3.12, a
   point release**, so `sum([0.1]*10)` is `0x1.0000000000000p+0` where a sequential fold
   is `0x1.fffffffffffffp-1`. That one ulp in `total` diverged 6 of the 24 posteriors in
   this family from Go's plain fold and flipped one verdict. `sum()`, `math.fsum`,
   `numpy.sum` and any `slices`-style helper are banned on the verdict path by name;
   both legs accumulate in an explicit loop. Enforced by
   `test_no_library_reduction_is_used_on_the_verdict_path` (AST scan, not prose).

Every operation on the verdict path is a mandated BINARY IEEE-754 operation, so the two
legs agree BIT FOR BIT on the same inputs — D-V's original requirement. **D-AP: that
sentence is now enforced.** It was not before: each leg checked its own posterior
against this manifest inside a 1e-12 tolerance (~4 orders looser than an ulp here) and
`bit_identical_to` compares two vectors *within* one language. `conformance_crosslang.sh`
now has each leg dump the raw IEEE-754 bits of every posterior it computed, and diffs
them. The assertion is **between the legs, never against the manifest**, and that is
forced rather than chosen: this referee rounds once in exact rationals while a float64
implementation rounds per multiply, so an independent generator and a bit-comparable
manifest cannot both exist. Keeping the independent generator puts the bit claim where
both operands are floats.

Both implementations compute in float64 while this referee computes in exact rationals,
so they may sit a few ulps from the derived value:

- **`tolerance` = 1e-12** (manifest), absolute, per posterior component. That is ~4
  orders of magnitude above the accumulated rounding of a 4-clique fusion, so it can
  absorb rounding without ever absorbing a verdict flip.
- The `verdict`, `vote_count` and `unknown_voters` fields are **exact** — no tolerance.
  Five vectors now sit *on* a threshold or on the withdrawn 1e-12 grid's own tipping
  point, where a one-ulp disagreement IS a verdict flip; the tolerance cannot hide one
  there, which is the whole point of them.

### `boundary`: where the oracle is not authoritative on the verdict (D-AQ)

A vector the generator places **within a few ulps of a Chow threshold** carries
`"boundary": true` in its manifest entry. The generator computes this itself, in exact
rationals, from the same cross-multiplied margins the rule uses — `BOUNDARY_ULPS = 4` of
the larger side. It is not a hand-applied label, and it is not a knife edge: across the
25 vectors the margins are either EXACTLY 0 (the three on-threshold constructions) or
≥ 1970 ulps, so any cutoff in between picks the same three.

- **Interior** vectors assert `posterior` (tolerance) and `verdict` (exact) against this
  referee, AND cross-leg identity.
- **Boundary** vectors assert `posterior` (tolerance) and cross-leg identity of the
  posterior AND the verdict — but **not** the verdict against this referee.

The reason is arithmetic, not convenience. This referee rounds ONCE, at the end, in
exact rationals; a float64 leg rounds per multiply. At a case built to sit *on* the
threshold, no float64 evaluation can be expected to reach the exact rational answer —
`chow_boundary_eta_exactly_one_minus_a_over_d` has both legs computing `refused` where
the exact η is exactly 8/9 and the rule says `satisfied`. **Agreement is the property
under test**, and a family that cannot tell "the two legs disagree" from "float cannot
represent the exact answer here" reports one number for two different failures. The
vectors stay, and the interior vectors are not loosened.

Tolerance cannot police iteration order (reordering a product moves the result by one
ulp), so order is policed separately, bit-exactly: `bit_identical_to` names a vector
whose posterior must compare `==` to this one's, component for component, inside each
language.

## Vector schema

Each `<name>.json` is one fusion input:

```json
{
  "name": "worked_example_06_32",
  "doc":  "why this vector exists",
  "priors": [0.55, 0.30, 0.10, 0.05],
  "verifiers": {
    "<verifier_id>": {
      "kind": "compile|lint|judge|...",
      "group": "syntactic",
      "confusion": [[a, r, b], [a, r, b], [a, r, b], [a, r, b]]
    }
  },
  "votes": [{"verifier_id": "...", "verdict": "satisfied|violated|refused|error", "tamper": false}]
}
```

- `priors` and every `confusion` are indexed by the FIXED latent-class order
  `[satisfied, violated, refused, error]` (06 §3, `manifest.classes`), and the three
  confusion columns are `[accept, reject, abstain]` — D-R: the third column IS the
  abstention likelihood, not a residual.
- `verdict` is the raw wire verdict a verifier reported. Drivers map it through their
  own normalizer; the family fixes that mapping so both legs agree:
  `satisfied→accept`, `violated→reject`, `refused→abstain`,
  **`error→abstain + infra_failed`** (the anchor RUN failed — uninformative about the
  customer's code, and never its own likelihood column).
- A vote whose `verifier_id` is absent from `verifiers` is the D-X unlisted voter. A
  verifier present in `verifiers` with no vote is the D-V absent member.
- `"quarantined": true` on a verifier spec is 07's quarantine list (optional, omitted
  when false). The drop belongs to the PRODUCTION bundle compiler — `frombundle.go` on
  the edge, `Bundle.from_verify` in the cloud — and drivers MUST feed it the raw
  `verifiers` section rather than pre-filtering, or the vector tests the driver instead
  of the implementation. (It did: Python had no production quarantine drop at all, and
  `quarantined_voter_no_coverage` could not see that.) Dropped, not zeroed, so the
  verifier reaches fusion indistinguishable from an unlisted one.
- **D-AB**: membership gates COVERAGE, not only likelihood. The D1 evidence count
  increments only for votes that survive the membership filter — unlisted or
  quarantined means no likelihood AND no coverage.
- Costs are NOT per-vector: the edge hardcodes D4's A=1, R=3, D=9, so a vector needing
  other costs would be undrivable there. `manifest.costs` records them for the reader.

`manifest.vectors[]` carries `name`, `file`, `file_sha256_hex` (drivers MUST check it —
a vector edited without regenerating the manifest is drift, not a fixture update),
`expect`, and the expectation block:

| `expect` | meaning |
|---|---|
| `fuse` | a fusion ran; assert `posterior`, `verdict`, `vote_count`, `unknown_voters` |
| `degenerate` | step 0 returned before any likelihood; `posterior` is the one-hot for `verdict` |
| `zero_mass` | the bundle is broken (see below); NO posterior is listed, because none is correct |

plus the optional `boundary` flag (above) and `bit_identical_to`, both emitted only when
set.

## Refusals: the `zero_mass` contract

`zero_mass_inconsistent_bundle` is the one place the two legs are permitted to differ
in FORM, and the family states the difference rather than papering over it. Every class
has been assigned probability 0 by the votes: the bundle contradicts itself, and any
posterior at all would be invented.

- Cloud: `adjudicate` raises `ValueError("zero posterior mass …")` — it is the
  reference, its caller is a request handler, and a broken bundle is an incident.
- Edge: `Fuse` returns `(Verdict, posterior)` and cannot raise on the hot path, so it
  answers the degenerate latent **error** class (`posterior[error] == 1.0`), which is
  06 §3's own name for "the outcome is unobservable because our plane failed".

Both refuse to guess; neither invents a distribution. Any other behavior — an epsilon,
a uniform posterior, a NaN — is a conformance failure in both languages.

## Vectors

| name | expect | proves |
|---|---|---|
| `worked_example_06_32` | fuse | 06 §3.2 verbatim: compile accepts, ruff abstains, judge rejects ⇒ `refused`, posterior [0.3414, 0.5320, 0.0844, 0.0422] to four places as the doc prints them |
| `anchor_reject_clamp` | fuse | 06 §3.2 counterfactual (a): the anchor's reject column collapses the satisfied mass through the ordinary product — Thm 4.2 needs no special-case branch |
| `absent_member` | fuse | **D-V**: a bundle member that has not reported consumes NOTHING. Synthesising its abstain column drove η to 0.3327 and blocked a developer on evidence nobody gathered |
| `absent_member_explicit_abstain` | fuse | the other half of D-V: the same member VOTING abstain does consume the abstain column, and lands on a different posterior. Silence ≠ abstention |
| `tampered_vote_excluded` | fuse | Thm 5.2 + D-V: a tampered vote never enters the likelihood and is not replaced by an abstain either |
| `unknown_voter` | fuse | **D-X**: an unlisted verifier contributes no likelihood (no per-kind default) and is COUNTED, `unknown_voters = 1`. Its unlisted INFRA sibling is not counted — the field counts votes that would otherwise have carried a likelihood |
| `unlisted_voter_no_coverage` | degenerate | **D-AB**: the only listed verifier abstains ⇒ `refused`. The unlisted stranger's reject supplies no likelihood term, so it must supply no coverage either — counted, it flipped this exact input to a BLOCK on a posterior it provably did not move |
| `quarantined_voter_no_coverage` | degenerate | D-AB: a LISTED but quarantined verifier (07) is dropped like an unlisted one, so an explicitly distrusted verifier cannot unlock a block either. `unknown_voters = 1` — dropped, never lost |
| `chow_boundary_eta_exactly_a_over_r` | fuse, **boundary** | **D-AK**: exact posterior[satisfied] = A/R = 1/3 ⇒ `violated`. With `log`/`exp` on the path, a leg's answer here was decided by which side of 1/3 its libm landed on rather than by the rule; with them gone every operation is correctly rounded and both legs decide it identically |
| `chow_boundary_a_over_r_two_cliques` | fuse, **boundary** | the same exact η = 1/3 through TWO cliques: the second is uninformative (flat accept column), so it moves η not at all while forcing the **power-of-two rescale** and the sorted-group loop to run between the boundary and the answer. A rescale that touched a mantissa bit shows up here |
| `chow_boundary_eta_exactly_one_minus_a_over_d` | fuse, **boundary** | the OTHER boundary, which no vector reached: exact η = 1 − A/D = 8/9. D-AQ: both legs compute `refused` here and that is the ANSWER, not a defect — no float64 evaluation reaches the exact rational verdict on the threshold itself, so this vector asserts cross-leg identity instead. Cross-multiplied as `u_S·D ≥ (D−A)·total`, because the float `1 − A/D` is itself a rounding sitting on the threshold |
| `chow_grid_half_point_above_a_over_r` | fuse | one of the constructions D-AC straddled: exact η = 0.3333333333335, so `η·1e12` is exactly `333333333333.5`. Quantised it rounds to `0.333333333334` ⇒ `refused`, one ulp lower to `0.333333333333` ⇒ `violated`. The rule's own answer is `refused` |
| `chow_grid_half_point_below_one_minus_a_over_d` | fuse | the same straddle at the upper threshold: exact η = 0.8888888888885, `η·1e12` exactly `888888888888.5`. Quantised ⇒ `satisfied`, one ulp lower ⇒ `refused`; the rule's own answer is `refused`, so here D-AC's rounding did not merely relocate the straddle — it shipped the wrong side of the band |
| `accept_tie_smallest_id` | fuse | **D-W**, accept branch: equal accept LR ⇒ the LEXICALLY SMALLEST id wins. A plain `max()` picks the largest, which is how the two legs collapsed the same clique to opposite members |
| `reject_tie_smallest_id` | fuse | D-W, reject branch: equal P(reject\|satisfied) ⇒ smallest id |
| `all_abstain_tie_smallest_id` | fuse | D-W, all-abstain branch: smallest id; a second clique supplies the D1 coverage |
| `group_even_split` | fuse | one accept and one reject inside one clique: any reject wins the collapse — the anchor's clamp is never averaged with a soft member |
| `zero_likelihood_veto` | fuse | an exact `0.0` is a legal veto: the class it zeroes gets exactly 0 posterior mass, never an epsilon that would soften a perfect-precision anchor |
| `negative_likelihood` | fuse | a malformed `-0.5` row zeroes its class outright, never becoming a NaN. NaN sails through every downstream comparison and reaches the wire |
| `extreme_log_scores` | fuse | four cliques of 1e-300 likelihoods: direct multiplication drives the mass through the smallest subnormal to zero, and the exact power-of-two rescale buys back exactly what log-space was protecting. Unrescaled this reads as a broken bundle |
| `multi_group_sorted` | fuse | four independent cliques whose product is order-sensitive; votes arrive in sorted id order |
| `group_order_permuted` | fuse | the SAME cliques, votes shuffled ⇒ **bit-identical** to `multi_group_sorted` (04 §2.3: groups are multiplied in sorted group-id order, never map/insertion order) |
| `insufficient_evidence_all_abstain` | degenerate | D1 step 0: no non-abstaining verifier ⇒ `refused`, and nothing was fused |
| `infra_dominant_error` | fuse | step 3: more than half the surviving votes are infra failures ⇒ `error` whatever the posterior says. An outage is never a coverage claim |
| `zero_mass_inconsistent_bundle` | zero_mass | the refusal contract above |

Every implementation MUST drive every manifest entry. Test-name filters are load-bearing
(`tools/ci/conformance_crosslang.sh`): Go `TestConfVectors*` — this family is counted by
the token `ConfVectorsFusion` — and Python `-k conf_vectors`, counted by the token
`conf_vectors_fusion`. Renaming a test to something outside those filters silently
removes a language from the lock, which is why the gate counts per family instead of
globally.

Every implementation MUST also emit its posteriors for the D-AP diff: when
`M1_POSTHEX_OUT` names a file, each leg appends one
`<vector> <verdict> <4 × big-endian float64 bits, hex>` line per vector it fused
(`zero_mass` excepted — neither leg produces a posterior there, by the contract above).
The gate fails if either file is empty, so removing the hook is a red gate, not a
quietly weakened one.
