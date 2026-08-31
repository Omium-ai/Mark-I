"""ADJUDICATE (06 §3.1, Paper II's algorithm) — weighted majority over verifier votes
with clique collapse, the four-verdict posterior [satisfied, violated, refused, error],
the error path (Thm 5.2), and the Chow band (Thm 5.1).

D-AK (lead, binding): the fusion is a DIRECT PRODUCT of likelihoods, not a logsumexp.
IEEE-754 mandates correctly-rounded `+ - * /` and `sqrt` and mandates NOTHING for
`exp`/`log`, so the transcendentals were the sole reason Go's pure-Go `math` and
CPython's platform libm could land one ulp apart on the same fusion — and one ulp is
the difference between the edge BLOCKING a developer and the cloud refusing to, since
the Chow rule compares against exactly A/R. Removing them restores bit-identity (D-V)
by deleting its cause; the quantisation D-AC added to paper over it is WITHDRAWN
(rounding only relocates the straddle set — the rounded value is still derived from
the transcendental). Log-space bought underflow headroom and nothing else, and that
is bought back exactly by the power-of-two rescale in the fusion loop below.

Phase 2 note: this IS the "weighted-majority with bundle priors" estimator 06 §4.3
degrades to — one algorithm; only the confusion matrices' provenance changes when the
Phase 4 spectral estimator starts writing `spectral` rows. The anchor step (Thm 4.2)
needs no special-case branch: the clamp IS the likelihood — an anchor's tiny
P(reject|satisfied) collapses the satisfied mass through the ordinary product, and
anchor confusion rows are never smoothed toward symmetry (§4.5), because their
asymmetry is the identifying fact."""

import math
from dataclasses import dataclass

from app.adjudicate.chow import Costs, chow_verdict
from app.adjudicate.likelihoods import Bundle, VerifierParams, likelihood
from app.registry.handlers import NormalizedVote

# D1 (06 §3.1 step 0): fewer than 1 non-abstaining verifier ⇒ insufficient evidence.
MIN_EVIDENCE = 1
# D3 (06 §3.1 step 3): posterior[error] above this ⇒ the error verdict.
THETA_ERROR = 0.5
# DESIGN, unnumbered in 06 (`infra_dominant(votes)` is named but not pinned): more than
# half the surviving votes carrying an infra failure means the window's evidence is
# about OUR plane, not the customer's code — Thm 5.2 says folding that into `violated`
# incurs unavoidable excess risk.
INFRA_DOMINANT_FRAC = 0.5

_S, _V, _R, _E = 0, 1, 2, 3
_VERDICT_BY_IX = ("satisfied", "violated", "refused", "error")
# Degenerate posteriors for the step-0 returns: all mass on the emitted verdict, so
# posterior[4] still disambiguates which kind of `refused`/`error` this was (06 §3,
# "Latent classes") and the wire's exactly-4 invariant holds.
_DEGENERATE = {
    "refused": (0.0, 0.0, 1.0, 0.0),
    "error": (0.0, 0.0, 0.0, 1.0),
}


@dataclass(frozen=True)
class VerdictEvent:
    """Mirror of proto m1p.v1.VerdictEvent (posterior: EXACTLY 4, FIXED ORDER), plus
    the pseudocode's local `reason` diagnostic and the likelihoods' `provenance`
    (not wire fields)."""

    stage: str
    verdict: str
    posterior: tuple[float, float, float, float]
    noise_cert_id: str  # "" ⇒ honestly uncertified/bootstrapping (proto comment)
    vote_count: int
    reason: str | None = None
    provenance: str = "prior"  # weakest 06 §1.3 provenance that entered the fusion
    # D-X accounting (the edge's Cached.UnknownVoters): votes whose verifier the
    # bundle does not list. They contribute no likelihood, and are not lost either.
    unknown_voters: int = 0


# 06 §1.3 vocabulary, weakest first: a fusion's provenance claim is only as strong as
# its weakest likelihood row (one literature default anywhere ⇒ the verdict is not
# built on measured matrices).
_PROVENANCE_RANK = {"prior": 0, "shrunk-global": 1, "spectral": 2}


def _stamp(used: list[VerifierParams], noise_cert_id: str) -> tuple[str, str]:
    """(stage, provenance) — the claims permitted about the math (06 §5, §3.1).

    `CERTIFIED` is earned twice over: every likelihood row that entered the fusion was
    measured (spectral/shrunk-global, never a literature `prior`) AND a noise
    certificate is actually stamped. Anything less gets the honest §5.3 vocabulary:
    `bootstrapping` when a certificate exists but the matrices are priors (§4.3's
    degradation wording verbatim), `uncertified` when nothing is stamped at all —
    which includes the step-0 degenerate verdicts, where no likelihood entered."""
    provenance = min(
        (p.provenance for p in used), key=_PROVENANCE_RANK.__getitem__, default="prior"
    )
    if noise_cert_id and provenance != "prior":
        return "CERTIFIED", provenance
    return ("bootstrapping" if noise_cert_id else "uncertified"), provenance


def _rescale(u: list[float]) -> list[float]:
    """Pull the mass vector back up to max ∈ [0.5, 1) by a POWER OF TWO — the exact
    replacement for what log-space was actually protecting (D-AK step 2).

    Scaling by 2**k shifts the exponent and touches no mantissa bit, so it introduces
    zero error, and a common factor cancels in the normalisation and in the
    cross-multiplied Chow comparison alike. Without it, four cliques of 1e-300
    likelihoods multiply straight through the smallest subnormal to zero and a
    perfectly ordinary fusion reads as a broken bundle.

    frexp/ldexp rather than D-AK's fixed 2**-512 threshold: that constant leaves only
    512 binary orders of headroom, and ONE 1e-300 likelihood (2**-996.6) eats all of
    it — `extreme_log_scores` underflows to zero mass under any placement of the fixed
    pair. Renormalising to a fixed window before every group multiply is the same
    exact mechanism with the shift chosen from the data instead of guessed."""
    _, exp2 = math.frexp(max(u))  # max = m·2**exp2, m ∈ [0.5, 1); frexp(0.0) ⇒ 0
    return [math.ldexp(x, -exp2) for x in u]


def _group_observation(
    members: list[tuple[NormalizedVote, VerifierParams]],
) -> tuple[NormalizedVote, VerifierParams]:
    """One observation PER GROUP (06 §3.1 step 2): correlated members are one fact
    about the diff, so the group contributes exactly one likelihood term — the single
    strongest signal, chosen deterministically.

    DESIGN (06 leaves the collapse rule open; recorded, not improvised):
    - any reject ⇒ the sharpest rejecter (min P(reject|satisfied)) — preserves the
      anchor's perfect-precision clamp whole, never averaged with a soft member;
    - else any accept ⇒ the most informative accepter (max accept likelihood ratio);
    - else all abstained ⇒ first by verifier_id; honest silence contributes its
      abstain likelihood (silence is information, never imputed — 06 §2.5)."""
    rejects = [(v, p) for v, p in members if v.vote == "reject"]
    if rejects:
        return min(rejects, key=lambda vp: (vp[1].confusion[_S][1], vp[0].verifier_id))
    accepts = [(v, p) for v, p in members if v.vote == "accept"]
    if accepts:

        def accept_lr(vp: tuple[NormalizedVote, VerifierParams]) -> float:
            a_s, a_v = vp[1].confusion[_S][0], vp[1].confusion[_V][0]
            return a_s / a_v if a_v > 0.0 else math.inf

        # D-W: highest LR wins, ties to the SMALLEST verifier id — like the other
        # two branches, and like the edge. A plain max() breaks ties toward the
        # largest id and cannot be told otherwise for string keys, which is how the
        # two implementations picked opposite members of the same clique.
        return min(accepts, key=lambda vp: (-accept_lr(vp), vp[0].verifier_id))
    return min(members, key=lambda vp: vp[0].verifier_id)


def _infra_dominant(votes: list[NormalizedVote]) -> bool:
    if not votes:
        return False
    # D-AO(a) bans library reductions on the VERDICT PATH because they may compensate;
    # this one reduces ints, where compensation is a no-op and exactness is total. It is
    # the single permitted `sum()` in this module — do not "fix" the loop at step 2 to
    # match it, and do not add a second one here.
    infra = sum(1 for v in votes if v.integrity.infra_failed)
    return infra / len(votes) > INFRA_DOMINANT_FRAC


def adjudicate(
    votes: list[NormalizedVote],
    bundle: Bundle,
    costs: Costs | None = None,
    noise_cert_id: str = "",
) -> VerdictEvent:
    """06 §3.1's pseudocode, step for step. The certificate is STAMPED, never
    consulted: the math does not change with its status, the claims permitted about
    the math do (06 §3)."""
    costs = costs or Costs()

    # Step 0 — integrity partition (Thm 5.2: infra failure ≠ violated).
    tampered = [v for v in votes if v.integrity.tamper]
    votes = [v for v in votes if not v.integrity.tamper]  # NEVER enter the likelihood
    # infra-failed votes are uninformative on E (λ ⊥ Y | E): they contribute no
    # likelihood term below, only the infra_dominant signal at step 3.
    informative = [v for v in votes if not v.integrity.infra_failed]

    # D-AB: membership gates COVERAGE, not only likelihood — so the bundle filter runs
    # BEFORE D1, not after. Counted first, an unlisted (or quarantined) verifier lifts
    # coverage over MIN_EVIDENCE while contributing no likelihood term at all: the
    # posterior is then priors × the listed members' columns alone, unchanged, yet the
    # gate flips from refused to a BLOCK. An unknown party must not unlock a block on
    # evidence it provably did not supply.
    groups: dict[str, list[tuple[NormalizedVote, VerifierParams]]] = {}
    unknown = 0
    coverage = 0
    for v in informative:
        p = bundle.params_for(v.verifier_id, v.kind)
        if p is None:  # D-X: unlisted verifier — no likelihood, but counted
            unknown += 1
            continue
        if v.vote != "abstain":
            coverage += 1
        # An empty group is "independent", its own clique — never a shared bucket
        # named "" that silently collapses every ungrouped verifier into one.
        groups.setdefault(p.group or f"\x00solo:{v.verifier_id}", []).append((v, p))

    if coverage < MIN_EVIDENCE:  # D1
        # `error` when the evidence is missing BECAUSE our plane failed (tamper or
        # infra failure — 06 §3's latent `error`: "the outcome is unobservable because
        # infrastructure failed"); `refused` only for honest silence. The pseudocode's
        # `error if tampered` names tamper alone; extending it to infra-failed votes
        # is Thm 5.2 applied to the same branch — an outage is never a coverage claim.
        infra = any(v.integrity.infra_failed for v in votes)
        verdict = "error" if (tampered or infra) else "refused"
        stage, provenance = _stamp([], noise_cert_id)
        return VerdictEvent(
            stage=stage,
            verdict=verdict,
            posterior=_DEGENERATE[verdict],
            noise_cert_id=noise_cert_id,
            vote_count=len(votes),
            reason="insufficient_evidence",
            provenance=provenance,
            unknown_voters=unknown,
        )

    # Step 1 — anchor step (Thm 4.2): no branch; the clamp is the likelihood (module
    # docstring). Step 2 — posterior by direct product, with clique collapse.
    u = list(bundle.priors)
    used: list[VerifierParams] = []
    # Sorted by group id, never insertion order: float products are not associative
    # and 06 §3's cross-implementation conformance is bit-exact (04 §2.3, which pins
    # the same rule on the edge twin).
    for _gid, members in sorted(groups.items()):
        obs, params = _group_observation(members)
        used.append(params)
        u = _rescale(u)
        for t in range(4):
            x = likelihood(params, obs.vote, t)
            # The perfect-precision anchor NEEDS an exact zero (Paper II §9: an anchor
            # reject forces the odds to 0 regardless of the other verifiers) and a
            # malformed negative row must not become a NaN that sails through every
            # downstream comparison onto the wire. Both are the same branch.
            u[t] = u[t] * x if x > 0.0 else 0.0
    # D-AO(a) (lead, binding): an EXPLICIT FOLD, never a library reduction. IEEE-754
    # pins BINARY `+`; it says nothing about an n-ary reduction, and a standard library
    # is free to compensate — CPython's built-in `sum()` over floats switched to Neumaier
    # summation in a POINT RELEASE (3.12), so `sum([0.1]*10)` is 0x1.0000000000000p+0
    # where this fold is 0x1.fffffffffffffp-1. That one ulp in `total` IS the verdict on
    # a vector sitting on a Chow threshold. `math.fsum`, `numpy.sum` and any other
    # library reduction are banned here for the same reason: Go's leg folds sequentially.
    total = 0.0
    for x in u:
        total += x
    if not (total > 0.0) or math.isinf(total):
        # The bundle assigns probability 0 to every class consistent with the votes:
        # a broken bundle, not a verdict — refuse loudly rather than invent one. The
        # same branch catches NaN and ±Inf (mirroring Go's `!(total > 0) || IsInf`):
        # both come only from a non-finite bundle value, and both would otherwise make
        # every `>=`/`<=` in the Chow band False and silently answer REFUSED.
        raise ValueError("zero posterior mass in every class — inconsistent bundle")
    posterior: tuple[float, float, float, float] = tuple(x / total for x in u)  # type: ignore[assignment]
    stage, provenance = _stamp(used, noise_cert_id)

    # Step 3 — the error path (Thm 5.2: folding this into `violated` incurs provably
    # unavoidable excess risk).
    if posterior[_E] > THETA_ERROR or _infra_dominant(votes):
        return VerdictEvent(
            stage=stage,
            verdict="error",
            posterior=posterior,
            noise_cert_id=noise_cert_id,
            vote_count=len(votes),
            provenance=provenance,
            unknown_voters=unknown,
        )

    # Step 4 — Chow band (Thm 5.1), on the UNNORMALISED mass: η = u[S]/total, compared
    # by cross-multiplication (D-AK step 3). D-AO(c): NOT because division is inexact or
    # non-deterministic — IEEE-754 mandates correct rounding for `/` as much as for `*`,
    # so both forms are bit-portable. It is chosen on ACCURACY: it needs no derived
    # constant (the divided form must first round `1 - A/D`) and it is scale-invariant
    # under the power-of-two rescale above. See chow.py for the measured trade, which
    # runs both ways. There is no second, "comparison" copy of the posterior any more —
    # the wire copy and the decision are the same numbers.
    return VerdictEvent(
        stage=stage,
        verdict=chow_verdict(u[_S], total, costs),
        posterior=posterior,
        noise_cert_id=noise_cert_id,
        vote_count=len(votes),
        provenance=provenance,
        unknown_voters=unknown,
    )
