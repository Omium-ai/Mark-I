"""ADJUDICATE (06 §3.1, Paper II's algorithm) — log-space weighted majority over
verifier votes with clique collapse, the four-verdict posterior [satisfied, violated,
refused, error], the error path (Thm 5.2), and the Chow band (Thm 5.1).

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


def _log(x: float) -> float:
    # math.log(0) raises; the perfect-precision anchor NEEDS an exact zero (Paper II
    # §9: anchor reject forces odds 0 regardless of the other verifiers), so zero
    # likelihood is a legal, exact -inf — never an epsilon that would soften the veto.
    return math.log(x) if x > 0.0 else -math.inf


def _softmax(logp: list[float]) -> tuple[float, float, float, float]:
    m = max(logp)
    if m == -math.inf:
        # Zero total mass: the bundle assigns probability 0 to every class consistent
        # with the votes. That is a broken bundle, not a verdict — refuse loudly.
        raise ValueError("zero posterior mass in every class — inconsistent bundle")
    w = [math.exp(x - m) for x in logp]
    z = sum(w)
    return tuple(x / z for x in w)  # type: ignore[return-value]


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

        return max(accepts, key=lambda vp: (accept_lr(vp), vp[0].verifier_id))
    return min(members, key=lambda vp: vp[0].verifier_id)


def _infra_dominant(votes: list[NormalizedVote]) -> bool:
    if not votes:
        return False
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
    coverage = sum(1 for v in informative if v.vote != "abstain")
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
        )

    # Step 1 — anchor step (Thm 4.2): no branch; the clamp is the likelihood (module
    # docstring). Step 2 — log-space posterior with clique collapse.
    groups: dict[str, list[tuple[NormalizedVote, VerifierParams]]] = {}
    for v in informative:
        p = bundle.params_for(v.verifier_id, v.kind)
        groups.setdefault(p.group, []).append((v, p))

    logp = [_log(pi) for pi in bundle.priors]
    used: list[VerifierParams] = []
    for members in groups.values():
        obs, params = _group_observation(members)
        used.append(params)
        for t in range(4):
            logp[t] += _log(likelihood(params, obs.vote, t))
    posterior = _softmax(logp)
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
        )

    # Step 4 — Chow band (Thm 5.1).
    eta = posterior[_S]
    return VerdictEvent(
        stage=stage,
        verdict=chow_verdict(eta, costs),
        posterior=posterior,
        noise_cert_id=noise_cert_id,
        vote_count=len(votes),
        provenance=provenance,
    )
