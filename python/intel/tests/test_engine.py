"""Engine measurement semantics (06 §8.1 sourcing table): p is certified-only with
refused/error out of the denominator, α/β provenance follows the certificate, γ̂/ρ̂ are
fitted quantities that refuse to fit non-decaying data, knee cross-check is ±1."""

import pytest
from app.tvo.engine import (
    AttemptRow,
    NoiseCertificate,
    fit_gamma,
    knee_consistent,
    measured_inputs,
    rho_hat,
    tvo_from_ledger,
)

CERT = NoiseCertificate("certified", rho_plus=0.15, rho_minus=0.20)


def test_p_is_certified_only_and_excludes_refused_error():
    rows = [
        AttemptRow("t1", 1, 10_000, 1_000, "satisfied", "certified"),
        AttemptRow("t2", 1, 10_000, 1_000, "violated", "certified"),
        AttemptRow("t3", 1, 10_000, 1_000, "satisfied", "provisional"),  # not certified: out
        AttemptRow("t4", 1, 10_000, 1_000, "refused", "certified"),  # verifier-plane: out
        AttemptRow("t5", 1, 10_000, 1_000, "error", "certified"),  # infra: out (Thm 5.2)
        AttemptRow("t6", 1, 10_000, 1_000, "satisfied", "revised"),  # revised counts
    ]
    inputs = measured_inputs(rows, CERT)
    assert inputs.p == pytest.approx(2 / 3)  # 2 satisfied / (2 satisfied + 1 violated)
    assert inputs.c == pytest.approx(10_000)  # c and v average over ALL attempts (totality)
    assert inputs.v == pytest.approx(1_000)


def test_alpha_beta_from_certificate_projection():
    inputs = measured_inputs([AttemptRow("t", 1, 1, 1, "satisfied", "certified")], CERT)
    assert inputs.alpha == pytest.approx(0.85)  # 1 − ρ₊
    assert inputs.beta == pytest.approx(0.20)  # ρ₋
    assert inputs.provenance["alpha"] == "measured"


def test_uncertified_cert_falls_back_to_calibrated_and_says_so():
    inputs = measured_inputs(
        [AttemptRow("t", 1, 1, 1, "satisfied", "certified")], NoiseCertificate("uncertified")
    )
    assert inputs.provenance["alpha"] == "calibrated"
    assert inputs.provenance["beta"] == "calibrated"


@pytest.mark.parametrize(
    "cert",
    [
        NoiseCertificate("certified"),
        NoiseCertificate("certified", rho_plus=0.15),
        NoiseCertificate("certified", rho_minus=0.20),
    ],
)
def test_certified_cert_missing_projection_raises_not_downgrades(cert):
    """A 'certified' row without its binary projection is a contract violation (06 §5.2):
    it must raise, never silently take literature-CALIBRATED (α, β) while report.py's
    status-string gate keeps the guarantee grade (06 §8.1 + §8.5)."""
    rows = [AttemptRow("t", 1, 1, 1, "satisfied", "certified")]
    with pytest.raises(ValueError, match="binary projection"):
        measured_inputs(rows, cert)
    with pytest.raises(ValueError, match="binary projection"):
        tvo_from_ledger(rows, cert)


def test_empty_or_unmeasurable_windows_refused():
    with pytest.raises(ValueError):
        tvo_from_ledger([], CERT)
    with pytest.raises(ValueError):
        # Only provisional verdicts: p is unmeasurable, never guessed.
        tvo_from_ledger([AttemptRow("t", 1, 1, 1, "satisfied", "provisional")], CERT)


def test_fit_gamma_recovers_geometric_decay():
    p1, gamma = 0.5, 0.7
    series = [p1 * gamma ** (k - 1) for k in range(1, 6)]
    assert fit_gamma(series) == pytest.approx(gamma)


def test_fit_gamma_refuses_non_decaying_series():
    with pytest.raises(ValueError):
        fit_gamma([0.3, 0.4, 0.5])  # improving per attempt: no geometric decay to report
    with pytest.raises(ValueError):
        fit_gamma([0.5])  # one point is not a fit


def test_rho_hat_and_knee_cross_check():
    # ρ̂ = c(1)/(p₁·V); at the paper's function-level point the table must agree within ±1.
    rho = rho_hat(30_000, 0.5, 200_000)  # = 0.3
    assert rho == pytest.approx(0.3)
    assert knee_consistent(2, rho, 0.5)  # k* = 2 exactly
    assert knee_consistent(3, rho, 0.5)  # ±1 tolerated: table encodes non-geometric reality
    assert not knee_consistent(5, rho, 0.5)  # beyond ±1 flags the compiler (06 §8.1)
