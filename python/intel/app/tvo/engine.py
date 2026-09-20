"""Ledger-shaped rows in → TVO out (06 §8.1). Rows are plain dataclasses so tests need no
ClickHouse; the real reader arrives with the query-choke integration row (08 §3.3: every
ClickHouse read goes through controld.query-choke — this module will consume its rows, it
will never hold ClickHouse credentials). That reader is a deliberate seam, not a gap."""

import math
import statistics
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from app.tvo.closed_forms import repair_knee, tvo, verifier_break_even

# CALIBRATED defaults (06 §8.1 sourcing table): used only when the noise certificate cannot
# supply measured (α, β), and the output's provenance says so. Values are Paper I's
# grounded-rubric operating point and its D calibration — literature, never our claim.
CALIBRATED_ALPHA = 0.85
CALIBRATED_BETA = 0.20
CALIBRATED_D = 150_000.0

# Verdict stages that count as certification-grade (06 §12.1 admits certified|revised).
_CERTIFIED_STAGES = frozenset({"certified", "revised"})


@dataclass(frozen=True)
class AttemptRow:
    """One attempt of one task — the grain 07's tvo_task rollup carries (attempt boundaries
    come from VerdictEvent rows, so this is pure ledger arithmetic, no inference)."""

    task_id: str
    attempt_n: int  # 1-based within the task
    gen_tokens: int  # generation tokens charged to this attempt (c's numerator)
    verifier_tokens: int  # judge tokens + amortized anchor cost (v's numerator, 06 §8.1)
    fused_verdict: str  # satisfied | violated | refused | error
    verdict_stage: str  # provisional | certified | revised
    # The terminal verdict's posterior mode — "satisfied" | "violated" | "refused" | "error" | ""
    # (unknown). The Chow band withholds the satisfied WORD below 8/9, unreachable while the
    # bootstrap bundle has one correlation group (06 §3.1), so the mode is what an outcome
    # count reads; the certified word stays the guarantee-grade gate.
    mode: str = ""


@dataclass(frozen=True)
class NoiseCertificate:
    """The binary projection this engine reads (06 §5.2); stamped onto every result.
    The status changes the *claims permitted*, never the math (06 §3)."""

    status: str  # uncertified | bootstrapping | certified
    rho_plus: float | None = None  # P(violated | gold satisfied) — false-reject
    rho_minus: float | None = None  # P(satisfied | gold violated) — false-accept


@dataclass(frozen=True)
class TvoInputs:
    c: float
    v: float
    p: float
    alpha: float
    beta: float
    d: float
    # Honest sourcing per input (06 §8.1 table): "measured" | "calibrated" | "configured".
    provenance: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class TvoResult:
    tvo: float
    break_even_v: float
    inputs: TvoInputs
    attempts: int
    certified_attempts: int
    cert_status: str


def measured_inputs(
    attempts: Sequence[AttemptRow],
    cert: NoiseCertificate,
    d: float | None = None,
) -> TvoInputs:
    """c, v, p measured from the window's attempt rows; α, β from the certificate's binary
    projection when `certified`, else literature-CALIBRATED and labeled (06 §8.1)."""
    if not attempts:
        raise ValueError("empty attempt window — TVO over nothing is not a number")

    c = statistics.fmean(a.gen_tokens for a in attempts)
    v = statistics.fmean(a.verifier_tokens for a in attempts)

    # p is the CERTIFIED pass rate (06 §8.1: "MEASURED, certified-only"): satisfied over
    # satisfied+violated at certification grade. refused/error attempts are statements
    # about the verifier plane, not the code (Paper II Thm 5.2) — they are neither
    # success nor failure evidence, so they leave the denominator.
    n_sat = sum(
        1
        for a in attempts
        if a.verdict_stage in _CERTIFIED_STAGES and a.fused_verdict == "satisfied"
    )
    n_vio = sum(
        1
        for a in attempts
        if a.verdict_stage in _CERTIFIED_STAGES and a.fused_verdict == "violated"
    )
    if n_sat + n_vio == 0:
        raise ValueError("no certified satisfied/violated attempts in window — p is unmeasurable")
    p = n_sat / (n_sat + n_vio)

    # α = 1 − ρ₊, β = ρ₋ under the accept↔satisfied projection (06 §8.1 sourcing table).
    if cert.status == "certified":
        # 06 §8.1: `certified` MEANS measured (α, β). A certified row missing
        # its binary projection is a contract violation upstream — refusing
        # here beats silently downgrading to CALIBRATED literature values
        # while report.py's status-string gate (06 §8.5) keeps the guarantee.
        if cert.rho_plus is None or cert.rho_minus is None:
            raise ValueError(
                "certified noise certificate is missing its binary projection "
                "(rho_plus/rho_minus) — refusing to substitute calibrated (α, β) "
                "under a certificate that claims they were measured (06 §5.2/§8.1)"
            )
        alpha, beta, ab_src = 1.0 - cert.rho_plus, cert.rho_minus, "measured"
    else:
        alpha, beta, ab_src = CALIBRATED_ALPHA, CALIBRATED_BETA, "calibrated"

    # D is tenant-configured and NEVER claimed as measured (06 §8.1).
    d_val, d_src = (d, "configured") if d is not None else (CALIBRATED_D, "calibrated")

    return TvoInputs(
        c=c,
        v=v,
        p=p,
        alpha=alpha,
        beta=beta,
        d=d_val,
        provenance={
            "c": "measured",
            "v": "measured",
            "p": "measured",
            "alpha": ab_src,
            "beta": ab_src,
            "D": d_src,
        },
    )


def tvo_from_ledger(
    attempts: Sequence[AttemptRow],
    cert: NoiseCertificate,
    d: float | None = None,
) -> TvoResult:
    """The engine's one job at this row: measured inputs → the frozen closed forms."""
    inputs = measured_inputs(attempts, cert, d)
    return TvoResult(
        tvo=tvo(inputs.c, inputs.v, inputs.p, inputs.alpha, inputs.beta, inputs.d),
        break_even_v=verifier_break_even(inputs.c, inputs.p, inputs.alpha, inputs.beta, inputs.d),
        inputs=inputs,
        attempts=len(attempts),
        certified_attempts=sum(1 for a in attempts if a.verdict_stage in _CERTIFIED_STAGES),
        cert_status=cert.status,
    )


def fit_gamma(pass_rate_by_attempt: Sequence[float]) -> float:
    """γ̂ from attempt-indexed certified pass rates, p_k ≈ p₁·γ^(k−1) (06 §8.1): log-linear
    least squares on ln p_k vs (k−1). Refuses (raises) when the series does not decay —
    a γ ≥ 1 has no knee, and inventing one would misgovern the edge gate."""
    pts = [(k, r) for k, r in enumerate(pass_rate_by_attempt) if r > 0.0]
    if len(pts) < 2:
        raise ValueError("need >= 2 positive attempt-indexed pass rates to fit gamma")
    slope, _ = statistics.linear_regression([k for k, _ in pts], [math.log(r) for _, r in pts])
    gamma_hat = math.exp(slope)
    if not 0.0 < gamma_hat < 1.0:
        raise ValueError(f"fitted gamma={gamma_hat:.4f} not in (0,1) — series does not decay")
    return gamma_hat


def rho_hat(c1: float, p1: float, task_value: float) -> float:
    """ρ̂ = c(1) / (p₁·V) — attempt-1 cost-to-expected-value ratio (06 §8.1 sourcing table)."""
    if p1 <= 0.0 or task_value <= 0.0:
        raise ValueError("rho_hat needs p1 > 0 and V > 0")
    return c1 / (p1 * task_value)


def knee_consistent(table_knee: int, rho: float, gamma: float) -> bool:
    """06 §8.1: the bundle's knee TABLE governs the edge; the closed form is the cross-check.
    True iff the table's implied knee is within ±1 of k*(ρ̂, γ̂); a False flags the compiler.
    Deriving the implied knee *from* a table's (n, c_n) rows is the compiler row's job —
    this function is only the ±1 arithmetic both sides agree on."""
    return abs(table_knee - repair_knee(rho, gamma)) <= 1


def group_by_task(attempts: Iterable[AttemptRow]) -> dict[str, list[AttemptRow]]:
    """Task-grain view, attempts ordered by attempt_n — the grain waste arithmetic runs at."""
    by_task: dict[str, list[AttemptRow]] = defaultdict(list)
    for a in attempts:
        by_task[a.task_id].append(a)
    return {t: sorted(rows, key=lambda a: a.attempt_n) for t, rows in by_task.items()}
