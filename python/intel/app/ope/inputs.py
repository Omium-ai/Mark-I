"""OPE input assembler (06 §11.2, contract C9): ledger RouteDecision rows through querychoke,
fidelity-gated, joined to the served model and the certified verdict. The `ope_route_decisions`
body lives in go/controld/internal/querychoke/templates.go; its column set is locked there."""

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

from app.tvo.reader import QuerychokeReader

TEMPLATE = "ope_route_decisions"

WIRE_ENFORCED, CONFIG_STEERED, ADVISORY = "wire_enforced", "config_steered", "advisory"
_FIDELITIES = frozenset({WIRE_ENFORCED, CONFIG_STEERED, ADVISORY})
_CERTIFIED = frozenset({"certified", "revised"})


@dataclass(frozen=True)
class DecisionRow:
    decision_id: str
    context: str
    action: str
    propensity: float
    fidelity: str
    served_model: str | None = None
    verdict: str | None = None
    verdict_stage: str | None = None
    label_confidence: float | None = None


@dataclass(frozen=True)
class LoggedRow:
    """One (x_i, a_i, r_i, p_i) tuple the estimators consume."""

    context: str
    action: str
    reward: float
    propensity: float


@dataclass(frozen=True)
class OpeInputs:
    rows: tuple[LoggedRow, ...]
    dropped: Mapping[str, int]


def _admit(row: DecisionRow) -> str | None:
    """Return the drop reason, or None when the row enters."""
    if row.fidelity == ADVISORY:
        return ADVISORY
    if row.fidelity == CONFIG_STEERED and row.served_model != row.action:
        return "config_steered_unconfirmed"
    if row.verdict_stage not in _CERTIFIED or row.label_confidence is None:
        return "uncertified"
    if row.verdict not in ("satisfied", "violated"):
        return "unresolved"
    return None


def assemble(rows: Iterable[DecisionRow]) -> OpeInputs:
    """C9 in order: WHERE on fidelity, the served-model join, then the certified reward join."""
    kept: list[LoggedRow] = []
    dropped: Counter[str] = Counter()
    for row in rows:
        if not (0 < row.propensity <= 1) or row.fidelity not in _FIDELITIES:
            raise ValueError(f"ledger invariant broken on {row.decision_id}: {row!r}")
        reason = _admit(row)
        if reason is not None:
            dropped[reason] += 1
            continue
        reward = float(row.label_confidence or 0.0) if row.verdict == "satisfied" else 0.0
        kept.append(LoggedRow(row.context, row.action, reward, row.propensity))
    return OpeInputs(rows=tuple(kept), dropped=dict(dropped))


def _float_or_none(v: Any) -> float | None:
    return None if v is None else float(v)


def decision_row(row: Mapping[str, Any]) -> DecisionRow:
    """Map one `ope_route_decisions` wire row; context = agent × ladder (the row's only x_i)."""
    candidates = row.get("candidates") or []
    return DecisionRow(
        decision_id=str(row["decision_id"]),
        context=f"{row.get('agent', '')}|{','.join(map(str, candidates))}",
        action=str(row["action"]),
        propensity=float(row["propensity"]),
        fidelity=str(row["fidelity"]),
        served_model=row.get("served_model") or None,
        verdict=row.get("verdict") or None,
        verdict_stage=row.get("verdict_stage") or None,
        label_confidence=_float_or_none(row.get("label_confidence")),
    )


async def fetch(
    reader: QuerychokeReader, window_start: date, window_end: date, *, bearer: str
) -> OpeInputs:
    result = await reader.run_template(
        TEMPLATE,
        {"from": window_start.isoformat(), "to": window_end.isoformat()},
        bearer=bearer,
    )
    return assemble(decision_row(r) for r in result.rows)
