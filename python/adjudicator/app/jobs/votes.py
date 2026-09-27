"""`adjudication_votes.v4` rows → what estimation and fusion read (16 §L6): the wire vote with an
RmScore folded through its calibration, the handler kind, and the correlation group from the
catalog row (16 §Independence rules), never the event family."""

import base64
import binascii
import logging
from collections.abc import Iterable, Mapping
from typing import Any

from app.certified.runner import TEST_ANCHORS
from app.registry.catalog import RegistryEntry, group_of
from app.rm.scorer import calibration_refusal, fold, rm_refused_total

log = logging.getLogger("adjudicator.votes")

E0 = "EVIDENCE_TIER_E0"
E0_COLUMN = "/E0"
AMBIGUOUS = "JUDGE_TRIGGER_AMBIGUOUS"
_FAMILY_KIND = {"JudgeVote": "judge", "RmScore": "rm", "ConsistencyVote": "consistency"}


def kind_of(row: Mapping[str, Any], registry: Mapping[str, RegistryEntry]) -> str | None:
    entry = registry.get(str(row["verifier_id"]))
    if entry is not None:
        return entry.kind
    if row["family"] == "AnchorVote":
        # ponytail: unlisted anchor = the wide lint row, never the clamp; kind lives in m1_verifiers
        return "test" if row["verifier_id"] in TEST_ANCHORS else "lint"
    return _FAMILY_KIND.get(str(row["family"]))


def rm_execution_ok(row: Mapping[str, Any], entry: RegistryEntry | None) -> bool:
    """An RmScore votes only under its model's sealed rm-exec/v1 hash, device and cloud alike."""
    sealed = entry.effective_execution_hash if entry is not None else None
    try:
        got = base64.b64decode(str(row.get("execution_hash") or ""), validate=True)
    except (binascii.Error, ValueError):
        got = b""
    if sealed is not None and got == sealed:
        return True
    reason = "refused_rm_unsealed" if sealed is None else "refused_rm_execution_hash"
    rm_refused_total[reason] += 1
    log.info("%s refused %s", row.get("verifier_id"), reason)
    return False


def vote_of(row: Mapping[str, Any], registry: Mapping[str, RegistryEntry]) -> str:
    """The wire verdict name; '' when the row did not vote (an RmScore nothing can fold, or a
    device's RmScore off its model's sealed execution)."""
    if row["family"] != "RmScore":
        return str(row["vote"])
    entry = registry.get(str(row["verifier_id"]))
    if not rm_execution_ok(row, entry):
        return ""
    definition = entry.definition if entry is not None else None
    version = str(row.get("calibration_version") or "")
    if reason := calibration_refusal(version, definition):
        rm_refused_total[reason.split(":", 1)[0]] += 1
        log.info("%s refused %s", row.get("verifier_id"), reason)
        return ""
    return fold(row.get("score"), version, definition) or ""


def estimable(row: Mapping[str, Any]) -> bool:
    """A vote whose running hung on another clique's vote feeds fusion only (16 §Independence)."""
    return row.get("vote_trigger") != AMBIGUOUS


def column_of(row: Mapping[str, Any], registry: Mapping[str, RegistryEntry]) -> str:
    """The estimation column: an E1 judge's E0-fallback votes (catalog `e0_fallback`, m1_100) read
    anchor rows, so they are a view of their own, `<id>/E0`, never pooled with its E1 votes."""
    vid = str(row["verifier_id"])
    if row["family"] == "JudgeVote" and row.get("tier_used") == E0:
        entry = registry.get(vid)
        if entry is not None and "e0_fallback" in entry.definition:
            return vid + E0_COLUMN
    return vid


def groups_of(
    rows: Iterable[Mapping[str, Any]], registry: Mapping[str, RegistryEntry]
) -> dict[str, str]:
    """column → correlation group; one E0 JudgeVote row makes that column syntactic."""
    rows = list(rows)
    e0 = {
        column_of(r, registry)
        for r in rows
        if r["family"] == "JudgeVote" and r.get("tier_used") == E0
    }
    out: dict[str, str] = {}
    for r in rows:
        col = column_of(r, registry)
        kind = kind_of(r, registry)
        if col in out or kind is None:
            continue
        entry = registry.get(str(r["verifier_id"]))
        out[col] = group_of(kind, entry.definition if entry is not None else {}, col in e0)
    return out
