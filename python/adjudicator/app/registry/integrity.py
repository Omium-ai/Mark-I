"""Effective-execution hash check + suppression annotation (06 §2.4).

Two distinct outcomes, deliberately not conflated:
- envelope hash ≠ registry hash (and no version bump — a bump is a NEW registry row
  the envelope would name instead) ⇒ `tamper`: quarantined from fusion and estimation.
- suppression_directive_delta non-empty (# noqa, @ts-ignore, #[allow] added in the
  same diff) ⇒ the vote STANDS but is annotated. WHY not quarantine: suppressions are
  sometimes legitimate; lying about their presence is not.
- absent worktree merkle root (cortexd down — proto AnchorIntegrity docstring) ⇒
  tamper-UNKNOWN, not tamper: the vote never feeds certification but is not an
  accusation; it rides as an infra failure (Paper II's observable event E)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class IntegrityFlags:
    """06 §2.1's `integrity: IntegrityFlags` — tamper / env_scrub_ok / merkle_match,
    plus the suppression annotation (§2.4) and the infra-failure marker (Thm 5.2's E)."""

    tamper: bool = False
    env_scrub_ok: bool = True
    merkle_match: bool = True
    suppression_delta: int = 0
    infra_failed: bool = False


def anchor_integrity(
    envelope_hash: bytes | None,
    registry_hash: bytes | None,
    env_scrub_ok: bool,
    merkle_root_present: bool,
    suppression_delta: int,
    envelope_tamper: bool,
    run_errored: bool = False,
) -> IntegrityFlags:
    """Fold one AnchorIntegrity envelope against the registry row (06 §2.4)."""
    # Hash mismatch OR a failed env scrub OR the device's own tamper bit ⇒ tamper
    # (proto AnchorIntegrity.tamper: "any integrity check failed"). A missing envelope
    # hash on an anchor is itself a mismatch — an anchor with nothing to compare is
    # not a verified execution.
    hash_mismatch = envelope_hash is None or envelope_hash != registry_hash
    return IntegrityFlags(
        tamper=envelope_tamper or hash_mismatch or not env_scrub_ok,
        env_scrub_ok=env_scrub_ok,
        merkle_match=merkle_root_present,
        suppression_delta=suppression_delta,
        # tamper-unknown ≠ tamper: no root to check is an infrastructure statement,
        # as is the anchor run itself erroring (a wire `error` verdict).
        infra_failed=run_errored or not merkle_root_present,
    )
