"""conf_vectors — the cloud leg of the two-language ADJUDICATE lock.

06 §3: "one algorithm, two deployment points ... divergence between them is a CI
failure, not a runtime surprise". The edge leg is
go/mark1d/internal/verdict/conf_vectors_test.go; both drive EVERY entry in
conformance/vectors/fusion/manifest.json, whose expectations are derived in exact
rational arithmetic (gen_fusion_vectors.py) rather than recorded from either side.

Test names contain ``conf_vectors`` because tools/ci/conformance_crosslang.sh collects
this suite with ``pytest -k conf_vectors``.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import struct
from pathlib import Path
from uuid import UUID

import pytest
from app.adjudicate.algorithm import adjudicate
from app.adjudicate.likelihoods import Bundle
from app.registry.handlers import NormalizedVote
from app.registry.integrity import IntegrityFlags

VECTORS = Path(__file__).resolve().parents[3] / "conformance/vectors/fusion"
MANIFEST = json.loads((VECTORS / "manifest.json").read_text())

# An emptied family would turn the parametrize below into a silent no-op.
if not MANIFEST["vectors"] or MANIFEST["tolerance"] <= 0:
    raise RuntimeError("fusion manifest is empty or carries no tolerance")

# handlers.py's wire mapping, restated as the vectors' own contract: a raw `error`
# verdict is the anchor RUN failing (Paper II's observable E) — an uninformative
# abstain carrying infra_failed, never a statement about the customer's code.
_WIRE = {
    "satisfied": ("accept", False),
    "violated": ("reject", False),
    "refused": ("abstain", False),
    "error": ("abstain", True),
}
_TASK = UUID("00000000-0000-0000-0000-000000000000")


def _load(entry: dict) -> dict:
    raw = (VECTORS / entry["file"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == entry["file_sha256_hex"], (
        f"{entry['name']}: vector bytes drifted from the frozen manifest digest"
    )
    return json.loads(raw)


def _bundle(vec: dict) -> Bundle:
    # The RAW verify section, straight through the production compiler: 07's quarantine
    # drop is Bundle.from_verify's, not this driver's. Pre-filtering here meant the
    # `quarantined_voter_no_coverage` vector tested the driver — Python had no
    # production quarantine drop at all, and the vector could not see that.
    return Bundle.from_verify(tuple(vec["priors"]), vec["verifiers"])


def _votes(vec: dict) -> list[NormalizedVote]:
    out = []
    for v in vec["votes"]:
        vote, infra = _WIRE[v["verdict"]]
        kind = vec["verifiers"].get(v["verifier_id"], {}).get("kind", "lint")
        out.append(
            NormalizedVote(
                verifier_id=v["verifier_id"],
                kind=kind,
                task_id=_TASK,
                attempt_id=_TASK,
                vote=vote,
                evidence_digest=b"",
                integrity=IntegrityFlags(tamper=v["tamper"], infra_failed=infra),
                tier="T0",
            )
        )
    return out


# D-AP: the cross-leg BIT-IDENTITY control. Asserting a posterior against the manifest
# cannot make it — the manifest's 1e-12 tolerance is ~4 orders looser than an ulp here,
# and the oracle is exact-rational while both legs are float64, so a bit-comparable
# manifest and an independent generator are mutually exclusive. So the bit assertion
# moves to where BOTH operands are floats: each leg appends the raw IEEE-754 bits of
# every posterior it computed, and conformance_crosslang.sh diffs the two files. Raw
# bits, not float.hex(), because Go's %x formatting is not Python's.
_DUMP = os.environ.get("M1_POSTHEX_OUT")


def _dump(name: str, verdict: str, posterior: tuple[float, ...]) -> None:
    if not _DUMP:
        return
    bits = " ".join(struct.pack(">d", x).hex() for x in posterior)
    with open(_DUMP, "a") as fh:
        fh.write(f"{name} {verdict} {bits}\n")


def _posterior(name: str) -> tuple[float, ...]:
    entry = next(e for e in MANIFEST["vectors"] if e["name"] == name)
    vec = _load(entry)
    return adjudicate(_votes(vec), _bundle(vec)).posterior


@pytest.mark.parametrize("entry", MANIFEST["vectors"], ids=lambda e: e["name"])
def test_conf_vectors_fusion(entry: dict) -> None:
    vec = _load(entry)
    votes, bundle = _votes(vec), _bundle(vec)

    if entry["expect"] == "zero_mass":
        # The bundle assigns probability 0 to every class: a broken bundle, not a
        # verdict. This side refuses loudly; the edge, whose signature cannot raise,
        # answers the latent error class. Both refuse; neither invents a posterior.
        with pytest.raises(ValueError, match="zero posterior mass"):
            adjudicate(votes, bundle)
        return

    event = adjudicate(votes, bundle)
    assert len(event.posterior) == 4, "the wire's exactly-4 invariant"
    for i, want in enumerate(entry["posterior"]):
        got = event.posterior[i]
        assert not math.isnan(got), f"posterior[{MANIFEST['classes'][i]}] is NaN"
        # A tolerance, not equality, and deliberately: the manifest carries the EXACT
        # rational posterior correctly rounded once, while any float implementation
        # accumulates a rounding per multiply. The claim a tolerance cannot make —
        # that a verdict on a Chow threshold does not flip — is made by `verdict` below,
        # asserted exactly, and by the bit_identical_to pairs.
        assert abs(got - want) <= MANIFEST["tolerance"], (
            f"posterior[{MANIFEST['classes'][i]}] = {got!r}, want {want!r}"
        )
    _dump(entry["name"], event.verdict, event.posterior)
    # D-AQ: at a construction placed ON a Chow threshold the rational oracle is not
    # authoritative on the VERDICT. It rounds once, at the end; any float64 leg rounds
    # per multiply, so no float64 evaluation reaches the exact answer there — both legs
    # agree on `refused` where the exact η is exactly 8/9. Agreement is the property
    # under test, and asserting the oracle here reports "float cannot represent this"
    # under the same red as "the two legs disagree". The verdict IS still asserted for
    # these, across the legs, by tools/ci/conformance_crosslang.sh's hex diff.
    if not entry.get("boundary"):
        assert event.verdict == entry["verdict"]
    assert event.vote_count == entry["vote_count"]
    assert event.unknown_voters == entry["unknown_voters"], "D-X accounting"

    if entry.get("bit_identical_to"):
        # The sorted-group rule, which a tolerance can never police: float multiplication
        # is not associative, so permuting the group order moves the posterior by one ulp
        # — enough to flip a verdict sitting on a Chow threshold.
        assert event.posterior == _posterior(entry["bit_identical_to"])
