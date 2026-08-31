"""unit_verdict_enum_diff — CON-006, P0 and Phase-1 green-required (02:52, 02:389,
named at 12:454).

CON-006 requires the vocabulary to be exactly satisfied|violated|refused|error "in
every schema, enum, API, and report", and 02:389 asks for the diff across proto, PG
and the Python constants to be empty. It is declared in five places that share no
parser, and the Python ORDER is load-bearing: algorithm._VERDICT_BY_IX indexes the
posterior that verify.proto:166-167 documents as posterior[0]=satisfied …
posterior[3]=error. A reordering there is a silent mis-mapping between two agreeing
type-checkers, not an error anything raises.

All five agree today. Nothing made them agree — that is the gap this closes.

The proto leg imports the GENERATED enum rather than re-parsing artifacts.proto: it
is what the services actually load, and gen-check already pins generated to source.
The Go and Rust enums come off the same .proto through the same gate, so diffing
them here would re-assert buf's output, not the vocabulary.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.adjudicate.algorithm import _VERDICT_BY_IX
from app.adjudicate.likelihoods import CLASSES
from app.gold.score import _BINARY
from app.registry.handlers import _WIRE_VOTE
from m1p.v1 import Verdict

VOCAB = ("satisfied", "violated", "refused", "error")
ROOT = Path(__file__).resolve().parents[3]


def _pg_enum() -> tuple[str, ...]:
    sql = (ROOT / "migrations/m1_020_verifier_registry.sql").read_text()
    body = re.search(r"CREATE TYPE verdict AS ENUM \(([^)]*)\)", sql)
    # Absent source ⇒ fail, never an empty tuple: a diff must not pass by finding nothing.
    assert body, "m1_020 no longer declares `CREATE TYPE verdict AS ENUM`"
    return tuple(re.findall(r"'([a-z_]+)'", body.group(1)))


def test_verdict_enum_diff_is_empty_across_proto_pg_and_python():
    # 0 stays reserved: a real verdict there makes an unset field read as that verdict.
    assert Verdict.UNSPECIFIED.value == 0
    assert tuple(v.name.lower() for v in Verdict if v.value) == VOCAB
    assert _pg_enum() == VOCAB
    assert _VERDICT_BY_IX == VOCAB
    assert CLASSES == VOCAB
    assert tuple(_WIRE_VOTE) == VOCAB
    assert _BINARY <= set(VOCAB)


def test_posterior_index_matches_the_proto_enum_number():
    # The only cross-source relation that is not name equality, so the only one the
    # assertions above cannot see: proto numbers start at 1, posterior indices at 0.
    for ix, name in enumerate(_VERDICT_BY_IX):
        assert Verdict(ix + 1).name.lower() == name
