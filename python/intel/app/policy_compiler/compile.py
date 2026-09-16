"""Compilation (06 §10.4): the six PolicyBundle v1 sections as canonical CBOR, 07's CDDL exactly.

Two things live here. (1) The section grammar as pydantic models whose every `tstr` position
is one of 07's productions — constrained identifier, RFC 6901 pointer, or closed enum — so the
compiler cannot author a command string even by bug (07 decode rule 1; rule 3's strict maps are
`extra="forbid"`). (2) An RFC 8949 §4.2.1 deterministic encoder for the value types the grammar
uses: definite lengths, minimal heads, keys sorted by encoded bytes, shortest float that
preserves the value, no NaN/Inf, no null. controld's strict Go decoder re-checks canonicality by
re-encoding (policydist.DecodeSections), and the tests round-trip a fixture through it.

The compiler authors `route`. `verify` (§4 estimates), `memory` (§9.5), `cortex`, `gates` and
`agent_maps` are compiled THROUGH: carried byte-for-byte from the tenant's last published draft,
or the conservative defaults below on a first publication.
"""

import hashlib
import math
import re
import struct
from collections.abc import Iterable, Mapping
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.policy_compiler.cpvs import CertifiedAttempt, Regime, certified, cpvs_table
from app.policy_compiler.knee import KneeInputs, knee_table
from app.policy_compiler.ladders import build_ladders

SECTION_NAMES = ("verify", "route", "memory", "cortex", "gates", "agent_maps")

_PRODUCTIONS = {
    "identifier": re.compile(r"[A-Za-z0-9_.:@-]{1,128}"),  # 07 rule 1(d), the fallback
    "catalog_id": re.compile(r"[a-z0-9_.-]{1,64}"),
    "verifier_id": re.compile(r"[a-z0-9_.@-]{1,128}"),
    "m1p_field": re.compile(r"[a-z0-9_.]{1,64}"),
    "json_pointer": re.compile(r"(/[^/~]*(~[01][^/~]*)*)*"),
}


def _production(name: str):
    rx = _PRODUCTIONS[name]

    def check(v: str) -> str:
        if name == "json_pointer" and len(v) > 1024:
            raise ValueError(f"{name}: {len(v)} bytes is over the 1024-byte pointer bound (07)")
        if rx.fullmatch(v) is None:
            raise ValueError(f"{name}: {v!r} is not the production {rx.pattern} (07 rule 1)")
        return v

    return AfterValidator(check)


Ident = Annotated[str, _production("identifier")]
CatalogID = Annotated[str, _production("catalog_id")]
VerifierID = Annotated[str, _production("verifier_id")]
M1PField = Annotated[str, _production("m1p_field")]
Pointer = Annotated[str, _production("json_pointer")]
Prob = Annotated[float, Field(ge=0.0, le=1.0)]
Finite = Annotated[float, Field(allow_inf_nan=False)]
UInt = Annotated[int, Field(ge=0)]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AnchorEnable(_Strict):
    catalog_id: CatalogID
    enabled: bool
    thresholds: dict[Ident, float] | None = None
    debounce_ms: UInt | None = None


class VerifierModel(_Strict):
    verifier_id: VerifierID
    confusion: tuple[tuple[Prob, Prob, Prob], ...] = Field(min_length=4, max_length=4)


class CorrelationGroup(_Strict):
    group_id: Ident
    members: tuple[VerifierID, ...] = Field(min_length=1)


class VerifySection(_Strict):
    anchors: tuple[AnchorEnable, ...]
    verifiers: tuple[VerifierModel, ...]
    priors: tuple[Prob, Prob, Prob, Prob]
    correlation_groups: tuple[CorrelationGroup, ...]
    quarantine: tuple[VerifierID, ...]


class CPVSRow(_Strict):
    task_class: Ident
    model_id: Ident
    p_pass: Prob
    tokens_est: UInt


class Rung(_Strict):
    model_id: Ident
    keep_prefix: bool


class Ladder(_Strict):
    ladder_id: Ident
    rungs: tuple[Rung, ...] = Field(min_length=1)


class KneeRow(_Strict):
    n: UInt
    c_n: float = Field(ge=0.0)
    p_lcb: Prob | None = None


class KneeTable(_Strict):
    cost_basis: Literal["usd", "quota"]
    rows: tuple[KneeRow, ...] = Field(min_length=1)
    v_default: float = Field(ge=0.0)


class Exploration(_Strict):
    epsilon: Prob = 0.0


class RouteSection(_Strict):
    cpvs: tuple[CPVSRow, ...]
    ladders: tuple[Ladder, ...]
    knee: KneeTable
    exploration: Exploration | None = None
    exploration_opt_in: bool | None = None


class InjectionRule(_Strict):
    facet: Ident
    max_items: UInt | None = None


class MemoryBudgets(_Strict):
    pack_tokens_max: UInt


class MemorySection(_Strict):
    injection_rules: tuple[InjectionRule, ...]
    budgets: MemoryBudgets


class BudgetRange(_Strict):
    min: UInt
    max: UInt


class LearnedRanker(_Strict):
    """07 `learned-ranker`: coefficients are one per cortexd file feature (l2_graph::FEATURES)."""

    stage: Literal["probation", "shadow", "active"]
    weight: Prob
    bias: Finite
    coefficients: tuple[Finite, Finite, Finite, Finite]


class CortexSection(_Strict):
    map_budget_tokens: BudgetRange
    channels: tuple[Literal["session_start", "prompt_submit", "before_model"], ...]
    learned_ranker: LearnedRanker | None = None  # absent ⇒ cortexd serves PPR order (06 §12.4)


class GatesSection(_Strict):
    stop_gate_enabled: bool
    max_consecutive_blocks: Annotated[int, Field(ge=0, le=3)]  # a bundle may only lower the cap
    hourly_block_ceiling: UInt


class AgentMap(_Strict):
    agent_id: Ident
    agent_version: Ident
    hook_fields: dict[M1PField, Pointer]
    tailer_rules: dict[Ident, Pointer]


class AgentMapsSection(_Strict):
    agents: tuple[AgentMap, ...]


SECTION_MODELS: dict[str, type[_Strict]] = {
    "verify": VerifySection,
    "route": RouteSection,
    "memory": MemorySection,
    "cortex": CortexSection,
    "gates": GatesSection,
    "agent_maps": AgentMapsSection,
}

# First-publication posture: nothing enabled, uniform (uninformative) priors, edge built-ins
# (0 ⇒ default at the edge for budgets/ceiling), stop gate armed only by local opt-in.
DEFAULT_SECTIONS: dict[str, _Strict] = {
    "verify": VerifySection(
        anchors=(),
        verifiers=(),
        priors=(0.25, 0.25, 0.25, 0.25),
        correlation_groups=(),
        quarantine=(),
    ),
    "memory": MemorySection(injection_rules=(), budgets=MemoryBudgets(pack_tokens_max=0)),
    "cortex": CortexSection(map_budget_tokens=BudgetRange(min=0, max=0), channels=()),
    "gates": GatesSection(stop_gate_enabled=True, max_consecutive_blocks=3, hourly_block_ceiling=0),
    "agent_maps": AgentMapsSection(agents=()),
}


class Raw(bytes):
    """Already-canonical CBOR spliced verbatim (a carried-forward section)."""


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | ai]) + struct.pack(fmt, n)
    raise OverflowError(f"{n} does not fit a CBOR head")


def _float(x: float) -> bytes:
    if math.isnan(x) or math.isinf(x):
        raise ValueError(f"{x} is not finite; a bundle carries no NaN or Inf (07)")
    for ai, fmt in ((25, ">e"), (26, ">f")):
        try:
            packed = struct.pack(fmt, x)
        except OverflowError:
            continue
        if struct.unpack(fmt, packed)[0] == x:
            return bytes([0xE0 | ai]) + packed
    return b"\xfb" + struct.pack(">d", x)


def encode(v: Any) -> bytes:
    """RFC 8949 §4.2.1 core deterministic encoding of the grammar's value types."""
    if isinstance(v, Raw):
        return bytes(v)
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, float):
        return _float(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, list | tuple):
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, Mapping):
        items = sorted(((encode(k), encode(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(f"{type(v).__name__} has no place in a bundle section")


def encode_section(section: _Strict) -> bytes:
    return encode(section.model_dump(exclude_none=True))


def sections_map(sections: Mapping[str, bytes]) -> bytes:
    """The six-section map over per-section canonical bytes — what controld decodes and hashes."""
    if set(sections) != set(SECTION_NAMES):
        raise ValueError(f"sections {sorted(sections)} are not exactly {sorted(SECTION_NAMES)}")
    return encode({name: Raw(b) for name, b in sections.items()})


class Compiled(BaseModel):
    model_config = ConfigDict(frozen=True)

    sections: dict[str, bytes]  # per-section canonical bytes, all six
    sections_cbor: bytes  # sections_map(sections)
    draft_hash: bytes  # sha256(sections_cbor)
    knee_gate_ok: bool  # 06 §10.3's sanity gate; False blocks publication
    note: str


class NothingToCompile(ValueError):
    """No certified attempt in the window: nothing measured, so no draft is minted (06 §5.4)."""


def compile_sections(
    attempts: Iterable[CertifiedAttempt],
    regime: Regime,
    previous: Mapping[str, bytes] | None = None,
) -> Compiled:
    attempts = tuple(attempts)
    if not certified(attempts):
        raise NothingToCompile("no certified attempts in the window")
    cells = cpvs_table(attempts, regime)
    knee = knee_table(
        KneeInputs(
            task_class="*",
            attempts=attempts,
            v_task=regime.v_default,
            price=regime.price,
            window_limit_tokens=regime.window_limit_tokens,
            shadow_price_usd=regime.shadow_price_usd,
        ),
        regime.cost_basis,
    )
    route = RouteSection.model_validate(
        {
            "cpvs": [c.wire() for c in cells],
            "ladders": [ladder.wire() for ladder in build_ladders(cells, attempts)],
            "knee": knee.wire(),
        }
    )
    carried = previous if previous is not None else {}
    sections = {
        name: bytes(carried[name]) if name in carried else encode_section(DEFAULT_SECTIONS[name])
        for name in SECTION_NAMES
        if name != "route"
    }
    sections["route"] = encode_section(route)
    body = sections_map(sections)
    inherited = sum(1 for c in cells if c.inherited)
    note = (
        f"{len(cells)} cpvs cells ({inherited} inherited), {len(route.ladders)} ladders, "
        f"knee[{knee.cost_basis}] {len(knee.rows)} rows over {knee.certified_attempts} certified "
        f"attempts: {knee.note}; "
        + ("non-route sections carried forward" if carried else "non-route sections defaulted")
    )
    return Compiled(
        sections=sections,
        sections_cbor=body,
        draft_hash=hashlib.sha256(body).digest(),
        knee_gate_ok=knee.publishable,
        note=note,
    )
