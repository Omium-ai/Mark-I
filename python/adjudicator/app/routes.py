"""adjudicator-svc's synchronous surface (06 §1.2) — the Phase 2 rows:

  GET  /v1/registry/verifiers      registry read (policy compiler, `mark1 doctor`)
  GET  /v1/certs/{tenant}/current  the §5.4 status check (intel's cert provider consumes
                                   exactly this shape: status + binary projection)
  POST /v1/adjudicate/preview      ADJUDICATE on supplied votes, nothing persisted
                                   (debug/conformance tooling)

`GET /v1/verdicts/{task_id}` (ledger lookup via controld.query-choke) is NOT built:
it needs the choke reader integration that lands with the readjudicate batch job.
Nothing latency-critical calls any of this: the edge gate reads mark1d's fused cache
(C3); if this service is down, sessions degrade to PROVISIONAL and certification lags —
fail-open for availability."""

from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.adjudicate.algorithm import VerdictEvent, adjudicate
from app.adjudicate.chow import Costs
from app.adjudicate.likelihoods import (
    CLASSES,
    DEFAULT_PRIORS,
    KIND_TO_GROUP,
    Bundle,
    VerifierParams,
)
from app.certs.store import current_cert
from app.registry.catalog import list_verifiers
from app.registry.handlers import _HANDLED_KINDS, NormalizedVote
from app.registry.integrity import IntegrityFlags

router = APIRouter()


def _pool(request: Request) -> asyncpg.Pool:
    return request.state.pool


@router.get("/v1/registry/verifiers")
async def registry_verifiers(request: Request) -> dict:
    entries = await list_verifiers(_pool(request))
    return {
        "verifiers": [
            {
                "id": str(e.id),
                "verifier_key": e.verifier_key,
                "version": e.version,
                "kind": e.kind,
                "db_kind": e.db_kind,
                "has_execution_hash": e.effective_execution_hash is not None,
            }
            for e in entries
        ]
    }


@router.get("/v1/certs/{tenant_id}/current")
async def certs_current(tenant_id: str, request: Request) -> dict:
    cert = await current_cert(_pool(request), tenant_id)
    return {
        "cert_id": str(cert.id) if cert.id else None,
        "status": cert.status,
        "rho_plus": cert.rho_plus,
        "rho_minus": cert.rho_minus,
        "natarajan_lcb": cert.natarajan_lcb,
        "issued_at": cert.issued_at.isoformat() if cert.issued_at else None,
        "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
    }


class PreviewVote(BaseModel):
    verifier_id: str
    kind: str  # one of the 06 §2.1 handler kinds — anything else is refused upstream
    vote: str  # accept | reject | abstain
    tamper: bool = False
    infra_failed: bool = False


class PreviewVerifier(BaseModel):
    """Optional bundle override for one verifier — the conformance fixtures supply the
    papers' exact matrices this way."""

    confusion: list[list[float]] = Field(min_length=4, max_length=4)  # 4×3, [S,V,R,E]
    group: str | None = None
    provenance: str = "prior"


class PreviewRequest(BaseModel):
    votes: list[PreviewVote]
    priors: list[float] | None = Field(default=None, min_length=4, max_length=4)
    verifiers: dict[str, PreviewVerifier] = Field(default_factory=dict)
    costs: dict[str, float] | None = None  # {"A": …, "R": …, "D": …}
    # Deliberately NO noise_cert_id: this route is unauthenticated, tenant-less debug
    # tooling — a caller-supplied cert id it cannot validate would be laundered into a
    # CERTIFIED-looking event. Preview always stamps "" (honestly uncertified).


@router.post("/v1/adjudicate/preview")
async def adjudicate_preview(req: PreviewRequest) -> dict:
    bundle = Bundle(
        priors=tuple(req.priors) if req.priors else DEFAULT_PRIORS,  # type: ignore[arg-type]
        verifiers={
            vid: VerifierParams(
                verifier_id=vid,
                kind="preview",
                confusion=tuple(tuple(row) for row in spec.confusion),  # type: ignore[arg-type]
                group=spec.group or vid,
                provenance=spec.provenance,  # type: ignore[arg-type]
            )
            for vid, spec in req.verifiers.items()
        },
    )
    votes = []
    for pv in req.votes:
        if pv.verifier_id not in bundle.verifiers and pv.kind not in _HANDLED_KINDS:
            # The §2.2 refusal discipline holds even in preview: no likelihood row can
            # be fabricated for a kind this build cannot interpret.
            return {
                "refusal": True,
                "reason": f"refused_unimplemented_kind:{pv.kind}",
                "verifier_id": pv.verifier_id,
            }
        votes.append(
            NormalizedVote(
                verifier_id=pv.verifier_id,
                kind=pv.kind,
                task_id=_PREVIEW_TASK,
                attempt_id=uuid4(),
                vote=pv.vote,  # type: ignore[arg-type]
                evidence_digest=b"",
                integrity=IntegrityFlags(tamper=pv.tamper, infra_failed=pv.infra_failed),
                tier="T0",
            )
        )
    costs = Costs(req.costs["A"], req.costs["R"], req.costs["D"]) if req.costs else Costs()
    event: VerdictEvent = adjudicate(votes, bundle, costs)
    return {
        "stage": event.stage,
        "verdict": event.verdict,
        "posterior": list(event.posterior),
        "classes": list(CLASSES),
        "noise_cert_id": event.noise_cert_id,
        "vote_count": event.vote_count,
        "reason": event.reason,
        "provenance": event.provenance,
        "groups": sorted(set(KIND_TO_GROUP.values())),
    }


_PREVIEW_TASK = UUID("00000000-0000-0000-0000-000000000000")  # preview persists nothing
