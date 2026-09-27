"""The report surface end-to-end over mocked reads: request → reader (httpx-mocked
querychoke) → engine → report.py assembly → the 08 §3.3 body. Golden numbers reuse the
Paper I fixture (06 §8.6 — the papers' numbers, not ours); the M1E-5004 refusal surfaces
in the doc's exact wire shape (200 body, "refusal": "M1E-5004 coverage below floor…")."""

import json
from pathlib import Path

import httpx
import pytest
from app.errors import install_exception_handlers
from app.tvo.engine import NoiseCertificate
from app.tvo.reader import QuerychokeReader
from app.tvo.report import ModelPrice
from app.tvo.routes import (
    get_cert_provider,
    get_price_row,
    get_reader,
    get_shadow_price,
    router,
)
from choke_mock import MockChoke
from fastapi import FastAPI

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "paper1_worked_example.json").read_text()
)
GROUNDED = next(r for r in FIXTURE["regimes"] if r["name"] == "grounded_rubric_auc_0.886")
POP = FIXTURE["population"]

BEARER = "op-token-tenant-a"
Q = {"tenant_id": "ten-a", "cost_basis": "usd"}
PRICE = ModelPrice("prices-v3", 3e-6, 15e-6, 3.75e-6, 0.3e-6)

# Five single-attempt tasks reproducing the Paper I grounded-rubric operating point from
# LEDGER shapes: c = 30k, v = 25k measured as means; p = 0.4 as 2 certified-satisfied of
# 5 certified terminal verdicts; (α, β) = (0.85, 0.20) from the certificate's binary
# projection (ρ₊ = 0.15, ρ₋ = 0.20); D stays the engine's calibrated 150k default.
PAPER1_ROWS = [
    {
        "task_id": f"t{i}",
        "attempt_n": 1,
        "gen_tokens": POP["c"],
        "verifier_tokens": GROUNDED["v"],
        "fused_verdict": "satisfied" if i < 2 else "violated",
        "verdict_stage": "certified",
        "task_seg_version": "task_seg.v1",
        "cost_usd": 0.5,
    }
    for i in range(5)
]
CERTIFIED = NoiseCertificate(
    "certified", rho_plus=1.0 - GROUNDED["alpha"], rho_minus=GROUNDED["beta"]
)

GOOD_COVERAGE = [{"observed_ms": 980_000, "bypass_ms": 10_000, "disabled_ms": 10_000}]
LOW_COVERAGE = [{"observed_ms": 850_000, "bypass_ms": 150_000, "disabled_ms": 0}]
NO_DROPS = [{"day": "2026-08-01", "dropped_billing": 0, "events_billing_ingested": 1000}]


def build_app(
    choke: MockChoke,
    cert: NoiseCertificate = CERTIFIED,
    price: ModelPrice | None = PRICE,
) -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)
    app.include_router(router)

    reader = QuerychokeReader(choke.client(), "http://choke")

    async def fetch_cert(tenant_id: str, bearer: str) -> NoiseCertificate:
        return cert

    app.dependency_overrides[get_reader] = lambda: reader
    app.dependency_overrides[get_cert_provider] = lambda: fetch_cert
    app.dependency_overrides[get_price_row] = lambda: price
    app.dependency_overrides[get_shadow_price] = lambda: (None, False)
    return app


def client_for(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://intel",
        headers={"Authorization": f"Bearer {BEARER}"},
    )


def choke_with(coverage_rows, rows=PAPER1_ROWS) -> MockChoke:
    choke = MockChoke()
    choke.templates["tvo_task_window"] = rows
    choke.templates["coverage_band"] = coverage_rows
    choke.templates["dropped_by_tenant_day"] = NO_DROPS
    return choke


async def test_golden_paper1_grounded_rubric_guarantee_grade():
    app = build_app(choke_with(GOOD_COVERAGE))
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params=Q)
    assert resp.status_code == 200
    body = resp.json()

    # Table 1 prints TVO to 0.1k tokens — same rounding as test_paper1_reconciliation.
    assert round(body["tvo"] / 100.0) * 100.0 == GROUNDED["tvo_tokens"]
    assert body["guarantee_grade"] is True
    assert body["grade"] == "guarantee-grade"
    assert "refusal" not in body
    assert body["cost_basis"] == "usd"
    assert body["task_seg_version"] == "task_seg.v1"
    assert body["coverage_band"]["observed_fraction"] == pytest.approx(0.98)
    assert body["coverage_band"]["floor"] == 0.95
    # 08 §3.3 wire names, exact (re_exploration_tokens, not reexploration_tokens).
    assert set(body["waste"]) == {
        "retry_loop_tokens",
        "re_exploration_tokens",
        "over_model_tokens",
    }
    assert body["trend"] == []
    assert body["input_provenance"]["alpha"] == "measured"


async def test_m1e_5004_refusal_in_wire_shape():
    app = build_app(choke_with(LOW_COVERAGE))
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params=Q)
    assert resp.status_code == 200  # 08 §9: M1E-5004 is a 200-body refusal, CLI exit 4
    body = resp.json()
    assert body["guarantee_grade"] is False
    assert body["grade"] == "indicative"
    assert body["refusal"].startswith("M1E-5004 coverage below floor")
    assert body["tvo"] > 0  # the number still renders — refused outright, not withheld


async def test_uncertified_cert_downgrades_and_states_status():
    app = build_app(choke_with(GOOD_COVERAGE), cert=NoiseCertificate("bootstrapping"))
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params=Q)
    body = resp.json()
    assert body["guarantee_grade"] is False
    assert "bootstrapping" in body["refusal"]  # §5.4: the status string appears verbatim
    assert body["input_provenance"]["alpha"] == "calibrated"


async def test_bad_window_is_m1e_2001():
    app = build_app(choke_with(GOOD_COVERAGE))
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params={**Q, "window": "banana"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "M1E-2001"


async def test_empty_window_is_m1e_2001():
    app = build_app(choke_with(GOOD_COVERAGE, rows=[]))
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params=Q)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "M1E-2001"


async def test_unmeasurable_window_is_m1e_2001_not_500():
    # All-provisional terminal verdicts: p has no denominator; the engine refuses and the
    # refusal crosses as a taxonomy error, never a bare 500.
    rows = [dict(r, verdict_stage="provisional") for r in PAPER1_ROWS]
    app = build_app(choke_with(GOOD_COVERAGE, rows=rows))
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params=Q)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "M1E-2001"
    assert "unmeasurable" in resp.json()["error"]["message"]


async def test_choke_outage_surfaces_as_retryable_503():
    choke = choke_with(GOOD_COVERAGE)
    choke.fail_with = (503, "M1E-9500", "clickhouse unavailable")
    app = build_app(choke)
    async with client_for(app) as client:
        resp = await client.get("/v1/reports/tvo", params=Q)
    assert resp.status_code == 503
    assert resp.headers["Retry-After"] == "5"
    assert resp.json()["error"]["code"] == "M1E-9500"


async def test_missing_bearer_fails_closed_as_403():
    app = build_app(choke_with(GOOD_COVERAGE))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://intel"
    ) as client:  # no Authorization header at all
        resp = await client.get("/v1/reports/tvo", params=Q)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "M1E-1001"
