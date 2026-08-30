"""The preview surface end-to-end over ASGITransport (no persistence, no DB —
`POST /v1/adjudicate/preview` is exactly the debug/conformance tool 06 §1.2 names).
The DB-backed routes (registry, certs) are exercised in test_pg_stores.py under the
estate's env-DSN gate."""

import httpx
from app.errors import install_exception_handlers
from app.routes import router
from fastapi import FastAPI

# 06 §3.2's example, as the conformance tooling would post it.
PREVIEW_06 = {
    "priors": [0.55, 0.30, 0.10, 0.05],
    "verifiers": {
        "cargo-check-warm": {
            "confusion": [
                [0.98, 0.02, 0.00],
                [0.60, 0.40, 0.00],
                [0.50, 0.05, 0.45],
                [0.50, 0.05, 0.45],
            ],
            "group": "syntactic",
        },
        "ruff": {
            "confusion": [[0.2, 0.1, 0.7]] * 4,
            "group": "syntactic",
        },
        "judge:grounded-rubric": {
            "confusion": [
                [0.80, 0.15, 0.05],
                [0.25, 0.70, 0.05],
                [0.20, 0.40, 0.40],
                [0.20, 0.40, 0.40],
            ],
            "group": "judges",
        },
    },
    "votes": [
        {"verifier_id": "cargo-check-warm", "kind": "compile", "vote": "accept"},
        {"verifier_id": "ruff", "kind": "lint", "vote": "abstain"},
        {"verifier_id": "judge:grounded-rubric", "kind": "judge", "vote": "reject"},
    ],
}


def build_app() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)
    app.include_router(router)
    return app


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=build_app()), base_url="http://adj")


async def test_preview_reproduces_the_06_worked_example():
    async with client() as c:
        resp = await c.post("/v1/adjudicate/preview", json=PREVIEW_06)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "refused"
    assert body["stage"] == "uncertified"  # preview stamps no cert; priors fused
    assert [round(p, 4) for p in body["posterior"]] == [0.3414, 0.5320, 0.0844, 0.0422]
    assert body["classes"] == ["satisfied", "violated", "refused", "error"]
    assert body["noise_cert_id"] == ""  # nothing stamped ⇒ honestly uncertified


async def test_preview_unimplemented_kind_is_refused():
    payload = {
        "votes": [{"verifier_id": "mystery", "kind": "vibes", "vote": "accept"}],
    }
    async with client() as c:
        resp = await c.post("/v1/adjudicate/preview", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["refusal"] is True
    assert body["reason"] == "refused_unimplemented_kind:vibes"


async def test_preview_calibrated_defaults_cover_handled_kinds():
    # No verifier overrides at all: kinds fall back to the literature-CALIBRATED
    # defaults (provenance 'prior') and still adjudicate.
    payload = {
        "votes": [
            {"verifier_id": "cargo-check-warm@1", "kind": "compile", "vote": "accept"},
            {"verifier_id": "judge:x@1", "kind": "judge", "vote": "accept"},
        ],
    }
    async with client() as c:
        resp = await c.post("/v1/adjudicate/preview", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] in {"satisfied", "violated", "refused", "error"}
    assert len(body["posterior"]) == 4
