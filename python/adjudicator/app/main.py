"""adjudicator-svc entrypoint — the estate skeleton (06 §1.1), intel's twin."""

from app.logging import configure_logging

# configure_logging() BEFORE the config import (06 §1.1): if Settings refuses to boot,
# the refusal must already be a structured JSON line, not a bare traceback on stderr.
configure_logging()

from contextlib import asynccontextmanager  # noqa: E402
from typing import Any  # noqa: E402

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from app.config import load_settings  # noqa: E402
from app.db import create_pool  # noqa: E402
from app.errors import install_exception_handlers  # noqa: E402
from app.routes import router  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    # Boot refusals crashloop, never limp (06 §1.1): a missing ADJ_PG_DSN raises out
    # of load_settings(), an unreachable Postgres raises out of create_pool(), and both
    # kill the process — k8s restarts us until the operator fixes the cause.
    settings = load_settings()
    pool = await create_pool(settings)
    # One AsyncClient owned by the lifespan (06 §1.1) — the judge-orchestration and
    # query-choke rows will share it; owning it now keeps the skeleton identical to
    # intel's rather than growing a second shape later.
    http = httpx.AsyncClient(timeout=settings.http_timeout_s)
    try:
        yield {"settings": settings, "pool": pool, "http": http}
    finally:
        await http.aclose()
        await pool.close()


app = FastAPI(title="adjudicator-svc", lifespan=lifespan)
install_exception_handlers(app)
app.include_router(router)


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}
