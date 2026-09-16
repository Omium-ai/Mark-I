"""mark1-intel entrypoint — deliberately minimal: the report/job surfaces arrive with later rows."""

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
from app.memory.routes import router as memory_router  # noqa: E402
from app.tvo.reader import QuerychokeReader  # noqa: E402
from app.tvo.routes import router as tvo_router  # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    # Boot refusals crashloop, never limp (06 §1.1): a missing INTEL_PG_DSN raises out
    # of load_settings(), an unreachable Postgres raises out of create_pool(), and both
    # kill the process — k8s restarts us until the operator fixes the cause.
    settings = load_settings()
    pool = await create_pool(settings)
    http = httpx.AsyncClient(timeout=settings.http_timeout_s)
    # The one ledger read path (08 §3.3): the querychoke HTTP client, on the lifespan's
    # shared httpx client. No ClickHouse driver exists in this service (05 §6).
    tvo_reader = QuerychokeReader(http, settings.querychoke_base_url)
    try:
        yield {"settings": settings, "pool": pool, "http": http, "tvo_reader": tvo_reader}
    finally:
        await http.aclose()
        await pool.close()


app = FastAPI(title="mark1-intel", lifespan=lifespan)
install_exception_handlers(app)
app.include_router(tvo_router)
app.include_router(memory_router)


@app.get("/healthz")
async def healthz() -> dict[str, bool]:
    return {"ok": True}
