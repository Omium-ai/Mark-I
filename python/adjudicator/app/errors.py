"""Exception handlers (06 §1.1): infrastructure timeouts surface as 503 + Retry-After,
never 500. Intel's errors.py minus the querychoke arm — this service reads the ledger
via controld.query-choke only on the verdict-lookup row, which is not built yet."""

from asyncpg import InterfaceError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(TimeoutError)
    @app.exception_handler(InterfaceError)
    async def _dependency_unavailable(request: Request, exc: Exception) -> JSONResponse:
        # 503 with Retry-After: the caller's retry policy is the recovery path — a 500
        # would read as a bug in us when the truth is a store being slow (fail-open for
        # availability, per the normative posture matrix; 06 §1.2's degradation note).
        return JSONResponse(
            status_code=503,
            content={"error": "dependency_unavailable"},
            headers={"Retry-After": "5"},
        )
