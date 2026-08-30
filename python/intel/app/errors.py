"""Exception handlers (06 §1.1): infrastructure timeouts surface as 503 + Retry-After, never 500."""

from asyncpg import InterfaceError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.tvo.reader import QuerychokeError


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(TimeoutError)
    @app.exception_handler(InterfaceError)
    async def _dependency_unavailable(request: Request, exc: Exception) -> JSONResponse:
        # 503 with Retry-After: the caller's retry policy is the recovery path — a 500
        # would read as a bug in us when the truth is a store being slow (fail-open for
        # availability, per the normative posture matrix).
        return JSONResponse(
            status_code=503,
            content={"error": "dependency_unavailable"},
            headers={"Retry-After": "5"},
        )

    @app.exception_handler(QuerychokeError)
    async def _choke_error(request: Request, exc: QuerychokeError) -> JSONResponse:
        # The choke's M1E code crosses intact — one taxonomy, every surface (08 §9).
        # Retryable (M1E-9001/M1E-9500 class) keeps the 503+Retry-After posture above.
        # An auth-class refusal (M1E-1xxx) is about the CALLER's forwarded token — it
        # passes through with its original status (fail-closed stays fail-closed).
        # Anything else (e.g. M1E-2008 unknown template) is OUR bug: 502 says "the
        # dependency refused us", never a silent 500.
        body = {"error": {"code": exc.code, "message": exc.message}}
        if exc.retryable:
            return JSONResponse(status_code=503, content=body, headers={"Retry-After": "5"})
        if exc.code.startswith("M1E-1") and 400 <= exc.http_status < 500:
            return JSONResponse(status_code=exc.http_status, content=body)
        return JSONResponse(status_code=502, content=body)
