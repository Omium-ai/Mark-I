"""The querychoke HTTP read seam (08 §3.3): POST /api/v1/query with a NAMED template; the
chokepoint refuses unknown templates (M1E-2008), it does not improvise. Tenancy is bound
from the bearer's verified claims — no tenant slot ever rides in params (05 §6.2). A service
job names its tenant in the BODY and rides /internal/v1/query under the service credential
(module.go serviceTenant / FromServiceJob) — /api/v1/query only knows device tokens, and
every nightly of every tenant 401ed there (prod 2026-09-20). intel's app/tvo/reader.py is
the fuller twin."""

from collections.abc import Mapping
from typing import Any

import httpx

QUERY_PATH = "/api/v1/query"
SERVICE_QUERY_PATH = "/internal/v1/query"


class QuerychokeError(Exception):
    def __init__(self, code: str, message: str, http_status: int) -> None:
        self.code, self.message, self.http_status = code, message, http_status
        super().__init__(f"{code} (HTTP {http_status}): {message}")


async def run_template(
    http: httpx.AsyncClient,
    base_url: str,
    template: str,
    params: Mapping[str, Any],
    *,
    bearer: str,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    body: dict[str, Any] = {"template": template, "params": dict(params)}
    path = QUERY_PATH
    if tenant_id is not None:
        body["tenant_id"] = tenant_id
        path = SERVICE_QUERY_PATH
    resp = await http.post(
        f"{base_url.rstrip('/')}{path}",
        json=body,
        headers={"Authorization": f"Bearer {bearer}"},
    )
    if resp.status_code != 200:
        try:
            err = resp.json()["error"]
            code, message = err["code"], err.get("message", "")
        except Exception:
            code, message = "M1E-9500", resp.text[:200]
        raise QuerychokeError(code, message, resp.status_code)
    body = resp.json()
    if "rows" not in body or "template_version" not in body:
        raise ValueError(f"querychoke response missing rows/template_version: {body!r}")
    return [dict(r) for r in body["rows"]]
