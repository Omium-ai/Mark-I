"""The platform llm-router client (16 §L1): Nebius Token Factory behind `POST /v1/chat/completions`.

Mark 1 identifies as its own system agent and never as a tenant: a tenant header or `tenant_id`
would send the prod router's adapter hop to Baseten, a subprocessor no consent names. The model
is a pinned catalog id and a reply served by any other model is refused."""

import asyncio
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from app.db import set_local_tenant

# Registered in the platform's INTERNAL_SYSTEM_AGENT_IDS (omium-gitops helm/values.prod.yaml)
MARK1_ROUTER_AGENT_ID = "82681657-38ac-4ca0-92ad-53134ddf724a"
COMPLETIONS_PATH = "/v1/chat/completions"
TIMEOUT_S = 190.0  # the router's own backend timeout is 180 s
CONCURRENCY = 4
RETRY_STATUSES = frozenset({429, 502, 503, 504})
BACKOFF_S = (1.0, 2.0, 4.0)

router_skipped_total: Counter[str] = Counter()


class RouterRefused(Exception):
    """No completion to use; `reason` is the counted, machine-readable form."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class Completion:
    text: str
    finish_reason: str | None
    model: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int


def _refuse(reason: str, detail: str = "") -> RouterRefused:
    router_skipped_total[reason.split(":", 1)[0]] += 1
    return RouterRefused(reason, detail)


class RouterClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        base_url: str,
        *,
        backoff: tuple[float, ...] = BACKOFF_S,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._http, self._url = http, base_url.rstrip("/") + COMPLETIONS_PATH
        self._backoff, self._sleep = backoff, sleep
        self._sem = asyncio.Semaphore(CONCURRENCY)

    async def complete(self, model: str, system: str, user: str, max_tokens: int) -> Completion:
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        headers = {
            "X-Omium-Agent-Id": MARK1_ROUTER_AGENT_ID,
            "X-Omium-Execution-Id": str(uuid.uuid4()),
        }
        async with self._sem:
            for wait in (*self._backoff, None):
                try:
                    resp = await self._http.post(
                        self._url, json=body, headers=headers, timeout=TIMEOUT_S
                    )
                except httpx.HTTPError as exc:
                    raise _refuse("refused_router_unreachable", type(exc).__name__) from exc
                if resp.status_code in RETRY_STATUSES and wait is not None:
                    await self._sleep(wait)
                    continue
                break
        if resp.status_code == 403 and resp.headers.get("X-Omium-Policy-Blocked") == "true":
            raise _refuse("refused_policy_blocked", resp.text[:200])
        if resp.status_code != 200:
            raise _refuse(f"refused_router_status:{resp.status_code}", resp.text[:200])
        return _completion(model, resp.json())


def _completion(model: str, data: dict) -> Completion:
    served = data.get("model")
    if served != model:
        raise _refuse(f"refused_model_mismatch:{model}", f"served {served!r}")
    choices = data.get("choices") or []
    if not choices:
        raise _refuse("refused_empty_choices", model)
    message = choices[0].get("message") or {}
    usage = data.get("usage") or {}
    return Completion(
        text=message.get("content") or "",
        finish_reason=choices[0].get("finish_reason"),
        model=served,
        input_tokens=int(usage.get("prompt_tokens") or 0),
        output_tokens=int(usage.get("completion_tokens") or 0),
        cached_tokens=int((usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0),
    )


async def reserve_today(conn: Any, tenant_id: str, key: str, want: int, cap: int) -> int:
    """Up to `want` units of the tenant's UTC-day allowance for `key` (m1_101), taken BEFORE any
    call: a rerun, retry or restart draws on the same day's row, so no schedule multiplies spend."""
    if want <= 0 or cap <= 0:
        return 0
    async with conn.transaction():
        await set_local_tenant(conn, tenant_id)
        row = await conn.fetchrow(
            "INSERT INTO m1_llm_spend_days (tenant_id, day, spend_key) "
            "VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2) "
            "ON CONFLICT (tenant_id, day, spend_key) DO UPDATE SET updated_at = now() "
            "RETURNING day, units",
            uuid.UUID(tenant_id),
            key,
        )
        grant = max(0, min(want, cap - int(row["units"])))
        if grant:
            await conn.execute(
                "UPDATE m1_llm_spend_days SET units = units + $4, updated_at = now() "
                "WHERE tenant_id = $1 AND day = $2 AND spend_key = $3",
                uuid.UUID(tenant_id),
                row["day"],
                key,
                grant,
            )
    return grant
