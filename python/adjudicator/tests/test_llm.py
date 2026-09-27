"""app/llm.py against a MockTransport router: retry on 429/502/503/504 with 1/2/4 s backoff, a
policy block counted and never retried, a reply from an unpinned model refused, Mark 1's agent id
on every call and never a tenant, at most four calls in flight."""

import asyncio
import json

import httpx
import pytest
from app.llm import MARK1_ROUTER_AGENT_ID, RouterClient, RouterRefused, router_skipped_total

MODEL = "zai-org/GLM-5.2"
OK = {
    "model": MODEL,
    "choices": [{"message": {"content": "satisfied"}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 9, "completion_tokens": 1},
}


def router(*answers: httpx.Response | Exception):
    seen: list[httpx.Request] = []
    queue = list(answers)

    async def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        assert not [h for h in req.headers if "tenant" in h.lower()]
        assert "tenant" not in req.content.decode().lower()
        assert req.headers["x-omium-agent-id"] == MARK1_ROUTER_AGENT_ID
        a = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(a, Exception):
            raise a
        return a

    sleeps: list[float] = []

    async def sleep(s: float) -> None:
        sleeps.append(s)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return RouterClient(http, "http://router/", sleep=sleep), seen, sleeps


@pytest.fixture(autouse=True)
def _clear():
    router_skipped_total.clear()


async def test_429_then_200_retries_once_after_one_second():
    client, seen, sleeps = router(httpx.Response(429), httpx.Response(200, json=OK))
    out = await client.complete(MODEL, "sys", "user", 64)
    assert (out.text, out.finish_reason, out.model, out.input_tokens) == (
        "satisfied",
        "stop",
        MODEL,
        9,
    )
    assert len(seen) == 2 and sleeps == [1.0]
    assert seen[0].url == "http://router/v1/chat/completions"
    assert seen[0].headers["x-omium-execution-id"] == seen[1].headers["x-omium-execution-id"]
    assert json.loads(seen[0].content) == {
        "model": MODEL,
        "max_tokens": 64,
        "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "user"}],
    }


async def test_a_router_that_stays_down_is_refused_after_three_retries():
    client, seen, sleeps = router(httpx.Response(503))
    with pytest.raises(RouterRefused, match="refused_router_status:503"):
        await client.complete(MODEL, "s", "u", 8)
    assert len(seen) == 4 and sleeps == [1.0, 2.0, 4.0]


async def test_a_policy_block_is_counted_and_not_retried():
    client, seen, _ = router(httpx.Response(403, headers={"X-Omium-Policy-Blocked": "true"}))
    with pytest.raises(RouterRefused, match="refused_policy_blocked"):
        await client.complete(MODEL, "s", "u", 8)
    assert len(seen) == 1 and router_skipped_total["refused_policy_blocked"] == 1


async def test_a_reply_from_another_model_is_refused():
    client, _, _ = router(httpx.Response(200, json={**OK, "model": "moonshotai/Kimi-K2.7-Code"}))
    with pytest.raises(RouterRefused, match=f"refused_model_mismatch:{MODEL}"):
        await client.complete(MODEL, "s", "u", 8)


async def test_an_unreachable_router_is_refused_not_raised_raw():
    client, seen, _ = router(httpx.ConnectError("no route"))
    with pytest.raises(RouterRefused, match="refused_router_unreachable"):
        await client.complete(MODEL, "s", "u", 8)
    assert len(seen) == 1


async def test_at_most_four_calls_in_flight():
    live = peak = 0

    async def handler(req: httpx.Request) -> httpx.Response:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return httpx.Response(200, json=OK)

    client = RouterClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)), "http://router"
    )
    await asyncio.gather(*(client.complete(MODEL, "s", str(i), 8) for i in range(10)))
    assert peak == 4
