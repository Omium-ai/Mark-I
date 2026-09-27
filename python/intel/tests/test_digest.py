"""The weekly email's body and the Customer.io wire (16-release L3): headers for one-click
unsubscribe, the postal footer, escaping, and tracking/retention off on every send."""

import json
from datetime import date

import httpx
import pytest
from app import mail
from app.digest.weekly import Totals, render


def test_render_carries_unsubscribe_headers_footer_and_estimate_label():
    m = render(
        "a@b.example",
        Totals(sessions=4, tasks_verified=3, tokens=12_345, tokens_saved=-200),
        date(2026, 9, 14),
        "https://api.omium.ai/api/v1/unsubscribe/" + "a" * 64,
        "Omium <Labs>, 1 Main St",
    )
    assert m.to == "a@b.example" and m.subject == "Your week with Mark 1: 3 verified tasks"
    assert m.headers == {
        "List-Unsubscribe": "<https://api.omium.ai/api/v1/unsubscribe/" + "a" * 64 + ">",
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    }
    for part in (m.text, m.html):
        assert "14 Sep – 20 Sep 2026" in part
        assert "12,345" in part and "-200" in part and "estimated" in part
        assert "/api/v1/unsubscribe/" + "a" * 64 in part
    assert "Omium <Labs>, 1 Main St" in m.text
    assert "Omium &lt;Labs&gt;" in m.html and "<Labs>" not in m.html


def test_render_restates_last_week_on_its_own_line():
    args = ("a@b.example", Totals(sessions=1, tokens=10, tokens_saved=5), date(2026, 9, 21))
    plain = render(*args, "https://u.example/x", "Omium")
    moved = render(*args, "https://u.example/x", "Omium", restated=(1_200, -300))
    for part in (plain.text, plain.html):
        assert "restated" not in part
    for part in (moved.text, moved.html):
        assert "tokens saved, restated" in part
        assert "1,200 (was -300)" in part and "arrived later" in part


def test_totals_active_is_any_session_or_token():
    assert not Totals().active
    assert Totals(tokens=1).active and Totals(sessions=1).active


async def test_send_turns_tracking_and_retention_off(monkeypatch):
    monkeypatch.setenv("CUSTOMERIO_APP_API_KEY", "k")
    monkeypatch.setenv("CUSTOMERIO_REGION", "eu")
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["auth"] = str(request.url), request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"delivery_id": "d-9"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        got = await mail.send(http, mail.Message("a@b.example", "s", "<p>h</p>", "h", {"X": "1"}))
    assert got == "d-9"
    assert seen["url"] == "https://api-eu.customer.io/v1/send/email" and seen["auth"] == "Bearer k"
    b = seen["body"]
    assert b["tracked"] is False and b["disable_message_retention"] is True
    assert b["from"] == mail.DEFAULT_FROM and b["body_plain"] == "h" and b["headers"] == {"X": "1"}
    assert b["identifiers"] == {"email": "a@b.example"}


async def test_send_refuses_without_a_key_and_names_status_not_key(monkeypatch):
    monkeypatch.delenv("CUSTOMERIO_APP_API_KEY", raising=False)
    async with httpx.AsyncClient() as http:
        with pytest.raises(mail.MailError, match="unset"):
            await mail.send(http, mail.Message("a@b.example", "s", "h", "h"))
    monkeypatch.setenv("CUSTOMERIO_APP_API_KEY", "secret-key")
    transport = httpx.MockTransport(lambda r: httpx.Response(401, json={"meta": {"error": "no"}}))
    async with httpx.AsyncClient(transport=transport) as http:
        with pytest.raises(mail.MailError, match="401") as exc:
            await mail.send(http, mail.Message("a@b.example", "s", "h", "h"))
    assert "secret-key" not in str(exc.value)


@pytest.mark.parametrize("region", ["apac", "US", "eu-central", " us"])
async def test_an_unknown_region_refuses_to_send_and_to_boot(monkeypatch, region):
    """The register names the configured region; a value it cannot name never falls back to US."""
    from app.config import Settings
    from pydantic import ValidationError

    monkeypatch.setenv("CUSTOMERIO_APP_API_KEY", "k")
    monkeypatch.setenv("CUSTOMERIO_REGION", region)
    transport = httpx.MockTransport(lambda r: pytest.fail(f"sent to {r.url}"))
    async with httpx.AsyncClient(transport=transport) as http:
        with pytest.raises(mail.MailError, match="CUSTOMERIO_REGION"):
            await mail.send(http, mail.Message("a@b.example", "s", "h", "h"))
    boot = {"pg_dsn": "postgres://x", "querychoke_base_url": "u", "adjudicator_base_url": "u"}
    with pytest.raises(ValidationError, match="CUSTOMERIO_REGION"):
        Settings(**boot)
    for ok, want in (("eu", "eu"), ("us", "us"), ("", "us")):
        monkeypatch.setenv("CUSTOMERIO_REGION", ok)
        assert Settings(**boot).customerio_region == want
