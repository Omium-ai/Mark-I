"""`digest.weekly` (Mondays, window = the previous Mon..Sun): one email per opted-in person of this
tenant who did any work that week. The ledger row goes in as `sending` before the send and becomes
`sent`/`failed` after, so a re-run retries only failures and never mails anyone twice. The row keeps
the tokens-saved figure it mailed; when late verdicts move that week's figure, the next email
carries a restated line (ADR-0013)."""

import contextlib
import html
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any
from uuid import UUID

import httpx

from app import mail
from app.db import set_local_tenant
from app.tvo.reader import QuerychokeReader

log = logging.getLogger("digest.weekly")

KIND = "weekly_digest"

_SUBSCRIBERS = """
SELECT p.subject, p.email, p.unsub_token FROM m1_notification_prefs p
 WHERE p.tenant_id = $1 AND p.weekly_digest AND p.email IS NOT NULL
   AND (p.subject = (SELECT owner_subject FROM m1_tenants WHERE id = $1)
        OR EXISTS (SELECT 1 FROM m1_team_members m WHERE m.tenant_id = $1 AND m.subject = p.subject
                    AND m.role = 'member' AND m.left_at IS NULL))
   AND NOT EXISTS (SELECT 1 FROM m1_notification_sends s
                    WHERE s.tenant_id = $1 AND s.subject = p.subject AND s.kind = $3
                      AND s.period_start = $2 AND s.outcome IN ('sending', 'sent'))
 ORDER BY p.subject"""

# ADR-0013: what last week's email said, so a verdict that landed after it is restated, not ignored.
_MAILED = """
SELECT subject, tokens_saved FROM m1_notification_sends
 WHERE tenant_id = $1 AND kind = $2 AND period_start = $3 AND outcome = 'sent'
   AND tokens_saved IS NOT NULL"""

_DEVICE_OWNERS = """
SELECT DISTINCT ON (device_id) device_id::text AS device_id, oidc_subject
  FROM m1_device_enrollments
 WHERE tenant_id = $1 AND device_id IS NOT NULL AND oidc_subject IS NOT NULL
   AND status IN ('approved', 'revoked')
 ORDER BY device_id, row_seq DESC"""


@dataclass
class Totals:
    sessions: int = 0
    tasks_verified: int = 0
    tokens: int = 0
    tokens_saved: int = 0

    def add(self, row: dict[str, Any]) -> None:
        self.sessions += int(row.get("sessions") or 0)
        self.tasks_verified += int(row.get("tasks_verified") or 0)
        self.tokens += int(row.get("tokens") or 0)
        self.tokens_saved += int(row.get("tokens_saved") or 0)

    @property
    def active(self) -> bool:
        return self.sessions > 0 or self.tokens > 0


def _n(v: int) -> str:
    return f"{v:,}"


def render(
    to: str,
    t: Totals,
    start: date,
    unsub_url: str,
    postal: str,
    restated: tuple[int, int] | None = None,
) -> mail.Message:
    """`restated` is (now, mailed) for the previous week's tokens saved when verdicts that
    landed after that email moved it (ADR-0013); a sent email is never restated in place."""
    end = start + timedelta(days=6)
    week = f"{start.day} {start:%b} – {end.day} {end:%b %Y}"
    saved = _n(t.tokens_saved)
    rows = [
        ("Sessions", _n(t.sessions)),
        ("Verified tasks", _n(t.tasks_verified)),
        ("Tokens used", _n(t.tokens)),
        ("Tokens saved (estimated)", saved),
    ]
    note = "Tokens saved is an estimate against plain Claude Code and can be negative."
    if restated is not None:
        rows.append(
            ("Last week's tokens saved, restated", f"{_n(restated[0])} (was {_n(restated[1])})")
        )
        note += " Last week's figure changed after verdicts that arrived later were counted."
    text = (
        f"Your week with Mark 1 ({week})\n\n"
        + "".join(f"{k}: {v}\n" for k, v in rows)
        + f"\n{note}\n\n"
        + "You get this because you turned on the weekly email in Mark 1.\n"
        + f"Unsubscribe: {unsub_url}\n\n{postal}\n"
    )
    e = html.escape
    cells = "".join(
        f'<tr><td style="padding:6px 16px 6px 0;color:#52525b">{e(k)}</td>'
        f'<td style="padding:6px 0;font-weight:600;text-align:right">{e(v)}</td></tr>'
        for k, v in rows
    )
    body = (
        '<div style="font:15px/1.5 system-ui,sans-serif;color:#18181b;max-width:480px">'
        f'<h1 style="font-size:18px;margin:0 0 4px">Your week with Mark 1</h1>'
        f'<p style="margin:0 0 16px;color:#71717a">{e(week)}</p>'
        f'<table style="border-collapse:collapse">{cells}</table>'
        f'<p style="margin:16px 0;color:#71717a;font-size:13px">{e(note)}</p>'
        '<p style="margin:24px 0 0;color:#a1a1aa;font-size:12px">'
        "You get this because you turned on the weekly email in Mark 1. "
        f'<a href="{e(unsub_url)}" style="color:#a1a1aa">Unsubscribe</a>'
        f"<br>{e(postal)}</p></div>"
    )
    return mail.Message(
        to=to,
        subject=f"Your week with Mark 1: {_n(t.tasks_verified)} verified tasks",
        html=body,
        text=text,
        headers={
            "List-Unsubscribe": f"<{unsub_url}>",
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        },
    )


async def _ledger(
    pool: Any, tenant: str, subject: str, start: date, outcome: str, **kw: Any
) -> None:
    async with pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        await conn.execute(
            "INSERT INTO m1_notification_sends "
            "(tenant_id, subject, kind, period_start, outcome, delivery_id, error, tokens_saved) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
            "ON CONFLICT (tenant_id, subject, kind, period_start) "
            "DO UPDATE SET outcome = EXCLUDED.outcome, "
            "delivery_id = EXCLUDED.delivery_id, error = EXCLUDED.error, "
            "tokens_saved = COALESCE(EXCLUDED.tokens_saved, m1_notification_sends.tokens_saved), "
            "updated_at = now()",
            UUID(tenant),
            subject,
            KIND,
            start,
            outcome,
            kw.get("delivery_id"),
            kw.get("error"),
            kw.get("tokens_saved"),
        )


async def weekly(
    ctx: Any,
    *,
    http: httpx.AsyncClient | None = None,
    send: Callable[[httpx.AsyncClient, mail.Message], Awaitable[str]] | None = None,
) -> str | None:
    """Scheduler target `app.digest.weekly:weekly`; refuses (raises) rather than send without a
    postal address or a Customer.io key, counting who would have been mailed."""
    send = send or mail.send
    start = ctx.window_start.date()
    tenant = ctx.tenant_id
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, tenant)
        subscribers = await conn.fetch(_SUBSCRIBERS, UUID(tenant), start, KIND)
        owners = (
            {}
            if not subscribers
            else {
                r["device_id"]: r["oidc_subject"]
                for r in await conn.fetch(_DEVICE_OWNERS, UUID(tenant))
            }
        )
        mailed = (
            {}
            if not subscribers
            else {
                r["subject"]: int(r["tokens_saved"])
                for r in await conn.fetch(_MAILED, UUID(tenant), KIND, start - timedelta(days=7))
            }
        )
    if not subscribers:
        return None
    bearer = os.environ.get("INTEL_QUERYCHOKE_TOKEN", "")
    if not bearer:
        raise RuntimeError("INTEL_QUERYCHOKE_TOKEN is required (intel's service credential)")
    own = (
        contextlib.nullcontext(http)
        if http
        else httpx.AsyncClient(timeout=ctx.settings.http_timeout_s)
    )
    async with own as client:
        reader = QuerychokeReader(client, ctx.settings.querychoke_base_url, tenant_id=tenant)

        async def totals(first: date) -> dict[str, Totals]:
            result = await reader.run_template(
                "team_device_totals",
                {"from": first.isoformat(), "to": (first + timedelta(days=6)).isoformat()},
                bearer=bearer,
            )
            out: dict[str, Totals] = {}
            for row in result.rows:
                subject = owners.get(str(row["device_id"]))
                if subject:
                    out.setdefault(subject, Totals()).add(row)
            return out

        per = await totals(start)
        due = [s for s in subscribers if per.get(s["subject"], Totals()).active]
        # last week read now (v2 resolves to today) differs from the mail iff a verdict moved it
        restated: dict[str, tuple[int, int]] = {}
        if any(s["subject"] in mailed for s in due):
            before = await totals(start - timedelta(days=7))
            for subject, was in mailed.items():
                now = before.get(subject, Totals()).tokens_saved
                if now != was:
                    restated[subject] = (now, was)
        skipped = len(subscribers) - len(due)
        postal = os.environ.get("EMAIL_POSTAL_ADDRESS", "").strip()
        missing = [
            n
            for n, v in (
                ("EMAIL_POSTAL_ADDRESS", postal),
                ("CUSTOMERIO_APP_API_KEY", mail.api_key()),
            )
            if not v
        ]
        if due and missing:
            raise RuntimeError(
                f"{' and '.join(missing)} unset: {len(due)} weekly digest(s) not sent"
            )
        base = os.environ.get("PUBLIC_BASE_URL", "https://api.omium.ai").rstrip("/")
        sent = failed = 0
        for s in due:
            msg = render(
                s["email"],
                per[s["subject"]],
                start,
                f"{base}/api/v1/unsubscribe/{s['unsub_token']}",
                postal,
                restated.get(s["subject"]),
            )
            await _ledger(
                ctx.pool,
                tenant,
                s["subject"],
                start,
                "sending",
                tokens_saved=per[s["subject"]].tokens_saved,
            )
            try:
                delivery = await send(client, msg)
            except Exception as exc:
                failed += 1
                await _ledger(
                    ctx.pool, tenant, s["subject"], start, "failed", error=repr(exc)[:500]
                )
                continue
            sent += 1
            await _ledger(
                ctx.pool, tenant, s["subject"], start, "sent", delivery_id=delivery or None
            )
    log.info(
        "digest.weekly %s %s: sent=%d failed=%d skipped_no_activity=%d",
        tenant,
        start,
        sent,
        failed,
        skipped,
    )
    if failed:
        raise RuntimeError(f"{failed} weekly digest(s) failed to send; a re-run retries only those")
    return None
