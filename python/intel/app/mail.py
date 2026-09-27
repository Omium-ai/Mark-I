"""Customer.io App API transactional send (16-release L3), the Python twin of controld's
internal/mail: no template, click/open tracking off, message retention off."""

import os
from dataclasses import dataclass, field

import httpx

DEFAULT_FROM = "noreply@mail.omium.ai"
_ENDPOINT = {
    "us": "https://api.customer.io/v1/send/email",
    "eu": "https://api-eu.customer.io/v1/send/email",
}


@dataclass(frozen=True)
class Message:
    to: str
    subject: str
    html: str
    text: str
    headers: dict[str, str] = field(default_factory=dict)


class MailError(RuntimeError):
    pass


def api_key() -> str:
    return os.environ.get("CUSTOMERIO_APP_API_KEY", "")


def endpoint() -> str:
    """The configured workspace region's send URL: the region the register names, never a
    fallback. Anything but us|eu refuses, as controld's config does (boot refusal R1)."""
    region = os.environ.get("CUSTOMERIO_REGION") or "us"
    if region not in _ENDPOINT:
        raise MailError(f"CUSTOMERIO_REGION={region!r} is not us or eu")
    return _ENDPOINT[region]


async def send(http: httpx.AsyncClient, m: Message) -> str:
    """Customer.io's delivery_id; a refusal raises MailError naming the status, never the key."""
    key = api_key()
    if not key:
        raise MailError("CUSTOMERIO_APP_API_KEY unset")
    url = endpoint()
    body = {
        "to": m.to,
        "identifiers": {"email": m.to},
        "from": os.environ.get("EMAIL_FROM") or DEFAULT_FROM,
        "subject": m.subject,
        "body": m.html,
        "body_plain": m.text,
        "tracked": False,
        "disable_message_retention": True,
    }
    if m.headers:
        body["headers"] = m.headers
    resp = await http.post(
        url,
        json=body,
        headers={"Authorization": f"Bearer {key}"},
    )
    if resp.status_code >= 300:
        raise MailError(f"customer.io: {resp.status_code} {resp.text[:300]}")
    try:
        return str(resp.json().get("delivery_id") or "")
    except ValueError:
        return ""
