"""E2B sandbox client (14 task 6.5: rent first). Two hosts, one key: the platform API
creates and kills sandboxes; envd on the shared sandbox host takes uploads and runs
processes for one sandbox under its per-sandbox access token. The API key lives only
in a SecretStr and is put on the wire per request, never on the instance or a log."""

import base64
import json
import struct
from dataclasses import dataclass

import httpx
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

ENVD_PORT = "49983"


class E2BSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADJ_E2B_", frozen=True)

    api_key: SecretStr  # X-API-Key on the platform host, never logged
    template: str = "base"
    region: str = "us"  # the geography of api_base/sandbox_base; the consent row must name it
    ttl_s: int = 600
    api_base: str = "https://api.e2b.app"
    sandbox_base: str = "https://sandbox.e2b.app"


_END_STREAM = 0x02


@dataclass(frozen=True)
class Sandbox:
    id: str
    token: SecretStr


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


def _envelope(payload: bytes, flags: int = 0) -> bytes:
    return struct.pack(">BI", flags, len(payload)) + payload


def _frames(body: bytes) -> list[tuple[int, dict]]:
    out, i = [], 0
    while i + 5 <= len(body):
        flags, n = struct.unpack(">BI", body[i : i + 5])
        out.append((flags, json.loads(body[i + 5 : i + 5 + n] or b"{}")))
        i += 5 + n
    return out


class E2BClient:
    def __init__(self, http: httpx.AsyncClient, settings: E2BSettings) -> None:
        self._http = http
        self._api_key = settings.api_key
        self._template = settings.template
        self._ttl_s = settings.ttl_s
        self._api_base = settings.api_base
        self._sandbox_base = settings.sandbox_base

    async def create(self) -> Sandbox:
        r = await self._http.post(
            f"{self._api_base}/sandboxes",
            headers={"X-API-Key": self._api_key.get_secret_value()},
            json={
                "templateID": self._template,
                "timeout": self._ttl_s,
                "allow_internet_access": False,
            },
        )
        r.raise_for_status()
        body = r.json()
        return Sandbox(id=body["sandboxID"], token=SecretStr(body.get("envdAccessToken") or ""))

    def _envd_headers(self, sb: Sandbox) -> dict[str, str]:
        return {
            "E2b-Sandbox-Id": sb.id,
            "E2b-Sandbox-Port": ENVD_PORT,
            "X-Access-Token": sb.token.get_secret_value(),
        }

    async def upload(self, sb: Sandbox, path: str, data: bytes) -> None:
        r = await self._http.post(
            f"{self._sandbox_base}/files",
            headers=self._envd_headers(sb),
            params={"path": path},
            files={"file": (path.rsplit("/", 1)[-1], data)},
        )
        r.raise_for_status()

    async def run(self, sb: Sandbox, argv: list[str], cwd: str) -> RunResult:
        req = {
            "process": {"cmd": argv[0], "args": argv[1:], "cwd": cwd, "envs": {}},
            "stdin": False,
        }
        r = await self._http.post(
            f"{self._sandbox_base}/process.Process/Start",
            headers={
                **self._envd_headers(sb),
                "Content-Type": "application/connect+json",
                "Connect-Protocol-Version": "1",
            },
            content=_envelope(json.dumps(req).encode()),
        )
        r.raise_for_status()
        out, err, exit_code = b"", b"", None
        for flags, msg in _frames(r.content):
            if flags & _END_STREAM:
                if msg.get("error"):
                    raise httpx.HTTPError(f"envd stream error: {msg['error'].get('code')}")
                continue
            ev = msg.get("event", {})
            if "data" in ev:
                out += base64.b64decode(ev["data"].get("stdout", ""))
                err += base64.b64decode(ev["data"].get("stderr", ""))
            if "end" in ev:
                exit_code = int(ev["end"].get("exitCode", 0))
        if exit_code is None:
            raise httpx.HTTPError("envd stream ended without a process end event")
        return RunResult(exit_code, out, err)

    async def destroy(self, sb: Sandbox) -> None:
        r = await self._http.delete(
            f"{self._api_base}/sandboxes/{sb.id}",
            headers={"X-API-Key": self._api_key.get_secret_value()},
        )
        if r.status_code != 404:
            r.raise_for_status()
