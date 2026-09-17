"""The end-to-end rig: real binaries, real stores, real processes — no in-process shortcut.

What `drive()` does, in order (03 §7.a's sequence, replayed from the frozen corpus):

  1. build   mark1d / mark1 / controld (`go build`), mark1-hookshim + mark1-verifier (cargo)
  2. stores  scratch Postgres database migrated by scripts/migrate-db.sh (the same runner
             `just migrate` is); TLS switched on at the local cluster because controld's
             AppDSN pins sslmode=require; m1p_query provisioned in ClickHouse; a per-run
             MinIO bucket carrying the R6 per-tenant-KMS Deny policy
  3. controld booted from its env contract, readiness polled
  4. enroll  a fake tenant IdP (RFC 8628 device grant, EdDSA id_token) onboarded into
             m1_tenants; the REAL `mark1 enroll` runs the device-code flow against controld
  5. enable  the REAL `mark1 enable` on a workspace under a fake $HOME, which registers the
             nine 08 §5.1 hooks in ~/.claude/settings.json pointing at the shipped shim
  6. mark1d  booted with a fake pinned `claude` on PATH, identity read from enrollment.json
  7. replay  each pinned hook body → the command settings.json registered, on stdin, the way
             Claude Code fires it; the pinned transcripts laid under
             ~/.claude/projects/<munged cwd>/ for the tailer (cwd rewritten to the real root)
  8. uplink  wait for the ledger, then SIGTERM = the 07 §6 shutdown drain + final Flush
  9. export  GET /api/v1/receipts/{export,keys} → local files → the REAL
             `mark1 verify-receipts --offline` over the REAL mark1-verifier

Every step that cannot complete fails with the seam it needs (pytest.fail); nothing skips.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

import asyncpg
import boto3
import httpx
import pytest
from botocore.config import Config as BotoConfig
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
PINNED_VERSION = "2.1.251"
CORPUS = ROOT / "conformance" / "hooks" / "claudecode" / f"v{PINNED_VERSION}"
FIXTURE_ROOT = "/home/devuser/workspace/acme-app"  # the corpus' recorded workspace
FIXTURE_FOREIGN = "/home/devuser/workspace-acme-app"  # its munge-colliding neighbour
FIXTURE_TX_DIR = "-home-devuser-workspace-acme-app"
SESSION_ID = uuid.UUID("3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55")

# The order Claude Code fires them in one session; transcripts land mid-session.
HOOKS_BEFORE_TRANSCRIPTS = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
]
HOOKS_AFTER_TRANSCRIPTS = ["Stop", "SubagentStop", "PreCompact", "SessionEnd"]

REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "1") == "1"
# MinIO's documented local-dev constant (justfile stores-up; allowlisted in .gitleaks.toml).
S3_KEY = os.environ.get("AWS_ACCESS_KEY_ID") or "minioadmin"
S3_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY") or "minioadmin"
S3_REGION = os.environ.get("AWS_REGION") or "us-east-1"


def fail(msg: str) -> None:
    pytest.fail(msg, pytrace=False)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tail(path: Path, n: int = 60) -> str:
    try:
        return "\n".join(path.read_text(errors="replace").splitlines()[-n:])
    except OSError:
        return "<no log>"


def munge_cwd(abs_path: str) -> str:
    """adapters/claudecode/claudecode.go mungeCwd: every rune outside ASCII [A-Za-z0-9] → '-'."""
    return "".join(c if (c.isascii() and c.isalnum()) else "-" for c in abs_path)


def usage_idem_key(
    tenant_root: bytes, session: uuid.UUID, message_id: str, request_id: str
) -> bytes:
    """internal/tailers/stream.go: HKDF(root, "m1p.usage.idem") then HMAC over
    session(16) || 0 || message_id || 0 || request_id — the events.proto recipe."""
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"m1p.usage.idem").derive(
        tenant_root
    )
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(session.bytes + b"\0" + message_id.encode() + b"\0" + request_id.encode())
    return mac.digest()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# The tenant's IdP: RFC 8628 device grant + an EdDSA-signed id_token. controld verifies the
# token against the JWKS PINNED in m1_tenants (never fetched), so the key lives here only.
# ---------------------------------------------------------------------------
class FakeIdP:
    def __init__(self) -> None:
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.grants = 0
        self.polls = 0
        idp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a: object) -> None:  # quiet
                pass

            def do_POST(self) -> None:  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(n).decode())
                if self.path == "/device_authorization":
                    idp.grants += 1
                    body = {
                        "device_code": f"idp-dc-{idp.grants}",
                        "user_code": "WDJB-MJHT",
                        "verification_uri": idp.url + "/activate",
                        "expires_in": 900,
                        "interval": 1,
                    }
                elif self.path == "/token":
                    idp.polls += 1
                    # The user "approved" on the IdP screen: the first poll succeeds.
                    body = {
                        "access_token": "at",
                        "token_type": "Bearer",
                        "id_token": idp.id_token("devuser", form["client_id"][0]),
                    }
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def jwks(self) -> str:
        pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return json.dumps(
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": _b64url(pub),
                        "kid": "e2e",
                        "use": "sig",
                        "alg": "EdDSA",
                    }
                ]
            }
        )

    def id_token(self, sub: str, aud: str) -> str:
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "EdDSA", "typ": "JWT", "kid": "e2e"}).encode())
        payload = _b64url(
            json.dumps(
                {"iss": self.url, "sub": sub, "aud": aud, "iat": now, "exp": now + 3600}
            ).encode()
        )
        signing_input = f"{header}.{payload}".encode()
        return f"{header}.{payload}.{_b64url(self.key.sign(signing_input))}"

    def close(self) -> None:
        self.srv.shutdown()


def _self_signed_cert() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


@dataclass
class HookRun:
    event: str
    command: str
    returncode: int
    stdout: str
    wall_ms: float


@dataclass
class Rig:
    tmp: Path = field(init=False)
    home: Path = field(init=False)
    state: Path = field(init=False)
    workspace: Path = field(init=False)  # canonical (realpath) enabled root
    bins: dict[str, Path] = field(default_factory=dict)
    procs: dict[str, subprocess.Popen] = field(default_factory=dict)
    logs: dict[str, Path] = field(default_factory=dict)

    pg_dsn: str = field(init=False)  # scratch db, as the migrator role
    scratch_db: str = field(init=False)
    ch_dsn: str = field(init=False)
    ch_native: str = field(init=False)
    s3_endpoint: str = field(init=False)
    bucket: str = field(init=False)

    controld_url: str = field(init=False)
    idp: FakeIdP | None = None
    tenant_id: uuid.UUID = field(init=False)
    device_id: uuid.UUID = field(init=False)
    device_token: str = field(init=False)
    device_key_id: str = field(init=False)
    tenant_root: bytes = field(init=False)  # delivered by enrollment (04 §2.9), read off the doc

    settings_hooks: dict[str, str] = field(default_factory=dict)  # event → command
    hook_runs: list[HookRun] = field(default_factory=list)
    transcript_dir: Path = field(init=False)
    mark1d_exit: int | None = None
    export_path: Path = field(init=False)
    keys_path: Path = field(init=False)
    verify: subprocess.CompletedProcess | None = None
    timings: dict[str, float] = field(default_factory=dict)

    # ---- store clients ---------------------------------------------------
    def pg(self, sql: str, *args: object, dsn: str | None = None) -> list[dict]:
        async def go() -> list[dict]:
            # ssl=False: the harness' own reads need no TLS; only controld's DSN pins it.
            conn = await asyncpg.connect(dsn or self.pg_dsn, ssl=False)
            try:
                return [dict(r) for r in await conn.fetch(sql, *args)]
            finally:
                await conn.close()

        return asyncio.run(go())

    def pg_exec(self, sql: str, dsn: str | None = None) -> None:
        async def go() -> None:
            conn = await asyncpg.connect(dsn or self.pg_dsn, ssl=False)
            try:
                await conn.execute(sql)
            finally:
                await conn.close()

        asyncio.run(go())

    def ch(self, sql: str, user: str | None = None, password: str | None = None) -> list[dict]:
        params = {"default_format": "JSONEachRow"}
        if user:
            params["user"] = user
            params["password"] = password or ""
        r = httpx.post(self.ch_dsn, params=params, content=sql.encode(), timeout=60)
        if r.status_code != 200:
            fail(f"ClickHouse {r.status_code} for {sql!r}: {r.text[:500]}")
        return [json.loads(line) for line in r.text.splitlines() if line]

    def ch_query(self, sql: str) -> list[dict]:
        """The read principal (m1p_query, 07: exactly two runtime CH users) — the credential
        the harness holds because controld's choke has no per-event Usage template."""
        return self.ch(sql, user="m1p_query", password="mark1")

    def s3(self):
        return boto3.client(
            "s3",
            endpoint_url=self.s3_endpoint,
            region_name=S3_REGION,
            aws_access_key_id=S3_KEY,
            aws_secret_access_key=S3_SECRET,
            config=BotoConfig(s3={"addressing_style": "path"}),
        )

    def choke(self, template: str, params: dict) -> list[dict]:
        r = httpx.post(
            f"{self.controld_url}/api/v1/query",
            json={"template": template, "params": params},
            headers={"Authorization": f"Bearer {self.device_token}"},
            timeout=60,
        )
        if r.status_code != 200:
            fail(f"querychoke {template}: HTTP {r.status_code}: {r.text[:500]}")
        return r.json()["rows"]

    # ---- the drive -------------------------------------------------------
    def drive(self) -> None:
        t0 = time.monotonic()
        self._dirs()
        self._build()
        self.timings["build"] = time.monotonic() - t0
        t1 = time.monotonic()
        self._stores()
        self.timings["stores"] = time.monotonic() - t1
        t2 = time.monotonic()
        self._controld()
        self._enroll()
        self._enable()
        self._mark1d()
        self.timings["boot+enroll+enable"] = time.monotonic() - t2
        t3 = time.monotonic()
        self._replay()
        self._await_uplink()
        self._shutdown_mark1d()
        self.timings["replay+uplink"] = time.monotonic() - t3
        self._export_and_verify()
        self.timings["total"] = time.monotonic() - t0

    def _dirs(self) -> None:
        # sun_path is ~108 bytes; the runtime dir must be short, whatever $TMPDIR says.
        base = tempfile.gettempdir()
        if len(base) > 40:
            base = "/tmp"  # noqa: S108 — sun_path forces a short, world-known root
        self.tmp = Path(tempfile.mkdtemp(prefix="m1e2e-", dir=base))
        self.home = self.tmp / "home"
        self.state = (
            self.home / ".omium" / "mark1"
        )  # the default state dir: shim, CLI and daemon agree
        self.workspace = Path(os.path.realpath(self.tmp / "ws" / "acme-app"))
        for d in (
            self.home / ".claude",
            self.state / "bin",
            self.workspace,
            self.tmp / "run",
            self.tmp / "fakebin",
            self.tmp / "bin",
            self.tmp / "log",
        ):
            d.mkdir(parents=True, exist_ok=True)
        (self.tmp / "run").chmod(0o700)
        # agentversion_test.go fakeClaudeOnPath, as a shell script: the version sniff execs it.
        claude = self.tmp / "fakebin" / "claude"
        claude.write_text(f"#!/bin/sh\necho '{PINNED_VERSION} (Claude Code)'\n")
        claude.chmod(0o755)
        # 08 §8.3: mechanism B refuses to create the user's file; Claude Code owns it.
        (self.home / ".claude" / "settings.json").write_text("{}\n")

    def _build(self) -> None:
        out = self.tmp / "bin"
        for name, mod, pkg in (
            ("mark1d", "go/mark1d", "./cmd"),
            ("mark1", "go/mark1", "./cmd"),
            ("controld", "go/controld", "./cmd/controld"),
        ):
            self._sh(["go", "build", "-o", str(out / name), pkg], cwd=ROOT / mod, timeout=900)
            self.bins[name] = out / name
        self._sh(
            ["cargo", "build", "-p", "mark1-hookshim", "-p", "mark1-verifier", "--locked"],
            cwd=ROOT,
            timeout=1800,
        )
        for name in ("mark1-hookshim", "mark1-verifier"):
            self.bins[name] = ROOT / "target" / "debug" / name
            if not self.bins[name].is_file():
                fail(f"cargo build produced no {self.bins[name]}")
        # 08 §8.1's command string is `~/.omium/mark1/bin/mark1-hookshim`; that is where the
        # fragment will point, so that is where the shipped binary goes.
        os.symlink(self.bins["mark1-hookshim"], self.state / "bin" / "mark1-hookshim")

    def _sh(
        self,
        cmd: list[str],
        *,
        cwd: Path,
        env: dict | None = None,
        timeout: int = 120,
        stdin: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        p = subprocess.run(
            cmd, cwd=cwd, env=env, input=stdin, capture_output=True, timeout=timeout, check=False
        )
        if check and p.returncode != 0:
            fail(
                f"{' '.join(cmd)} (cwd {cwd}) exited {p.returncode}\n"
                f"stdout: {p.stdout.decode(errors='replace')[-2000:]}\n"
                f"stderr: {p.stderr.decode(errors='replace')[-4000:]}"
            )
        return p

    # ---- stores ----------------------------------------------------------
    def _stores(self) -> None:
        migrate = os.environ["M1_MIGRATE_PG_DSN"]
        self.ch_dsn = os.environ["M1_TEST_CH_DSN"]
        self.s3_endpoint = os.environ["M1_TEST_S3_ENDPOINT"]
        u = urlparse(migrate)
        ch_host = urlparse(self.ch_dsn).hostname or "127.0.0.1"
        m = re.search(r"--port\s+(\d+)", os.environ.get("CLICKHOUSE_CLIENT", ""))
        self.ch_native = f"{ch_host}:{m.group(1) if m else 9000}"

        # Reachability first: under M1_REQUIRE_STORES a down store is a failing test.
        try:
            self.pg("SELECT 1", dsn=migrate)
        except Exception as exc:  # noqa: BLE001
            fail(f"M1_MIGRATE_PG_DSN={migrate!r} unreachable: {exc!r} — run `just stores-up`")
        self.ch("SELECT 1")
        if httpx.get(f"{self.s3_endpoint}/minio/health/live", timeout=10).status_code != 200:
            fail(f"M1_TEST_S3_ENDPOINT={self.s3_endpoint} not live — run `just stores-up`")

        self._ensure_pg_tls(migrate)

        # Scratch database, migrated by the same runner `just migrate` drives.
        self.scratch_db = f"m1e2e_{uuid.uuid4().hex[:10]}"
        self.pg_exec(f"CREATE DATABASE {self.scratch_db}", dsn=migrate)
        self.pg_dsn = urlunparse(u._replace(path="/" + self.scratch_db))
        env = dict(os.environ, DATABASE_URL=self.pg_dsn)
        env.setdefault("CLICKHOUSE_HOST", ch_host)
        if not env.get("CLICKHOUSE_CLIENT"):
            local_ch = ROOT / ".stores" / "bin" / "clickhouse"
            if not local_ch.is_file():
                fail(
                    "CLICKHOUSE_CLIENT unset and .stores/bin/clickhouse absent: "
                    "scripts/migrate-db.sh cannot apply m1_ch_*.sql — export CLICKHOUSE_CLIENT "
                    "as ci.yml's integration job does"
                )
            env["CLICKHOUSE_CLIENT"] = (
                f"{local_ch} client --host {ch_host} --port {self.ch_native.rsplit(':', 1)[1]}"
            )
        if shutil.which("psql", path=env["PATH"]) is None:
            pg_bin = ROOT / ".stores" / "pg_bin"
            if pg_bin.is_file():
                env["PATH"] = pg_bin.read_text().strip() + os.pathsep + env["PATH"]
        self._sh(["scripts/migrate-db.sh", "migrations", "m1"], cwd=ROOT, env=env, timeout=600)

        # 07: exactly two runtime ClickHouse users. stores-up's users.xml defines m1p_ingest;
        # the SELECT principal is provisioned by SQL here, the way the querychoke suite does.
        self.ch("CREATE USER IF NOT EXISTS m1p_query IDENTIFIED WITH plaintext_password BY 'mark1'")
        self.ch("GRANT SELECT ON mark1.* TO m1p_query")

        # Per-run landing bucket with the R6 policy (s3land.Open refuses a bucket without the
        # per-tenant-KMS Deny; root credentials bypass bucket policy, which is what lets
        # S3_DISABLE_SSEKMS=1 land against KMS-less MinIO).
        self.bucket = f"m1e2e-{uuid.uuid4().hex[:12]}"
        s3 = self.s3()
        s3.create_bucket(Bucket=self.bucket)
        s3.put_bucket_policy(
            Bucket=self.bucket,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{self.bucket}/t/*",
                            "Condition": {
                                "StringNotLike": {
                                    "s3:x-amz-server-side-encryption-aws-kms-key-id": [
                                        "*alias/mark1-tenant-*",
                                        "*alias/mark1-personal",  # ADR-0011 pooled key (MinIO form)
                                    ]
                                }
                            },
                        }
                    ],
                }
            ),
        )

    def _ensure_pg_tls(self, migrate: str) -> None:
        """config.AppDSN (go/controld/internal/config/config.go) pins sslmode=require — not a
        knob — and `just stores-up` initdb's a cluster with ssl=off. The shipped binary can only
        boot against this lane once the cluster serves TLS: a self-signed pair in the data
        directory (PostgreSQL's default ssl_cert_file/ssl_key_file) and a SIGHUP-reloadable
        `ssl = on`, persisted next to the cluster it belongs to."""
        row = self.pg(
            "SELECT current_setting('ssl') AS ssl, current_setting('data_directory') AS d",
            dsn=migrate,
        )[0]
        if row["ssl"] == "on":
            return
        data = Path(row["d"])
        if not os.access(data, os.W_OK):
            fail(
                f"Postgres at {migrate} has ssl=off and its data directory {data} is not writable "
                "from here; controld's AppDSN pins sslmode=require (config.go AppDSN), so the "
                "shipped binary cannot connect. Seam: enable TLS on the store, or a config seam "
                "for sslmode — neither exists in this lane."
            )
        crt, key = _self_signed_cert()
        (data / "server.crt").write_bytes(crt)
        (data / "server.key").write_bytes(key)
        (data / "server.key").chmod(0o600)
        self.pg_exec("ALTER SYSTEM SET ssl = on", dsn=migrate)
        self.pg("SELECT pg_reload_conf()", dsn=migrate)
        for _ in range(50):
            if self.pg("SELECT current_setting('ssl') AS ssl", dsn=migrate)[0]["ssl"] == "on":
                return
            time.sleep(0.2)
        fail("ALTER SYSTEM SET ssl = on + pg_reload_conf() did not take within 10 s")

    # ---- controld --------------------------------------------------------
    def _controld(self) -> None:
        u = urlparse(self.pg_dsn)
        port, metrics = _free_port(), _free_port()
        self.controld_url = f"http://127.0.0.1:{port}"
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "CONTROLD_PORT": str(port),
            "METRICS_PORT": str(metrics),
            "POSTGRES_HOST": u.hostname or "127.0.0.1",
            "POSTGRES_PORT": str(u.port or 5432),
            "POSTGRES_DB": self.scratch_db,
            # m1_060 creates controld_app LOGIN (no password; stores-up's cluster is --auth=trust,
            # the password is a placeholder the derived DSN needs to be well-formed).
            "POSTGRES_APP_USER": "controld_app",
            "POSTGRES_APP_PASSWORD": "trust",
            "CLICKHOUSE_ADDR": self.ch_native,
            "CLICKHOUSE_DATABASE": "mark1",
            "CLICKHOUSE_INGEST_PASSWORD": "mark1",
            "CLICKHOUSE_QUERY_PASSWORD": "mark1",
            "S3_INGEST_BUCKET": self.bucket,
            "S3_ENDPOINT": self.s3_endpoint,
            "AWS_ACCESS_KEY_ID": S3_KEY,
            "AWS_SECRET_ACCESS_KEY": S3_SECRET,
            "AWS_REGION": S3_REGION,
            # The dev/compose posture (deploy/compose/compose.yaml x-controld-dev-env): MinIO has
            # no KMS. AUTH_DEV_MODE keeps the HMAC seam reachable; the enrollment below uses the
            # production Ed25519 verifier, which stays first in line.
            "AUTH_DEV_MODE": "1",
            "AUTH_DEV_TOKEN_HMAC_KEY": "e2e-dev-hmac-key",
            "S3_DISABLE_SSEKMS": "1",
            "AUTH_TOKEN_ED25519_SEED": os.urandom(32).hex(),
            "SERVER_CHAIN_ED25519_SEED": os.urandom(32).hex(),
            # Deployed in prod; without it no tenant gets its bootstrap bundle at enrollment.
            "BUNDLE_SECTION_ED25519_SEED": os.urandom(32).hex(),
            "PUBLIC_BASE_URL": self.controld_url,
        }
        self._spawn("controld", [str(self.bins["controld"])], env)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.procs["controld"].poll() is not None:
                fail(
                    f"controld exited {self.procs['controld'].returncode} during boot:\n"
                    f"{_tail(self.logs['controld'])}"
                )
            try:
                if httpx.get(f"{self.controld_url}/readyz", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        fail(f"controld never became ready:\n{_tail(self.logs['controld'])}")

    def _spawn(self, name: str, cmd: list[str], env: dict, cwd: Path | None = None) -> None:
        log = self.tmp / "log" / f"{name}.log"
        self.logs[name] = log
        fh = open(log, "wb")  # noqa: SIM115 — lives as long as the process
        self.procs[name] = subprocess.Popen(
            cmd,
            env=env,
            cwd=cwd or self.tmp,
            stdout=fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )

    # ---- enrollment + enablement (the real CLI) ---------------------------
    def _cli_env(self) -> dict:
        env = {
            "HOME": str(self.home),
            "XDG_RUNTIME_DIR": str(self.tmp / "run"),
            "PATH": os.pathsep.join(
                [str(self.tmp / "fakebin"), str(self.tmp / "bin"), "/usr/bin", "/bin"]
            ),
            "MARK1_VERIFIER": str(self.bins["mark1-verifier"]),
        }
        # Detect() reads ANTHROPIC_API_KEY to classify the regime; MARK1_DISABLE is the shim's
        # kill switch. Neither may leak in from the developer's shell.
        return env

    def _mark1(self, *args: str, timeout: int = 120) -> dict:
        p = self._sh(
            [str(self.bins["mark1"]), "--state-dir", str(self.state), "--json", *args],
            cwd=self.workspace,
            env=self._cli_env(),
            timeout=timeout,
        )
        return json.loads(p.stdout.decode())

    def _enroll(self) -> None:
        self.idp = FakeIdP()
        org = self.pg(
            "INSERT INTO m1_organizations (name, primary_domain) "
            "VALUES ('e2e', 'e2e.example') RETURNING id"
        )[0]["id"]
        self.tenant_id = self.pg(
            """INSERT INTO m1_tenants (org_id, name,
                 oidc_issuer, oidc_client_id, oidc_jwks_uri, oidc_jwks_pinned,
                 oidc_device_authorization_endpoint, oidc_token_endpoint, oidc_discovered_at,
                 operator_audience, operator_admin_claim, operator_admin_value)
               VALUES ($1, 'acme', $2, 'mark1-cli-client', $3, $4, $5, $6, now(),
                       'mark1-console', 'roles', 'm1-admin') RETURNING id""",
            org,
            self.idp.url,
            self.idp.url + "/jwks",
            self.idp.jwks(),
            self.idp.url + "/device_authorization",
            self.idp.url + "/token",
        )[0]["id"]
        res = self._mark1("--server", self.controld_url, "enroll", "--tenant", str(self.tenant_id))
        if not res.get("ok") or res.get("state") != "active":
            fail(f"mark1 enroll did not reach ACTIVE: {res}")
        doc = json.loads((self.state / "enrollment.json").read_text())
        self.device_id = uuid.UUID(doc["device_id"])
        self.device_token = doc["device_token"]
        # 04 §2.9's per-tenant HMAC root, delivered on the ACTIVE poll body as tenant_root_hex
        # (additive to 08 §3.1) and persisted beside the token: the harness recomputes idem
        # keys from what the server delivered, never from a value it chose itself.
        self.tenant_root = bytes.fromhex(doc["tenant_root_hex"])
        if len(self.tenant_root) != 32:
            fail(f"enrollment.json tenant_root_hex is {len(self.tenant_root)} bytes, want 32")
        if uuid.UUID(doc["tenant_id"]) != self.tenant_id:
            fail(f"enrollment.json names tenant {doc['tenant_id']}, onboarded {self.tenant_id}")
        rows = self.pg("SELECT key_id FROM m1_device_keys WHERE device_id = $1", self.device_id)
        if len(rows) != 1:
            fail(f"m1_device_keys holds {len(rows)} rows for the enrolled device, want 1")
        self.device_key_id = rows[0]["key_id"]

    def _enable(self) -> None:
        res = self._mark1("enable", str(self.workspace))
        if not res.get("ok") or "claudecode" not in res.get("agents_provisioned", []):
            fail(f"mark1 enable did not provision claudecode: {res}")
        settings = json.loads((self.home / ".claude" / "settings.json").read_text())
        for event, entries in settings.get("hooks", {}).items():
            cmds = [
                h["command"]
                for e in entries
                for h in e.get("hooks", [])
                if h.get("type") == "command"
            ]
            if len(cmds) != 1:
                fail(f"settings.json registers {len(cmds)} commands for {event}, want exactly one")
            # The vendor expands the leading `~` (fragment.go DefaultShimPath).
            self.settings_hooks[event] = cmds[0].replace("~", str(self.home), 1)
        want = set(HOOKS_BEFORE_TRANSCRIPTS + HOOKS_AFTER_TRANSCRIPTS)
        if set(self.settings_hooks) != want:
            fail(
                f"settings.json hooks {sorted(self.settings_hooks)} != 08 §5.1's nine "
                f"{sorted(want)}"
            )

    # ---- mark1d ----------------------------------------------------------
    def _mark1d(self, *extra: str) -> None:
        env = self._cli_env()
        # Started the way a customer's supervisor unit starts it (04 §9.3): --state-dir only.
        # Token, tenant, device, tenant root and the ingest endpoint all come from the
        # enrollment.json `mark1 enroll` just wrote; the DEV SEAM flags stay unset.
        cmd = [str(self.bins["mark1d"]), "--state-dir", str(self.state), *extra]
        self._spawn("mark1d", cmd, env)
        sock = self.tmp / "run" / "omium-mark1" / "m1p.sock"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.procs["mark1d"].poll() is not None:
                fail(
                    f"mark1d exited {self.procs['mark1d'].returncode} during boot:\n"
                    f"{_tail(self.logs['mark1d'])}"
                )
            if sock.exists():
                return
            time.sleep(0.1)
        fail(f"mark1d never bound {sock}:\n{_tail(self.logs['mark1d'])}")

    # ---- replay ----------------------------------------------------------
    def _replay(self) -> None:
        for h in HOOKS_BEFORE_TRANSCRIPTS:
            self._fire_hook(h)
        self._lay_transcripts()
        for h in HOOKS_AFTER_TRANSCRIPTS:
            self._fire_hook(h)

    def _fire_hook(self, event: str, body: bytes | None = None) -> HookRun:
        if body is None:
            body = (CORPUS / "hooks" / f"{event}.json").read_bytes()
        cmd = self.settings_hooks[event]
        t0 = time.monotonic()
        p = self._sh(
            [cmd], cwd=self.workspace, env=self._cli_env(), stdin=body, timeout=40, check=False
        )
        run = HookRun(
            event,
            cmd,
            p.returncode,
            p.stdout.decode(errors="replace"),
            (time.monotonic() - t0) * 1000,
        )
        self.hook_runs.append(run)
        if p.returncode != 0:
            fail(
                f"{event}: the shim exited {p.returncode} (08 §5.1: every exit is 0): "
                f"{p.stderr.decode(errors='replace')[-500:]}"
            )
        return run

    def _lay_transcripts(self) -> None:
        """~/.claude/projects/<munged cwd>/ (08 §5.1), files whole and newline-terminated so the
        tailer never reads a torn head. The fixture's recorded cwd becomes the real enabled
        root; the foreign stream's cwd becomes the real root's munge-colliding neighbour, which
        reproduces the corpus' collision byte for byte (expectations.json out_of_workspace)."""
        self.transcript_dir = self.home / ".claude" / "projects" / munge_cwd(str(self.workspace))
        foreign = str(self.workspace.parent) + "-" + self.workspace.name
        assert munge_cwd(foreign) == munge_cwd(str(self.workspace)), (
            "collision fixture must collide"
        )
        src_dir = CORPUS / "transcripts" / FIXTURE_TX_DIR
        for src in sorted(src_dir.rglob("*.jsonl")):
            out_lines = []
            for line in src.read_text().splitlines():
                if not line.strip():
                    continue
                d = json.loads(line)
                if d.get("cwd") == FIXTURE_ROOT:
                    d["cwd"] = str(self.workspace)
                elif d.get("cwd") == FIXTURE_FOREIGN:
                    d["cwd"] = foreign
                out_lines.append(json.dumps(d, separators=(",", ":")))
            dst = self.transcript_dir / src.relative_to(src_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_suffix(".tmp")
            tmp.write_text("\n".join(out_lines) + "\n")
            os.rename(tmp, dst)

    # ---- uplink ----------------------------------------------------------
    def landed(self) -> dict[str, int]:
        rows = self.ch_query(f"""
            SELECT event_type, uniqExact(event_id) AS n
            FROM mark1.m1p_events WHERE tenant_id = toUUID('{self.tenant_id}')
            GROUP BY event_type""")
        return {r["event_type"]: int(r["n"]) for r in rows}

    def checkpoint_leaves(self) -> int:
        rows = self.pg(
            "SELECT COALESCE(SUM(event_count), 0) AS n FROM m1_receipts "
            "WHERE tenant_id = $1 AND record_type = 'checkpoint'",
            self.tenant_id,
        )
        return int(rows[0]["n"])

    def _await_uplink(self) -> None:
        """The uplink drains the spool on its own cadence (uplink.go defaultPoll = 1 s), seals
        each acked batch and uploads the checkpoint on the next pass. Wait for the corpus'
        Usage events plus the hook-derived events to be on the ledger and the first
        checkpoint to be on the chain, then for the ledger to go quiet (the sealer's
        checkpoint-of-a-checkpoint loop terminates, sealer.go allMine)."""
        want_usage = sum(len(s["usage_events"]) for s in self.expectations()["streams"])
        deadline = time.monotonic() + 180
        landed: dict[str, int] = {}
        while time.monotonic() < deadline:
            if self.procs["mark1d"].poll() is not None:
                fail(
                    f"mark1d died mid-session (exit {self.procs['mark1d'].returncode}):\n"
                    f"{_tail(self.logs['mark1d'])}"
                )
            landed = self.landed()
            if (
                landed.get("Usage", 0) >= want_usage
                and landed.get("SessionEnd", 0) >= 1
                and self.pg(
                    "SELECT count(*) AS n FROM m1_receipts WHERE tenant_id = $1", self.tenant_id
                )[0]["n"]
                >= 1
            ):
                self._settle()
                return
            time.sleep(1)
        fail(
            f"uplink never landed the corpus within 180 s; ledger has {landed}\n"
            f"--- mark1d ---\n{_tail(self.logs['mark1d'])}\n"
            f"--- controld ---\n{_tail(self.logs['controld'])}"
        )

    def _settle(self, quiet_for: float = 4.0, limit: float = 60.0) -> None:
        """Ledger + chain unchanged for `quiet_for` seconds (several uplink cycles)."""
        last, since, t0 = None, time.monotonic(), time.monotonic()
        while time.monotonic() - t0 < limit:
            now = (self.landed(), self.checkpoint_leaves())
            if now != last:
                last, since = now, time.monotonic()
            elif time.monotonic() - since >= quiet_for:
                return
            time.sleep(0.5)

    def _shutdown_mark1d(self) -> None:
        p = self.procs["mark1d"]
        p.send_signal(signal.SIGTERM)  # the 07 §6 shutdown drain: fsync, then the final Flush
        try:
            self.mark1d_exit = p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            p.kill()
            fail(
                f"mark1d did not drain and exit within 30 s of SIGTERM:\n"
                f"{_tail(self.logs['mark1d'])}"
            )
        self._settle()  # whatever the final Flush carried lands asynchronously post-ack

    # ---- export + offline verify ------------------------------------------
    def _export_and_verify(self) -> None:
        hdr = {"Authorization": f"Bearer {self.device_token}"}
        export = httpx.get(
            f"{self.controld_url}/api/v1/receipts/export?since_seq=0&limit=5000",
            headers=hdr,
            timeout=60,
        )
        keys = httpx.get(f"{self.controld_url}/api/v1/receipts/keys", headers=hdr, timeout=60)
        if export.status_code != 200 or keys.status_code != 200:
            fail(
                f"receipts export {export.status_code} / keys {keys.status_code}: "
                f"{export.text[:300]} {keys.text[:300]}"
            )
        self.export_path = self.tmp / "export.jsonl"
        self.keys_path = self.tmp / "keys.json"
        self.export_path.write_bytes(export.content)
        self.keys_path.write_bytes(keys.content)
        # From here on nothing talks to controld: the customer's offline verify (08 §7.7).
        self.verify = self._sh(
            [
                str(self.bins["mark1"]),
                "--state-dir",
                str(self.state),
                "--json",
                "verify-receipts",
                "--offline",
                "--from",
                str(self.export_path),
                "--keys",
                str(self.keys_path),
            ],
            cwd=self.tmp,
            env=self._cli_env(),
            check=False,
        )

    # ---- oracle ----------------------------------------------------------
    @staticmethod
    def expectations() -> dict:
        return json.loads((CORPUS / "transcripts" / "expectations.json").read_text())

    # ---- teardown --------------------------------------------------------
    def teardown(self) -> None:
        for name in ("mark1d", "controld"):
            p = self.procs.get(name)
            if p and p.poll() is None:
                p.send_signal(signal.SIGTERM)
                try:
                    p.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    p.kill()
        if self.idp:
            self.idp.close()
        try:
            s3 = self.s3()
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket):
                for o in page.get("Contents", []):
                    s3.delete_object(Bucket=self.bucket, Key=o["Key"])
            s3.delete_bucket(Bucket=self.bucket)
        except Exception:  # noqa: BLE001, S110 — best-effort scratch cleanup
            pass
        try:
            self.pg_exec(
                f"DROP DATABASE IF EXISTS {self.scratch_db} WITH (FORCE)",
                dsn=os.environ["M1_MIGRATE_PG_DSN"],
            )
        except Exception:  # noqa: BLE001, S110
            pass
        if os.environ.get("M1_E2E_KEEP"):
            print(f"\nM1_E2E_KEEP set: rig left at {self.tmp}")
        else:
            shutil.rmtree(self.tmp, ignore_errors=True)
