"""16 L8: consented, unwithdrawn OutcomeContributions -> rm/contributions/<tenant>.parquet."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import asyncpg
import boto3
import pyarrow as pa
import pyarrow.parquet as pq
from m1p.v1 import Batch, OutcomeLabel, Verdict
from pyarrow import fs as pafs

from app.corpus.export import _uuid7, task_digest, tenant_root, write
from app.db import set_local_tenant

SCHEMA = "rm_contribution.v1"
RETENTION_DAYS = 365
MODEL_PROVIDERS = {
    "claude": "anthropic",
    "gpt": "openai",
    "o1": "openai",
    "o3": "openai",
    "o4": "openai",
    "codex": "openai",
    "gemini": "google",
}
AGENT_PROVIDERS = {"claudecode": "anthropic", "codex": "openai", "gemini": "google"}
TRI = {OutcomeLabel.YES: True, OutcomeLabel.NO: False}

contributions_refused_total: Counter[str] = Counter()

PARQUET_SCHEMA = pa.schema(
    [
        pa.field("event_id", pa.string(), False),
        pa.field("tenant_id", pa.string(), False),
        pa.field("task_id", pa.string(), False),
        pa.field("intent", pa.string(), False),
        pa.field("diff", pa.string(), False),
        pa.field("survival_30d", pa.float64()),
        pa.field("reverted", pa.bool_()),
        pa.field("tests_pass", pa.bool_()),
        pa.field("human", pa.string()),
        pa.field("label_age_days", pa.int32(), False),
        pa.field("generator", pa.string(), False),
        pa.field("provider", pa.string(), False),
        pa.field("training_eligible", pa.bool_(), False),
        pa.field("redaction_receipt_ref", pa.string(), False),
        pa.field("received_at", pa.timestamp("us", "UTC"), False),
    ]
)

LIVE_ROWS = """
SELECT c.event_id, c.batch_id, c.session_id, c.task_id, c.object_key, c.received_at
  FROM m1_outcome_contributions c
 WHERE c.withdrawn_at IS NULL AND c.deleted_at IS NULL
   AND coalesce((SELECT d.contribute_outcomes FROM m1_device_consents d
                  WHERE d.device_id = c.device_id ORDER BY d.row_seq DESC LIMIT 1), false)
   AND NOT EXISTS (SELECT 1 FROM m1_quarantined_batches q WHERE q.batch_id = c.batch_id)
 ORDER BY c.received_at, c.event_id
"""


@dataclass(frozen=True)
class Snapshot:
    parquet: tuple[str, bytes]
    manifest: tuple[str, bytes]
    fields: dict[str, Any]


def providers(generator: str) -> set[str]:
    """Every provider behind the diff: one per model id, the agent's own when no model was seen."""
    agent, _, models = generator.partition("/")
    names = [m.strip().lower() for m in models.split(",") if m.strip()]
    if not names:
        return {AGENT_PROVIDERS.get(agent, "unknown")}
    return {
        next((p for pre, p in MODEL_PROVIDERS.items() if n.startswith(pre)), "unknown")
        for n in names
    }


async def live_rows(conn: asyncpg.Connection) -> tuple[list[asyncpg.Record], int]:
    """The exportable index rows under the caller's tenant GUC, and how many were withdrawn."""
    rows = await conn.fetch(LIVE_ROWS)
    withdrawn = await conn.fetchval(
        "SELECT count(*) FROM m1_outcome_contributions WHERE withdrawn_at IS NOT NULL"
    )
    return list(rows), int(withdrawn)


async def human_labels(conn: asyncpg.Connection) -> dict[bytes, str]:
    """m1_086 human gold by task_digest; the only human label source (never a fused verdict)."""
    rows = await conn.fetch(
        "SELECT task_digest, true_label::text AS label FROM gold_set_members"
        " WHERE label_source = 'human'"
    )
    return {bytes(r["task_digest"]): r["label"] for r in rows}


def decode(blob: bytes) -> Batch:
    raw = pa.CompressedInputStream(pa.BufferReader(blob), "zstd").read()
    return Batch().parse(bytes(raw))


def build(
    tenant_id: str,
    rows: Iterable[Mapping[str, Any]],
    fetch: Callable[[str], bytes | None],
    human: Mapping[bytes, str],
    *,
    hmac_root: bytes,
    authorized: Iterable[str],
    withdrawn: int = 0,
    now: datetime | None = None,
) -> Snapshot:
    """Both objects in memory; nothing touches the root until write()."""
    now = now or datetime.now(UTC)
    allowed = {p.strip().lower() for p in authorized if p.strip()}
    excluded: Counter[str] = Counter()
    out: list[dict[str, Any]] = []
    batches: dict[str, Batch | None] = {}
    for r in rows:
        key = r["object_key"]
        if key not in batches:
            blob = fetch(key)
            batches[key] = decode(blob) if blob is not None else None
        batch = batches[key]
        event_id = uuid.UUID(str(r["event_id"]))
        ev = (
            next((e for e in batch.events if e.event_id == event_id.bytes), None) if batch else None
        )
        if ev is None or not ev.outcome_contribution.diff_redacted:
            excluded["missing_object"] += 1
            continue
        c = ev.outcome_contribution
        provs = providers(c.generator)
        digest = task_digest(hmac_root, str(r["session_id"]), str(r["task_id"]))
        survival = c.labels.survival_30_d
        out.append(
            {
                "event_id": str(event_id),
                "tenant_id": tenant_id,
                "task_id": str(r["task_id"]),
                "intent": c.intent_text_redacted,
                "diff": c.diff_redacted,
                "survival_30d": survival if survival >= 0 else None,
                "reverted": TRI.get(c.labels.reverted),
                "tests_pass": TRI.get(c.labels.tests_pass),
                "human": human.get(digest)
                or (None if c.labels.human == Verdict.UNSPECIFIED else c.labels.human.name.lower()),
                "label_age_days": int(c.label_age_days),
                "generator": c.generator,
                "provider": ",".join(sorted(provs)),
                "training_eligible": provs <= allowed,
                "redaction_receipt_ref": c.redaction_receipt_ref.hex(),
                "received_at": r["received_at"],
            }
        )
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pylist(out, schema=PARQUET_SCHEMA), buf, compression="zstd")
    data = buf.getvalue()
    key = f"rm/contributions/{tenant_id}.parquet"
    eligible = sum(1 for r in out if r["training_eligible"])
    fields = {
        "schema": SCHEMA,
        "export_id": _uuid7(now),
        "tenant_id": tenant_id,
        "built_at": now.isoformat(),
        "object": {"key": key, "byte_len": len(data), "sha256": hashlib.sha256(data).hexdigest()},
        "rows": len(out),
        "training_eligible_rows": eligible,
        "eval_only_rows": len(out) - eligible,
        "consent": {
            "class": "contribute_outcomes",
            "record": "m1_device_consents (m1_082 + m1_096), latest row per device",
            "withdrawn_excluded": withdrawn,
        },
        "licence": {
            "source": "mark1_user_contribution",
            "use": "evaluation always; training only where training_eligible",
            "providers_with_authorization_on_file": sorted(allowed),
            "retention_days": RETENTION_DAYS,
        },
        "excluded": dict(sorted(excluded.items())),
    }
    manifest = json.dumps(fields, sort_keys=True, indent=1).encode()
    return Snapshot((key, data), (f"rm/contributions/{tenant_id}.manifest.json", manifest), fields)


def _fetcher(root_uri: str) -> Callable[[str], bytes | None]:
    fs, base = pafs.FileSystem.from_uri(root_uri)

    def fetch(key: str) -> bytes | None:
        try:
            with fs.open_input_stream(f"{base}/{key}") as f:
                return f.read()
        except (FileNotFoundError, OSError):
            return None

    return fetch


def put(root_uri: str, blobs: Iterable[tuple[str, bytes]], kms_key_arn: str | None) -> None:
    """S3: one single-part PutObject per object under SSE-KMS naming the rm/contributions key,
    the only write intel's grant and the bucket policy admit (pyarrow's writer HEADs the bucket,
    PUTs rm/ and rm/contributions/ markers and uploads multipart, whose parts carry no key
    header). A local root rides export.write."""
    if not root_uri.startswith("s3://"):
        return write(root_uri, blobs)
    if not kms_key_arn:
        raise RuntimeError(
            "INTEL_RM_CONTRIBUTIONS_KMS_KEY_ARN is required for an s3:// INTEL_RM_ROOT_URI: the"
            " bucket refuses any rm/contributions/* write not encrypted under that key"
        )
    bucket, _, prefix = root_uri.removeprefix("s3://").partition("/")
    s3 = boto3.client("s3")
    for key, data in blobs:
        s3.put_object(
            Bucket=bucket,
            Key="/".join(p for p in (prefix.strip("/"), key) if p),
            Body=data,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key_arn,
        )
    return None


async def export(ctx: Any) -> str | None:
    """Overwrite the tenant's snapshot, an empty one included: that is how withdrawal leaves."""
    s = ctx.settings
    pepper = getattr(s, "tenant_hmac_pepper", None)
    if pepper is not None and hasattr(pepper, "get_secret_value"):
        pepper = pepper.get_secret_value()
    source, dest = getattr(s, "contributions_root_uri", None), getattr(s, "rm_root_uri", None)
    if not (source and dest and pepper):
        raise RuntimeError(
            "INTEL_CONTRIBUTIONS_ROOT_URI, INTEL_RM_ROOT_URI and INTEL_TENANT_HMAC_PEPPER are"
            " required: rm.contributions has no source, no destination or no digest root"
        )
    kms = getattr(s, "rm_contributions_kms_key_arn", None)
    if dest.startswith("s3://") and not kms:
        contributions_refused_total["no_kms_key_arn"] += 1
        raise RuntimeError(
            "INTEL_RM_CONTRIBUTIONS_KMS_KEY_ARN is required for an s3:// INTEL_RM_ROOT_URI:"
            " rm.contributions writes nothing it cannot encrypt under the contributions key"
        )
    async with ctx.pool.acquire() as conn, conn.transaction():
        await set_local_tenant(conn, ctx.tenant_id)
        rows, withdrawn = await live_rows(conn)
        human = await human_labels(conn)
    snap = await asyncio.to_thread(
        build,
        ctx.tenant_id,
        rows,
        _fetcher(source),
        human,
        hmac_root=tenant_root(bytes.fromhex(pepper), ctx.tenant_id),
        authorized=s.authorized_training_providers.split(","),
        withdrawn=withdrawn,
    )
    await asyncio.to_thread(put, dest, [snap.parquet, snap.manifest], kms)
    return snap.fields["export_id"]
