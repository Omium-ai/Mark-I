"""Corpus exporter (06 §12.1, 07 §Corpus schemas): both forms under one export_id, one receipt.

Selection is gated by `corpus_admissions` (the m1_021 trigger is the certification gate at
admission time; `load_gate` re-checks freshness at export time) and by the ledger row's own
`noise_cert_id` resolving to a currently-certified certificate. Candidate rows are the
`corpus_candidates` template's columns (the ledger's verdict-row fields + `prompt_digest`,
`attempts`, `tamper`) plus the optional assembler fields `prompt`, `completion`,
`failure_signature_hash`, `decisive_step_source`. `task_digest` is minted HERE under the
tenant root — the ledger carries no such column and the choke cannot mint it.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import secrets
import uuid
from collections import Counter
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import groupby
from typing import Any

import asyncpg
import pyarrow as pa
import pyarrow.parquet as pq
import xxhash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from mark1_receipts import canonical_json
from pyarrow import fs as pafs

RECEIPT_TYPE = "corpus_export"
SCHEMA_VERSION = "mark1_trajectory.v1"
HOLDOUT_PCT = 10  # estate default: recovery-orchestrator config.HOLDOUT_PCT
LABELS = {"satisfied": ("desirable", 1), "violated": ("undesirable", 0)}  # ADR-0009

# training_jobs.rows.KtoRow / CompletionRef, field-for-field (07 §Corpus schemas (b)).
KTO_FIELDS = (
    "recovery_attempt_id",
    "tenant_id",
    "prompt",
    "label",
    "reward",
    "holdout_bucket",
    "failure_signature_hash",
    "fix_class",
    "completion_ref",
    "verification_confidence",
    "consensus_verdict",
    "decisive_step_source",
    "propensity",
    "created_at",
    "completion",
)
COMPLETION_REF_FIELDS = ("solution_id", "jsonl_ref", "strategy_type")

PARQUET_SCHEMA = pa.schema(
    [
        pa.field("task_id", pa.binary(), False),
        pa.field("tenant_id", pa.binary(), False),
        pa.field("session_id", pa.binary(), False),
        pa.field("task_seg_version", pa.string(), False),
        pa.field("agent", pa.string(), False),
        pa.field("model", pa.string(), False),
        pa.field("prompt_digest", pa.binary(), False),
        pa.field("verdict", pa.string(), False),
        pa.field("verdict_stage", pa.string(), False),
        pa.field("p_satisfied", pa.float32(), False),
        pa.field("p_violated", pa.float32(), False),
        pa.field("p_refused", pa.float32(), False),
        pa.field("p_error", pa.float32(), False),
        pa.field("label_confidence", pa.float32(), False),
        pa.field("noise_cert_id", pa.binary(), False),
        pa.field("input_tokens", pa.int64(), False),
        pa.field("output_tokens", pa.int64(), False),
        pa.field("cache_read_input_tokens", pa.int64(), False),
        pa.field("attempts", pa.int32(), False),
        pa.field("propensity", pa.float64()),
        pa.field("fidelity", pa.string()),
        pa.field("checkpoint_seq", pa.int64(), False),
        pa.field("created_at", pa.timestamp("us", "UTC"), False),
    ]
)


@dataclass(frozen=True)
class Export:
    export_id: str
    dataset_uri: str  # what the trainer's load_dataset() reads
    receipt_fields: dict[str, Any]  # the corpus_export receipt's class fields; subject_id=export_id
    objects: tuple[tuple[str, bytes], ...]  # (root-relative key, bytes): parquet parts + rows.jsonl
    manifest: tuple[str, bytes]  # manifest.json, written LAST — its absence is "never served"

    @property
    def receipt_key(self) -> str:
        """receipt.json beside the pair: what data-refinery verifies against; never in objects."""
        return self.manifest[0].rsplit("/", 1)[0] + "/receipt.json"


def holdout_bucket(tenant_id: str, session_id: str, pct: int = HOLDOUT_PCT) -> str:
    """Estate rule (recovery-orchestrator consumer.holdout_bucket): xxh64(tenant:key) % 100."""
    digest = xxhash.xxh64_intdigest(f"{tenant_id}:{session_id}".encode())
    return "holdout" if digest % 100 < pct else "train"


def tenant_root(pepper: bytes, tenant_id: str) -> bytes:
    """controld enroll.TenantRoot verbatim: HKDF-SHA256(pepper, info=mark1-tenant-root-v1:<id>)."""
    info = f"mark1-tenant-root-v1:{uuid.UUID(tenant_id)}".encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(pepper)


def task_digest(root: bytes, session_id: str, task_id: str) -> bytes:
    """m1_021's join key: HMAC-SHA256(tenant root, session_id ‖ task_id) — the one definition."""
    msg = uuid.UUID(session_id).bytes + uuid.UUID(task_id).bytes
    return hmac.new(root, msg, hashlib.sha256).digest()


def label_confidence(p_verdict: float, natarajan_lcb: float) -> float:
    """f(posterior, cert) = posterior × LCB₉₅ of the Natarajan margin 1−(ρ₊+ρ₋) (06 §5.2)."""
    return round(min(1.0, max(0.0, float(p_verdict) * float(natarajan_lcb))), 6)


async def training_consented(conn: asyncpg.Connection, tenant_id: str) -> bool:
    """The Step-4 training opt-in as controld persisted it per device (m1_082, relayed by mark1d
    from gates/consents.json). A device speaks for itself only, and corpus_candidates carries no
    device_id to separate one device's tasks from another's, so the tenant exports only when
    every device that ever recorded a consent currently consents, and at least one did."""
    ok = await conn.fetchval(
        "SELECT bool_and(training) FROM (SELECT DISTINCT ON (device_id) training"
        " FROM m1_device_consents WHERE tenant_id = $1"
        " ORDER BY device_id, recorded_at DESC) d",
        uuid.UUID(tenant_id),
    )
    return ok is True


async def load_gate(
    conn: asyncpg.Connection, tenant_id: str
) -> tuple[set[bytes], dict[str, float]]:
    """The gate's inputs: admitted task digests + currently-certified certs (id → natarajan_lcb)."""
    tid = uuid.UUID(tenant_id)
    admitted = await conn.fetch(
        "SELECT task_digest FROM corpus_admissions WHERE tenant_id = $1", tid
    )
    certs = await conn.fetch(
        "SELECT id, natarajan_lcb FROM noise_certificates"
        " WHERE tenant_id = $1 AND status = 'certified' AND expires_at > now()",
        tid,
    )
    return {bytes(r["task_digest"]) for r in admitted}, {
        str(r["id"]): float(r["natarajan_lcb"]) for r in certs
    }


def _exclusion(
    c: Mapping[str, Any], digest: bytes, admitted: Collection[bytes], certs: Mapping[str, float]
) -> str:
    if c.get("tamper"):
        return "tamper"
    if c["verdict_stage"] not in ("certified", "revised"):
        return "provisional"
    if str(c["noise_cert_id"]) not in certs:
        return "uncertified"
    if digest not in admitted:
        return "not_admitted"
    return ""


def _uuid7(now: datetime) -> str:
    """RFC 9562 v7: ms-timestamp prefix, so S3 listing ≈ chronological replay (06 §12.3)."""
    ms = int(now.timestamp() * 1000)
    n = (ms << 80) | (7 << 76) | (secrets.randbits(12) << 64) | (2 << 62) | secrets.randbits(62)
    return str(uuid.UUID(int=n))


def _utc(ts: datetime) -> datetime:
    return ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)


def build(
    root_uri: str,
    tenant_id: str,
    candidates: Iterable[Mapping[str, Any]],
    admitted: Collection[bytes],
    certs: Mapping[str, float],
    *,
    hmac_root: bytes,
    now: datetime | None = None,
    holdout_pct: int = HOLDOUT_PCT,
) -> Export:
    """Both forms in memory, receipt fields over their exact bytes; nothing touches the root."""
    now = _utc(now or datetime.now(UTC))
    export_id = _uuid7(now)
    excluded: Counter[str] = Counter()
    parquet_rows: list[dict[str, Any]] = []
    kto_rows: list[dict[str, Any]] = []
    for c in candidates:
        digest = task_digest(hmac_root, str(c["session_id"]), str(c["task_id"]))
        if reason := _exclusion(c, digest, admitted, certs):
            excluded[reason] += 1
            continue
        verdict = str(c["verdict"])
        conf = label_confidence(c[f"p_{verdict}"], certs[str(c["noise_cert_id"])])
        created = _utc(c["occurred_at"])
        parquet_rows.append(
            {
                "task_id": uuid.UUID(str(c["task_id"])).bytes,
                "tenant_id": uuid.UUID(tenant_id).bytes,
                "session_id": uuid.UUID(str(c["session_id"])).bytes,
                "task_seg_version": str(c["task_seg_version"]),
                "agent": str(c["agent"]),
                "model": str(c["model"]),
                "prompt_digest": bytes(c["prompt_digest"]),
                "verdict": verdict,
                "verdict_stage": str(c["verdict_stage"]),
                "p_satisfied": float(c["p_satisfied"]),
                "p_violated": float(c["p_violated"]),
                "p_refused": float(c["p_refused"]),
                "p_error": float(c["p_error"]),
                "label_confidence": conf,
                "noise_cert_id": uuid.UUID(str(c["noise_cert_id"])).bytes,
                "input_tokens": int(c["input_tokens"]),
                "output_tokens": int(c["output_tokens"]),
                "cache_read_input_tokens": int(c["cache_read_input_tokens"]),
                "attempts": int(c.get("attempts") or 1),
                "propensity": None if c.get("propensity") is None else float(c["propensity"]),
                "fidelity": c.get("fidelity") or None,
                "checkpoint_seq": int(c["checkpoint_seq"]),
                "created_at": created,
            }
        )
        if verdict not in LABELS:  # refused/error: Parquet keeps them, KTO never sees them
            excluded[verdict] += 1
            continue
        if not c.get("prompt"):
            excluded["no_prompt"] += 1
            continue
        if not c.get("completion"):
            excluded["no_completion"] += 1
            continue
        label, reward = LABELS[verdict]
        kto_rows.append(
            {
                "recovery_attempt_id": str(c["task_id"]),
                "tenant_id": tenant_id,
                "prompt": str(c["prompt"]),
                "label": label,
                "reward": reward,
                "holdout_bucket": holdout_bucket(tenant_id, str(c["session_id"]), holdout_pct),
                "failure_signature_hash": c.get("failure_signature_hash") or None,
                "fix_class": None,
                "completion_ref": dict.fromkeys(COMPLETION_REF_FIELDS),
                "verification_confidence": conf,
                "consensus_verdict": verdict,
                "decisive_step_source": c.get("decisive_step_source") or None,
                "propensity": None if c.get("propensity") is None else float(c["propensity"]),
                "created_at": created.isoformat(),
                "completion": str(c["completion"]),
            }
        )

    blobs: list[tuple[str, bytes]] = []
    objects: list[dict[str, Any]] = []

    def put(key: str, data: bytes) -> None:
        blobs.append((key, data))
        objects.append(
            {"key": key, "byte_len": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )

    tenant_prefix = f"t/{tenant_id}"
    by_day = groupby(
        sorted(parquet_rows, key=lambda r: r["created_at"]),
        key=lambda r: r["created_at"].date().isoformat(),
    )
    for dt, group in by_day:
        buf = io.BytesIO()
        pq.write_table(
            pa.Table.from_pylist(list(group), schema=PARQUET_SCHEMA), buf, compression="zstd"
        )
        put(f"{tenant_prefix}/parquet/v1/export={export_id}/dt={dt}/part-0.parquet", buf.getvalue())

    kto_dir = f"{tenant_prefix}/kto/v1/export={export_id}"
    manifest = {  # training_jobs.dataset.DatasetManifest, 1:1
        "dataset_id": export_id,
        "tenant_id": tenant_id,
        "cluster_id": "mark1",
        "split": "train",
        "kto_rows": len(kto_rows),
        "preference_pairs": 0,
        "n_desirable": sum(r["reward"] for r in kto_rows),
        "dedup_ratio": 0.0,
        "isomorphic_verified": False,
        "influence_selected": False,
        "leak_free_asserted": True,
        "arrow_uri": f"{root_uri}/{tenant_prefix}/parquet/v1/export={export_id}",
        "built_at": now.isoformat(),
    }
    put(
        f"{kto_dir}/rows.jsonl",
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in kto_rows).encode(),
    )
    put(f"{kto_dir}/manifest.json", json.dumps(manifest, sort_keys=True, indent=1).encode())

    ckpts = [r["checkpoint_seq"] for r in parquet_rows]
    fields = {
        "schema": SCHEMA_VERSION,
        "export_id": export_id,
        "objects": objects,
        "rows": {"parquet": len(parquet_rows), "kto": len(kto_rows)},
        "excluded": dict(sorted(excluded.items())),
        "checkpoint_seq": {"min": min(ckpts), "max": max(ckpts)} if ckpts else None,
        "holdout_pct": holdout_pct,
    }
    canonical_json(fields)  # integers-only receipt contract, refused here rather than at append
    return Export(export_id, f"{root_uri}/{kto_dir}", fields, tuple(blobs[:-1]), blobs[-1])


def write(root_uri: str, blobs: Iterable[tuple[str, bytes]]) -> None:
    fs, base = pafs.FileSystem.from_uri(root_uri)
    for key, data in blobs:
        fs.create_dir(f"{base}/{key}".rsplit("/", 1)[0], recursive=True)
        with fs.open_output_stream(f"{base}/{key}") as out:
            out.write(data)


def export(root_uri: str, *args: Any, **kwargs: Any) -> Export:
    """The one-shot form with no chain behind it: objects, manifest, then receipt.json carrying the
    unsigned fields. jobs.export() is the receipted form (controld's signed payload in between)."""
    e = build(root_uri, *args, **kwargs)
    write(
        root_uri,
        [*e.objects, e.manifest, (e.receipt_key, canonical_json(e.receipt_fields).encode())],
    )
    return e
