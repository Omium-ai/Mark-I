"""FR-LEARN-007: an erased session names every export that carried it (07: checkpoint_seq
is the erasure→retrain join key; the receipt is m1_receipts WHERE subject_id = export_id)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pyarrow.compute as pc
import pyarrow.dataset as ds
from pyarrow import fs as pafs

MARKER = "retrain_required.json"


def exports_carrying(root_uri: str, tenant_id: str, session_id: str) -> list[dict[str, Any]]:
    """[{export_id, checkpoint_seq_min, checkpoint_seq_max}] from the tenant's Parquet mirror."""
    fs, base = pafs.FileSystem.from_uri(root_uri)
    try:
        mirror = ds.dataset(
            f"{base}/t/{tenant_id}/parquet/v1", filesystem=fs, format="parquet", partitioning="hive"
        )
    except FileNotFoundError:
        return []
    hits = mirror.to_table(
        columns=["export", "checkpoint_seq"],
        filter=pc.field("session_id") == uuid.UUID(session_id).bytes,
    )
    agg = hits.group_by("export").aggregate([("checkpoint_seq", "min"), ("checkpoint_seq", "max")])
    return sorted(
        (
            {
                "export_id": r["export"],
                "checkpoint_seq_min": r["checkpoint_seq_min"],
                "checkpoint_seq_max": r["checkpoint_seq_max"],
            }
            for r in agg.to_pylist()
        ),
        key=lambda r: r["export_id"],
    )


def mark_retrain_required(
    root_uri: str, tenant_id: str, export_id: str, session_id: str, *, now: datetime | None = None
) -> str:
    """Idempotent sidecar beside the pair the trainer reads; receipted files stay byte-identical."""
    fs, base = pafs.FileSystem.from_uri(root_uri)
    key = f"{base}/t/{tenant_id}/kto/v1/export={export_id}/{MARKER}"
    try:
        with fs.open_input_stream(key) as f:
            marker = json.loads(f.read())
    except FileNotFoundError:
        marker = {"retrain_required": True, "erased_sessions": []}
    if session_id not in marker["erased_sessions"]:
        marker["erased_sessions"].append(session_id)
    marker["marked_at"] = (now or datetime.now(UTC)).isoformat()
    with fs.open_output_stream(key) as f:
        f.write(json.dumps(marker, sort_keys=True).encode())
    return key


def erase_session(
    root_uri: str, tenant_id: str, session_id: str, *, now: datetime | None = None
) -> list[str]:
    """The FR-LEARN-007 entry point: every export that carried the session gets the marker."""
    return [
        mark_retrain_required(root_uri, tenant_id, x["export_id"], session_id, now=now)
        for x in exports_carrying(root_uri, tenant_id, session_id)
    ]
