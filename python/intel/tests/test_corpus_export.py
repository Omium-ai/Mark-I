"""FR-LEARN-001/002/007 over a local root (pyarrow's FileSystem seam is what S3 also rides)."""

import ast
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pyarrow.parquet as pq
import pytest
import xxhash
from app.corpus import export as ex
from app.corpus import jobs, lineage
from mark1_receipts import (
    ROLE_SERVER_CHAIN,
    Ed25519Signer,
    PublishedKey,
    canonical_json,
    receipt_hash,
    verify_chain,
)

# training-jobs/src/training_jobs/rows.py KtoRow + CompletionRef, dataset.py DatasetManifest —
# transcribed 2026-09-16; the AST check below re-derives them when that repo is on this machine.
TRAINER_ROWS = Path(
    "/home/anurag/workspace/Omium/omium-training-plane/training-jobs/src/training_jobs"
)
KTO_ROW_FIELDS = {
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
}
MANIFEST_FIELDS = {
    "dataset_id",
    "tenant_id",
    "cluster_id",
    "split",
    "kto_rows",
    "preference_pairs",
    "n_desirable",
    "dedup_ratio",
    "isomorphic_verified",
    "influence_selected",
    "leak_free_asserted",
    "arrow_uri",
    "built_at",
}

# The 22 keys the querychoke lane locked its Go column-set test to.
CANDIDATE_KEYS = {
    "task_id",
    "session_id",
    "task_seg_version",
    "agent",
    "model",
    "prompt_digest",
    "verdict",
    "verdict_stage",
    "p_satisfied",
    "p_violated",
    "p_refused",
    "p_error",
    "noise_cert_id",
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "attempts",
    "propensity",
    "fidelity",
    "checkpoint_seq",
    "occurred_at",
    "tamper",
}

TENANT = str(uuid.uuid4())
CERT = str(uuid.uuid4())
ROOT = ex.tenant_root(bytes(range(32)), TENANT)
NOW = datetime(2026, 9, 16, 3, tzinfo=UTC)


def cand(**kw):
    c = {
        "task_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "task_seg_version": "task_seg.v1",
        "agent": "claudecode",
        "model": "m",
        "prompt_digest": os.urandom(32),
        "verdict": "satisfied",
        "verdict_stage": "certified",
        "p_satisfied": 0.9,
        "p_violated": 0.05,
        "p_refused": 0.03,
        "p_error": 0.02,
        "noise_cert_id": CERT,
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_read_input_tokens": 0,
        "propensity": 1.0,
        "fidelity": "wire_enforced",
        "checkpoint_seq": 41,
        "occurred_at": datetime(2026, 9, 15, 12, tzinfo=UTC),
        "prompt": "fix the failing test",
        "completion": "diff --git a b",
    }
    c.update(kw)
    return c


def digest(c):
    return ex.task_digest(ROOT, c["session_id"], c["task_id"])


def run(tmp_path, cands, admitted=None, certs=None, now=NOW):
    admitted = {digest(c) for c in cands} if admitted is None else admitted
    return ex.export(
        str(tmp_path), TENANT, cands, admitted, certs or {CERT: 0.7}, hmac_root=ROOT, now=now
    )


def read_kto(tmp_path, r):
    d = Path(r.dataset_uri)
    rows = [json.loads(line) for line in (d / "rows.jsonl").read_text().splitlines()]
    return rows, json.loads((d / "manifest.json").read_text())


def read_parquet(tmp_path, r):
    return pq.read_table(tmp_path / "t" / TENANT / "parquet" / "v1" / f"export={r.export_id}")


def _ast_fields(path: Path, cls: str) -> set[str]:
    tree = ast.parse(path.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls)
    return {s.target.id for s in node.body if isinstance(s, ast.AnnAssign)}


def test_corpus_refuses_uncertified_labels(tmp_path):
    """06 §13 row 1: an uncertified cert withholds the row from BOTH forms, counted in receipt."""
    good, bad = cand(), cand(noise_cert_id=str(uuid.uuid4()))
    r = run(tmp_path, [good, bad])
    rows, manifest = read_kto(tmp_path, r)
    assert [x["recovery_attempt_id"] for x in rows] == [good["task_id"]]
    assert read_parquet(tmp_path, r).num_rows == 1 and manifest["kto_rows"] == 1
    assert r.receipt_fields["excluded"] == {"uncertified": 1}
    assert r.receipt_fields["rows"] == {"parquet": 1, "kto": 1}


def test_admission_gate_and_verdict_mapping(tmp_path):
    ok_s, ok_v = cand(), cand(verdict="violated", checkpoint_seq=43)
    refused, error = cand(verdict="refused"), cand(verdict="error")
    outs = [cand(tamper=True), cand(verdict_stage="provisional"), cand(), cand(prompt="")]
    admitted = {digest(c) for c in [ok_s, ok_v, refused, error, *outs[:2], outs[3]]}
    r = run(tmp_path, [ok_s, ok_v, refused, error, *outs], admitted)
    rows, manifest = read_kto(tmp_path, r)
    assert {(x["label"], x["reward"], x["consensus_verdict"]) for x in rows} == {
        ("desirable", 1, "satisfied"),
        ("undesirable", 0, "violated"),
    }
    table = read_parquet(tmp_path, r)
    assert table["verdict"].to_pylist() == [
        "satisfied",
        "violated",
        "refused",
        "error",
        "satisfied",
    ]
    assert table["label_confidence"].to_pylist() == pytest.approx(
        [ex.label_confidence(p, 0.7) for p in (0.9, 0.05, 0.03, 0.02, 0.9)]
    )
    assert r.receipt_fields["excluded"] == {
        "error": 1,
        "no_prompt": 1,
        "not_admitted": 1,
        "provisional": 1,
        "refused": 1,
        "tamper": 1,
    }
    assert r.receipt_fields["checkpoint_seq"] == {"min": 41, "max": 43}
    assert r.receipt_fields["rows"] == {"parquet": 5, "kto": 2}
    assert manifest["n_desirable"] == 1 and manifest["split"] == "train"


def test_one_receipt_covers_both_artifacts(tmp_path):
    r = run(tmp_path, [cand(), cand(occurred_at=datetime(2026, 9, 16, 1, tzinfo=UTC))])
    keys = [o["key"] for o in r.receipt_fields["objects"]]
    assert [k.rsplit("/", 1)[1] for k in keys] == [
        "part-0.parquet",
        "part-0.parquet",
        "rows.jsonl",
        "manifest.json",
    ]
    assert {k.split("/")[2] for k in keys} == {"parquet", "kto"}
    for o in r.receipt_fields["objects"]:
        data = (tmp_path / o["key"]).read_bytes()
        assert (len(data), hashlib.sha256(data).hexdigest()) == (o["byte_len"], o["sha256"])
    assert r.receipt_fields["export_id"] == r.export_id
    # receipt.json rides beside the pair for data-refinery's scan_mark1 and is never in objects.
    receipt = json.loads((tmp_path / r.receipt_key).read_text())
    assert (receipt["export_id"], receipt["objects"]) == (r.export_id, r.receipt_fields["objects"])
    assert r.receipt_key == f"t/{TENANT}/kto/v1/export={r.export_id}/receipt.json"
    assert r.receipt_key not in keys and [k for k, _ in r.objects] + [r.manifest[0]] == keys
    # Composes into an m1_002 server-record row: no reserved keys, integers-only, verifiable.
    server = Ed25519Signer(bytes(range(32)))
    payload = {
        "v": 1,
        "type": ex.RECEIPT_TYPE,
        "tenant_id": TENANT,
        "seq": 1,
        "prev_receipt_hash": "00" * 32,
        "issued_at": NOW.isoformat(),
        "subject_id": r.export_id,
        **r.receipt_fields,
    }
    assert len(payload) == 7 + len(r.receipt_fields)
    text = canonical_json(payload)
    row = {
        "seq": 1,
        "record_type": ex.RECEIPT_TYPE,
        "payload": text,
        "receipt_hash": receipt_hash(payload),
        "server_key_id": server.key_id,
        "server_signature": server.sign(b"mark1-label-v1\x00" + text.encode()),
    }
    ring = {server.key_id: PublishedKey(server.public_raw, ROLE_SERVER_CHAIN)}
    assert verify_chain([row], ring)["valid"], verify_chain([row], ring)["defects"]


def test_kto_rows_match_trainer_field_set(tmp_path):
    r = run(tmp_path, [cand(), cand(verdict="violated")])
    rows, manifest = read_kto(tmp_path, r)
    assert set(ex.KTO_FIELDS) == KTO_ROW_FIELDS
    for row in rows:
        assert set(row) == KTO_ROW_FIELDS
        assert set(row["completion_ref"]) == {"solution_id", "jsonl_ref", "strategy_type"}
        assert row["reward"] == (1 if row["label"] == "desirable" else 0)
        assert row["prompt"] and row["completion"] and row["holdout_bucket"] in ("train", "holdout")
        assert row["verification_confidence"] == ex.label_confidence(
            0.9 if row["reward"] else 0.05, 0.7
        )
    assert set(manifest) == MANIFEST_FIELDS
    if TRAINER_ROWS.exists():
        rm_assembler_only = {"weight", "group_id"}
        assert _ast_fields(TRAINER_ROWS / "rows.py", "KtoRow") - rm_assembler_only == KTO_ROW_FIELDS
        assert _ast_fields(TRAINER_ROWS / "rows.py", "CompletionRef") == set(
            ex.COMPLETION_REF_FIELDS
        )
        assert _ast_fields(TRAINER_ROWS / "dataset.py", "DatasetManifest") == MANIFEST_FIELDS


def test_holdout_bucket_deterministic_by_session(tmp_path):
    # A session that is "holdout" under the estate's tenant-salted hash but "train" unsalted.
    sid = next(
        s
        for s in (str(uuid.UUID(int=i)) for i in range(1, 10_000))
        if xxhash.xxh64_intdigest(f"{TENANT}:{s}".encode()) % 100 < 10
        and xxhash.xxh64_intdigest(s.encode()) % 100 >= 10
    )
    r = run(tmp_path, [cand(session_id=sid), cand(session_id=sid, verdict="violated")])
    assert {row["holdout_bucket"] for row in read_kto(tmp_path, r)[0]} == {"holdout"}
    assert (
        ex.holdout_bucket(TENANT, sid, 100) == "holdout"
        and ex.holdout_bucket(TENANT, sid, 0) == "train"
    )


def test_tenant_root_matches_controld_and_task_digest_is_keyed():
    """Vector from Go crypto/hkdf (controld enroll.TenantRoot): pepper=bytes(range(32))."""
    root = ex.tenant_root(bytes(range(32)), "0191c2f0-0000-7000-8000-000000000001")
    assert root.hex() == "9441ddec7be2a20d9004dc44135ca26d7f1b519d0502d4bb7b98055d90082a79"
    s, t = "0191c2f0-0000-7000-8000-00000000000a", "0191c2f0-0000-7000-8000-00000000000b"
    assert ex.task_digest(root, s, t).hex() == (
        "4e27d1d0671ba8851db959bbd0ca6994b6b283608c3a937c116e882437584024"
    )
    assert ex.task_digest(root, s, t) != ex.task_digest(root, t, s)
    assert ex.task_digest(root, s, t) != ex.task_digest(ex.tenant_root(bytes(32), TENANT), s, t)


def test_label_confidence():
    assert ex.label_confidence(0.9, 0.7) == 0.63
    assert ex.label_confidence(1.0, 1.5) == 1.0 and ex.label_confidence(0.5, -0.2) == 0.0


def test_lineage_finds_exports_and_erasure_marks_them(tmp_path):
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    r1 = run(tmp_path, [cand(session_id=a, checkpoint_seq=7), cand(session_id=b, checkpoint_seq=9)])
    r2 = run(
        tmp_path, [cand(session_id=a, checkpoint_seq=12)], now=datetime(2026, 9, 17, tzinfo=UTC)
    )
    assert lineage.exports_carrying(str(tmp_path), TENANT, a) == sorted(
        [
            {"export_id": r1.export_id, "checkpoint_seq_min": 7, "checkpoint_seq_max": 7},
            {"export_id": r2.export_id, "checkpoint_seq_min": 12, "checkpoint_seq_max": 12},
        ],
        key=lambda x: x["export_id"],
    )
    assert [x["export_id"] for x in lineage.exports_carrying(str(tmp_path), TENANT, b)] == [
        r1.export_id
    ]
    assert lineage.exports_carrying(str(tmp_path), TENANT, str(uuid.uuid4())) == []
    assert lineage.exports_carrying(str(tmp_path), str(uuid.uuid4()), a) == []

    marks = lineage.erase_session(str(tmp_path), TENANT, a, now=NOW)
    assert marks == lineage.erase_session(str(tmp_path), TENANT, a, now=NOW)  # idempotent
    assert {Path(m).parent for m in marks} == {Path(r1.dataset_uri), Path(r2.dataset_uri)}
    for m in marks:
        assert json.loads(Path(m).read_text()) == {
            "retrain_required": True,
            "erased_sessions": [a],
            "marked_at": NOW.isoformat(),
        }
    for r in (r1, r2):  # the receipted objects are untouched by marking
        for o in r.receipt_fields["objects"]:
            assert hashlib.sha256((tmp_path / o["key"]).read_bytes()).hexdigest() == o["sha256"]


def test_holdout_bucket_boundary_is_half_open():
    at = {
        r: next(
            s
            for s in (f"s{i}" for i in range(10**6))
            if xxhash.xxh64_intdigest(f"t:{s}".encode()) % 100 == r
        )
        for r in (9, 10)
    }
    assert ex.holdout_bucket("t", at[9], 10) == "holdout"
    assert ex.holdout_bucket("t", at[10], 10) == "train"


def test_controld_fixture_rows_export(tmp_path):
    """Two-way wire lock: controld's `corpus_candidates` fixture rows (the Go side asserts the
    template's aliases equal these keys) go through jobs._candidate() + export() unchanged."""
    fixture = Path(__file__).resolve().parents[3] / (
        "go/controld/internal/querychoke/testdata/intel_template_rows.json"
    )
    rows = json.loads(fixture.read_text())["corpus_candidates"]
    assert rows and {k for r in rows for k in r} == CANDIDATE_KEYS
    cands = [jobs._candidate(r) for r in rows]
    certs = {r["noise_cert_id"]: 0.7 for r in rows}
    r = run(tmp_path, cands, certs=certs)
    assert r.receipt_fields["rows"]["parquet"] == len(rows)
    assert r.receipt_fields["excluded"] == {"no_prompt": len(rows)}
