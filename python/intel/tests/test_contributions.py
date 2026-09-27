"""16 L8's rm.contributions: labels, eligibility, and what never ships (withdrawn, missing)."""

import io
import os
import random
import uuid
from datetime import UTC, datetime

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from app.corpus import contributions as co
from app.corpus.export import task_digest
from app.db import set_local_tenant
from m1p.v1 import Batch, Event, OutcomeContribution, OutcomeLabel, OutcomeLabels
from tests.roles import service_pool

TENANT = "0191a000-0000-7000-8000-000000000001"
ROOT = b"\x01" * 32


def _blob(event_id: uuid.UUID, task: uuid.UUID, generator: str, **labels) -> bytes:
    ev = Event(
        event_id=event_id.bytes,
        task_id=task.bytes,
        outcome_contribution=OutcomeContribution(
            task_id=task.bytes,
            intent_text_redacted="add arithmetic",
            diff_redacted="diff --git a/x.go b/x.go\n+func Add() {}\n",
            labels=OutcomeLabels(**labels),
            redaction_receipt_ref=b"\x07" * 32,
            generator=generator,
            label_age_days=30,
        ),
    )
    raw = bytes(Batch(batch_id=uuid.uuid4().bytes, events=[ev]))
    return pa.Codec("zstd").compress(raw, asbytes=True)


def _row(key: str, event_id: uuid.UUID, session: uuid.UUID, task: uuid.UUID) -> dict:
    return {
        "object_key": key,
        "event_id": event_id,
        "session_id": session,
        "task_id": task,
        "received_at": datetime(2026, 9, 26, tzinfo=UTC),
    }


def test_snapshot_labels_eligibility_and_missing_objects():
    session = uuid.uuid4()
    claude, gpt, gone = (uuid.uuid4(), uuid.uuid4()), (uuid.uuid4(), uuid.uuid4()), uuid.uuid4()
    objects = {
        "k/claude": _blob(
            claude[0],
            claude[1],
            "claudecode/claude-opus-4-1",
            survival_30_d=0.75,
            reverted=OutcomeLabel.NO,
            tests_pass=OutcomeLabel.YES,
        ),
        "k/gpt": _blob(gpt[0], gpt[1], "codex/gpt-5", survival_30_d=-1, reverted=OutcomeLabel.YES),
    }
    human = {task_digest(ROOT, str(session), str(claude[1])): "satisfied"}
    snap = co.build(
        TENANT,
        [
            _row("k/claude", claude[0], session, claude[1]),
            _row("k/gpt", gpt[0], session, gpt[1]),
            _row("k/gone", gone, session, uuid.uuid4()),
        ],
        objects.get,
        human,
        hmac_root=ROOT,
        authorized=["anthropic"],
        withdrawn=2,
    )
    rows = {r["event_id"]: r for r in pq.read_table(io.BytesIO(snap.parquet[1])).to_pylist()}
    assert snap.parquet[0] == f"rm/contributions/{TENANT}.parquet"
    c, g = rows[str(claude[0])], rows[str(gpt[0])]
    assert (c["survival_30d"], c["reverted"], c["tests_pass"], c["human"]) == (
        0.75,
        False,
        True,
        "satisfied",
    )
    assert (g["survival_30d"], g["reverted"], g["tests_pass"], g["human"]) == (
        None,
        True,
        None,
        None,
    )
    assert c["training_eligible"] and c["provider"] == "anthropic"
    assert not g["training_eligible"] and g["provider"] == "openai"
    assert str(gone) not in rows
    assert snap.fields["excluded"] == {"missing_object": 1}
    assert snap.fields["consent"]["withdrawn_excluded"] == 2
    assert (snap.fields["training_eligible_rows"], snap.fields["eval_only_rows"]) == (1, 1)


def test_no_authorization_means_eval_only_and_empty_snapshot_still_writes():
    assert co.providers("claudecode/") == {"anthropic"}
    assert co.providers("claudecode/claude-x,qwen3-coder") == {"anthropic", "unknown"}
    snap = co.build(TENANT, [], lambda _k: None, {}, hmac_root=ROOT, authorized=[])
    assert pq.read_table(io.BytesIO(snap.parquet[1])).num_rows == 0
    assert snap.fields["licence"]["providers_with_authorization_on_file"] == []


DSN = os.environ.get("M1_TEST_PG_DSN", "")
REQUIRE_STORES = os.environ.get("M1_REQUIRE_STORES", "0") == "1"


@pytest.mark.integration
@pytest.mark.skipif(not DSN and not REQUIRE_STORES, reason="M1_TEST_PG_DSN not set")
async def test_live_rows_exclude_withdrawn_revoked_and_quarantined(admin):
    if not DSN:
        pytest.fail("M1_TEST_PG_DSN unset under M1_REQUIRE_STORES=1", pytrace=False)
    pool = await service_pool(min_size=1, max_size=2)
    try:
        tag, tenant = f"contrib-{random.randbytes(4).hex()}", uuid.uuid4()
        async with admin.acquire() as conn, conn.transaction():
            org = await conn.fetchval(
                "INSERT INTO m1_organizations (name, primary_domain) VALUES ($1, $2) RETURNING id",
                tag,
                f"{tag}.example",
            )
            await set_local_tenant(conn, str(tenant))
            await conn.execute(
                "INSERT INTO m1_tenants (id, org_id, name) VALUES ($1, $2, $3)", tenant, org, tag
            )
            keep, revoked, withdrawn, quarantined = [
                await conn.fetchval(
                    "INSERT INTO m1_devices (tenant_id, platform, hostname_hmac)"
                    " VALUES ($1, 'linux', $2) RETURNING id",
                    tenant,
                    random.randbytes(32),
                )
                for _ in range(4)
            ]
            for i, (device, on) in enumerate(
                (
                    (keep, True),
                    (revoked, True),
                    (revoked, False),
                    (withdrawn, True),
                    (quarantined, True),
                )
            ):
                await conn.execute(
                    "INSERT INTO m1_device_consents (tenant_id, device_id, e1, cloud_judge,"
                    " training, contribute_outcomes, recorded_at)"
                    " VALUES ($1, $2, false, false, false, $3, now() + $4 * interval '1 second')",
                    tenant,
                    device,
                    on,
                    i,
                )
            events = {}
            for device in (keep, revoked, withdrawn, quarantined):
                events[device], batch = uuid.uuid4(), uuid.uuid4()
                await conn.execute(
                    "INSERT INTO m1_outcome_contributions (tenant_id, event_id, batch_id,"
                    " device_id, session_id, task_id, object_key, withdrawn_at)"
                    " VALUES ($1, $2, $3, $4, $5, $6, 'k', $7)",
                    tenant,
                    events[device],
                    batch,
                    device,
                    uuid.uuid4(),
                    uuid.uuid4(),
                    datetime.now(UTC) if device == withdrawn else None,
                )
                if device == quarantined:
                    await conn.execute(
                        "INSERT INTO m1_quarantined_batches (tenant_id, batch_id, object_key)"
                        " VALUES ($1, $2, 'q')",
                        tenant,
                        batch,
                    )
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(tenant))
            rows, n_withdrawn = await co.live_rows(conn)
        assert [r["event_id"] for r in rows] == [events[keep]]
        assert n_withdrawn == 1
        async with pool.acquire() as conn, conn.transaction():
            await set_local_tenant(conn, str(uuid.uuid4()))
            assert (await co.live_rows(conn)) == ([], 0)
    finally:
        await pool.close()


class _RecordingS3:
    """A loopback S3 that records every request: what intel's IAM grant is evaluated against."""

    def __init__(self):
        import http.server
        import threading

        calls = self.calls = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n) if n else b""
                calls.append((self.command, self.path, dict(self.headers), body))
                self.send_response(200)
                self.send_header("ETag", '"e"')
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_PUT = do_POST = do_HEAD = do_DELETE = _any

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"


def test_s3_snapshot_is_single_part_puts_under_the_contributions_key(monkeypatch):
    s3 = _RecordingS3()
    try:
        for k, v in {
            "AWS_ENDPOINT_URL": s3.url,
            "AWS_ACCESS_KEY_ID": "x",
            "AWS_SECRET_ACCESS_KEY": "y",
            "AWS_REGION": "us-east-1",
            "AWS_S3_ADDRESSING_STYLE": "path",
        }.items():
            monkeypatch.setenv(k, v)
        snap = co.build(TENANT, [], lambda _k: None, {}, hmac_root=ROOT, authorized=[])
        kms = "arn:aws:kms:us-east-1:1:key/rm-contributions"
        with pytest.raises(RuntimeError, match="KMS_KEY_ARN"):
            co.put("s3://training", [snap.parquet], None)
        assert s3.calls == []
        co.put("s3://training", [snap.parquet, snap.manifest], kms)
    finally:
        s3.srv.shutdown()
    assert [(m, p.split("?")[0]) for m, p, _, _ in s3.calls] == [
        ("PUT", f"/training/rm/contributions/{TENANT}.parquet"),
        ("PUT", f"/training/rm/contributions/{TENANT}.manifest.json"),
    ], "no HeadBucket, no directory markers, no multipart"
    for _, path, headers, _ in s3.calls:
        assert "?" not in path
        h = {k.lower(): v for k, v in headers.items()}
        assert h["x-amz-server-side-encryption"] == "aws:kms"
        assert h["x-amz-server-side-encryption-aws-kms-key-id"] == kms


async def test_an_s3_root_without_the_kms_key_refuses_before_reading_anything():
    from types import SimpleNamespace

    class NoPool:
        def acquire(self):
            raise AssertionError("read contributions it could not write")

    settings = SimpleNamespace(
        contributions_root_uri="s3://ingest",
        rm_root_uri="s3://training",
        tenant_hmac_pepper="00" * 32,
        rm_contributions_kms_key_arn=None,
        authorized_training_providers="",
    )
    before = co.contributions_refused_total["no_kms_key_arn"]
    with pytest.raises(RuntimeError, match="INTEL_RM_CONTRIBUTIONS_KMS_KEY_ARN"):
        await co.export(SimpleNamespace(settings=settings, pool=NoPool(), tenant_id=TENANT))
    assert co.contributions_refused_total["no_kms_key_arn"] == before + 1
