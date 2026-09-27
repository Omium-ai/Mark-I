"""tools/rm-publish: an export artifact becomes the edge catalog entry and the m1_103 seal in one
step, refusing anything the edge or the gates would refuse; the seal against real Postgres."""

import base64
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from hashlib import sha256
from pathlib import Path

import asyncpg
import pytest
from app.jobs.readjudicate import registry_by_wire_id
from app.jobs.votes import vote_of
from app.registry.catalog import list_verifiers
from app.rm.scorer import rm_refused_total
from blake3 import blake3
from tests.roles import service_pool
from tests.test_jobs import VOTE_ROW

ROOT = Path(__file__).resolve().parents[3]
_loader = importlib.machinery.SourceFileLoader("rm_publish", str(ROOT / "tools/rm-publish"))
_spec = importlib.util.spec_from_loader("rm_publish", _loader)
pub = importlib.util.module_from_spec(_spec)
_loader.exec_module(pub)
GGUF = b"GGUF published model"
DSN = os.environ.get("M1_TEST_PG_DSN", "")


@pytest.fixture
async def pool():
    if not DSN:
        pytest.skip("M1_TEST_PG_DSN not set (estate skipif idiom)")
    p = await service_pool(min_size=1, max_size=3)
    try:
        yield p
    finally:
        await p.close()


def export(tmp: Path, **over) -> tuple[Path, dict, dict]:
    """The stage dir export.py writes: manifest.json + eval_card.json, gates as recorded."""
    sha = hashlib.sha256(GGUF).hexdigest()
    xh = blake3(GGUF + b"\x00llama.cpp b11193\x00" + pub.TEMPLATE_SHA.encode()).hexdigest()
    ev = {
        "gates": {"rm1_heldout_auroc": {"pass": True}, "rm2_shift_v1": {"pass": True}},
        "served_parity": {"q8_0": {"pass": True}},
        "calibration": {
            "method": "platt",
            "a": 0.9,
            "b": -0.1,
            "version": "platt-abc123",
            "gguf_sha256": sha,
            "thresholds": {"t_lo": 0.2, "t_hi": 0.8},
        },
        "calibration_hf": {"model_checksum": "cd" * 32},
        **over.pop("ev", {}),
    }
    raw = json.dumps(ev).encode()
    m = {
        "name": "mark1-rm-a",
        "version": 1,
        "sha256": sha,
        "size_bytes": len(GGUF),
        "calibration_version": "platt-abc123",
        "template_sha": pub.TEMPLATE_SHA,
        "eval_card_sha": hashlib.sha256(raw).hexdigest(),
        "execution_hash": xh,
        "scoring": {"method": "logit_diff", "yes": " yes", "no": " no"},
        **over,
    }
    d = tmp / "artifact"
    d.mkdir(exist_ok=True)
    (d / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")
    (d / "eval_card.json").write_bytes(raw)
    return d, m, ev


def test_one_command_writes_the_catalog_entry_and_the_seal_and_reruns_cleanly(tmp_path):
    d, m, _ = export(tmp_path)
    catalog, sql = tmp_path / "catalog.json", tmp_path / "seal.sql"
    catalog.write_text("[]")
    assert pub.main([str(d), "--sql", str(sql), "--catalog", str(catalog)]) == 0
    assert json.loads(catalog.read_text()) == [m]  # verbatim: the edge serves what export wrote
    first = sql.read_text()
    assert "decode('" + m["execution_hash"] + "', 'hex')" in first and "platt-abc123" in first
    assert pub.publish(d, sql, catalog) == (False, "rm:mark1-rm-a@1")
    assert json.loads(catalog.read_text()) == [m] and sql.read_text() == first


@pytest.mark.parametrize(
    ("over", "why"),
    [
        ({"ev": {"gates": {"rm1_heldout_auroc": {"pass": False}}}}, "gates did not pass"),
        ({"ev": {"gates": {}}}, "gates did not pass"),
        ({"ev": {"served_parity": {"q8_0": {"pass": False}}}}, "gates did not pass"),
        ({"calibration_version": "platt-other"}, "served calibration"),
        ({"eval_card_sha": "0" * 64}, "eval_card_sha"),
        ({"execution_hash": "AB" * 32}, "64 lowercase hex"),
        ({"template_sha": "1" * 64}, "rm-input/v1"),
        ({"name": "mark1-rm-c"}, "mark1-rm-a or mark1-rm-b"),
        ({"version": "1"}, "integer"),
        ({"version": 2**31}, "integer in"),
        ({"size_bytes": 2**63}, "int64"),
        (
            {
                "ev": {
                    "calibration": {
                        "a": 0.9,
                        "b": -0.1,
                        "version": "platt-abc123",
                        "gguf_sha256": hashlib.sha256(GGUF).hexdigest(),
                        "thresholds": {"t_lo": 0.9, "t_hi": 0.1},
                    }
                }
            },
            "t_lo 0.9 > t_hi",
        ),
        ({"slot": "a"}, "not the export's"),
    ],
)
def test_refused_artifacts_write_nothing(tmp_path, over, why):
    d, _, _ = export(tmp_path, **over)
    catalog, sql = tmp_path / "catalog.json", tmp_path / "seal.sql"
    catalog.write_text("[]")
    with pytest.raises(pub.Refused, match=why):
        pub.publish(d, sql, catalog)
    assert catalog.read_text() == "[]" and not sql.exists()


def test_a_different_artifact_for_a_published_version_is_refused_and_writes_no_seal(tmp_path):
    d, m, _ = export(tmp_path)
    catalog, sql = tmp_path / "catalog.json", tmp_path / "seal.sql"
    before = json.dumps([{**m, "sha256": "e" * 64}])
    catalog.write_text(before)
    assert pub.main([str(d), "--sql", str(sql), "--catalog", str(catalog)]) == 1
    with pytest.raises(pub.Refused, match="another artifact"):
        pub.publish(d, sql, catalog)
    assert catalog.read_text() == before and not sql.exists()
    assert sorted(x.name for x in tmp_path.iterdir()) == ["artifact", "catalog.json"]


def test_a_failed_catalog_rename_rolls_the_seal_back(tmp_path, monkeypatch):
    d, _, _ = export(tmp_path)
    catalog, sql = tmp_path / "catalog.json", tmp_path / "seal.sql"
    catalog.write_text("[]")
    sql.write_text("-- previous seal\n")
    real = Path.replace

    def replace(self, target):
        if Path(target) == catalog:
            raise OSError("disk full")
        return real(self, target)

    monkeypatch.setattr(Path, "replace", replace)
    with pytest.raises(OSError):
        pub.publish(d, sql, catalog)
    assert sql.read_text() == "-- previous seal\n" and catalog.read_text() == "[]"
    sql.unlink()
    with pytest.raises(OSError):
        pub.publish(d, sql, catalog)
    assert not sql.exists()
    assert sorted(x.name for x in tmp_path.iterdir()) == ["artifact", "catalog.json"]


HOSTILE = ["x$do$; DROP TABLE m1_verifiers; --", "x$a$", "x'; --", "x\nDROP", "x;y", "$", " "]
WHERE = {
    "calibration_version": lambda bad: {"calibration_version": bad},
    "gate names": lambda bad: {"ev": {"gates": {bad: {"pass": True}, "rm2": {"pass": True}}}},
    "model_checksum": lambda bad: {"ev": {"calibration_hf": {"model_checksum": bad}}},
}


@pytest.mark.parametrize("bad", HOSTILE)
@pytest.mark.parametrize("where", sorted(WHERE))
def test_hostile_free_text_is_refused_and_writes_nothing(tmp_path, bad, where):
    d, _, _ = export(tmp_path, **WHERE[where](bad))
    catalog, sql = tmp_path / "catalog.json", tmp_path / "seal.sql"
    catalog.write_text("[]")
    with pytest.raises(pub.Refused, match=where):
        pub.publish(d, sql, catalog)
    assert catalog.read_text() == "[]" and not sql.exists()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, "0.9"])
def test_non_finite_or_non_numeric_calibration_is_refused(tmp_path, bad):
    cal = {"a": bad, "b": -0.1, "version": "platt-abc123", "thresholds": {"t_lo": 0.2, "t_hi": 0.8}}
    d, _, _ = export(tmp_path, ev={"calibration": {**cal, "gguf_sha256": sha256(GGUF).hexdigest()}})
    with pytest.raises(pub.Refused, match="finite platt"):
        pub.publish(d, tmp_path / "seal.sql", tmp_path / "catalog.json")
    assert not (tmp_path / "seal.sql").exists()


@pytest.mark.parametrize("bad", HOSTILE)
def test_seal_sql_itself_refuses_any_dollar_even_past_the_checks(tmp_path, bad):
    _, m, ev = export(tmp_path)
    for mm, ee in (
        ({**m, "calibration_version": bad}, ev),
        (m, {**ev, "gates": {bad: {"pass": True}}}),
        (m, {**ev, "calibration_hf": {"model_checksum": bad}}),
    ):
        if "$" in bad:
            with pytest.raises(pub.Refused, match="quoted safely"):
                pub.seal_sql(mm, ee)
    with pytest.raises(pub.Refused, match="quoted safely"):
        pub.seal_sql({**m, "execution_hash": "0'); DROP TABLE x; --"}, ev)
    with pytest.raises(pub.Refused, match="quoted safely"):
        pub.seal_sql(m, ev, verifier_key="rm:a'; --")


def test_the_seal_quotes_the_artifact_with_tags_derived_from_it(tmp_path):
    _, m, ev = export(tmp_path)
    sql = pub.seal_sql(m, ev)
    tag = hashlib.sha256(
        json.dumps(pub.artifact(m, ev), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    assert sql.count(f"$do_{tag}$") == 2 and sql.count(f"$a_{tag}$") == 4
    assert sql.count("$") == 2 * 2 + 4 * 2 and sql == pub.seal_sql(m, ev)


def test_the_sealed_artifact_is_what_the_adjudicator_reads(tmp_path):
    _, m, ev = export(tmp_path)
    art = pub.artifact(m, ev)
    assert art["status"] == "sealed" and art["execution_hash"] == m["execution_hash"]
    assert art["calibration"] == {
        "version": "platt-abc123",
        "scale": 0.9,
        "shift": -0.1,
        "reject_below": 0.2,
        "accept_above": 0.8,
    }
    assert art["eval_card"]["passed"] is True and art["gguf_sha256"] == m["sha256"]


@pytest.mark.integration
async def test_the_seal_lands_once_on_real_postgres_and_the_vote_folds(admin, pool, tmp_path):
    from tests.test_pg_stores import _mk_tenant
    from tests.test_rm_pg import PENDING, _mk_rm_verifier

    tenant = await _mk_tenant(admin)
    key = f"rm:pub-{tenant[:8]}"
    await _mk_rm_verifier(admin, key, {**PENDING, "group": "rm-a"}, tenant=tenant)
    _, m, ev = export(tmp_path)
    sql = pub.seal_sql(m, ev, verifier_key=key)
    async with admin.acquire() as conn:
        await conn.execute(sql)
        await conn.execute(sql)  # idempotent re-run
        (tmp_path / "other").mkdir()
        _, m2, ev2 = export(tmp_path / "other", execution_hash="f" * 64)
        with pytest.raises(asyncpg.RaiseError, match="sealed to another artifact"):
            await conn.execute(pub.seal_sql(m2, ev2, verifier_key=key))
        await conn.execute("ROLLBACK")  # the raise aborted the script's own transaction
        row = await conn.fetchrow(
            "SELECT definition, effective_execution_hash FROM m1_verifiers WHERE verifier_key = $1",
            key,
        )
    assert row["effective_execution_hash"] == bytes.fromhex(m["execution_hash"])
    assert json.loads(row["definition"])["artifact"] == json.loads(json.dumps(pub.artifact(m, ev)))
    registry = registry_by_wire_id(await list_verifiers(pool))
    vote = {
        **VOTE_ROW,
        "family": "RmScore",
        "verifier_id": f"{key}@1",
        "vote": "",
        "score": 0.9,
        "calibration_version": "platt-abc123",
        "execution_hash": base64.b64encode(bytes.fromhex(m["execution_hash"])).decode(),
    }
    assert vote_of(vote, registry) == "satisfied"  # σ(0.9·logit(0.9) − 0.1) ≈ 0.87 > 0.8
    assert vote_of({**vote, "execution_hash": ""}, registry) == ""
    before = rm_refused_total["refused_rm_calibration_not_sealed"]
    for picked in ("rm-cal@1", "platt-other", ""):  # the device names a wider band than the seal's
        assert vote_of({**vote, "score": 0.7, "calibration_version": picked}, registry) == ""
    assert rm_refused_total["refused_rm_calibration_not_sealed"] == before + 3
