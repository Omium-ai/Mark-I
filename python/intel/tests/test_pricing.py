"""app/pricing — the pinned model_prices table (06 §8.4): schema, digest, refusal of the unpinned.
Prices below are the vendor pages' numbers as of the file's retrieved_at, never derived here."""

import hashlib
import json

import pytest
from app.pricing import TABLE_PATH, UnpinnedModel, load_table, price_for
from app.tvo.report import ModelPrice, usd_cost

DOC = json.loads(TABLE_PATH.read_text())


def _per_token(p: ModelPrice) -> tuple[float, float, float, float]:
    return (p.price_in, p.price_out, p.price_cache_creation, p.price_cache_read)


def test_shipped_table_schema_and_digest():
    table = load_table()
    digest = hashlib.sha256(TABLE_PATH.read_bytes()).hexdigest()
    assert table.version == f"model_prices.v1@sha256:{digest}"  # sha256sum reproduces it
    assert DOC["unit"] == "usd_per_mtok" and DOC["retrieved_at"] == "2026-09-16"
    ids = [r["model_id"] for r in DOC["rows"]]
    assert len(ids) == len(set(ids))
    assert {r["provider"] for r in DOC["rows"]} == {"anthropic", "openai", "google"}
    for r in DOC["rows"]:
        assert r["source"].startswith("https://") and r["retrieved_at"] == "2026-09-16"
        assert r["effective_from"] <= r["retrieved_at"]
        pinned = all(r[c] is not None for c in ("input", "output", "cache_write", "cache_read"))
        assert (r["model_id"] in table.rows) is pinned
        assert (r["model_id"] in table.unpinned) is not pinned
    assert all(p.price_table_version == table.version for p in table.rows.values())


def test_pinned_rows_carry_the_vendor_numbers_per_token():
    sonnet = price_for("claude-sonnet-5")  # $2 / $10, 5m cache write $2.50, cache read $0.20
    assert sonnet.price_table_version == load_table().version
    assert _per_token(sonnet) == pytest.approx((2e-6, 10e-6, 2.5e-6, 0.2e-6))
    assert _per_token(price_for("claude-opus-5")) == pytest.approx((5e-6, 25e-6, 6.25e-6, 0.5e-6))
    assert price_for("claude-haiku-4-5") == price_for("claude-haiku-4-5-20251001")
    gpt = price_for("gpt-5.4")  # GPT-5.5 and earlier: no additional cache-write charge
    assert _per_token(gpt) == pytest.approx((2.5e-6, 15e-6, 2.5e-6, 0.25e-6))
    luna = price_for("gpt-5.6-luna")  # GPT-5.6+: cache writes at 1.25x input, from the page
    assert luna.price_cache_creation == pytest.approx(0.25e-6)
    # 1M input + 1M output + 1M cache write + 1M cache read on Sonnet 5 = 2 + 10 + 2.5 + 0.2.
    assert usd_cost(10**6, 10**6, 10**6, 10**6, sonnet) == pytest.approx(14.7)


def test_unpinned_model_is_refused_never_priced():
    with pytest.raises(UnpinnedModel, match="claude-mythos-5.*no row in model_prices.v1@sha256"):
        price_for("claude-mythos-5")
    # Google publishes no cache-write price: the row is on record and refused by name.
    with pytest.raises(UnpinnedModel, match="google publishes no cache_write price"):
        price_for("gemini-2.5-flash")
    assert "gemini-2.5-flash" not in load_table().rows


def test_digest_follows_the_bytes(tmp_path):
    edited = dict(DOC)
    edited["rows"] = [
        dict(r, input=0.0) if r["model_id"] == "claude-opus-5" else r for r in DOC["rows"]
    ]
    path = tmp_path / "model_prices.v1.json"
    path.write_text(json.dumps(edited))
    table = load_table(path)
    assert table.version != load_table().version
    assert (
        table.version == f"model_prices.v1@sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    )
    assert table.price_for("claude-opus-5").price_in == 0.0
    assert table.price_for("claude-opus-5").price_table_version == table.version


def test_malformed_tables_are_refused(tmp_path):
    def write(rows):
        path = tmp_path / f"{len(list(tmp_path.iterdir()))}.json"
        path.write_text(json.dumps({"version": "model_prices.vX", "rows": rows}))
        return path

    row = next(r for r in DOC["rows"] if r["model_id"] == "claude-opus-5")
    with pytest.raises(ValueError, match="duplicate row"):
        load_table(write([row, row]))
    with pytest.raises(ValueError):
        load_table(write([dict(row, input=-1.0)]))
    with pytest.raises(ValueError):
        load_table(write([dict(row, provider="mistral")]))
    with pytest.raises(ValueError):
        load_table(write([dict(row, source="http://insecure")]))
    with pytest.raises(ValueError):
        load_table(write([dict(row, batch_input=1.0)]))
