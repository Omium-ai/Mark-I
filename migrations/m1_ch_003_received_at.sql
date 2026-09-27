-- =============================================================================
-- m1_ch_003_received_at.sql  --  ClickHouse: when controld first received a row.
--
-- ADR-0013 §10: a closed day's savings figure is restated against the ledger AS
-- IT STOOD at the close, which is a question about arrival, not about the edge's
-- clock. `ingested_at` cannot answer it: it is the ReplacingMergeTree version
-- column, DEFAULT now64 on every insert, so an S3 replay re-stamps it and the
-- surviving row carries the replay's time. `received_at` is written by the
-- projector: the request's receive time on live ingest, and on replay the landing
-- object's S3 LastModified (the replay log is written once, at receipt, under
-- object lock), so a replay reproduces it to the second instead of moving it.
-- Rows that predate this column read `ingested_at` through the DEFAULT, the best
-- evidence they have.
--
-- Additive, idempotent (IF NOT EXISTS), metadata-only on existing parts.
-- =============================================================================

ALTER TABLE mark1.m1p_events
    ADD COLUMN IF NOT EXISTS received_at DateTime64(6, 'UTC') DEFAULT ingested_at
        CODEC(Delta(8), ZSTD(1))
    AFTER ingested_at;
