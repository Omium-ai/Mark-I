-- =============================================================================
-- m1_ch_003_arrest_recommendations.sql  --  ClickHouse: the RECOMMEND sink's rows.
--
-- ADR-0015 (08 §4.7): a host whose profile says ARREST_MODE_RECOMMEND gets the
-- gate's judgement as an ArrestRecommendation event INSTEAD OF a GuardDecision.
-- The GuardDecision-derived figures (arrests, blocks, tokens_saved — 07 §MV,
-- querychoke's session row) therefore count acted arrests only, untouched.
-- This file gives recommendations their own counted shape so the two are never
-- confused: one row per ArrestRecommendation event, keyed like m1p_events so a
-- replay collapses to the same row.
--
-- ADDITIVE. m1_ch_001_events.sql is not edited (its ORDER BY is irreversible,
-- ADR-0001); the rows below are projected from it. No existing migration moves.
-- =============================================================================

CREATE TABLE IF NOT EXISTS mark1.arrest_recommendations
(
    tenant_id        UUID,
    day              Date,
    session_id       UUID,
    event_id         UUID,
    device_id        UUID,
    task_id          UUID,
    occurred_at      DateTime64(3, 'UTC'),
    kind             LowCardinality(String),   -- stop_gate_block | knee_arrest | block_cap
    k_star_estimate  UInt32,                   -- the attempt the governor evaluated at
    projected_cost   UInt64,                   -- tokens the next attempt would have spent (what ACT would have saved)
    turn             UInt32,
    evidence_ref     String
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, session_id, event_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS mark1.mv_arrest_recommendations TO mark1.arrest_recommendations AS
SELECT
    tenant_id,
    toDate(occurred_at)                                   AS day,
    session_id,
    event_id,
    device_id,
    task_id,
    occurred_at,
    JSONExtractString(payload, 'kind')                    AS kind,
    toUInt32(JSONExtractUInt(payload, 'k_star_estimate')) AS k_star_estimate,
    JSONExtractUInt(payload, 'projected_cost')            AS projected_cost,
    toUInt32(JSONExtractUInt(payload, 'turn'))            AS turn,
    JSONExtractString(payload, 'evidence_ref')            AS evidence_ref
FROM mark1.m1p_events
WHERE event_type = 'ArrestRecommendation';
