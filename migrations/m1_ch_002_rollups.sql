-- =============================================================================
-- m1_ch_002_rollups.sql  --  ClickHouse: the three TVO rollups.
--
-- Three rollups, one grain each: session, task, tenant-day. All three are
-- AggregatingMergeTree -- Aggregating rather than Summing because the
-- verified-outcome counts need uniqExactState (a task must count ONCE no matter
-- how many VerdictEvent rows it emits across PROVISIONAL→CERTIFIED→REVISED), and
-- mixing summed counters with unique states in one Summing table silently
-- miscounts.
--
-- RATIOS ARE NEVER STORED. TVO is always computed at read time from summed
-- numerator and merged denominator, because a stored ratio cannot be
-- re-aggregated (avg-of-ratios != ratio-of-sums).
--
-- MV SEMANTICS THAT SHAPE EVERYTHING HERE: a ClickHouse MV fires per INSERT
-- BLOCK, before ReplacingMergeTree dedupe. So the MVs aggregate with -If
-- combinators over stage-final rows only, and the read-time queries in
-- `mark1-intel.tvo` re-verify against the base table for any number that leaves
-- the building (certified reports). The MVs are the cheap first pass, not the
-- audit path.
--
-- All three rollups key on the same (tenant_id, day, ...) prefix as the base
-- table's ordering key -- same pruning behaviour, no impedance mismatch
-- (ADR-0001 §Consequences). Retention is 760 d on `day`, per 07's retention
-- matrix ("rollup tables | 760 d | partition TTL on day").
--
-- Idempotent: IF NOT EXISTS throughout, safe to re-run. Requires m1_ch_001.
-- =============================================================================

-- ── Per-session rollup ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mark1.tvo_session
(
    tenant_id            UUID,
    day                  Date,
    session_id           UUID,
    -- SimpleAggregateFunction, not a plain column. In an AggregatingMergeTree a
    -- plain column outside the ORDER BY keeps an ARBITRARY value after a
    -- background merge -- ClickHouse rejects the plain form outright for exactly
    -- this reason (BAD_ARGUMENTS: "silently produces wrong results"). `agent` is
    -- functionally dependent on session_id (a session belongs to one agent), so
    -- `any` is the correct merge and is declared rather than assumed. Adding it
    -- to ORDER BY would be the other fix and is rejected: sort keys are
    -- effectively irreversible once written (ADR-0001).
    agent                SimpleAggregateFunction(any, LowCardinality(String)),
    tokens_in            AggregateFunction(sum, UInt64),
    tokens_out           AggregateFunction(sum, UInt64),
    tokens_cache_read    AggregateFunction(sum, UInt64),
    tokens_cache_create  AggregateFunction(sum, UInt64),
    cost_usd             AggregateFunction(sum, Decimal64(8)),
    tasks_opened         AggregateFunction(uniqExact, UUID),          -- uniqExact on task_id: exact, tenant-billable numbers, never HLL
    tasks_satisfied      AggregateFunction(uniqExactIf, UUID, UInt8), -- verdict='satisfied' AND stage final
    tasks_violated       AggregateFunction(uniqExactIf, UUID, UInt8),
    tasks_refused        AggregateFunction(uniqExactIf, UUID, UInt8),
    tasks_error          AggregateFunction(uniqExactIf, UUID, UInt8),
    tasks_unresolved     AggregateFunction(uniqExactIf, UUID, UInt8), -- TaskClose{reason=session_end, no verdict} — the honest denominator class
    dropped_billing      AggregateFunction(sum, UInt64)               -- Dropped{} quantities whose DURABILITY CLASS is billing_grade → coverage band input
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, session_id)
TTL day + INTERVAL 760 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS mark1.mv_tvo_session TO mark1.tvo_session AS
SELECT
    tenant_id,
    toDate(occurred_at)                                        AS day,
    session_id,
    any(agent)                                                 AS agent,
    sumState(input_tokens)                                     AS tokens_in,
    sumState(output_tokens)                                    AS tokens_out,
    sumState(cache_read_input_tokens)                          AS tokens_cache_read,
    sumState(cache_creation_input_tokens)                      AS tokens_cache_create,
    sumState(cost_usd)                                         AS cost_usd,
    uniqExactStateIf(task_id, event_type = 'TaskOpen')         AS tasks_opened,
    uniqExactStateIf(task_id, verdict = 'satisfied'
                          AND verdict_stage IN ('certified','revised')) AS tasks_satisfied,
    uniqExactStateIf(task_id, verdict = 'violated'
                          AND verdict_stage IN ('certified','revised')) AS tasks_violated,
    uniqExactStateIf(task_id, verdict = 'refused'
                          AND verdict_stage IN ('certified','revised')) AS tasks_refused,
    uniqExactStateIf(task_id, verdict = 'error'
                          AND verdict_stage IN ('certified','revised')) AS tasks_error,
    uniqExactStateIf(task_id, event_type = 'TaskClose'
                          AND payload_json_close_reason = 'session_end_no_verdict') AS tasks_unresolved,
    -- The predicate reads `dropped_durability_class`, NOT `event_class`. A Dropped{}
    -- row is ITSELF a diagnostic-class event -- `event_class` describes the row, while
    -- `dropped_durability_class` describes the thing that was LOST (07 §3). Filtering
    -- the loss ledger on `event_class = 'billing'` matches zero rows for all time: a
    -- coverage band that never narrows, which is the exact failure Dropped{} exists to
    -- prevent. See 07 §"Materialized views and rollups".
    sumStateIf(dropped_quantity, event_type = 'Dropped'
                          AND dropped_durability_class = 'billing_grade') AS dropped_billing
FROM mark1.m1p_events
GROUP BY tenant_id, day, session_id;

-- ── Per-task rollup: the grain the waste taxonomy is computed at ──────────
-- Same sums as the session rollup, plus the segmentation version, the TERMINAL
-- verdict pair, the open/close bracket, and the attempt count.
CREATE TABLE IF NOT EXISTS mark1.tvo_task
(
    tenant_id            UUID,
    day                  Date,
    task_id              UUID,
    -- max, not any: task_seg_version is stamped on TaskOpen ONLY, so a block
    -- without the TaskOpen row carries ''. `any` over an AggregatingMergeTree
    -- merge could let that '' win and silently unlabel a task's denominator
    -- rules; max('' , 'task_seg.v1') = 'task_seg.v1' deterministically.
    task_seg_version     AggregateFunction(max, String),
    tokens_in            AggregateFunction(sum, UInt64),
    tokens_out           AggregateFunction(sum, UInt64),
    tokens_cache_read    AggregateFunction(sum, UInt64),
    tokens_cache_create  AggregateFunction(sum, UInt64),
    cost_usd             AggregateFunction(sum, Decimal64(8)),
    -- argMaxIf over verdict-bearing rows only: the LAST verdict a task received,
    -- not the last event it emitted. Plain argMax would return '' whenever a
    -- non-verdict event closed the block.
    verdict              AggregateFunction(argMaxIf,
                             Enum8('' = 0, 'satisfied' = 1, 'violated' = 2, 'refused' = 3, 'error' = 4),
                             DateTime64(6, 'UTC'), UInt8),
    verdict_stage        AggregateFunction(argMaxIf,
                             Enum8('' = 0, 'provisional' = 1, 'certified' = 2, 'revised' = 3),
                             DateTime64(6, 'UTC'), UInt8),
    first_open_at        AggregateFunction(min, DateTime64(6, 'UTC')),
    last_close_at        AggregateFunction(max, DateTime64(6, 'UTC')),
    attempts             AggregateFunction(uniqExactIf, UUID, UInt8),  -- CERTIFIED/REVISED verdicts only: task_seg.v1 R3 closes an attempt on those, so a PROVISIONAL→CERTIFIED pair is one attempt, not two
    dropped_billing      AggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, task_id)
TTL day + INTERVAL 760 DAY DELETE;

-- Every column reference is qualified `e.` on purpose. The output aliases here
-- share names with base-table columns that appear inside the same expressions
-- (`... AS verdict` over `e.verdict != ''`), and ClickHouse resolves an unqualified
-- alias recursively -- yielding ILLEGAL_AGGREGATION ("aggregate function found
-- inside another aggregate function"). The table alias breaks the cycle.
CREATE MATERIALIZED VIEW IF NOT EXISTS mark1.mv_tvo_task TO mark1.tvo_task AS
SELECT
    e.tenant_id                                                    AS tenant_id,
    toDate(e.occurred_at)                                          AS day,
    e.task_id                                                      AS task_id,
    maxStateIf(e.task_seg_version, e.event_type = 'TaskOpen')      AS task_seg_version,
    sumState(e.input_tokens)                                       AS tokens_in,
    sumState(e.output_tokens)                                      AS tokens_out,
    sumState(e.cache_read_input_tokens)                            AS tokens_cache_read,
    sumState(e.cache_creation_input_tokens)                        AS tokens_cache_create,
    sumState(e.cost_usd)                                           AS cost_usd,
    argMaxIfState(e.verdict, e.occurred_at, e.verdict != '')       AS verdict,
    argMaxIfState(e.verdict_stage, e.occurred_at, e.verdict != '') AS verdict_stage,
    minState(e.occurred_at)                                        AS first_open_at,
    maxState(e.occurred_at)                                        AS last_close_at,
    uniqExactStateIf(e.event_id, e.verdict != ''
                          AND e.verdict_stage IN ('certified','revised')) AS attempts,
    sumStateIf(e.dropped_quantity, e.event_type = 'Dropped'
                          AND e.dropped_durability_class = 'billing_grade') AS dropped_billing -- durability class, never event_class; see mv_tvo_session above
FROM mark1.m1p_events AS e
-- The zero-UUID sentinel means "no task" (07 §ClickHouse: sentinel, not
-- Nullable). Without this filter every task-less event in a tenant-day would
-- collapse into one meaningless row that the waste taxonomy would then divide by.
WHERE e.task_id != toUUID('00000000-0000-0000-0000-000000000000')
GROUP BY tenant_id, day, task_id;

-- ── Tenant-day rollup: TVO + the deterministic waste taxonomy ─────────────
CREATE TABLE IF NOT EXISTS mark1.tvo_tenant_day
(
    tenant_id            UUID,
    day                  Date,
    task_seg_version     LowCardinality(String),               -- rollups are keyed by segmentation version; §task_seg.v1
    tokens_total         AggregateFunction(sum, UInt64),
    cost_usd             AggregateFunction(sum, Decimal64(8)),
    tasks_verified       AggregateFunction(uniqExact, UUID),   -- certified 'satisfied' only: the TVO denominator
    tasks_unresolved     AggregateFunction(uniqExact, UUID),
    retry_loop_tokens    AggregateFunction(sum, UInt64),
    reexploration_tokens AggregateFunction(sum, UInt64),
    over_model_tokens    AggregateFunction(sum, UInt64),
    observed_ms          AggregateFunction(sum, UInt64),       -- from CoverageTransition durations
    bypass_ms            AggregateFunction(sum, UInt64),
    disabled_ms          AggregateFunction(sum, UInt64),
    dropped_billing      AggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(day)
ORDER BY (tenant_id, day, task_seg_version)
TTL day + INTERVAL 760 DAY DELETE
-- Without this setting, `insert_deduplication_token` is a NO-OP on a
-- non-replicated MergeTree and ADR-0010's idempotency layer 2 is decoration:
-- a retried rollup insert would land a second block and the additive merge
-- would double the day. 10_000 block hashes ≈ 27 years of daily job blocks
-- per table — the window must outlive any plausible retry horizon, and at
-- ~100 bytes a hash the cost is nothing.
SETTINGS non_replicated_deduplication_window = 10000;

-- Idempotent-upgrade twin of the SETTINGS clause above: CREATE IF NOT EXISTS
-- will not re-shape a table that already exists, so a pre-existing dev table
-- gets the setting here. MODIFY SETTING is itself idempotent.
ALTER TABLE mark1.tvo_tenant_day MODIFY SETTING non_replicated_deduplication_window = 10000;

-- NO MATERIALIZED VIEW FEEDS tvo_tenant_day, and this is not an omission.
-- 07 §"Materialized views and rollups" describes all three rollups as MV-fed,
-- but 07 §"The arithmetic each derived number computes" places these numbers
-- read-time in `mark1-intel.tvo`. The second statement is the one that can
-- actually be built; an insert-block MV cannot produce this table:
--
--   1. `task_seg_version` is in the ORDER BY key, and it is stamped on TaskOpen
--      ONLY. A base-table MV grouping by it would bucket almost every token
--      under '' and split each tenant-day into a labelled row and an unlabelled
--      one -- silently corrupting the denominator every product number divides
--      by. The version is knowable at TASK grain (mark1.tvo_task above), never
--      at insert-block grain.
--   2. `retry_loop_tokens` needs attempt n-1's fused verdict -- cross-event
--      sequencing within a task, across insert blocks.
--   3. `reexploration_tokens` needs a digest-to-digest join against the
--      CortexInjection served-set for the session.
--   4. `over_model_tokens` needs the cheapest ladder rung with an actual passing
--      anchor-verified signal on the same task.
--
--   5. The row is a JOIN ACROSS TWO STORES: the token and task terms come from
--      mark1.tvo_task, the observed/bypass/disabled durations from the Postgres
--      `coverage_transitions` log. No ClickHouse MV can see the second one.
--
-- So the daily `tvo.rollup_tenant_day` job in `mark1-intel` DRIVES this write,
-- rolled up from mark1.tvo_task (which HAS the version and the attempt bracket)
-- plus the coverage durations -- but it does not execute it: `mark1-intel` never
-- holds a ClickHouse credential (05 §6, querychoke is the only principal). The
-- statement is emitted by `controld.querychoke` through the Build-constructed
-- write template `tvo_rollup_tenant_day`, carrying the same mandatory
-- {{tenant_pred}} marker every read template carries. Owning the write in the
-- batch job also keeps the "MVs are the cheap first pass, not the audit path"
-- rule true for the one rollup that certified reports are issued from.
--
-- A written day is NEVER re-run over. `intel_jobs.job_key` is UNIQUE, so
-- re-running a day without naming a new `series` yields the same key and is a
-- no-op by database constraint; a correction is a NEW series written beside the
-- original (task_seg_version carries the `-restated.N` label), never a partition
-- rebuild. This table is AggregatingMergeTree: a duplicate row MERGES ADDITIVELY
-- -- sumState adds, uniqExactState unions -- so a double write inflates the
-- numerator, leaves the denominator alone, and doubles TVO plausibly, with no
-- error and no NULL. That is why the dedupe is mandatory rather than defensive.
--
-- That writer does not exist yet, so this table is EMPTY until it does and any
-- TVO query against it divides by a zero denominator. The full contract --
-- ownership, the three idempotency layers, the correction path, and the refusal
-- rule for a report window containing an unwritten day -- is
-- docs/adr/0010-tvo-rollup-writer.md, which is signed before the first write to
-- this table exactly as ADR-0001 is signed before the first write to m1p_events.
