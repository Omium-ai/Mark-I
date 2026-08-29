-- =============================================================================
-- m1_ch_001_events.sql  --  ClickHouse: the M1P token-event ledger.
--
-- NAMING. Postgres migrations in this directory are `m1_0NN_*.sql` and run
-- against RDS; ClickHouse migrations are `m1_ch_0NN_*.sql` and run against the
-- ClickHouse host. Same directory (13 §R-13.3: the root `migrations/` holds the
-- controld-owned core schema), same Argo CD Sync-hook Job, two runners:
-- `psql -v ON_ERROR_STOP=1 -f` for `m1_0NN_`, `clickhouse-client --queries-file`
-- for `m1_ch_0NN_` (09 §4.2), the latter as the DDL-only third ClickHouse user
-- whose credential exists solely in that Job.
--
-- -----------------------------------------------------------------------------
-- *** THE ORDER BY BELOW IS IRREVERSIBLE. SEE docs/adr/0001-clickhouse-ordering-key.md ***
--
-- A MergeTree ORDER BY cannot be altered in place. Everything else in this file
-- -- codecs, TTLs, skip indexes, even the partition key (via new partitions) --
-- can be adjusted after the fact. This key cannot. Changing it after the first
-- production write means a new table plus a full re-ingest from the S3 replay
-- log: hours at pilot scale, days and four-to-five-figure S3 spend at 100x.
--
--     ORDER BY (tenant_id, toDate(occurred_at), session_id, event_id)
--
-- ADR-0001 is signed before the first production write. Do not edit this line
-- without a superseding ADR; the migration path is ADR-0001 §"Migration path
-- and cost" (new table -> dual-write -> replay -> parity check -> cutover),
-- not an ALTER.
-- -----------------------------------------------------------------------------
--
-- ACCESS CONTROL IS NOT IN THIS FILE, DELIBERATELY. ClickHouse is reachable
-- ONLY through `controld.querychoke` (05 §6: "querychoke is the only ClickHouse
-- principal"). Exactly two runtime users exist -- `m1p_ingest` (INSERT only) and
-- `m1p_query` (SELECT only, readonly profile) -- and both credentials are held
-- solely by controld. Nothing else gets a grant: no human, no dashboard, no
-- other service. Those users and their settings profiles are created in
-- `users.d/m1p-users.yaml`, rendered at instance boot from Secrets Manager
-- (09 §4.2), because config-file-defined users cannot be modified by SQL GRANT
-- and mixing the two access-control models produces a file that fails to apply.
-- Row policies are ABSENT BY DESIGN (07 §ClickHouse): the isolation mechanism is
-- the choke's construction proof, and a decorative row policy alongside it is
-- exactly the mistake the estate already paid for once in Postgres.
--
-- ASYNC INSERT. `async_insert=1, wait_for_async_insert=1` are set in two places,
-- deliberately redundant, and NEITHER of them is DDL: (1) server-side in the
-- `m1p_ingest` settings profile in `users.d/`, so a client bug cannot silently
-- revert to synchronous small-part inserts; (2) per-connection in
-- `controld.ingest`'s client settings, asserted at startup, so a misconfigured
-- server is detected rather than tolerated. Together they remove the need for an
-- event bus at pilot: the coalescing a broker would do happens in the
-- async-insert buffer, and `wait_for_async_insert=1` means the insert call
-- returns only once the data is durably in a part.
--
-- Idempotent: IF NOT EXISTS throughout, safe to re-run.
-- =============================================================================

CREATE DATABASE IF NOT EXISTS mark1;

CREATE TABLE IF NOT EXISTS mark1.m1p_events
(
    -- ── Identity + ordering ─────────────────────────────────────────────
    tenant_id        UUID                    CODEC(ZSTD(1)),          -- stamped by controld from token claims, never from the envelope
    occurred_at      DateTime64(6, 'UTC')    CODEC(Delta(8), ZSTD(1)),-- near-monotonic within a part → Delta collapses it
    session_id       UUID                    CODEC(ZSTD(1)),
    event_id         UUID                    CODEC(ZSTD(1)),          -- UUIDv7: dedupe key, spool cursor, receipt leaf — one identity, three layers
    seq              UInt64                  CODEC(Delta(8), ZSTD(1)),-- monotonic within a (session, epoch) → Delta; causal order is the PAIR below, never seq alone (dev clocks drift, so it is not occurred_at either)
    session_epoch    UInt32                  CODEC(Delta(4), ZSTD(1)),-- query-time causal order is the PAIR (session_epoch, seq), never seq alone: seq restarts at 1 on daemon reboot (07 §2). Not part of the ORDER BY below — that key is unalterable. Constant across a boot ⇒ Delta collapses it to nothing
    ingested_at      DateTime64(6, 'UTC') DEFAULT now64(6)
                                             CODEC(Delta(8), ZSTD(1)),-- the ReplacingMergeTree version column: latest server ingest wins
    device_id        UUID                    CODEC(ZSTD(1)),
    task_id          UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000')
                                             CODEC(ZSTD(1)),          -- zero-UUID sentinel, not Nullable: Nullable costs a mask subcolumn and poisons skip indexes
    task_seg_version LowCardinality(String)  CODEC(ZSTD(1)),          -- stamped on TaskOpen; §task_seg.v1

    -- ── Family + class ───────────────────────────────────────────────────
    event_type       LowCardinality(String)  CODEC(ZSTD(1)),          -- LowCardinality not Enum: adding an event family must never need a DDL mutation
    event_class      Enum8('billing' = 1, 'verdict' = 2, 'receipt' = 3, 'route' = 4, 'diagnostic' = 5)
                                             CODEC(ZSTD(1)),          -- Enum not LowCardinality: this set is closed by design and drives the TTL below. NOT the spool durability class — that is the two-value byte [16] the edge stamps (07 §6), which no ClickHouse column can reach back and set; {billing,verdict,receipt} are the billing-grade three, {route,diagnostic} are not
    agent            LowCardinality(String)  CODEC(ZSTD(1)),          -- claudecode|codex|gemini|…
    model            LowCardinality(String)  CODEC(ZSTD(1)),

    -- ── Usage (billing-grade) ────────────────────────────────────────────
    input_tokens                 UInt64      CODEC(T64, ZSTD(1)),     -- small ints with shared high zero bits → T64
    output_tokens                UInt64      CODEC(T64, ZSTD(1)),
    cache_creation_input_tokens  UInt64      CODEC(T64, ZSTD(1)),
    cache_read_input_tokens      UInt64      CODEC(T64, ZSTD(1)),
    cost_usd         Decimal64(8)            CODEC(ZSTD(1)),          -- exact money, never Float
    cost_basis       Enum8('' = 0, 'usd' = 1, 'quota' = 2) CODEC(ZSTD(1)),
    idem_key         FixedString(32)         CODEC(ZSTD(1)),          -- HMAC_tenant(session_id, message.id, request_id): the ~2.5× streaming-overcount defense

    -- ── Verdicts (vocabulary frozen at the type level) ───────────────────
    verdict          Enum8('' = 0, 'satisfied' = 1, 'violated' = 2, 'refused' = 3, 'error' = 4)
                                             CODEC(ZSTD(1)),          -- Enum ON PURPOSE: a fifth verdict value must fail the INSERT, not sneak in
    verdict_stage    Enum8('' = 0, 'provisional' = 1, 'certified' = 2, 'revised' = 3)
                                             CODEC(ZSTD(1)),
    p_satisfied      Float32                 CODEC(Gorilla, ZSTD(1)), -- posterior[4] as four columns: locks arity, feeds rollups without array unnesting
    p_violated       Float32                 CODEC(Gorilla, ZSTD(1)),
    p_refused        Float32                 CODEC(Gorilla, ZSTD(1)),
    p_error          Float32                 CODEC(Gorilla, ZSTD(1)),
    noise_cert_id    UUID                    CODEC(ZSTD(1)),

    -- ── Routing (C9) ─────────────────────────────────────────────────────
    propensity       Float64                 CODEC(Gorilla, ZSTD(1)), -- ε defaults 0 ⇒ propensity 1.0, logged honestly
    fidelity         Enum8('' = 0, 'wire_enforced' = 1, 'config_steered' = 2, 'advisory' = 3)
                                             CODEC(ZSTD(1)),
    bundle_seq       UInt64                  CODEC(Delta(8), ZSTD(1)),

    -- ── Receipts + coverage + shed accounting ────────────────────────────
    checkpoint_seq   UInt64                  CODEC(Delta(8), ZSTD(1)),
    inclusion_path   String                  CODEC(ZSTD(1)),          -- Merkle path to the checkpoint root; empty until checkpointed
    coverage_kind    Enum8('' = 0, 'enable' = 1, 'disable' = 2, 'bypass' = 3) CODEC(ZSTD(1)),
    coverage_duration_ms UInt64              CODEC(T64, ZSTD(1)),
    dropped_reason   LowCardinality(String)  CODEC(ZSTD(1)),          -- DropReason suffix, lowercased: spool_shed|crc_loss|gate_timeout|… LowCardinality not Enum8 — reasons grow additively inside m1p.v1, and a new one must land as data, not DDL
    dropped_durability_class Enum8('' = 0, 'billing_grade' = 1, 'diagnostic' = 2) CODEC(ZSTD(1)), -- Dropped.durability_class; Enum8 because THIS set is contractually closed at two (07 §3), values equal to the spool class byte
    dropped_quantity UInt64                  CODEC(T64, ZSTD(1)),

    -- ── Everything else ──────────────────────────────────────────────────
    payload          String                  CODEC(ZSTD(3)),          -- canonical JSON remainder; ZSTD(3): cold column, read rarely, compress harder

    -- Extracted ONCE at insert so the rollup MVs never parse JSON at merge time
    -- (07 §Materialized views: "a MATERIALIZED JSONExtractString(payload,
    -- 'close_reason') column on the base table"). It is the TaskClose reason
    -- that puts a task in the `unresolved` denominator class (task_seg.v1 R4).
    payload_json_close_reason LowCardinality(String)
        MATERIALIZED JSONExtractString(payload, 'close_reason') CODEC(ZSTD(1)),

    INDEX idx_event_id event_id TYPE bloom_filter(0.01) GRANULARITY 4, -- point dedupe / receipt-leaf lookups off the ordering key's tail
    INDEX idx_task     task_id  TYPE bloom_filter(0.01) GRANULARITY 4, -- task drilldown without a session_id in hand
    INDEX idx_idem     idem_key TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(occurred_at)
-- IRREVERSIBLE — ADR-0001. tenant_id first (the mandatory tenant predicate
-- prunes to one contiguous range: the isolation control IS the performance
-- control, and future tenant-hash sharding stays a pure split); toDate second
-- (coarse time pruning inside the tenant range, a day of one session adjacent);
-- session_id third (per-session TVO is one sequential range read); event_id last
-- (unique tiebreaker, UUIDv7 so it sorts near-chronologically, keeping Delta
-- codecs effective and ReplacingMergeTree dedupe granule-local).
ORDER BY (tenant_id, toDate(occurred_at), session_id, event_id)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY  DELETE WHERE event_class = 'diagnostic',
    toDateTime(occurred_at) + INTERVAL 760 DAY DELETE                 -- 25 months: covers a full billing-dispute year plus audit lookback; §Retention
SETTINGS index_granularity = 8192;

-- Dedupe is EVENTUAL. ReplacingMergeTree collapses duplicates at merge time, so
-- readers must use `GROUP BY event_id` / `LIMIT 1 BY event_id` forms rather than
-- FINAL on hot paths -- a naive `SELECT count(*)` over-counts until merges run.
-- The query choke's builder owns this; by design no other reader exists.
