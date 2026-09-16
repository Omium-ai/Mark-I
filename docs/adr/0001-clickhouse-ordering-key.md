# ADR-0001 — ClickHouse ordering key and `ReplacingMergeTree` layout

- **Status:** Accepted — signed by Anurag Upadhyay (founder) 2026-09-16, as recommended by the lead; the ruling is recorded in docs/RECONCILIATION.md (D-EI).
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** expensive — a MergeTree `ORDER BY` cannot be altered in place; reversing means a new table plus a full re-ingest from the S3 replay log. At pilot scale (~10⁷–10⁸ events, tens of GB of zstd batches) that is hours of one backfill worker and negligible S3 GET cost. At 100× (~10¹⁰ events, tens of TB) it is days of parallel backfill, four-to-five-figure S3 GET + transfer spend, and a dual-write window in `controld.ingest` while the backfill catches up. Painful, bounded, and *possible* — which is exactly why the S3-first landing exists. Without the replay log this decision would be unrecoverable, not merely expensive.
- **Blocks:** the first production write to `mark1.m1p_events`; the `migrations/` DDL for the events table and all three materialized-view rollups; the `controld.ingest` ClickHouse insert path. The plan is explicit: this ADR is signed before the first production write.

## Context

Mark 1's token-event ledger is one wide ClickHouse table, `mark1.m1p_events`, holding every M1P event for every tenant. Every TVO query joins event families by `(session_id, task_id)`, so one table beats a star of identically-keyed narrow tables. The transport is at-least-once by design (spool replay, S3 re-ingest), so duplicates are normal and must collapse. The table is reachable only through `controld.query-choke`, which appends the tenant predicate to every query by construction — meaning the tenant predicate is on *every single query the system will ever run*.

The `ORDER BY` of a MergeTree table is the one physical-layout decision ClickHouse does not let you change in place. Everything else in the analytics plane — codecs, TTLs, materialized views, skip indexes, even the partition key (via new partitions) — can be adjusted after the fact. This key cannot. That is why it gets the first signed ADR.

The query shapes the product actually runs, in observed-frequency order:

1. Tenant + date-range aggregation — TVO reports, waste rollups, coverage bands, billing reconciliation (the materialized views, and most ad-hoc choke queries).
2. Session drilldown given `(tenant, day)` — per-session TVO, task reconstruction.
3. Point lookup by `event_id` — receipt-leaf verification, idempotent re-ingest.
4. (Rare, internal) cross-tenant fleet queries — ops questions like "which tenants shed events today".

## Decision

```sql
ENGINE = ReplacingMergeTree(ingested_at)          -- dedupe on the sorting key; newest server ingest wins
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (tenant_id, toDate(occurred_at), session_id, event_id)
```

with `event_id` a UUIDv7 (time-prefixed) that is simultaneously the server dedupe key, the spool cursor, and the receipt-checkpoint leaf; bloom-filter skip indexes on `event_id`, `task_id`, and `idem_key` for the point-lookup shapes the key does not serve.

**Why each component, in order:**

- `tenant_id` first — the mandatory tenant predicate always prunes to one contiguous key range. Tenancy isolation and physical data locality become the same axis: the isolation control is also the performance control. It also makes future tenant-hash sharding a pure split with no re-sort — a compatibility argument neither alternative below has.
- `toDate(occurred_at)` second — coarse time pruning inside the tenant range while keeping a whole day of one session's events adjacent.
- `session_id` third — a session's events are contiguous; per-session TVO is a single sequential range read.
- `event_id` last — the unique tiebreaker; being UUIDv7 it sorts near-chronologically within the session, keeping Delta codecs effective and making ReplacingMergeTree dedupe granule-local.

**Dedupe semantics:** `ReplacingMergeTree(ingested_at)` collapses duplicates at merge time; dedupe is *eventual*. The query choke's builder therefore emits `GROUP BY event_id` / `LIMIT 1 BY event_id` forms rather than `FINAL` on hot paths — correctness never waits on background merges.

**Fast shapes:** tenant + date-range aggregation; session drilldown given `(tenant, day)`; task reconstruction within a session; idempotent re-ingest (duplicate keys land in the same granule and collapse at merge).

**Slow shapes, named honestly:**

- *Cross-tenant fleet queries* scan every tenant's range for the day. Acceptable: internal, infrequent, bounded by the date component.
- *Session lookup without a date* degrades to a tenant-wide scan. Mitigated by convention, not index: every session-scoped query carries the session's date range (`mark1d` knows it; the choke requires it).
- *`event_id` point lookup* — served by the bloom-filter skip index, not the key.
- *A session crossing UTC midnight* splits into two key ranges. Deliberate: the choke widens session queries by ±1 day automatically; a coarser bucket would heal the split but blunt pruning for the 99% of queries that are date-ranged.

**Behaviour at volume.** At 10×: nothing changes — monthly partitions stay in the hundreds-of-parts regime, granule pruning is logarithmic in parts, async-insert keeps part counts sane. At 100×: merge pressure and per-partition part counts become the constraint *before the key does*; the remedies are orthogonal to the ordering key — move `PARTITION BY` to `toYYYYMMDD` for hot months, then shard by `tenant_id`, which the tenant-first ordering makes a pure split.

## Alternatives considered

### `session_id` first — `ORDER BY (session_id, event_id)` or `(session_id, toDate(occurred_at), event_id)`

**Strongest case:** session drilldown is the highest-value *interactive* query — a user staring at one session's timeline wants sub-second response, and session-first makes that a single primary-key range read with no date needed. It also makes the ReplacingMergeTree dedupe maximally local, since all replays of a session land in one range. If the product were a session-inspector first and a reporting engine second, this would be the right key.

**Why it lost:** session UUIDs are effectively uniformly random across sessions (even UUIDv7 prefixes only order sessions *by creation time*, which scatters any one tenant's sessions across the whole keyspace as other tenants interleave). Tenant-range pruning dies: the mandatory tenant predicate on every query becomes a full-scan filter instead of a range bound. Compression collapses, because adjacent rows share no tenant, no day, no session context. And it optimises a shape the chosen key already serves well — session drilldown given `(tenant, day)` is a short range read anyway. It buys marginal improvement on shape 2 by destroying shapes 1 and 4 and the sharding path.

### A coarser or finer time bucket — `toStartOfWeek(occurred_at)`, no time component, or `toStartOfHour(occurred_at)`

**Strongest case (coarser):** fewer midnight splits, better session contiguity — a week-long-lived session stays one range; sessions never split on day boundaries. **Strongest case (finer):** hourly buckets sharpen pruning for intraday billing reconciliation and ops queries.

**Why it lost:** coarser — date-range queries then prune only via the partition key (month granularity), a ~30× read amplification on "last 7 days" reports, which are the *most common* report shape; the midnight-split problem it heals is already handled by the choke's ±1-day widening at near-zero cost. Finer — hourly bucketing multiplies the number of distinct key prefixes per session by up to 24, fragmenting session contiguity (shape 2 regresses from one range read to up to 24) for a pruning gain that matters only to queries the skip indexes and partition pruning already serve adequately. Day granularity is the knee of this curve: coarse enough that sessions rarely split, fine enough that week-scale reports prune ~4× better than month-partition pruning alone.

### A separate projection — session-first projection alongside the tenant-first base order

**Strongest case:** ClickHouse projections give you *both* physical orders; the optimizer picks per query. Session lookups without a date stop being a slow shape at all. This is the "why choose?" option, and for a read-heavy analytics table it is often correct.

**Why it lost:** it doubles storage and merge cost from day one for a query shape with no demonstrated need at pilot — and, decisively, **projections can be added later without a table rewrite**. The reversible option is deferred precisely *because* it is reversible; this ADR decides only the irreversible thing. If query-shape telemetry ever shows date-less session lookups mattering, adding the projection is an `ALTER TABLE ... ADD PROJECTION` plus a materialization pass, not a migration.

## Consequences

### What this makes easy

- Every product query (tenant + date range) is a contiguous range read; the tenant-isolation predicate and the performance predicate are the same physical axis.
- The three MV rollups (`tvo_session`, `tvo_task`, `tvo_tenant_day`) key naturally as `(tenant_id, day, …)` — same prefix, same pruning behaviour, no impedance mismatch.
- Idempotent re-ingest and spool replay are free: duplicates land in the same granule and collapse at merge; `GROUP BY event_id` forms stay granule-local.
- Future sharding by `tenant_id` is a pure split; moving hot months to daily partitions requires no key change.
- Delta/T64/Gorilla codecs stay effective because rows arrive near-sorted within `(tenant, day, session)`.

### What this makes hard

- Cross-tenant analytics (fleet ops, aggregate product metrics) always pay a scan across tenant ranges — acceptable while internal and infrequent, but a real cost if a cross-tenant product surface ever ships.
- Session lookups without a date are tenant-wide scans, held safe only by the choke-level convention that session queries carry a date range. The convention must be enforced in the choke's builder, with a test.
- Sessions crossing UTC midnight split into two ranges; the choke's ±1-day widening is mandatory complexity, not optional.

### What we accept

- Eventual dedupe: readers must use `GROUP BY event_id` / `LIMIT 1 BY` forms; a naive `SELECT count(*)` over-counts until merges run. The choke owns this; no other reader exists by design.
- Double specification of `async_insert=1, wait_for_async_insert=1` (server profile *and* client, asserted at startup) as the price of no event bus at pilot.
- Durability lives in S3, not ClickHouse: the ledger is a downstream view of the replay log, and we accept ClickHouse loss as a re-ingest event, not a data-loss event.

## How we would know we were wrong

**Leading indicator:** query-shape telemetry in `controld.query-choke` (it sees every query by construction). The signal is a sustained shift of the read mix into the named slow shapes — concretely, if over a trailing month either (a) >10% of choke queries are session lookups arriving without a date bound, or (b) cross-tenant scans exceed 5% of total rows read — the key is optimising for a workload we do not have. Secondary indicator: p95 latency on the standard tenant + 7-day report exceeding 2 s at pilot volume with healthy part counts, which would mean the pruning math is not delivering.

**Migration path and cost:** (1) create `m1p_events_v2` with the new `ORDER BY`; (2) flip `controld.ingest` to dual-write; (3) replay S3 `ingest/` landings oldest-first into v2 — idempotent, since `event_id` dedupe makes replays safe; (4) verify row-count and checksum parity per `(tenant, day)`; (5) point query-choke at v2; (6) drop v1 after a full retention cycle. Cost as stated under Reversibility: hours at pilot, days and four-to-five-figure S3 spend at 100×. Before reaching for a key change, the cheap escape hatches are: add a projection (reversible, no rewrite), add a skip index, or repartition future data — the full migration is the last resort, not the first.

## References

- `/home/anurag/workspace/Omium/omium-mark1/docs/spec/execution-plan-v2.md` — Data stores table ("the one irreversible decision; ADR signed before the first production write"); "Decisions to make before code" item 1.
- `/home/anurag/workspace/Omium/omium-mark1/docs/.parts/07-part3-analytics.md` — full DDL for `mark1.m1p_events`, codec rationale, the "ADR-0001 on the record" section this record formalizes, MV definitions, S3 `ingest/` replay-log layout.
- `/home/anurag/workspace/Omium/omium-mark1/docs/RECONCILIATION.md` — R-14 (two ClickHouse credentials, INSERT-only and SELECT-only, both held solely by `controld`; all reads through the choke).
