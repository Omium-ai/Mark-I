# ADR-0010 — Who writes `tvo_tenant_day`: a daily job-keyed batch writer, never a materialized view

- **Status:** Proposed — founder sign-off required **before the first `tvo_tenant_day` write**, the same gate ADR-0001 carries and for the same reason
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap for the mechanics, irreversible for the rows. Schedule, grace lag, dedupe-window size and the job's SQL are config and a migration — hours. What cannot be reversed is a written `(tenant_id, day, task_seg_version)` row: it is append-only by decision, so a number assembled from it and quoted to a customer stays quotable forever and stays *wrong* forever if it was wrong. Correction is a new, differently-keyed series, never an edit. A wholesale rebuild stays possible — `tvo_task` is retained 760 d, so the writer's input outlives its output — which keeps this expensive rather than fatal, exactly as the S3 replay log does for ADR-0001.
- **Blocks:** the first production write to `mark1.tvo_tenant_day`; the `tvo.rollup_tenant_day` job in `mark1-intel` (`06` §7); the `tvo_rollup_tenant_day` write template in `controld.querychoke` (`05` §6.3); every certified customer TVO report, because this is the table they are issued from. Resolves decision **D-F** and finding **F37**.

## Context

`migrations/m1_ch_002_rollups.sql` creates three rollups. Two are fed by materialized views defined in the same file. The third — `mark1.tvo_tenant_day` — has **no writer anywhere in the migration set**. It holds `tasks_verified`, the TVO *denominator*, so the first TVO query written against it divides by nothing. It is also the grain certified reports are issued from, which makes it the one rollup where a silently wrong number is a customer-facing claim rather than an internal metric.

The intended writer exists, but only as prose in a SQL comment (lines 198–207). That comment is doing real work: it settles a genuine contradiction inside `07`, which calls all three rollups MV-fed in §"Materialized views and rollups" and then places these numbers read-time in `mark1-intel.tvo` in §"The arithmetic each derived number computes". A SQL comment is the wrong place for it — invisible to the doc set, no alternatives, no consequences, no signature line, and the next engineer to open `07` has no way to learn the question was asked.

Its four reasons why an insert-block MV cannot produce this table are **correct and carried forward below unchanged**. What it does not answer, and what a writer cannot be built without, is: what the idempotency key is, what happens when a day is re-run, what happens when a day is never run, and who holds the pen — because `05` §6 makes `querychoke` the *only* ClickHouse principal, which "`mark1-intel.tvo` writes this table" contradicts on its face.

## Decision

**One writer: `tvo.rollup_tenant_day`, a daily `mark1-intel` job, executing a write-shaped `querychoke` template.**

1. **Schedule and inputs.** A job spec in the `06` §7.2 scheduler: daily, one job row per `(tenant, day)`, firing after the UTC day closes **plus the 2 h grace lag** (D20) so events whose `ingested_at` trails their `occurred_at` land in the window they belong to. Token and task terms come from `mark1.tvo_task`, which carries the segmentation version, attempt bracket and terminal verdict pair the base table cannot expose at insert-block grain; the `observed_ms` / `bypass_ms` / `disabled_ms` terms come from the Postgres `coverage_transitions` log. **The write is a join across two stores** — a fifth structural reason no MV can produce this row, and this record's one addition to the comment's four. The hourly `tvo.rollup_verify` becomes its checker.

2. **Who holds the pen.** `mark1-intel` never holds a ClickHouse credential. The job *drives* the write; `controld.querychoke` *executes* it, through a `Build`-constructed template `tvo_rollup_tenant_day` carrying the same mandatory `{{tenant_pred}}` marker every read template carries — a named write-shaped carve-out alongside the offboarding deletion mutation (`05` §6.2), tenant-scoped by construction rather than by review.

3. **Idempotency, in three layers, because one is not enough.**
   - **Logical (primary).** `intel_jobs.job_key = ('tvo.rollup_tenant_day', day, day+1, params_hash)` is UNIQUE (`06` §7.3), with `params = {tenant_id, series, watermark}`. A completed day cannot be re-run; a re-run request is a no-op. A database constraint, not a convention.
   - **Physical.** The insert carries `insert_deduplication_token = job_key`, and the table declares a `non_replicated_deduplication_window` sized past the retry budget (D21). This catches the one race the ledger cannot see: insert commits, ack is lost, lease expires, another replica reclaims.
   - **Structural.** One `(tenant, day, series)` is one row, one insert block, one atomic insert — so there is no partial night to reconcile and no staging-then-swap to engineer.

4. **`AggregatingMergeTree` is retained, so the dedupe is mandatory, not defensive.** Under an Aggregating engine a duplicate row is *merged additively*: `sumState` adds, `uniqExactState` unions — a double write inflates the numerator and leaves the denominator untouched. Measured on ClickHouse 24.8 against the shipped DDL, three verified tasks, 300 tokens, true TVO 100:

   | case | tokens | verified | TVO |
   |---|---|---|---|
   | duplicate insert, table as the migration creates it today (dedupe window defaults to **0 = off**) | 600 | 3 | **200** |
   | dedupe window on, but the retry re-read a source that had gained one late row | 700 | 4 | **175** |
   | `insert_deduplication_token = job_key` | 300 | 3 | **100** |

   Row 1 is the defect this record prevents: TVO doubles *plausibly* — no error, no NULL, no zero denominator, just a number twice as flattering as the truth. Row 2 is why content-hash dedupe alone is insufficient: the default block dedupe keys on bytes, and a retry re-reading a ledger that has since gained a late event produces different bytes. Identity must be pinned to the *job*, not to what the job happened to read.

5. **Backfill is not a special case.** The table has no history because the writer never existed. Filling it is ordinary job rows walking backward to each tenant's first event day: same code path, same key, same dedupe. No backfill tool ships, and append-only is not violated — a backfill is the **first** write for its key, overwriting nothing.

6. **Restatement is a new series, never a re-run.** `series` is a job *parameter*, so it enters `params_hash`; re-running a written day without naming a new series yields the same `job_key` and is a no-op **by the UNIQUE constraint**. Naming one writes a new row whose `task_seg_version` carries the restatement label — `task_seg.v1-restated.2` — exactly the `v2-restated` shape `07` §`task_seg.v1` specifies, generalized from version restatement to input corrections; the original row and its receipts stay valid forever. `07`'s own discipline, made enforceable by a constraint instead of asserted by a paragraph.

7. **Failure posture: fail-open for the job, fail-closed for the report.** A missed run is an availability failure of Omium's own batch plane and takes the availability posture — nothing at the edge blocks, nothing is lost (the inputs are durable in `tvo_task` and S3), capture continues, the job parks and alerts. The *report* takes the opposite posture, and that is the deliberate exception worth recording: a window containing a day with **no rollup row** is refused guarantee grade — produced, labeled `indicative`, missing days enumerated, refusal receipted. One clause added to `06` §8.5's four-clause refusal rule, not a new mechanism.

   **Why the coverage band is not stretched to cover this.** Technically decisive: the band's own inputs — `observed_ms`, `bypass_ms`, `disabled_ms` — are *columns of the row that is missing*, so a day with no row yields `0/0`, not a low band. And on honesty: the band answers "was Mark 1 observing?", and it was — what failed was Omium's arithmetic. Encoding a vendor batch failure as customer capture loss replaces a hole with a lie pointing the other way.

## Alternatives considered

### A materialized view over the base table — `07` §"Materialized views and rollups", taken literally

**Strongest case:** it is what `07` says and what the other two rollups do; it needs no scheduler, no job ledger, no idempotency reasoning and no write carve-out in `querychoke`, and it is always current rather than T+1.

**Why it lost — the migration comment's four reasons, carried forward unchanged:**

1. `task_seg_version` is in the `ORDER BY` key and is stamped on `TaskOpen` **only**. A base-table MV grouping by it would bucket almost every token under `''` and split each tenant-day into a labelled row and an unlabelled one — silently corrupting the denominator every product number divides by. The version is knowable at *task* grain (`mark1.tvo_task`), never at insert-block grain.
2. `retry_loop_tokens` needs attempt *n−1*'s fused verdict — cross-event sequencing within a task, across insert blocks.
3. `reexploration_tokens` needs a digest-to-digest join against the `CortexInjection` served-set for the session.
4. `over_model_tokens` needs the cheapest ladder rung with an actual passing anchor-verified signal on the same task.

All four follow from one fact: a ClickHouse MV is a trigger on an insert *block*, and every number here is a function of relationships spanning blocks. Chaining a second MV off `tvo_task` does not help — it fires per insert block into `tvo_task`, so 1–4 bite identically. Keeping the write in the batch job also keeps the file header's own rule true — "the MVs are the cheap first pass, not the audit path" — for the one rollup certified reports are issued from.

### `ReplacingMergeTree(computed_at)` — make a double write structurally harmless

**Strongest case:** the strongest available form of idempotency, and it fits unusually well: the writer produces a *complete* row per key rather than an increment, so replacing on `(tenant_id, day, task_seg_version)` is semantically exact — nothing to accumulate, no window to size, no token to forget. And unlike `m1p_events`, where ADR-0001 forbids `FINAL` outright, this table is tiny, so `FINAL` is affordable here.

**Why it lost:** it makes silent restatement-in-place the engine's default. Measured on the same fixture, a corrected re-run after a late event reads 700 / 4 without `FINAL` — double-counting exactly as the Aggregating table does, having only moved correctness into a read-side discipline every future reader must remember — and 400 / 4 with it, which works, and by working replaces the 300 quoted last quarter: no new key, no new receipt, no way for an auditor to see a number moved. **Kept as the named escape hatch** — if the dedupe window proves too narrow this is the next move, and it must arrive with a guard forbidding replacement of any row a report has cited.

### Staging table plus `ALTER TABLE … REPLACE PARTITION`

**Strongest case:** ClickHouse's canonical batch-rebuild idiom, and the only option atomic *regardless of output size* — a metadata-only parts swap, no dedupe window, no token, no reliance on a single-block assumption a future column could quietly invalidate.

**Why it lost:** the swap unit is the partition, and `PARTITION BY toYYYYMM(day)` makes that a whole month **across all tenants**. A one-day correction for one tenant rebuilds every tenant's month, and no `{{tenant_pred}}` marker fits an `ALTER TABLE … REPLACE PARTITION`, so it cannot be `Build`-constructed and would need an `OpsScope` write path that does not exist. Two structural changes to buy atomicity for a write already one row and already atomic.

### No table at all — compute the tenant-day grain at read time

**Strongest case:** the shortest possible diff, and arguably what `07` §"The arithmetic each derived number computes" already says. Nothing stored is nothing to double-count, nothing to backfill, nothing to restate, and no such thing as a missing day.

**Why it lost:** cost and reproducibility. The waste-taxonomy arithmetic is cross-event and cross-session; over months of base rows it blows the choke's 30 s report-class timeout and its `max_rows_to_read` bound — which is why a materialized tenant-day grain exists at all. And a read-time-only number is reproducible only while its inputs are unchanged: recomputed in Q4 over a Q3 window it moves whenever a late event lands or retention expires a source row, with no artifact recording that it moved. `tvo_reports.body` pins what was *issued*; the rollup row is the auditable intermediate an auditor re-derives against.

## Consequences

### What this makes easy

- **The table stops being a trap.** Today a correct TVO query against it divides by zero. After this it returns a number with a named producer, a schedule and a key.
- **Correction without betrayal.** A restated day is a new labelled series beside the original — the same mechanism `task_seg.v2` uses for a version bump — so `06` §8.5's existing refusal on an unshown version boundary covers it with no new clause.
- **Backfill is free, and the verifier gains a subject.** One job, one code path, no separate correctness argument; and `tvo.rollup_verify`, previously scheduled hourly with nothing to verify, now re-derives sampled tenant-days from `tvo_task`.

### What this makes hard

- **Reports become T+1 with a hard scheduled dependency.** Yesterday's certified number does not exist until last night's job ran, which is why Decision 7's refusal clause must be explicit rather than implied.
- **`task_seg_version` now carries two facts** — segmentation version and restatement series. Legal only because `07` declares the string opaque and compared by equality. It means it can *never* be parsed: "every restatement of v1" needs a side table, not a `LIKE`.
- **Adding a column becomes a backfill decision.** Existing rows cannot be updated, so a new column is either zero-for-history or forces a new series across every day ever written — the price of append-only, paid at every schema change rather than once.
- **The dedupe window is a *sized* control, not an absolute one.** A job parked for days and resumed by hand has aged out of it, leaving the UNIQUE `job_key` as the only layer standing — enough, but layer 1 must never be bypassed by an operator doing a manual re-run. (`ponytail:` window sized to the retry budget; routine manual resumption is the signal to take the `ReplacingMergeTree` escape hatch.)

### What we accept

- **A tenant-day row can be permanently slightly short.** Events arriving after the grace lag belong to the next window and are never retro-fitted into a closed day — which is why restatement is an explicit, receipted, separately-keyed act rather than a silent top-up.
- **A version cutover mid-day produces two rows for that day,** shown as two series and never blended: ADR-0002's accepted friction, arriving as a row count instead of a series count.
- **The first write to any `(tenant, day, series)` is irreversible in the ADR-0002 sense** — not because the bytes cannot be deleted, but because a number assembled from them and handed to a customer cannot be un-handed. Every layer above exists so the first write is the only write.
- **Backfill is N job rows,** and a third carve-out — the second write-shaped one — in `querychoke`'s construction proof. Fine at pilot; at 100× a multi-year backfill floods a 60 s scheduler tick and needs a rate limit, a known ceiling rather than an incident.

## How we would know we were wrong

**Leading indicators, all measurable from the job ledger and the rollups themselves:**

1. **Restatement rate.** More than ~1% of tenant-days ever needing a restated series means the grace lag is too short — late events are systematically landing after their window closed. The fix is the lag (config), not the discipline; a design needing frequent restatement is one where "append-only" has become ceremony wrapped around a routine overwrite.
2. **`tvo.rollup_verify` mismatches.** Any non-zero mismatch between a stored row and its re-derivation from `tvo_task` means the dedupe failed, or the one-row-per-insert assumption stopped holding because a new column makes a tenant-day emit more than one row. The direct detector for the doubled-TVO failure, running hourly against data that already exists.
3. **Refusals attributable to missing rows.** Above ~0.1% of report-days over a trailing month, the problem is the job's reliability rather than the report's honesty. The answer is job engineering — not relaxing the refusal, which converts a visible gap into an invisible one.

**Migration path and cost:** cheapest first — resize the dedupe window, move the grace lag, change the schedule, alter the job's SQL: config or a one-line migration, minutes. Middling: mint a new series and rewrite a range of days as `-restated.N`, one job row per day corrected. Expensive: if the *output identity* proves wrong — the key, the grain, or the append-only rule — the move is a new table `tvo_tenant_day_v2` rebuilt in full from `tvo_task`, retained 760 d precisely so the writer's input outlives its output; point reports at v2, keep v1 for the life of every report citing it, drop it after a full retention cycle. What no migration can do is change a number already quoted — the sentence ADR-0002 ends on, for the same reason.

## References

- `migrations/m1_ch_002_rollups.sql` — the `tvo_tenant_day` DDL (156–177), the four MV-impossibility reasons preserved above (185–196), the writer prose this record replaces (198–207).
- `docs/07-data-model.md` — the two contradicting sections (§"Materialized views and rollups" vs §"The arithmetic each derived number computes"); §`task_seg.v1` "Version bumps without restating history"; §Coverage (`coverage_transitions`, `tvo_reports.coverage_band`, the guarantee CHECK).
- `docs/06-lld-intelligence.md` — §7.2 scheduler and lease model (D19); §7.3 idempotency and re-run semantics (`job_key` UNIQUE, watermarked reads, grace lag D20, retry budget D21); §8.5 the refusal rule (D23) this record extends by one clause.
- `docs/05-lld-cloud.md` — §6 the `querychoke` construction proof and its write-shaped carve-outs; §6.3 the template registry this record adds `tvo_rollup_tenant_day` to.
- `docs/RECONCILIATION.md` — **D-F** and finding **F37**. ADR-0001 — the shared `(tenant_id, day, …)` prefix. ADR-0002 — version stamping, the append-only rule, and the irreversibility class a quoted number belongs to.
