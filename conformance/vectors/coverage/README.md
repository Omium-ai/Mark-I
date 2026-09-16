# Coverage-band conformance vectors — from a batch's loss rows to the band

`manifest.json` freezes the arithmetic from the `Dropped[]` rows a batch carries to the
coverage band `(coverage_lower, coverage)` that every TVO report prints. It is
NFR-OPERABILITY-001's second half: `go/mark1d/cmd/wiring_test.go
TestSpoolShedReachesTheWire` proves a spool shed leaves an assembled daemon as
`Dropped{reason: SPOOL_SHED, durability_class: DIAGNOSTIC, quantity: N}`; this family
is what that row does to the band, asserted through the production band code in each
language. This README is normative where the docs delegate a construction detail
(12 §3.4); everything else restates 07 "Coverage", `migrations/m1_ch_002_rollups.sql`
and the `dropped_by_tenant_day` template body (`go/controld/internal/querychoke/templates.go`).

Regenerate with `python3 gen_vectors.py` (stdlib only). The manifest is the frozen
contract: if regeneration ever changes a byte, that is a finding against `gen_vectors.py`,
never a license to update the manifest.

## The chain (what each vector traverses)

```
Batch.dropped[]   Dropped{reason, quantity, durability_class}            proto/m1p/v1/envelope.proto
   │  ingest projects each row to m1p_events: event_type='Dropped',
   │  dropped_reason / dropped_durability_class = enum suffix lowercased
   │  ('' for UNSPECIFIED), dropped_quantity                               controld ingest/chproj droppedRow
   ▼
dropped_billing = sumIf(dropped_quantity, event_type='Dropped'
                        AND dropped_durability_class = 'billing_grade')    dropped_by_tenant_day / mv_tvo_session
events_billing_ingested = countIf(event_class = 'billing')                 dropped_by_tenant_day
observed_ms, bypass_ms, disabled_ms                                        coverage_band (tvo_tenant_day)
   ▼
coverage        = observed_ms / (observed_ms + bypass_ms + disabled_ms)                    (0 on 0/0)
coverage_lower  = coverage × (1 − dropped_billing / (dropped_billing + events_billing_ingested))  (shed 0 on 0/0)
                                                    python/intel/app/tvo/coverage.py coverage_band
                                                    go/controld/internal/querychoke/module.go coverageBand
```

Two facts the vectors pin, both normative in 07 and in `Dropped.durability_class`'s
field comment:

1. **Only billing-grade loss narrows the band.** The predicate is the LOSS's durability
   class, never the reason and never the `event_class` of the `Dropped` row itself (a
   `Dropped` row is diagnostic-class; filtering on it sums to zero forever — the
   `mv_tvo_session` lesson). A `DIAGNOSTIC` shed of any size folds to `dropped_billing = 0`.
   The `UNSPECIFIED` zero value projects to `''` and is likewise outside the predicate —
   "retain, don't guess" (07 §3) means an unknown class is not guessed to be billing.
2. **Only the lower edge ever moves on a drop.** `coverage` is a pure surface-time ratio;
   drops narrow `coverage_lower` and nothing else. "Shed narrows only the lower edge" is a
   statement about billing-grade shed; a diagnostic shed narrows neither.

## Inputs (wire shapes, so a Go consumer can drive them)

Per case:

| field | shape | source |
|---|---|---|
| `dropped[]` | `{reason, durability_class, quantity}` — proto enum NAMES (`DROP_REASON_*`, `DURABILITY_CLASS_*`), `quantity` a uint64 | `Batch.dropped` (07's `Dropped`, fields 1/4/3; field 2 `category` is reserved) |
| `rollup.observed_ms`, `bypass_ms`, `disabled_ms` | uint64 ms | `coverage_band` template columns (`tvo_tenant_day`) |
| `rollup.events_billing_ingested` | uint64 | `dropped_by_tenant_day` column: rows that DID land whose own class is `billing` |

Expectations: `expect.dropped_billing` (the frozen intermediate — a consumer that skips
the fold and reads it is not driving the chain), `expect.coverage`, `expect.coverage_lower`
(float64, compare within `tolerance` = 1e-12), and `expect.exact` (the rationals, for
hand-checking; informative). A Go consumer decodes each `dropped[]` row with
`protojson.Unmarshal` into `m1pv1.Dropped` (proto field names are accepted on input);
Python resolves the names against the generated `m1p.v1` enums. A row naming a value the
wire does not carry is a red in both.

## Cases, hand-computed

| case | dropped rows | fold | coverage | coverage_lower |
|---|---|---|---|---|
| `zero_loss_point_band` | none | 0 | 94 000 / 100 000 = **0.94** | shed 0/(0+1000) = 0 → **0.94** |
| `diagnostic_shed_does_not_narrow` | SPOOL_SHED · DIAGNOSTIC · 50 | **0** (class ≠ billing) | 98 000 / 100 000 = **0.98** | shed 0/950 = 0 → **0.98** |
| `billing_grade_loss_narrows_only_the_lower_edge` | CRC_LOSS · BILLING_GRADE · 50 | 50 | **0.98** (unchanged) | 0.98 × (1 − 50/1000) = 0.98 × 0.95 = **0.931** |
| `mixed_rows_fold_by_class_not_reason` | SPOOL_SHED·DIAG·54, CRC_LOSS·BILLING·1, LOCAL_QUARANTINE·DIAG·1, UNSPECIFIED·UNSPECIFIED·7, QUARANTINED·BILLING·2 | 1 + 2 = **3** | 86 400 000 / 86 400 000 = **1.0** | 1 × (1 − 3/(3+9)) = 1 − 0.25 = **0.75** |
| `spool_shed_reaches_the_wire` | SPOOL_SHED · DIAGNOSTIC · **54** | 0 | **1.0** | shed 0/(0+0) → 0 → **1.0** |

Cases 2 and 3 share every input but the class: the same quantity moves the lower edge by
0.049 as billing-grade loss and by nothing as diagnostic shed. That pair is the family's
whole point.

### Deriving 54 — what `TestSpoolShedReachesTheWire` actually sheds

The test runs the assembled daemon with `--spool-cap 1 KiB` and sends 32 HUMAN `Turn`
events on one session, then asserts `FlushAck.drained < 32` and `SPOOL_SHED/DIAGNOSTIC
> 0` (the Go leg pins the exact 54). The exact quantity follows from the record layout and the segmenter:

- Spool accounting (`internal/spool`): a fresh segment starts at `writeOff = 64`
  (segment header); each record is `28 + len(payload)` (len + crc32c + 20-byte record id);
  a diagnostic is shed iff `total + recSize > 1024`; the active segment is never freed, so
  the cap is a hard ceiling for the run.
- Each admitted `Turn` marshals to 44 bytes (event_id 18, seq 2, session_id 18,
  session_epoch 2, `turn{initiator}` 4) → **72-byte record**. Nothing stamps
  `occurred_at` or `task_id` on it.
- The segmenter (`internal/taskseg` `Observe`) runs BEFORE admission on the same path.
  HUMAN turns do not advance `ss.turn`, so prompt 1 mints a task (`TaskOpen`), prompt 2
  only marks it pending (proximity rule), and every prompt from 3 on flushes the pending
  task into a fresh mint: **31 `TaskOpen` events across 32 prompts** (1 + 0 + 30). A
  `TaskOpen` carries event_id, seq, session_id, task_id, `occurred_at` (seconds 5-byte
  varint + nanos 1–5 bytes), epoch and `{task_seg_version:"task_seg.v1",
  task_class:"*", file_set_digest:32B}` → 118–124 payload bytes → **146–152-byte record**.
- Admission order and running total (R = one `TaskOpen` record, 146 ≤ R ≤ 152; cap 1040):
  `64 + R + 72 (P1) + 72 (P2) + R + 72 (P3) + R + 72 (P4) + R + 72 (P5)` = 424 + 4R ∈
  [1008, 1032] ≤ 1040 — all admitted. Prompt 6's `TaskOpen` needs `+R > 8` bytes and its
  `Turn` `+72`: both shed, and so is everything after, because nothing is ever freed.
- Result: 4 `TaskOpen` + 5 `Turn` admitted (`drained = 5`); **27 `TaskOpen` + 27 `Turn`
  shed = 54**, all `SPOOL_SHED / DIAGNOSTIC`, all raised inside the one synchronous send
  loop; the ledger is read-and-reset at compose, so whichever batch(es) the 9 admitted
  records ride, the union across batches is 54 (the test's `tap.dropped` is that union).
  The `EdgeHealth` the uploader admits after the ack is shed against the still-full
  segment but never rides a batch inside the test — a rows-only batch does not exist.
- The Go test asserts `== 54` under the 1040-byte cap (`TestSpoolShedReachesTheWire`); the manifest's `> 0` is the cross-language floor.

That daemon's day has no `CoverageTransition` (no workspace) and no billing-grade event
(`Turn`/`TaskOpen` are diagnostic), so `events_billing_ingested = 0`. The surface terms
are stipulated as one fully observed day so the arithmetic is legible; with the test's
literal zeros the band is `(0, 0)` by the zero-surface rule, which the golden fixture
already locks.

## Consumers and required tests

Every consumer MUST drive every case: resolve the enum names, fold `dropped[]` to
`dropped_billing` and assert it equals `expect.dropped_billing`, then feed the FOLDED
value (never the expectation) with the rollup columns to the production band function
and assert both edges within `tolerance`.

- **Python** (present): `python/intel/tests/test_conf_vectors_coverage_band.py` —
  enum names via `m1p.v1.DropReason` / `DurabilityClass`, fold restated in the test (the
  production fold is SQL), band via `app/tvo/coverage.py coverage_band`.
- **Go** (due): `go/controld/internal/querychoke/` — `TestConfVectorsCoverage`, decoding
  rows with `protojson` into `m1pv1.Dropped`, folding on `GetDurabilityClass() ==
  DURABILITY_CLASS_BILLING_GRADE`, band via `coverageBand` (module.go). Under
  `M1_TEST_CH_DSN` the fold should additionally run as the REAL predicate: insert the
  rows through `chproj.droppedRow`'s projection into a scratch `m1p_events` and read
  `dropped_billing` back through the `dropped_by_tenant_day` template (the shape
  `TestIntegrationReadTemplatesReturnOnlyCallingTenant` already seeds). The row SHAPE the
  family consumes is proven by `go/mark1d/cmd/wiring_test.go` (`TestSpoolShedReachesTheWire`,
  `TestEdgeLossLedgersBothReachTheWire`); tightening the former to `== 54` pins case 5's
  quantity at its source.

Test-name filters are load-bearing (`tools/ci/conformance_crosslang.sh`): Go
`TestConfVectorsCoverage*`, Python `*conf_vectors_coverage*`. The family is NOT yet listed
in `conformance/vectors/EXPECTED`: the gate requires a Go twin for every listed family and
would fail on this one until `TestConfVectorsCoverage` lands — list it, add `coverage` to
the script's `PY_REQUIRED`, and land the Go test in the same commit. Until then the Python
consumer still runs under the gate's `-k conf_vectors` sweep (a red there fails the script);
only the per-family two-leg requirement is unarmed.
