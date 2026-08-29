# 11 — Observability, SLOs and Operations

**Status:** Authored 2026-08-28 against the frozen execution plan (`docs/spec/execution-plan-v2.md`) and the architecture spec v2.0. Where this document and either of those disagree, they win.
**Scope:** how Mark 1 watches itself — metrics, logs, health, SLOs, alerts, runbooks, dashboards — and how `Dropped{}`/coverage accounting is treated as first-class product telemetry. The components instrumented here are `04-lld-edge.md`'s four edge processes and `05-lld-cloud.md`'s `controld` plus the two Python services of `06`. Budgets cited from those documents are theirs; this document adds no new budgets, only the instruments that prove them.
**Owns:** the consolidated metrics catalog (04 §2.11 and 05 §1.7 defer it here), SLI/SLO definitions, alert rules, runbooks, dashboard inventory.
**Does not own:** infrastructure wiring of Prometheus/Grafana (`09`), the tests that enforce CI budget thresholds (`12`), the DDL behind ledger-derived signals (`07`).

---

## 0. Philosophy, and why there is no OpenTelemetry

### 0.1 The decision, restated as a positive

Mark 1 contains **zero OpenTelemetry. Anywhere.** No OTel SDK on the edge, no OTel SDK in the cloud, no OTLP endpoint, no collector, no "just the propagation headers." This is not an austerity measure — it is the recognition that Mark 1 already ships a telemetry fabric as its *product*, and a second fabric riding alongside it would be strictly worse on every axis that matters to this product:

1. **M1P already carries what OTel would carry.** The product's own protocol moves typed, receipted, idempotent, durability-classed events from every edge process to a queryable ledger: `SessionStart/End`, `Turn`, `ToolUse`, `ModelRequest/Response`, `Usage`, `VerdictEvent`, `RouteDecision`, `GuardDecision`, `CoverageTransition`, `ReceiptCheckpoint`, `Dropped{reason, durability_class, quantity}`. That is a span stream in everything but name — except it is *better* than a span stream where it counts: every event has a durability class (billing-grade events block-on-full and are never shed; OTel spans are best-effort by design), every event is idempotent end-to-end (`event_id` upsert), and loss is *accounted* (`Dropped{}`) rather than silent. An OTel pipeline on the edge would duplicate the uploader, the spool, the retry automaton, and the batching — four subsystems Mark 1 already builds to a higher standard because customers are billed from them.

2. **A second telemetry fabric on the edge is a liability, not an asset.**
   - **Binary size and dependency surface.** The edge budgets are brutal on purpose: `mark1-proxy` ≤35 MB RSS and ≤1 ms median added latency; `mark1-hookshim` is a static binary with a ≤10 ms cold start and no async runtime at all (04 §5). `opentelemetry` + `opentelemetry-otlp` + `tonic`/`hyper` exporter stacks pull tens of crates and an exporter runtime into binaries whose whole design brief is "boring, small, auditable." The shim *cannot* take a tokio dependency for a metrics exporter — it deliberately has no runtime.
   - **Egress ambiguity.** Mark 1's compliance story is that exactly one channel leaves a developer machine: M1P/1 to `controld.ingest`, through one redaction chokepoint, with one admission path (04 §0.3 invariants 1 and 5). An OTLP exporter is a second egress channel with its own endpoint configuration, its own retry buffer, and its own serialization of whatever an instrumentation author put in a span attribute. Every span attribute is a place a path, a prompt fragment, or a credential can leak *around* the redaction chokepoint. The admit-to-upload scanner has no off switch precisely because "a second path that skips it" is the failure class; adding OTel would build that second path on purpose.
   - **A second thing that can leak a secret.** The proxy handles customer LLM credentials under a `Secret<T>` discipline with an explicit tee field allow-list because `Request::clone()` carries headers and headers carry credentials (04 §3.2). Auto-instrumentation is a request-clone factory. The safest amount of instrumentation framework in that binary is none.

3. **Nothing that exists today is being given up.** The estate's own observability posture, verified by direct read: scraping is by pod annotation (`prometheus.io/scrape` / `port` / `path` — every service template in `Omium-platform/infrastructure/helm/omium-platform/templates/`); there are **no ServiceMonitor objects anywhere**; the Terraform observability module's header says logs and traces are deferred ("Logs (Loki) and traces (Tempo + OTEL collector) are added in a follow-up once apps emit telemetry" — `infrastructure/terraform/modules/observability/main.tf`); **no OTel collector is deployed in any environment**. The only OTel in the estate is an optional, fail-soft hook in `omium-training-plane` that activates on an env var nobody sets. Mark 1 declining OTel forfeits no deployed capability, no dashboard, no integration.

### 0.2 What is genuinely given up, honestly

Three things OTel would have provided "for free," and what Mark 1 does instead, with the cost stated:

| Given up | What OTel provides | What Mark 1 does instead | The honest cost |
|---|---|---|---|
| **Distributed trace propagation** | W3C `traceparent` flows through every hop; one trace ID stitches shim → daemon → cloud → store automatically | **Identity-tuple correlation** (§0.3): `session_id` / `event_id` (UUIDv7, time-ordered) / `seq` / `batch_id` are already on every event, every landing object, every ClickHouse row, and every structured log line. Correlation is a *join on product identifiers*, not a trace-context header | No automatic per-request flame graph. Cross-hop latency for one request is reconstructed from timestamps on the joined records, not rendered by a trace UI. Acceptable because the topology is shallow and fixed — three hops, no fan-out mesh; traces earn their keep in topologies Mark 1 deliberately does not have |
| **Auto-instrumentation of libraries** | HTTP/DB client spans appear without code | Hand-placed Prometheus histograms at every stage that has a budget (05 §2.1 names one metric per ingest stage). Coverage is exactly the set of things we decided to measure | An unmeasured code path stays unmeasured until someone adds a metric. Mitigated by the rule that **a budget without an enforcement point does not appear in an LLD** (04 §0.2) — every budget line already names its instrument |
| **Vendor-portable telemetry schema** | OTLP consumers interchangeable | Prometheus exposition on the cloud (the estate's format), M1P in the ledger (the product's format) | If Omium ever buys a SaaS observability vendor, an exporter shim gets written then. Speculative portability is not a Phase-1 cost worth paying |

### 0.3 The correlation story — following one request without trace context

The identity tuple that replaces trace context, and where each element is minted:

```
session_id   — minted at SessionStart; on every event of the session
event_id     — UUIDv7, minted at the producer (shim/tailer/proxy/cortexd);
               simultaneously the dedupe key, the ClickHouse ordering component,
               the spool cursor, and the receipt-checkpoint leaf
seq          — per-session monotonic, stamped by mark1d at admission (04 R-4);
               carries causal order because wall clocks drift
batch_id     — UUIDv7, minted by the uplink batcher; names the S3 landing object
checkpoint_seq + inclusion_path — bind the event into the receipt chain
```

Because `event_id` and `batch_id` are UUIDv7, **identifiers sort by time** — the ID *is* a coarse timestamp, which is half of what a trace span gives you.

**What a debugging engineer actually types**, tracing a customer report of "my Usage events from this morning are missing":

```bash
# 1. Edge: what does the daemon think happened? (developer machine or screen-share)
mark1 status --json | jq '{spool: .spool, uplink: .uplink, dropped: .dropped, coverage: .coverage}'
#    → parked batches? quarantined batches? Dropped{} counters by (reason, durability_class)?

# 2. Edge: find the session and its events in the local diagnostic log
grep '"session_id":"0192f3a1-…"' ~/.omium/mark1/log/mark1d.log | jq -c '{ts,msg,event_id,batch_id}'
#    → which batch_id the events were composed into, and what the uplink did with it

# 3. Cloud: did that batch land? The batch_id names the S3 object directly.
aws s3 ls "s3://mark1-ingest-prod/t/${TENANT}/ingest/v1/dt=2026-08-28/" | grep "${BATCH_ID}"
#    (absent → check the quarantine prefix; present → it landed and was acked)

# 4. Cloud: did controld see it? Structured logs carry batch_id on every ingest line.
kubectl -n omium logs deploy/controld --since=6h | grep "${BATCH_ID}" | jq -c '{ts,stage,msg}'

# 5. Ledger: did it project? (operator token, querychoke template — never raw SQL)
curl -s -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
  "https://api.mark1.omium.ai/reports/usage_by_session?session_id=${SESSION_ID}&from=2026-08-28&to=2026-08-28" | jq .
#    Row count vs edge count; gaps are either Dropped{}-accounted or a projection-lag issue:
curl -s localhost:9092/metrics | grep controld_ingest_ch_project_lag_seconds

# 6. Integrity: is the customer's copy of history consistent with ours?
mark1 verify-receipts --tenant ${TENANT} --from 2026-08-28 --against-witness
```

Every step joins on an identifier that exists *because the product needs it* — dedupe, replay, receipts — not because observability asked for it. That is the design point: **the correlation fabric is load-bearing product structure, so it cannot rot into optional instrumentation.** A trace header that nobody asserts on goes stale; a `batch_id` that names the replay-log object cannot.

### 0.4 The two rules that fall out

1. **Cloud components expose Prometheus `/metrics` and are scraped by pod annotation** — the estate convention, verbatim (05 §1.7: `prometheus.io/scrape: "true"`, `prometheus.io/port: "9092"`; no ServiceMonitors). Go uses `promauto`; Python uses the estate's `omium_observability` package (`omium_http_requests_total`, `omium_http_request_duration_seconds`, `omium_http_in_flight`, `omium_http_exceptions_total`) plus service-scoped families.
2. **Edge components expose no metrics endpoint at all** (04 §2.11: "a laptop daemon exposing a metrics port is attack surface with no scraper"). Edge self-observation travels three ways: locally via `mark1 status --json` and the diagnostic log; as product telemetry via `Dropped{}` / `CoverageTransition` / `GuardDecision` in the ledger; and as a low-cadence diagnostic-class self-metrics event (§2.3). Nothing else leaves the machine.

---

## 1. Two audiences, two systems

### 1.1 The distinction

| | **Product telemetry** | **Operational telemetry** |
|---|---|---|
| Whose data | **The customer's.** Session events, usage, verdicts, receipts — the TVO Ledger. Tenanted, receipted, billed from, contractually governed | **Ours.** Process health, latencies, queue depths, error rates. Never tenanted beyond a bounded `tenant` label where per-tenant ops health needs it |
| Fabric | M1P/1 → S3 → ClickHouse/Postgres, through `controld.ingest` | Prometheus scrape (pod annotation) → kube-prometheus-stack; local logs |
| Durability | Billing-grade classes: block-on-full, at-least-once, idempotent, `Dropped{}`-accounted. Loss is a product defect | Best-effort. A scrape gap is a scrape gap |
| Retention | Ledger retention per `07` (contractual); receipts effectively forever | Prometheus retention per `09` (weeks); logs days |
| Access | Tenant-scoped through `querychoke` templates only; customer-visible surfaces (`mark1 report`, dashboard) | Internal Grafana; never customer-visible |
| Integrity | Merkle-checkpointed, dual-signed, externally witnessed | None claimed, none needed |

### 1.2 Why they are not merged

The temptation is obvious — the ledger is a superb time-series store and already receives events from every component. Three reasons the ops signals do not move into it, and the product signals do not move out:

1. **Different loss contracts.** Ops telemetry must be sheddable under load (a saturated service that also *must* durably record its own saturation is a positive feedback loop). Product telemetry must never be silently sheddable. One fabric cannot honor both contracts without per-event flags that someone will eventually set wrong; two fabrics make the contract a property of *which system you wrote to*.
2. **Different trust boundaries.** The ledger is customer-auditable by design — receipts, witness, the offline verifier. Omium's internal pod restart counts and goroutine profiles do not belong in a customer-verifiable evidence chain, and putting them there would bloat the receipt surface and invite "why is this in my export" questions. Conversely, ops dashboards must never become a side channel onto customer content — Prometheus label sets here are bounded enums and tenant UUIDs, never paths, prompts, or session content (§5).
3. **Different query planes.** Ops questions are "now and the last hour, across the fleet" — Prometheus's home turf. Product questions are "this tenant, this quarter, exactly" — `querychoke`'s. A merged store serves both badly.

### 1.3 The one place they touch

`Dropped{reason, durability_class, quantity}` and coverage accounting are **simultaneously an ops signal and a product-integrity signal**, and this dual citizenship is by design:

- As *product* telemetry: `Dropped{}` events ride M1P batches into the ledger, feed the coverage band (§10), and appear in customer reports. They are billing-grade adjacent — the accounting of loss is itself never lost.
- As *ops* telemetry: `mark1-intel.tvo-engine` periodically evaluates the `dropped_by_tenant_day` and `coverage_band` querychoke templates and re-exposes the results as Prometheus gauges (`intel_dropped_billing_events_total`, `intel_coverage_ratio{tenant}` — §4.4). That exporter loop is **the single sanctioned bridge** from ledger to Prometheus. It is read-only, aggregate-only, and its label set is `{tenant, durability_class, reason}` — bounded enums plus tenant UUIDs, nothing free-text. `durability_class` and not the event-family name for the reason §3 gives: a family name is an open string, and this label set has to stay closed to survive the conformance test.

The bridge points only one way. Nothing flows from Prometheus into the ledger, ever — an ops metric that mattered enough to be in a customer report would be evidence, and evidence enters through capture, not through a scrape.

---

## 2. Edge self-monitoring

The edge cannot be scraped: there is no Prometheus with a route to a developer's laptop, and Mark 1 refuses to open one (04 §2.11). Edge observability is therefore built from four local surfaces plus one narrow, privacy-ruled uplink.

### 2.1 `mark1 status` — the local truth surface

`mark1 status` (and `--json` for tooling) is the developer- and support-facing view of everything the daemon knows about itself, read from `mark1d`'s atomic counter/gauge tables over the fabric:

```
$ mark1 status
mark1d        running (pid 4211, 2d14h, restarts: 0)   rss 96 MB
workspaces    2 enabled (~/work/api, ~/work/web)       .mark1ignore active
capture       claudecode v2.1.3 (subscription regime)  hooks OK, tailer lag 0 B
spool         3 segments / 41 MiB (cap 2 GiB)          fsync p99 4.1 ms
uplink        last ack 28s ago                         parked: 0, quarantined: 0
policy        bundle seq 142 (stable), age 11m         stale: false
verdict       cache: 1 task, PROVISIONAL, knee holding blocks this hour: 0/ceiling
proxy         not running (no api-key agent detected)
cortexd       2 running, index_clock 8841              rss 210 MB / 188 MB
dropped (24h) gate_timeout: 2 (diagnostic)             spool_shed: 0, crc_loss: 0
coverage      no open bypass windows                    last transition: enable, 2d ago
```

Every line answers a support question that would otherwise be a screen-share archaeology session. `--json` emits the same tree with stable keys; `mark1 doctor` goes deeper (consent catalog, fenced-fragment checksums, per-adapter detection).

### 2.2 What Omium can and cannot see about a developer machine

**Can see** (only via the ledger, only for enrolled devices): the M1P event stream the tenant consented to at enrollment — typed capture events, `Dropped{}` counters, `CoverageTransition` windows, `GuardDecision` samples, device `last_seen_at`, and the §2.3 self-metrics event. **Cannot see, structurally:** file paths (typed `path_role` only), code, prompts (digests only, per-tenant HMAC-salted), anything outside enrolled workspace roots, anything while `mark1 off` is in effect, local log contents, spill-ring contents (sealed to a key only `mark1d` holds), or any per-process detail beyond what §2.3 enumerates.

The boundary sits exactly where the product's legal posture sits: **"raw sessions and code stay client-side" is a capture rule, so it must also be the observability rule** — an ops channel with more reach than the capture channel would make the capture guarantees decorative. Omium debugging a misbehaving edge beyond the ledger's view requires the developer to run `mark1 status`/`doctor` and share output, and that friction is accepted deliberately.

### 2.3 Self-metrics as M1P events — the `EdgeHealth` event

A diagnostic-class event family carrying the edge's own gauges to the fleet-health view. **Ratified:** `07` §3 admits it as `Event.body` field 22 — an additive message, non-breaking under `buf breaking`, absent from the frozen plan's original family list. **This section is its single source of truth**: `07` deliberately does not transcribe the field set, because a health gauge added in two documents is a health gauge that drifts. A gauge is added or refused here; `events.proto` is transcribed from here.

- **Cadence:** one event per successful uploader cycle, rate-limited to one per 15 minutes per device. Diagnostic durability class — it sheds first under pressure, and its own loss shows up in `Dropped{}` like everything else.
- **Content — counters and gauges only:** per-process `{rss_bytes, restarts, uptime_s}` for `mark1d`/`cortexd`/`proxy`; spool `{segments, bytes_used, oldest_unacked_age_s}` (`bytes_used`, not `bytes`: `bytes` is a protobuf scalar keyword and the pinned betterproto plugin emits it as a class attribute that shadows the builtin inside the message body — renamed here, in the owning document, before codegen froze the JSON name); uplink `{parked, quarantined, last_ack_age_s}`; bundle `{seq, age_s, stale}`; gate `{reads, allows, blocks, timeouts, read_p99_us}`; proxy `{added_latency_p50_us, added_latency_p99_us}` (self-timer digests, not raw samples); shim `{delivered, spilled}`; cortexd `{index_clock, refusals}`; versions `{edge_version, dialect_revs}`.
- **Why `read_p99_us` is in the gate group and `read_p50_us` is not.** SLO-7 (§7) is judged as *fleet* p99 of `gate_read_seconds`, and laptops cannot be scraped — this event is the only vehicle, so a "closed field set" that omitted it would put the conformance test and the SLO in direct contradiction, each correct and each making the other fail. There is no p50 counterpart because no budget reads one: the gate budget is a tail budget (≤5 ms p99, 04 §2.3), and a gauge with no consumer is fleet-wide bytes bought for nothing. The proxy group carries p50 *and* p99 because its budget is stated as a **median** (≤1 ms, §3.2).
- **The privacy rule, normative:** an `EdgeHealth` event carries **no code, no paths, no hostnames, no workspace names, and no identifiers beyond what capture already carries** (`tenant_id`/`device_id` stamped server-side from the token, `session_id` absent — health is per-device, not per-session). The proto has no string field except the version strings, which are release-artifact identifiers; `conf_schema_closed_field_set` (`12` §3.6) asserts the field set stays closed by diffing the buf descriptor against a committed golden, so a widening arrives as a reviewed diff line rather than by accretion. That test ships in Phase 1 with the emitter; until it does this rule is enforced by review only, tracked as G-5 in §12.

### 2.4 Local diagnostic logs

- `~/.omium/mark1/log/mark1d.log` (and `cortexd-<ws>.log`, `proxy.log`): `slog` JSON lines, 0600, size-rotated at 32 MiB × 4 files (~128 MiB ceiling), **≤7 days retention** enforced by the daemon's own sweep — the log must never become a shadow transcript archive.
- **Redaction:** log emission passes through the same admit-to-upload scanner discipline as capture — but the stronger rule is structural (§5.2): log call sites take typed fields (`event_id`, `batch_id`, counts, error codes), never interpolated content. The scanner is the backstop, not the mechanism.
- Logs never leave the machine. `mark1 doctor --bundle` can package the last 24 h *for the developer to attach themselves* — the tool writes a local archive and prints its path; it uploads nothing.

### 2.5 Crash reports

- Native crash dumps are **suppressed** in the proxy (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` — a core file is a credential-disclosure vector, 04 §3.3) and unconfigured elsewhere; Mark 1 never registers a crash-dump uploader.
- What exists instead: Go panics and Rust panics are caught at the top level where recoverable, logged as structured `panic` records (message + our own frames only — no environment capture, no locals), and counted. The *fact* of a crash reaches Omium as supervision data in the next `EdgeHealth` event (`restarts` counter) and, where capture was affected, as a `CoverageTransition`. The *content* of a crash stays on the machine, in the local log, for `mark1 doctor` to show.
- A fleet-wide crash-rate signal therefore exists (§4.4's exporter aggregates `EdgeHealth.restarts`) without any developer machine ever uploading a stack dump.

---

## 3. Metrics catalog — edge

Edge "metrics" are in-process atomic counters/gauges/self-timer digests. They are read by `mark1 status --json`, summarized into `EdgeHealth` (§2.3), and — for the budget metrics — asserted as CI bench thresholds in `12`. Names below are the stable JSON keys and `EdgeHealth` fields; there is no Prometheus exposition on the edge (§0.4). Label cardinality is bounded by construction: every label is a closed enum from the protocol or the component registry.

### 3.1 `mark1d`

| Metric | Type | Labels (bound) | Measures | Alert relevance |
|---|---|---|---|---|
| `spool_segments` | gauge | `class` ∈ {billing, diagnostic} (2) | live segment count per durability class | fleet: sustained growth ⇒ ingest outage or parked uploads (§8 A-02 feeds from the exporter) |
| `spool_bytes` | gauge | — | total spool occupancy vs the 2 GiB cap | approach to cap ⇒ billing-grade writers about to block (by design), doctor warns |
| `spool_oldest_unacked_age_seconds` | gauge | — | age of the oldest durable-but-unacked record | the truthful "how far behind is this device" signal; drives A-02 |
| `spool_fsync_seconds` | histogram digest | — | group-commit fsync latency (250–500 ms cadence, 04 §2.4) | p99 ≫ cadence ⇒ dying disk; doctor warns locally |
| `dropped_total` | counter | `reason` ∈ the 10 `DropReason` values, suffix-lowercased (spool_shed, crc_loss, unsupported_agent_version, local_quarantine, gate_timeout, quarantined, fabric_unavailable, ring_evicted, ring_expired, parse_degraded) × `durability_class` ∈ {billing_grade, diagnostic} (2) | every accounted loss anywhere in the daemon | **the product-integrity signal** — mirrors the ledger `Dropped{}` stream (§10); any `billing_grade` count pages via A-04 |
| `admit_seconds` | histogram digest | — | capture admission latency (redact → stamp → enqueue) | budget: cheap by design (fsync off-path); regression caught in `12` bench |
| `admit_quarantine_total` | counter | — | events locally quarantined by scanner failure (fail-closed, 04 §2.0) | nonzero ⇒ redaction subsystem fault; doctor + A-13 via exporter |
| `uplink_batches_total` | counter | `outcome` ∈ {acked, retried, parked, quarantined} (4) | uploader automaton outcomes | quarantined > 0 ⇒ poison batch (RB-3); parked sustained ⇒ ingest reachability |
| `uplink_parked` / `uplink_quarantined` | gauge | — | current parked/quarantined batch counts | surfaces in `status`; fleet aggregate drives A-02 |
| `gate_read_seconds` | histogram digest | — | `GateQuery`→`GateVerdict` round trip (map lookup; budget ≤5 ms, 04 §2.3) | budget enforced in `12/gate-latency`; fleet p99 in `EdgeHealth` |
| `gate_answers_total` | counter | `answer` ∈ {allow, block, allow_timeout, allow_off} (4) | gate outcomes incl. fail-open allows | `allow_timeout` rate ⇒ daemon overload; `block` rate feeds guard-anomaly baseline (A-08) and the canary health signals (05 §4.3) |
| `verdict_cache_age_seconds` | gauge | — | staleness of the newest cached verdict | high ⇒ anchors not running; correlates with F-03/F-34 |
| `bundle_seq` / `bundle_age_seconds` / `bundle_stale` | gauge | — | applied policy seq, age, `max_age` breach (0/1) | `stale=1` ⇒ fail-static on built-ins (F-29); fleet count drives A-09 |
| `child_restarts_total` | counter | `child` ∈ {cortexd, proxy} (2) | supervision restarts | breaker trips receipt a `CoverageTransition` (F-05); fleet crash rate §2.5 |
| `shim_events_total` | counter | `outcome` ∈ {delivered, spilled, dropped} (3) | shim hand-offs, counted at drain | rising `spilled` ⇒ daemon availability problem on that machine |
| `shim_spill_ring_bytes` | gauge | — | spill-ring occupancy | near cap ⇒ prolonged daemon outage; TTL expiry is receipted |
| `tailer_lag_bytes` | gauge | — | unconsumed transcript bytes across streams | sustained ⇒ tailer wedged; usage capture at risk |
| `coverage_bypass_windows_open` | gauge | — | currently open bypass windows | any open window is a live coverage hole; shows in `status` |
| `rss_bytes` | gauge | — | daemon RSS vs the 200/300 MB watchdog (04 §1.3) | >300 MB ⇒ controlled self-restart with drain |

### 3.2 `mark1-proxy`

| Metric | Type | Labels (bound) | Measures | Alert relevance |
|---|---|---|---|---|
| `added_latency_seconds` | histogram digest (µs buckets) | — | per-request self-timer, `t_client_byte_in → t_upstream_byte_out` | **the ≤1 ms median budget**, enforced in `12/bench-proxy-latency-rss`; p50/p99 digests ride `EdgeHealth` |
| `rss_bytes` | gauge | — | proxy RSS | **the ≤35 MB budget**; supervise poll + CI bench |
| `requests_total` | counter | `dialect` (≤5) × `outcome` ∈ {forwarded, refused, contaminated} (3) | guarded request outcomes | `contaminated` > 0 is the P0 (A-01); `refused` rate feeds A-08 |
| `guard_refusals_total` | counter | `reason` ∈ {no_cred_ref, unknown_ref, fp_mismatch, oauth_shape} (4) | provenance-guard refusals by cause (04 §3.1) | `oauth_shape` on a *provisioned* credential ⇒ P1 provisioning bug; sampled `GuardDecision` receipts carry the same taxonomy |
| `tee_shed_chunks_total` | counter | — | `try_send` drops on the tee channel | observation narrowing, never client impact (04 §3.2); sustained ⇒ undersized channel |
| `parse_degraded_total` | counter | `dialect` (≤5) | `mark1-frames` degradations to opaque passthrough | vendor format drift signal — pair with the golden-fixture CI failure (F-09); wire Usage loss is `Dropped{}`-accounted |
| `upstream_pool_conns` | gauge | `dialect` (≤5) | live upstream connections | leak detection; pools are per `(upstream, credential-identity)` but the label is dialect-only — credential identity never labels anything |

### 3.3 `mark1-hookshim`

The shim is a transient process (≤50 ms wall) and holds no counters; its observability is **externalized by design**: outcomes are counted by `mark1d` at drain (`shim_events_total`, §3.1), its deadline compliance is a CI bench (`12`: ≤10 ms cold start, ≤50 ms wall — the shim's own timers enforce at runtime, the bench proves the margin), and its failures are visible as *absence* — missing hook events surfaced by `mark1 doctor`'s per-adapter capture check. A shim that cannot reach the daemon writes to the sealed spill ring; the ring's byte gauge and drain counters are `mark1d`'s. This is deliberate: instrumenting a 50 ms fire-and-forget process with its own metrics store would spend the budget on the thermometer.

### 3.4 `cortexd` (per workspace)

| Metric | Type | Labels (bound) | Measures | Alert relevance |
|---|---|---|---|---|
| `index_clock` | gauge | — | monotone index version (04 §6.1) | stuck clock + fs activity ⇒ wedged writer task |
| `index_settle_seconds` | histogram digest | — | notify event → index settled | drives map freshness; large monorepo tuning input |
| `rss_bytes` | gauge | — | per-workspace RSS vs the 500 MB ladder (shed L3 → coarsen L2 → refuse) | ladder engagement is logged + visible in `status` |
| `mcp_requests_total` | counter | `tool` (6) × `outcome` ∈ {ok, refused_stale, refused_scope, refused_failed} (4) | MCP tool outcomes incl. refusal taxonomy (`M1E-64xx`) | high `refused_stale` ⇒ indexing can't keep up; `refused_scope` spikes are probe-attempt signals |
| `map_serve_seconds` / `map_tokens_used` | histogram digest | — | session-start map assembly serve + budget fit (04 §6.4) | `CortexInjection` events carry the per-serve values into the ledger; this is the local aggregate |
| `reindex_total` | counter | `trigger` ∈ {overflow, corruption, grammar_bump} (3) | full-rescan causes (04 §6.6) | `corruption` > 0 ⇒ shard deleted + rebuilt (F-04); frequent `overflow` ⇒ watcher sizing |

### 3.5 Budget-enforcement summary

Every frozen-plan edge budget, its instrument, and its enforcement point — the closed loop this catalog exists to serve:

| Budget | Instrument | Enforced at |
|---|---|---|
| proxy ≤1 ms median added latency | `proxy.added_latency_seconds` p50 | runtime self-timer + `12/bench-proxy-latency-rss` CI threshold |
| proxy ≤35 MB RSS | `proxy.rss_bytes` | supervise poll + same CI bench |
| shim ≤50 ms fire-and-forget / ≤10 ms cold start | shim-internal deadline timers | timers abandon-and-spill at 45 ms; `12` bench proves margin |
| gate read ≤5 ms | `gate_read_seconds` | `12/gate-latency` |
| `mark1d` ≤200 MB steady / 300 MB restart | `rss_bytes` | self-watchdog |
| cortexd ≤500 MB per workspace | `cortexd.rss_bytes` | shed ladder |
| spool ≤2 GiB / 95 % disk | `spool_bytes` + statfs | pre-append check; `CoverageTransition{disk_hard_stop}` |

---

## 4. Metrics catalog — cloud

All cloud metrics are Prometheus exposition, scraped by pod annotation on the metrics port (`controld`: 9092 per 05 §1.1; Python services: the estate's per-service metrics port convention). Namespacing follows 05 §0.2: `controld_<module>_*` per module, plus the estate's shared `omium_http_*` families from the `obs` package. Stage metrics named in 05 §2.1 are listed here once, consolidated; 05 owns their placement in the pipeline.

### 4.1 `controld.ingest`

| Metric | Type | Labels (bound) | Measures | Alert relevance |
|---|---|---|---|---|
| `controld_ingest_requests_total` | counter | `stage` (stage enum, 11) × `outcome` ∈ {ok, client_error, server_error, shed} | per-stage throughput and failure | funnel view; `shed` = pre-decompression 503s under saturation (05 §2.4) |
| `controld_ingest_auth_failures_total` | counter | `reason` ∈ {expired, invalid, revoked} (3) | stage-2 rejections | `revoked` spikes during an emergency are *expected*; see RB-6 |
| `controld_ingest_identity_disagreements_total` | counter | — | envelope vs token-claim mismatch (stage 3) | **any nonzero pages** (A-05) — edge bug or spoofing attempt, both P1 |
| `controld_ingest_zstd_bomb_trips_total` / `decode_failures_total` / `invariant_violations_total{kind}` | counter | `kind` bounded (≤6) | stages 4–6 rejections | sustained from one device ⇒ quarantine loop; RB-3 |
| `controld_ingest_scanner_hits_total` | counter | `class` (SecretClass enum, ≤8) | second-scanner detections (stage 7) | every hit = a secret nearly entered the replay log; A-13 tickets, tenant notified |
| `controld_ingest_quarantines_total` | counter | `tenant` (bounded: enrolled tenants) | flagged batches diverted to quarantine prefix | tenant-visible via `mark1 status`; A-13 |
| `controld_ingest_s3_land_seconds` | histogram | — | stage-8 PUT latency (the dominant ack cost, ~150–400 ms) | input to the ack SLO; S3/KMS degradation shows here first |
| `controld_ingest_s3_land_failures_total` | counter | `cause` ∈ {throttle, kms, 5xx, conflict} (4) | landing failures (no ack sent — the promise kept by withholding) | RB-1; `conflict` = 409 byte-divergence (edge spool corruption) |
| `controld_ingest_ack_seconds` | histogram | — | stage-1 entry → response write. **The ingest SLI** (05 §2.7) | SLO-1/SLO-2 burn alerts |
| `controld_ingest_ch_project_seconds` | histogram | — | stage-10 ClickHouse async-insert latency | CH health from the writer's seat |
| `controld_ingest_ch_project_lag_seconds` | gauge | — | newest landed batch vs newest projected | **SLO-4**; alarmed at 5 min (05 §8.1); RB-1/RB-2 |
| `controld_ingest_ch_project_failures_total` | counter | — | projection attempts failed (3-strikes → dead-letter park) | park events drive RB-3 (poison batch) |
| `controld_ingest_sidefx_seconds` / `checkpoint_pending_leaves` | histogram / gauge | — | stage-11 Postgres side-effects; leaves awaiting the next checkpoint | pending leaves growing without checkpoints ⇒ receipt cadence broken (A-11) |

### 4.2 `controld.enroll`, `controld.policydist`, `controld.dprelease`, `controld.querychoke`

| Metric | Type | Labels (bound) | Measures | Alert relevance |
|---|---|---|---|---|
| `controld_enroll_flows_total` | counter | `outcome` ∈ {active, expired, denied} (3) | device-code flow completions | funnel only |
| `controld_enroll_revocations_total` | counter | `source` ∈ {operator, sweep, scim} (3) | revocations by trigger | context for RB-6 |
| `controld_enroll_revocation_cache_age_seconds` | gauge | — | staleness of the shared revocation cache (≤60 s ceiling, 05 §3.4) | **A-06:** ≥45 s warn, ≥60 s critical — past 60 s verification fails closed and ingest 401s fleet-wide |
| `controld_enroll_sweep_last_success_timestamp` | gauge | — | daily IdP reconciliation sweep heartbeat | >26 h ⇒ offboarded users' devices not being caught; ticket |
| `controld_policydist_bundles_published_total` | counter | `channel` ∈ {canary, stable} (2) | publications (incl. rollback-by-append) | context for RB-4 |
| `controld_policydist_acks_total` | counter | `result` ∈ {applied, rejected, partial} (3) | fleet ACK ledger writes | any `rejected` with `M1E-3005` halts + pages (A-07) |
| `controld_policydist_ack_coverage_ratio` | gauge | `channel` (2) | fraction of 24 h-active devices ACKed on the newest seq | **SLO-5**; A-09 at <0.9 sustained |
| `controld_policydist_rollout_halted` | gauge | — | canary controller in halted state (0/1) | halts page by design (05 §4.3) |
| `controld_policydist_sse_connections` | gauge | — | live SSE streams (bound 5,000/pod) | capacity trigger (05 §8.5) |
| `controld_policydist_tlog_witness_last_success_timestamp` | gauge | — | last successful hourly witness head publication | **A-10:** >2 h ⇒ the "verify Omium" claim is degrading; RB-9 |
| `controld_policydist_kms_sign_queue_depth` | gauge | — | queued sign ops vs the 50/min budget | sustained depth ⇒ publication latency; never blocks serving |
| `controld_dprelease_epsilon_spent` | gauge | `tenant` (bounded) | ε consumed this window vs `ε_budget` 4.0/yr | **A-12:** >80 % ticket, >95 % warn; exhaustion refuses (05 §5.6), RB-7 |
| `controld_dprelease_releases_total` | counter | `state` ∈ {approved, rejected, blocked_epsilon, expired} (4) | review-queue dispositions | `blocked_epsilon` growth ⇒ RB-7 |
| `controld_dprelease_review_queue_depth` | gauge | `state` (4) | queue occupancy | 14-day expiry means depth is informational, not paging |
| `controld_querychoke_queries_total` | counter | `template` (closed registry, ~10) × `outcome` ∈ {ok, refused, timeout, error} (4) | choke executions | `refused` = unknown template (`M1E-2008`) — client bug or probe |
| `controld_querychoke_query_seconds` | histogram | `template` (~10) | per-template latency vs the 30 s/5 s classes | SLO-7 input |
| `controld_querychoke_render_refusals_total` | counter | — | render-invariant violations ("cannot happen if boot validation is correct", 05 §6.2) | **any nonzero pages** (A-05 family) — a structural assumption broke |
| `controld_querychoke_queue_wait_seconds` / `saturation` | histogram / gauge | — | semaphore wait (8 concurrent/pod) and occupancy | capacity trigger before user-visible 503s |
| `controld_pg_pool_wait_seconds` / `controld_pg_pool_conns` | histogram / gauge | `pool` ∈ {app, worker} (2) | pgx pool acquire wait and occupancy | **pool saturation** — acquire p99 near the 2 s budget (05 §8.3) pages before requests start dying |

### 4.3 Stores

- **ClickHouse** exposes its native Prometheus endpoint (wired in `09`), scraped by the same annotation convention. The series that matter operationally: `ClickHouseAsyncMetrics_AsyncInsertQueueSize` (**async-insert queue depth** — the `wait_for_async_insert=1` backpressure precursor), `ClickHouseMetrics_DelayedInserts` and parts-count per table (merge pressure), disk free (RB-2 fires from it). Application-side truth remains `controld_ingest_ch_project_*` — when the two disagree, the writer's view wins for paging.
- **Postgres (RDS)** is watched via the estate's existing CloudWatch/RDS integration (`09`); the application-side signals above (`pg_pool_*`, per-query 5 s timeouts) are the paging surface because they measure what requests actually experience.
- **S3/KMS** have no scrape; their health is observed through `s3_land_seconds`/`s3_land_failures_total{cause}` — deliberate: we alert on the promise (acks), not the provider's status page.

### 4.4 `adjudicator-svc` and `mark1-intel` (Python, estate `omium_observability` + service families)

| Metric | Type | Labels (bound) | Measures | Alert relevance |
|---|---|---|---|---|
| `omium_http_*` (both services) | — | estate-standard | request rate/latency/exceptions | the estate's generic HTTP alerts apply as-is (§8 preamble) |
| `adjudicator_verdicts_total` | counter | `verdict` ∈ {satisfied, violated, refused, error} (4) | adjudication throughput by verdict | **adjudication throughput**; `error` fraction ⇒ verifier-substrate trouble, never conflated with `violated` |
| `adjudicator_cert_status` | gauge | `tenant` (bounded) | certificate status as an ordinal: 0 = uncertified, 1 = bootstrapping, 2 = certified | **A-03: any decrease** = certification regression — guarantee-grade reporting for that tenant is now refused |
| `adjudicator_certificates_total` | counter | `status` ∈ {certified, bootstrapping, uncertified} (3) | issuance mix — **the certificate status distribution** | drift toward `uncertified` fleet-wide ⇒ gold-set freshness/size gate failing (C5) |
| `adjudicator_gold_set_size` / `gold_set_age_seconds` | gauge | `tenant` (bounded) | the C5 preconditions, as numbers | below threshold ⇒ certs will honestly degrade; ticket before it happens |
| `adjudicator_ds_identifiability_gate_total` | counter | `outcome` ∈ {passed, refused} (2) | spectral D–S identifiability gate | rising `refused` ⇒ estimation falling back to weighted-majority (by design) |
| `intel_tvo_runs_total` / `intel_tvo_run_seconds` | counter / histogram | `outcome` ∈ {ok, failed} (2) | TVO engine batch runs | failed runs ⇒ stale customer numbers; SLO-6 |
| `intel_report_generation_seconds` | histogram | — | end-to-end report build (queries + render + receipt) | **SLO-6** |
| `intel_coverage_ratio` | gauge | `tenant` (bounded) × `bound` ∈ {lower, upper} (2) | the coverage band, re-exposed from the ledger (§1.3 bridge) | **A-04: lower bound < guarantee floor** — product promise at risk |
| `intel_dropped_billing_events_total` | counter | `tenant` × `reason` (bounded) | ledger-derived `Dropped{}` whose `durability_class` is `billing_grade` | **A-04: any increase pages** — billing-grade loss is a product defect wherever it occurred |
| `intel_policy_compile_total` | counter | `outcome` ∈ {published, rejected} (2) | compiler → publication outcomes | `rejected` = the publish-time decoder caught a compiler bug (P1 context for A-07) |
| `intel_memory_admissions_total` | counter | `outcome` ∈ {admitted, rejected_lcb, rejected_scope} (3) | REMEMBER admission gate | product health, not paging |
| `intel_ope_runs_total` / `intel_corpus_exports_total` | counter | `outcome` (2) | OPE scoring and receipted corpus exports | export failures ⇒ training-plane feed stalls; ticket |

---

## 5. Logging

### 5.1 Conventions

- **Python services** (`adjudicator-svc`, `mark1-intel`): the estate's `configure_logging` discipline verbatim — called in `main.py` *before* config import, JSON lines to stdout, collected by the cluster's log pipeline (`09`; note §12 — that pipeline is itself a gap today).
- **Go** (`controld`, `mark1d`, `mark1` CLI): `log/slog` JSON handler. `controld` → stdout (pod logs); `mark1d` → the local rotating file (§2.4).
- **Rust** (`mark1-proxy`, `cortexd`): `tracing` crate with the JSON subscriber — used strictly as a *structured logger*, no distributed anything, no OTLP layer; the shim logs nothing in the happy path (a 50 ms process writes spill records, not log files).
- **Mandatory fields** on every line: `ts` (RFC 3339), `level`, `service`, `module`, `msg`, plus whichever correlation identifiers are in scope: `tenant_id`, `device_id`, `session_id`, `event_id`, `batch_id`, `bundle_seq`, `template`. The identifiers are §0.3's join keys — a log line without them is a log line that cannot be correlated, which defeats the no-OTel bargain. Code review enforces the field set; the linter enforces JSON-only emission (no `fmt.Println`/`print` escapes — grep gate in `12`).

### 5.2 Levels

| Level | Belongs here | Does not belong here |
|---|---|---|
| `ERROR` | A contract was broken or a fail-closed refusal fired: unlanded batch after retries, boot refusal context, `oauth_contamination`, render refusal, scanner internal failure | Expected client errors (a 401 from an expired token is the system working) |
| `WARN` | Degradation the system absorbed: fail-static to LKG, parse degraded, park entered, cache staleness approaching ceiling, breaker trips | Anything that recurs by design at high rate (per-request warns are ERROR-in-denial or INFO-in-costume) |
| `INFO` | State transitions with operational meaning: boot (with config *names*, never values), bundle applied (seq), enrollment transitions, canary steps, checkpoint published, drain begun/completed | Per-event capture traffic (that is the ledger's job, not the log's) |
| `DEBUG` | Off in production. Enabled per-component via config rollout, never hot-toggled (05 §1.3: no hot reload — a debug toggle that bypasses rollout is a config back door) | — |

### 5.3 The hard rule, and how it is enforced rather than asked for

> **No log line, at any level, in any component, may contain customer code, a file path, a prompt, or a credential.**

Enforcement is structural, in four layers — politeness is not one of them:

1. **Typed logging call sites.** Log helpers take typed fields (`slog.String("batch_id", …)`, counts, enum codes, durations). There is no sanctioned call that interpolates a payload, an error *body*, or request content into `msg`. Upstream error messages that might embed content (S3 SDK errors quoting keys, SQL errors quoting values) are logged as **error codes + our own context**, with the vendor message length-capped and scanner-passed.
2. **The redaction scanner as backstop.** Edge log emission passes through the `mark1-redact` admit axis before hitting disk (§2.4); `controld`'s log path runs the ingest scanner ruleset over assembled lines in the JSON handler. A hit replaces the span with `⟨redacted:class:hash⟩` and increments `admit_quarantine_total`/`scanner_hits_total{class}` — a secret in a log is *detected*, not hoped against.
3. **What the code never holds, the log can never leak.** `controld` holds no customer LLM credentials, no raw code, no prompts, no pre-redaction plaintext (05 §10.2 closing list); the proxy's credentials are `Secret<T>` with no `Debug`/`Display` — a credential in a Rust log line is a *compile error*, and the CI grep gate rejects any impl that would change that.
4. **CI negative tests** (`12`): golden log-capture runs of each service under fixture load, asserting no line matches the path/secret/prompt detectors — the same detectors production uses, so the test and the backstop cannot drift apart.

### 5.4 Sampling and retention

- **No sampling of WARN/ERROR** — they are rare by the level definitions above; if they are not rare, that is the incident.
- INFO on high-frequency paths (per-batch ingest lines) is sampled 1:100 after steady state, always with counters carrying the true totals — logs are for *shape*, metrics are for *count*.
- Retention: edge 7 days local (§2.4); cloud pod logs per the `09` pipeline (target 30 days searchable) — but note the honest current state in §12: until a log pipeline lands, cloud logs are `kubectl logs`-deep and die with the pod. Sized as acceptable for pilot only because every billing-relevant fact lives in the ledger, not the logs.

---

## 6. Health and readiness

### 6.1 The cautionary tale, and the rule it produces

The estate's training plane ran 6/6 pods `Running` with green `/readyz` while being **a complete no-op**: missing Secret keys silently defaulted its DSN to localhost, every dependency connection failed, and readiness — which only asserted "the process is up and serving HTTP" — kept saying yes. The service lied about the only thing anyone asks readiness: *is this thing doing its job?*

The rule that makes this impossible for Mark 1, normative for every component:

> **Readiness asserts the thing the service actually does, not that its process started.** Each readiness contributor must exercise (or verifiably cache, ≤30 s) the dependency required to honor that component's *specific promise*. A component with a missing credential, an unreachable required store, or a default-valued required config MUST be not-ready — and where the estate convention applies, must have refused to boot at all (05 §1.2's crashloop-on-purpose refusals R1–R7: a control plane that would guess its own S3 bucket never gets a listener to probe).

Corollary: a dependency **not** required for the promise MUST NOT be in readiness — over-inclusion inverts failure postures (the worked example is ingest vs ClickHouse, below).

### 6.2 Cloud components

| Component | `/healthz` (liveness) | `/readyz` (traffic-worthiness) | Deliberately excluded from readiness | Why the boundary is there |
|---|---|---|---|---|
| `controld` (per-module contributors, AND-ed; 05 §1.4) | listener up; only deadlock/panic fails it | `ingest`: PG app-pool ping AND cached ≤30 s S3 `HeadBucket` on the ingest bucket. `enroll`/`policydist`: PG ping. `querychoke`: ClickHouse ping. `dprelease`: PG worker-pool ping | **ClickHouse is NOT in ingest readiness.** KMS is not in any readiness (probed at boot R5/R6; signing is queue-buffered) | The ingest promise is "an ack means S3 durability" — S3 and PG (revocation) are that promise; CH is a rebuildable view. CH-in-readiness would turn a degraded ledger view into a fleet-wide capture outage, inverting fail-open. Reports fail separately (querychoke 503s) because *their* promise is CH |
| `adjudicator-svc` | process/event-loop alive | PG ping AND gold-set table readable AND (when cloud judges enabled for any tenant) judge-credential presence *validated against a live no-op call at boot* | ClickHouse (reads via querychoke templates over HTTP — a dependency's dependency is not ours to probe) | The no-op lesson applied: a judge orchestration service whose judge credentials are absent must be not-ready, not quietly issuing `error` verdicts |
| `mark1-intel` | same | PG ping AND (for tvo/report modules) querychoke endpoint reachable AND its DuckDB scratch volume writable | S3 corpus bucket (exporter is a batch job that fails loudly per-run) | Report generation is the user-visible promise; batch exports have their own run-level failure accounting |

Both endpoints are unauthenticated (08 §3.5) and served on the metrics port alongside `/metrics` (05 §1.1 step 9) — probes and scrapes share the surface that has nothing secret on it.

**The readiness-truth test (`12`, per component):** deploy the component with each required Secret key deleted in turn; assert the pod either crashloops (boot refusal) or reports not-ready — **green-with-missing-Secret is a release-blocking failure.** This test exists *because* the training plane proved the failure mode is real in this estate, and it is cheap: it is the same fixture matrix as the boot-refusal tests.

### 6.3 Edge components

No kubelet probes a laptop; edge "readiness" is answered by supervision plus `mark1 status`, with the same truth rule:

| Component | Alive means | Ready means | Enforced by |
|---|---|---|---|
| `mark1d` | pidfile + supervisor state | fabric socket accepting AND spool writable (a probe append/rotate on boot) AND identity loaded. NOT network reachability — capture is fail-open offline by design | boot refusal on spool/custody failure (F-40, F-42); `status` shows degraded subsystems individually |
| `mark1-proxy` | supervise child state | guard registry loaded AND listener bound. A proxy that cannot verify provenance refuses requests (fail-closed) — it is "ready to refuse", which is its promise | guard fail-closed posture (04 §3.5); breaker → fragment revert + receipted bypass |
| `cortexd` | supervise child state | serving MCP with a settled index for the workspace; stale/corrupt ⇒ *refuses per-query* (`M1E-6401/6404`) rather than reporting globally unready | refusal-beats-fabrication (04 §6.3) — per-answer honesty replaces a binary readiness bit |
| `mark1-hookshim` | n/a (transient) | n/a — its "readiness" is the daemon's | absence surfaces in `mark1 doctor` |

The design echo: where Kubernetes readiness is a gate on *traffic*, edge readiness is a gate on *claims* — `mark1 status` never says "capturing" unless events are actually flowing through admission, because it reads the admission counters, not the process table.

---

## 7. SLIs, SLOs and error budgets

Targets are justified against what the product promises, not round numbers. Two structural facts shape every choice: **(a)** the edge spool (≈2 GiB, block-on-full for billing-grade) makes the fleet tolerant of *days* of ingest unavailability without data loss — so ingest availability buys freshness, not durability, and does not need heroic nines; **(b)** durability and legality promises are absolute in the design (S3-first ack, fail-closed guard), so their SLOs are zero-tolerance with no error budget — any occurrence is an incident, full stop.

Burn-rate alerting uses the standard multiwindow pairs: **fast burn** = 14.4× budget rate over (5 m and 1 h) → page; **slow burn** = 1× over (6 h and 3 d) → ticket. Zero-tolerance rows alert on occurrence instead.

| # | Surface | SLI (exact query) | SLO | Window | Error budget | Burn alert |
|---|---|---|---|---|---|---|
| SLO-1 | **Ingest availability** | `sum(rate(controld_ingest_requests_total{stage="ack",outcome="ok"}[5m])) / sum(rate(controld_ingest_requests_total{stage="admit",outcome!="client_error"}[5m]))` (client-fault 4xx excluded: a quarantined batch is the system working) | **99.5 %** | 30 d | 3 h 36 m | fast/slow burn on the ratio. WHY 99.5: the spool absorbs outages losslessly; the cost of downtime is ledger freshness and spool disk, not data. 99.9+ would buy nothing the durability design hasn't already bought, at real on-call cost |
| SLO-2 | **Ingest ack latency** | `histogram_quantile(0.99, sum(rate(controld_ingest_ack_seconds_bucket[5m])) by (le))` | **p99 ≤ 800 ms** in ≥99 % of 5-min windows | 30 d | 1 % of windows | fast burn only. WHY 800 ms: 05 §2.7's stated budget — dominated by the S3+KMS PUT that *is* the durability promise; the uploader is async to the agent so this buys throughput headroom, not UX |
| SLO-3 | **Ingest durability, billing-grade classes** | negative SLI: `increase(intel_dropped_billing_events_total[24h])` + the `12` replay-completeness check (every acked `event_id` present in ledger ∪ quarantine within 24 h) | **zero loss post-ack. No budget** | continuous | none | **A-04 on any occurrence.** WHY absolute: customers are billed and TVO is computed from these events; the plan's kill-9 test demands zero billing-grade loss — an SLO below 100 % would license losing money-grade data |
| SLO-4 | **Ledger freshness (CH projection)** | `controld_ingest_ch_project_lag_seconds` | **≤ 60 s p99 of minutes; 99.9 % of minutes ≤ 300 s** | 30 d | 43 m of lag-minutes | page at 300 s for 5 m (05 §8.1's alarm). WHY: reports and canary health signals read the ledger; 60 s keeps "live" surfaces honest while acknowledging projection is deliberately off the ack path |
| SLO-5 | **Bundle distribution freshness** | serving: `controld_policydist_ack_coverage_ratio{channel="stable"}`; latency: time from publication → device ACK, from the ACK ledger | **95 % of 24 h-active devices ACK within 15 m of their channel exposure; coverage ≥ 90 % within 24 h** | 30 d | 5 % of publications | A-09. WHY 15 m: SSE delivers in seconds when connected; the jittered 5-min poll is the correctness path, so 15 m = 3 poll intervals. Tighter would fight laptop lids, not engineering |
| SLO-6 | **Report generation** | `histogram_quantile(0.95, rate(intel_report_generation_seconds_bucket[1h]))` and success ratio of report requests | **p95 ≤ 30 s, 99 % success** | 30 d | 1 % of requests | slow burn → ticket. WHY 30 s: the querychoke report timeout class is 30 s (05 §6.5); a report SLO faster than its query budget would be fiction, slower would mask regressions |
| SLO-7 | **Gate-decision latency (edge)** | `gate_read_seconds` p99 per device (EdgeHealth digests) + `12/gate-latency` CI bench | **p99 ≤ 5 ms locally; shim total ≤ 50 ms** | per release + fleet 7 d | none (budget, not SLO — breach blocks release, not pages) | fleet p99 regression across a release ⇒ A-14 ticket + release investigation. WHY: this budget protects the *developer's* keystroke-to-response feel; it is enforced at CI because prod cannot scrape laptops |
| SLO-8 | **Proxy client-visible impact** | `proxy_added_latency_seconds` p50 per device; `proxy_requests_total{outcome="contaminated"}`; `12` chaos-suite pass | **median ≤ 1 ms; zero client-visible stream regressions; zero contamination. No budget on the zeros** | per release / continuous | none | contamination pages P0 (A-01) on one occurrence. WHY absolute: the frozen Phase-3 gate is literally "zero client-visible streaming regressions under chaos"; the proxy's licence to exist is that the customer cannot tell it is there |
| SLO-9 | **Receipt/witness continuity** | `controld_policydist_tlog_witness_last_success_timestamp`; checkpoint cadence via `checkpoint_pending_leaves` age | **every hour has a witnessed head within 2 h; checkpoints never older than 2× their T-cadence** | continuous | none | A-10 / A-11. WHY: "verify Omium, don't trust Omium" is the sales claim (plan: without the witness "the receipt product is decoration") — a witness gap is a product-integrity incident even though zero packets were dropped |
| SLO-10 | **Enrollment availability** | success ratio on `/enroll/*` excluding IdP-attributable failures (B2 boundary — their outage is not our SLO) | **99 %** | 30 d | 7 h 12 m | slow burn only. WHY lowest: enrollment is rare, retryable, human-in-the-loop; the shed-load policy (05 §8.4) deliberately sacrifices `/start` first |

**Budget policy:** a surface that exhausts its 30 d error budget freezes its feature work in favor of reliability work until back under — the standard discipline, adopted so the SLO table has teeth. Zero-tolerance rows (SLO-3, SLO-8's zeros, SLO-9) skip the budget machinery entirely: one occurrence opens an incident with a postmortem obligation, because each is a broken *promise*, not a missed *target*.

---

## 8. Alerts

Rules ship as PrometheusRule ConfigMaps in the estate's exact staging shape (`omium-gitops/staging/monitoring/omium-alerts.yml`: `expr`/`for`/`labels.severity`/`annotations{summary, description, runbook}`) — but landed in **both** environment trees (§12 gap 1). The estate's generic HTTP rules (`HighHTTPErrorRate`, `HighHTTPLatencyP99`, `UnhandledExceptionsBurst`) apply to the Python services as-is via `omium_http_*`.

**A named caveat before the table:** in the estate today, **Alertmanager is effectively a comment** — kube-prometheus-stack deploys it with `alertmanagerSpec.storage = null` and not a single receiver or route configured anywhere in Terraform or GitOps; staging's carefully-written rules fire into a void, and prod does not even load the rules. **Mark 1 must land a real Alertmanager configuration (receivers, routing tree, on-call escalation) before the Phase 1 gate** — an alert table without a delivery path is documentation cosplay. This is a `09` deliverable; §12 tracks it.

Severities: `page` (wake a human), `ticket` (next business day), `notify-tenant` (customer-facing surface + support loop).

| ID | Alert | Expression (sketch) | Severity | Why it pages (or doesn't) | Runbook |
|---|---|---|---|---|---|
| A-01 | **OAuthContamination** | `increase(proxy oauth_contamination ledger events[5m]) > 0` (via exporter) or `controld` receipt of an `M1E-8002` event | **page, P0, always** | The legal-regime boundary was crossed; the plan makes this a receipted P0 by name. Nothing about this path is rate-limited | RB-5 |
| A-02 | **IngestBacklog** | fast/slow burn on SLO-1 ratio, or `histogram_quantile(0.99, rate(controld_ingest_ack_seconds_bucket[5m])) > 0.8` for 10 m, or fleet `EdgeHealth` parked-batch aggregate rising | page (fast burn) / ticket (slow) | Freshness degrading; durability is not (spools absorb). Pages on fast burn because a full fleet spool eventually blocks developers' billing-grade writers | RB-1 |
| A-03 | **CertificateRegression** | `delta(adjudicator_cert_status{tenant=~".+"}[1h]) < 0` — status regressing toward `uncertified` | ticket + notify-tenant | Does **not** page: nothing is down — but that tenant's verdicts stop gating memory/corpus admission and reports lose guarantee grade, which is a product commitment; customer comms within a business day | RB-8 §context |
| A-04 | **BillingGradeDropOrCoverageFloor** | `increase(intel_dropped_billing_events_total[1h]) > 0` **or** `intel_coverage_ratio{bound="lower"} < <floor>` for 1 h | **page** | The two product-integrity signals (§1.3). A billing-grade `Dropped{}` is SLO-3's zero broken; a sub-floor band means guarantee-grade reporting is being refused for a paying tenant right now | RB-1 / RB-10 |
| A-05 | **StructuralAssumptionBroken** | `increase(controld_ingest_identity_disagreements_total[5m]) > 0` or `increase(controld_querychoke_render_refusals_total[5m]) > 0` | **page, P1** | Each counter is a "cannot happen" made observable: envelope/token disagreement is an attack or edge bug; a render refusal means the boot-validated template invariant failed at runtime | RB-3 §escalation |
| A-06 | **RevocationCacheStale** | `controld_enroll_revocation_cache_age_seconds > 45` for 2 m (warn), `>= 60` (critical) | page at critical | At 60 s the fail-closed ceiling engages and token verification starts refusing fleet-wide (05 §3.4) — correct behavior, but an outage in the making | RB-6 §cache |
| A-07 | **CommandStringReachedEdge** | any ACK with `reject_code="M1E-3005"`: `increase(controld_policydist_acks_total{result="rejected"}[5m]) > 0` refined by reject code | **page, P1** | The policy compiler emitted an executable string past publish-time validation — one occurrence auto-halts the rollout (05 §4.3) and indicts the publish gate | RB-4 |
| A-08 | **GuardDecisionAnomaly** | fleet `GuardDecision{REFUSED}` rate (exporter) > 3× trailing-7-day baseline for 15 m, or `guard_refusals_total{reason="oauth_shape"}` > 0 on provisioned credentials | page | A refusal *spike* means provisioning broke and API-key developers are being 403'd (availability), or a probe is underway (security). Baseline-relative because absolute refusal counts are healthy — refusal is the guard working | RB-5 §anomaly |
| A-09 | **BundleACKLag** | `controld_policydist_ack_coverage_ratio{channel="stable"} < 0.9` for 24 h, or `controld_policydist_rollout_halted == 1` | halted: page; lag: ticket | A halt is the canary controller detecting harm — a human must disposition it (05 §4.3 pages by design). Slow ACK coverage alone is laptops on vacation until proven otherwise | RB-4 / RB-10 |
| A-10 | **WitnessPublicationFailure** | `time() - controld_policydist_tlog_witness_last_success_timestamp > 7200` | **page** | SLO-9: the external-verifiability claim degrades silently otherwise — exactly the class of failure nobody notices until an auditor does | RB-9 |
| A-11 | **ReceiptCadenceBroken** | `checkpoint_pending_leaves` age > 2× checkpoint T-cadence for 30 m; or `mark1 verify-receipts` scheduled run (CI cron) fails | page | Billing-grade events accumulating without checkpoint inclusion = the receipt chain is not advancing; the verifier cron failing means chain integrity itself is in question | RB-8 |
| A-12 | **EpsilonBudgetNearExhaustion** | `controld_dprelease_epsilon_spent / 4.0 > 0.8` (ticket), `> 0.95` (warn ticket + notify-tenant) | ticket, never page | Releases are days-latency and exhaustion **refuses safely** (05 §5.6) — nothing degrades, publication just stops. Paging would train responders that pages are ignorable | RB-7 |
| A-13 | **SecretNearMiss** | `increase(controld_ingest_scanner_hits_total[1h]) > 0` or `increase(controld_ingest_quarantines_total[1h]) > 0` | ticket + notify-tenant | Fail-closed already contained it (quarantine prefix, never replayed); the follow-up is tenant hygiene + edge-ruleset gap analysis, not a 3am fix | RB-3 §quarantine |
| A-14 | **EdgeFleetRegression** | across a release cohort (exporter, by `edge_version`): crash-restarts, `Dropped{}` rate, gate p99, or spill rate > 2σ vs prior version's trailing baseline | page during rollout window, ticket after | The edge cannot be scraped, so release health is judged from `EdgeHealth` + ledger deltas cohort-vs-cohort — the same statistical shape as the bundle canary (05 §4.3), applied to binaries | RB-10 |
| A-15 | **ChokeSaturation / PoolSaturation** | `controld_querychoke_queue_wait_seconds` p99 > 2 s for 10 m; `controld_pg_pool_wait_seconds{pool="app"}` p99 > 1 s for 10 m | ticket (page if coinciding with SLO-1 burn) | Capacity signals with clear scaling levers (05 §8.5); they precede user-visible failure, so they should precede a page too | RB-1 §capacity |

Unusual-for-infra rows worth flagging to future responders: A-01, A-03, A-04, A-07, A-10 and A-12 alert on **product-integrity and legality invariants**, not on resource exhaustion — several fire precisely when the system is *refusing correctly* (A-12, quarantines in A-13). The runbooks below therefore say "confirm the refusal is right" before they say "make it stop."

---

## 9. Runbooks

Hosted alongside these docs; the `runbook:` annotation on every rule links here. Conventions: `$OP` = an operator token; ops-scope ledger reads go through the querychoke ops templates (there is **no** raw ClickHouse access at the application layer — SRE break-glass onto the CH pod exists at the infra layer and every use of it is incident-logged). All `kubectl` in namespace `omium` unless noted.

### RB-1 — Ingest backlog

**Symptom:** A-02 — ack p99 breaching, SLO-1 burn, or fleet parked-batch count rising in the tenant-health dashboard.
**Diagnose, in dependency order (the pipeline funnel tells you which stage):**
```bash
kubectl top pods -l app=controld
curl -s controld:9092/metrics | grep -E 'controld_ingest_requests_total|ack_seconds_bucket|s3_land'
# stage funnel: where do counts drop? admit≫ack ⇒ mid-pipeline; shed>0 ⇒ pool saturation (05 §2.4)
curl -s controld:9092/metrics | grep controld_pg_pool_wait   # revocation-cache/PG stall?
aws s3api head-bucket --bucket mark1-ingest-prod             # R6's probe, by hand
aws cloudwatch get-metric-statistics --namespace AWS/KMS ... # KMS throttling? (per-tenant blast radius)
kubectl logs deploy/controld --since=15m | jq -c 'select(.level=="ERROR")' | head -50
```
**Remediate:** S3/KMS throttle ⇒ request quota raise, do nothing else — the system is behaving (no false acks; edges parked losslessly). Pool saturation with healthy stores ⇒ scale: `kubectl scale deploy/controld --replicas=3` (HPA is on the ack SLI, 05 §8.5 — check why it didn't act). One-device flood ⇒ check `duplicates/accepted` ratio per device (dupe-flood row, 05 §9); rate limits are already throttling it; revoke if malicious.
**Verify recovery:** ack p99 back under 800 ms; fleet `spool_oldest_unacked_age_seconds` falling; `uplink_parked` aggregate → 0.
**Escalate:** backlog growing with all stores healthy and CPU idle ⇒ a pipeline-stage bug; page the ingest owner with the stage funnel snapshot. Remember the floor rule: never "fix" a backlog by touching anything that could shed billing-grade classes — there is no such lever on the server by design (05 §2.4), and finding one means filing a P1 against the design.

### RB-2 — ClickHouse full or unavailable

**Symptom:** SLO-4 lag alert; `querychoke` readiness contributor down; report endpoints 503ing. **Ingest keeps acking — that is correct** (05 §1.4); do not treat this as a capture outage.
**Diagnose:**
```bash
curl -s controld:9092/metrics | grep -E 'ch_project_lag_seconds|ch_project_failures'
kubectl -n omium exec sts/clickhouse -- clickhouse-client -q "SELECT free_space, total_space FROM system.disks"   # infra break-glass, incident-logged
kubectl -n omium exec sts/clickhouse -- clickhouse-client -q "SELECT count() FROM system.parts WHERE table='m1p_events' AND active"  # part explosion?
curl -s clickhouse:9363/metrics | grep AsyncInsertQueueSize
```
**Remediate:** *Full disk:* expand the volume (`09`'s procedure) — never delete parts by hand; if pressure is TTL-related, the TTL DDL change goes through `07`+migration, not a live `ALTER`. *Down/unreachable:* restart/recover per `09`; then the projector self-heals — it resumes from its Postgres cursor and replays landing objects (05 §2.5): `kubectl exec deploy/controld -- /controld ingest-replay --from=<lag-start> --tenants=all`. Nothing is re-requested from edges; nothing was lost — the S3 prefix **is** the replay log.
**Verify:** `ch_project_lag_seconds` draining; post-heal, run the `12` replay-completeness check (ledger row count == landed `event_id` count for the window).
**Escalate:** rebuild-from-S3 (total loss) is the ADR-0001 documented path — hours of replay, ledger reads stale meanwhile, reports carry a freshness banner; page the data owner before starting.

### RB-3 — Poison batch

**Symptom:** `controld_ingest_ch_project_failures_total` climbing then plateauing (3-strikes park, 05 §9); a dead-letter row; possibly A-05 if the poison is an invariant violation.
**Diagnose:**
```bash
psql -c "SELECT batch_id, tenant_id, attempts, last_error FROM ingest_dead_letter ORDER BY parked_at DESC LIMIT 10"
aws s3 cp s3://mark1-ingest-prod/t/$TENANT/ingest/v1/dt=$DT/$BATCH_ID.m1p.zst /tmp/  # the batch IS the landing object
zstd -d /tmp/$BATCH_ID.m1p.zst && m1p-decode --stats /tmp/$BATCH_ID.m1p               # the conformance decoder tool
```
**Remediate:** the ack already happened and the data is durable — this is a projector bug, not data loss. Fix the projector (usually an unhandled event-shape from a newer edge; check `edge_version` on the batch), deploy, then `ingest-replay --batch=$BATCH_ID`. Idempotency makes re-projection safe.
**Verify:** dead-letter row cleared; the batch's `event_id`s present via the `usage_by_session` template; tenant's coverage accounting no longer flags the hole.
**Escalate:** if the payload is *hostile* (crafted to crash the decoder) rather than merely new: security incident — the fuzz corpus gains the sample, the device gets scrutiny (revoke if warranted), and the decoder fix ships as a security release. Quarantine-release requests (A-13 follow-up) require the tenant's direction, per 05 §2.3 — never release a flagged batch unilaterally.

### RB-4 — Bundle rollback

**Symptom:** A-09 rollout halted (automatic), A-07 (command string — halt already fired), or a human decision that a live bundle is bad (gate misbehavior reports, verdict quality drop).
**Diagnose:**
```bash
psql -c "SELECT channel, seq, result, reject_code, count(*) FROM bundle_acks WHERE tenant_id=$T GROUP BY 1,2,3,4 ORDER BY seq DESC"
psql -c "SELECT * FROM canary_state WHERE tenant_id=$T"           # exposure %, halt reason
# health-signal deltas the controller saw (the three fixed templates, 05 §4.3):
curl -s -H "Authorization: Bearer $OP" "https://api.mark1.omium.ai/ops/canary_signals?tenant=$T&seq=$SEQ"
```
**Remediate:** **rollback = publish the previous content at seq+1** — there is no unpublish verb anywhere (05 §4.6):
```bash
mark1-intel policy republish --tenant $T --channel stable --content-of-seq $((SEQ-1))
# → signs, tlog-appends, receipts, and serves as seq+1; stragglers converge naturally
```
Then watch ACKs converge: `controld_policydist_ack_coverage_ratio` on the new seq. Do **not** clear the halt until the bad seq's cohort is re-covered.
**Verify:** health-signal deltas back to baseline for two evaluation ticks; the halted gauge cleared by the controller itself.
**Escalate:** A-07 (command string) additionally means the *publish-time* validator missed what the edge decoder caught — file P1 on the compiler AND the publish gate; the transparency log retains the bad bundle as evidence by design (05 §4.6 point 3), so the postmortem cites `tlog` leaf indexes, not screenshots.

### RB-5 — `oauth_contamination` P0

**Symptom:** A-01. The proxy already acted: session killed, base-URL fragment rolled back (traffic now bypasses the proxy), per-event receipt written (04 §3.1 step 6).
**First 15 minutes:**
```bash
# 1. Confirm containment — the receipted event names device, session, timestamps:
curl -s -H "Authorization: Bearer $OP" "https://api.mark1.omium.ai/ops/guard_events?class=oauth_contamination&since=24h"
# 2. Confirm the rollback took: the device's next EdgeHealth shows proxy detached;
#    fleet check that this is ONE device, not a pattern:
curl -s -H "Authorization: Bearer $OP" "https://api.mark1.omium.ai/ops/guard_events?class=refused&reason=oauth_shape&since=24h"
# 3. Freeze the blast radius while diagnosing: disable proxy provisioning fleet-wide
#    via the gates section (open-direction change — allowed without opt-in, 04 §2.6):
mark1-intel policy republish --channel stable --set gates.proxy_enabled=false
```
**Diagnose:** how did an OAuth credential get provisioned as `apikey`? The chain to audit: adapter `Detect()` output → provisioning fragment → fingerprint registration (05 §3.6) → guard shape-tripwire (why did step 5 pass?). One of those four lied; the receipts and `GuardDecision` samples localize which.
**Remediate:** fix the detection/provisioning bug; re-run the token-shape canary corpus against the fix; re-enable proxy provisioning only after the `12` canary is green.
**Escalate & disclose:** this is the plan's named P0. Founder + counsel notified same-day; the receipted event chain is the disclosure artifact (what was intercepted, for how long, what was captured — the tee field allow-list bounds the answer). The weekly token-shape canary gains the offending shape permanently.

### RB-6 — Device-revocation emergency

**Symptom:** tenant reports a stolen laptop / compromised device token; or A-08 anomaly attribution points at one device.
**Act first, diagnose second (fail-closed class):**
```bash
curl -s -X POST -H "Authorization: Bearer $OP" \
  "https://api.mark1.omium.ai/enroll/devices/$DEVICE_ID/revoke" -d '{"reason":"compromise"}'
# propagation: ≤60 s to hard cutoff at every controld instance; SSE push is immediate for connected edges
watch 'curl -s controld:9092/metrics | grep controld_enroll_revocation_cache_age_seconds'
```
**Verify cutoff:** attempted uploads from the device now 403 `M1E-1003` (`controld_ingest_auth_failures_total{reason="revoked"}` ticks); the device row's `last_seen_at` freezes.
**Assess exposure — the receipts answer it exactly:** everything the device ever uploaded is enumerable (`device_id` on every event, chain attribution per 04 §9.3); the ≤24 h token ceiling bounds the worst case even if revocation had failed entirely. Confirm the edge-side fail-closed actions occurred when the device next connects: memory-artifact cache purged, uplink stopped (04 §2.9 `OnRevoked`).
**Cache stale during the emergency (A-06 co-firing):** the system is failing closed — fleet-wide 401s until the cache refreshes. That is the designed trade; fix the PG connectivity behind the cache rather than loosening the ceiling. **There is no override to serve stale revocation state.**
**Escalate:** if the compromised device uploaded poisoned data, its events are identifiable by `device_id` for ledger annotation; re-enrollment mints a fresh identity — never "un-revoke."

### RB-7 — ε budget exhausted

**Symptom:** A-12 at 95 %+, or a release parked `blocked_epsilon` (05 §5.6).
**Confirm the refusal is right (it almost certainly is):**
```bash
curl -s -H "Authorization: Bearer $TENANT_TOKEN" "https://api.mark1.omium.ai/federation/epsilon"
psql -c "SELECT tenant_id, sum(epsilon) FROM epsilon_ledger WHERE ts > date_trunc('year', now()) GROUP BY 1 ORDER BY 2 DESC"
psql -c "SELECT candidate_id, state, blocking_tenants FROM review_queue WHERE state='blocked_epsilon'"
```
**Remediate — the only three levers, all human:** (1) wait for the calendar-window boundary; (2) contractual budget raise with the binding tenant's consent — a commercial conversation, not a config change; (3) let the candidate expire (14 d). **Never:** re-parameterize noise to "fit", drop the binding tenant from the cluster (side channel — 05 §5.6 names it), or backdate ledger entries (append-only trigger will refuse, and should).
**Escalate:** if spend reached budget far faster than modeled, audit release cadence vs the ε_release=0.25 default before raising anything — a runaway *caller* is the likelier bug than a wrong *budget*.

### RB-8 — Receipt chain fails verification

**Symptom:** A-11 (verifier cron red), or a customer's own `mark1 verify-receipts` reports a defect. **Treat as P1 product-integrity until proven benign.**
**Diagnose — the verifier names the defect kind and the first bad seq (estate `verify_chain` discipline: five defect kinds + `intact_prefix_seq`/`last_good_seq`):**
```bash
mark1 verify-receipts --tenant $T --from $DATE --against-witness --json | jq '{defect, at_seq, intact_prefix_seq, last_good_seq}'
psql -c "SELECT seq, checkpoint_seq, key_id, created_at FROM effect_receipts WHERE tenant_id=$T AND seq BETWEEN $((BAD-2)) AND $((BAD+2))"
```
**Interpret by defect class:** *bad signature at one seq* ⇒ key-rotation window bug — check the key manifest's validity windows against the receipt's `key_id` (a verification bug, chain intact). *Hash-chain break* ⇒ storage corruption or tampering — compare against the witnessed head for that hour: **if the witness matches our head, the corruption is local and restorable from backup; if the witness disagrees, our stored history diverged after witnessing — the tamper-evidence design is now evidence, and this is a declared security incident.** *Gap in seq* ⇒ the append-only guarantees failed — check the `test_append_only_receipts` trigger set is still installed (a dropped trigger is itself the finding).
**Remediate:** restore the affected range from PG backup + re-verify; the chain is never rewritten forward — a repaired range must re-verify against the *already-witnessed* heads or the incident stands.
**Escalate:** witness-mismatch ⇒ founder + counsel same-day, customer disclosure per contract; the standalone verifier's offline result is the shared ground truth with the customer — that symmetry is the product working as sold.

### RB-9 — Witness publication failure

**Symptom:** A-10 (>2 h since a witnessed head).
**Diagnose:**
```bash
kubectl logs deploy/controld --since=3h | jq -c 'select(.module=="policydist.tlog")'
aws s3 ls s3://mark1-witness-prod/witness/heads/ --recursive | tail -5     # our side
# customer-side object-lock buckets: check the per-tenant publisher results table
psql -c "SELECT target, last_success, last_error FROM witness_targets ORDER BY last_success ASC"
```
**Interpret:** publication is a background loop, cursor-resumable (05 §1.5) — a gap **delays** witnessing but the log itself is intact and heads for missed hours publish retroactively with their original timestamps in the leaf data. The integrity property degraded during the gap is *external verifiability of recency*, not chain correctness.
**Remediate:** fix the failing target (bucket policy drift, expired customer-bucket credentials, object-lock misconfig); the loop back-fills on next success. Verify: `mark1 verify-receipts --against-witness` passes over the gap window.
**Escalate:** if only *one customer's* witness bucket fails ⇒ notify that customer (their auditors rely on it); if *our* transparency-log endpoint is also down, bundle publication has already halted by design (05 §9: never servable before logged) — coordinate with RB-4 context and treat as a control-plane incident.

### RB-10 — Edge fleet on a bad release

**Symptom:** A-14 — the new `edge_version` cohort shows regression (crash rate, `Dropped{}`, gate p99, spill rate) vs the prior version's baseline.
**Diagnose:**
```bash
curl -s -H "Authorization: Bearer $OP" "https://api.mark1.omium.ai/ops/fleet_health?group_by=edge_version&window=24h"
# → per-version: devices, restarts, dropped by (reason,durability_class), gate p99 digest, spool ages
curl -s -H "Authorization: Bearer $OP" "https://api.mark1.omium.ai/ops/coverage_transitions?since=24h&reason=proxy_failed"
```
**Remediate, in preference order:** (1) **If the defect is behavioral and bundle-addressable** (a bad field map, an over-aggressive gate threshold): push a corrective bundle — minutes to fleet, no binary involved (the maps-as-data design exists for this, 04 §5.4). (2) **If binary:** halt the release channel's rollout, publish the prior binary as the current release on the update channel; edges converge on their update cadence. There is no forced remote downgrade — Mark 1 does not have remote-exec on developer machines *on purpose*; convergence latency is the price of that boundary. (3) **Meanwhile, protect the developers:** if the regression is in the gate path, ship a bundle with `gates` opened (the closed→open direction needs no tenant opt-in, 04 §2.6) so no developer is blocked by a buggy gate while binaries roll back.
**Verify:** cohort deltas re-converge to baseline; `CoverageTransition` bypass windows from crash-looping components close; spool ages normalize.
**Escalate:** if billing-grade `Dropped{}` occurred on the bad version (A-04 co-fired), the affected tenants' coverage bands already reflect it honestly — customer comms lead with that fact; it is the difference between "we lost data" and "we can show you exactly what a bug cost, to the event" (§10).

---

## 10. `Dropped{}` and coverage as first-class product telemetry

### 10.1 Why loss accounting is a product feature

Mark 1 sells **numbers** — TVO, waste taxonomies, intervention savings — and a number computed over an unknown fraction of the truth is marketing, not measurement. The competitive claim is not "we never lose an event" (nothing distributed can claim that honestly); it is "**every loss is counted, attributed, and priced into every number we quote.**" That converts loss from a liability into evidence quality — the same move the receipt chain makes for integrity.

Hence the design stance repeated across 04/05: *silence is the one failure the ledger cannot price* (04 §2.4). Every shed, CRC loss, quarantine, spill expiry, and parse degradation anywhere on the edge emits `Dropped{reason, durability_class, quantity}` into the next batch; every capture-affecting state change routes through the single coverage door and emits a receipted `CoverageTransition` (04 §2.7). The two channels are exhaustive by construction: a gap is either *counted* (`Dropped{}` — we know exactly how many) or *windowed* (`CoverageTransition` — we know exactly when and why, and estimate how many). There is no third category, and `12`'s chaos suites exist to prove each failure row lands in one of the two.

### 10.2 The arithmetic

For a tenant, a report window, and the **billing-grade durability class** (the class, not one event family — `Dropped{}` carries the class, so this is the finest grain the counted term can honestly be computed at; see 07 §3):

```
observed   = count of billing-grade ledger events        (exact, from ClickHouse)
counted    = Σ Dropped.quantity where                    (exact — the events are gone,
             durability_class = BILLING_GRADE             their COUNT is not)
             over the window
windowed   = Σ open/closed bypass-window durations       (exact durations, unknown volumes)
             from CoverageTransition receipts

rate_est   = tenant's per-active-hour billing-grade event rate, from the
             surrounding 14 days, with an interquartile spread [r_lo, r_hi]

est_lo     = Σ window_hours × r_lo         est_hi = Σ window_hours × r_hi

coverage_lower = observed / (observed + counted + est_hi)
coverage_upper = observed / (observed + counted + est_lo)
```

**Worked example.** Window: 30 days. `observed` = 1,000,000 billing-grade events. `counted` = 120 (a CRC-loss incident, `Dropped{CRC_LOSS, BILLING_GRADE, 120}`). `windowed` = 3.2 h of bypass (one `proxy_failed` window, one `disk_hard_stop`) against 400 active hours; rate estimate 2,300 events/h, spread [1,900, 2,700]:

```
est_lo = 3.2 × 1,900 = 6,080        est_hi = 3.2 × 2,700 = 8,640
coverage_lower = 1,000,000 / 1,008,760 = 99.13 %
coverage_upper = 1,000,000 / 1,006,200 = 99.38 %
→ coverage band = [99.1 %, 99.4 %]
```

The band is computed server-side (`mark1-intel.tvo-engine`, via the `coverage_band` template) — the edge's only duty is the narrow, total one: *no capture-affecting state change without a transition event* (04 §2.7).

### 10.3 How the band gates reporting

- **Every number carries its band. A number is never quoted without it.** `mark1 report`, the dashboard, and the corpus exporter all render `TVO: 41.2k tokens/verified-outcome (coverage 99.1–99.4 %)`. The rendering layer has no code path for a bandless number — the report template's schema makes the band field required, which is enforcement by construction, not editorial policy.
- **The guarantee floor.** Below the floor (bundle-configurable; default 95 % on the *lower* bound), guarantee-grade issuance is **refused** (`M1E-5004`): the report still renders, watermarked `indicative — coverage below guarantee floor`, and is excluded from anything contractual (the $-backed claims, the AIOS demo numbers). The refusal is the feature: a vendor that keeps quoting confident numbers through a coverage hole is exactly the vendor the receipt product exists to displace.
- **Downstream gates inherit the discipline:** noise-cert issuance and corpus admission already refuse `uncertified` inputs (C5); coverage-sub-floor windows likewise taint the *denominator* classes (`task_seg` closes tasks `unresolved`, never silently excludes them — 04 §9.2), so the flywheel's training data is band-honest too.

### 10.4 What the customer sees

In `mark1 status` (live): open bypass windows and the running `Dropped{}` counters — the developer sees a coverage hole *as it happens*, attributably (`reason_code`, duration so far). In reports: the band, the floor verdict, and the loss ledger — a table of `(reason, durability_class, quantity | window, duration)` for the period, each row traceable to receipted events. Nothing about loss is Omium-private: the customer's offline verifier can recompute the band from their receipt chain's `Dropped{}` and `CoverageTransition` leaves, which is what makes the coverage claim *verifiable* rather than asserted — the same trust conversion the witness performs for integrity, applied to completeness.

---

## 11. Dashboards

Three dashboards, three audiences, and a rule inherited from the metric split (§1): Grafana panels read Prometheus only; customer-facing numbers come from querychoke templates only. A number that appears on both (the coverage band) flows ledger → exporter → Grafana for ops, and ledger → template → product surface for the customer — same source of truth, two renderings, never a Grafana screenshot in a customer deck.

### 11.1 Internal ops (Grafana, on-call's home)

| Panel group | Panels | Decision each supports |
|---|---|---|
| SLO header | SLO-1/2/4/5 current + budget-remaining gauges | "are we burning budget; do I need to act before the pager does" |
| Ingest funnel | stage-by-stage `requests_total` Sankey; `ack_seconds` heatmap; `s3_land_seconds`; quarantine + identity-disagreement counters | localize a backlog to a stage (RB-1's first question, pre-answered) |
| Ledger health | `ch_project_lag_seconds`, dead-letter depth, CH async-insert queue, parts count, disk | RB-2/RB-3 trigger and progress |
| Fleet (from `EdgeHealth` via exporter) | devices by `edge_version`; crash-restarts, spool ages, parked/quarantined, gate p99 digests — cohort-compared | release go/widen/rollback (A-14, RB-10) |
| Policy plane | ACK coverage per seq, rollout/halt state, canary health-signal deltas, tlog witness age | RB-4's disposition; A-10 watch |
| Identity | revocation cache age, enrollment funnel, sweep heartbeat, per-device anomaly flags | A-06/RB-6 |
| Capacity | pool waits, choke saturation, SSE connections, per-pod ev/s vs the 40 % trigger | scale-out decisions (05 §8.5) |

### 11.2 Per-tenant health (internal, support + account owners)

Per-tenant: coverage band trend vs floor; `Dropped{}` by (reason, durability_class); cert status (`adjudicator_cert_status`) and gold-set freshness; ε spent vs budget; device fleet (last-seen, versions, open bypass windows); quarantine events awaiting tenant triage. Decision supported: "is this tenant's *product* healthy" — distinct from "is our infra healthy," because a tenant can be fully degraded (uncertified, sub-floor coverage) while every ops panel is green. This dashboard is the account owner's pre-QBR read and the support engineer's first stop on any ticket.

### 11.3 Customer-facing TVO view (product surface, not Grafana)

Served by the dashboard/`mark1 report` from querychoke templates; every number band-annotated (§10.3). Panels: TVO trend with coverage band; waste taxonomy breakdown (retry-loop / re-exploration / over-model tokens); interventions and their measured savings; certification status with plain-language meaning ("numbers below are guarantee-grade" / "bootstrapping — indicative only"); the loss ledger (§10.4); receipt-verification status (last `verify-receipts` result, witness continuity).

**Customer-visible:** everything above, scoped to their tenancy, plus their ε ledger (`GET /federation/epsilon`) and their device list. **Never customer-visible:** any other tenant's anything (structurally — querychoke's `TenantID` construction, 05 §6), Omium's internal ops metrics (latency internals, capacity, fleet-wide aggregates), other tenants' contribution to federation candidates, and raw `GuardDecision` streams (their own sampled refusal receipts are visible; the fleet baseline that contextualizes anomalies is not).

---

## 12. Gaps — what Mark 1 must land before the Phase 1 gate

Honest inventory, estate-verified 2026-08-28. Each row is a deliverable with a home; none is inherited-by-default.

| # | Gap (verified where) | Consequence if inherited silently | Mark 1 must land |
|---|---|---|---|
| G-1 | **Prod has no monitoring kustomization.** `omium-gitops/staging/monitoring/` exists (alert-rule ConfigMaps, pushgateway, cronjob); `omium-gitops/prod/kustomization.yaml` has no monitoring entry at all | Mark 1's alert rules would exist only where nothing important runs — the estate's exact current state | The `monitoring/` tree in **both** env overlays, prod first; §8's rules ship in it. `09` owns the wiring; `12` gates the deploy on `promtool check rules` passing in CI |
| G-2 | **Alertmanager is unconfigured** — deployed by kube-prometheus-stack with `alertmanagerSpec.storage = null` and zero receivers/routes anywhere in Terraform or GitOps (§8 caveat) | Every alert in §8 fires into a void; the on-call rotation is a Slack habit, not a system | A real Alertmanager config: receiver(s), routing tree keyed on `severity`, escalation, silence discipline. Phase 1 gate blocker — the ingest durability promise is only as good as A-04's delivery path |
| G-3 | **Annotation scraping is not verified against the deployed Prometheus.** The estate sets `prometheus.io/*` annotations everywhere, but kube-prometheus-stack does not honor those annotations out of the box and the Terraform module shows no `additionalScrapeConfigs`; a separate hand-rolled `prometheus.yml` with `kubernetes_sd_configs` exists in `Omium-platform/monitoring/` — two Prometheis, unclear which (if either) actually scrapes prod pods | Mark 1 could annotate perfectly and be scraped by nothing — a monitoring no-op with green dashboards, the training-plane failure shape at the observability layer | `09` must verify the live scrape path and, if absent, add the annotation-based scrape job (`additionalScrapeConfigs`) to the stack. `12` adds a smoke test: after deploy, assert `controld_ingest_requests_total` is queryable in Prometheus — readiness-truth applied to monitoring itself |
| G-4 | **No log pipeline.** Loki/log aggregation explicitly deferred in the observability module's own comment; cloud logs are `kubectl logs`-deep and die with the pod | RB diagnosis steps that grep controld logs stop working after any pod churn; §5.4's 30-day target is aspirational | Acceptable for pilot **only** with eyes open (every billing fact is in the ledger, not logs); a minimal Loki (or CloudWatch Logs shipping, whichever `09` costs cheaper) lands by Phase 3 when the proxy's guard events make log forensics load-bearing |
| G-5 | **The `EdgeHealth` event family is not in the frozen event list** — *closed*: `07` §3 ratified it as `Event.body` field 22 (§2.3) | Fleet observability of laptops has no vehicle; A-14/RB-10 have no data | Remaining: the privacy field-set test is now specified as `conf_schema_closed_field_set` (`12` §3.6) and lands in Phase 1 with the emitter — the closed-field-set assertion is what keeps the ratification from widening by accretion, and until it runs, §2.3's privacy rule is a review convention rather than a control |
| G-6 | **Ledger→Prometheus exporter (§1.3) is new code with no estate precedent** | A-03/A-04/A-08/A-14 — the product-integrity alerts — have no metric to fire on | The exporter loop in `mark1-intel` ships in Phase 1 with the TVO engine; it is ~a template evaluation on a timer, but it is on the critical path of the alert table and must not slip to "later" |
| G-7 | **Runbook hosting.** The estate's staging rules link `https://docs.omium.ai/runbooks/*` — targets unverified, likely dead; §9's runbooks live in this repo | Pager links 404 at 3am | Runbook URLs in §8's annotations point at this document's anchors in the repo host; a link-check runs in docs CI |
| G-8 | **No SLO tooling.** The estate has alert rules but no error-budget accounting anywhere | §7's budget policy is unenforceable arithmetic | Recording rules for each SLI + budget-remaining gauges ship with G-1's rule tree; Grafana's SLO panels (§11.1) read them. No new system — recording rules suffice at pilot scale |

The one-line summary the gate reviewer needs: **the estate's observability is rules without a pager, staging without prod, and scrape-by-convention without a verified scraper — Mark 1 inherits the conventions, not the gaps, and G-1/G-2/G-3/G-6 are Phase 1 blockers because §7's promises are unenforceable without them.**

---

*End of 11 — Observability, SLOs and Operations. Components and budgets: `04`, `05`, `06`. Infrastructure wiring: `09`. Every test named here: `12`. Ledger schemas behind the exporter and templates: `07`.*
