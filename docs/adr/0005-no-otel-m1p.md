# ADR-0005 — No OpenTelemetry anywhere; M1P is the capture fabric

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap today, expensive later — today no OTel exists to remove and no M1P exists to protect; after Phase 1 the ledger, the receipts, the spool format, and the billing pipeline are all keyed to M1P identities, and re-platforming onto OTel would mean rebuilding the billing-grade delivery guarantees OTel does not natively provide
- **Blocks:** nothing — this ADR records a decision already made (the founder rejected plan v1 partly for using OpenTelemetry); it exists so the decision survives the people who remember the argument

## Context

Plan v1 proposed OpenTelemetry as the primary token source. The founder rejected it, and plan v2 is explicit: "a proprietary capture fabric (M1P) and **zero OpenTelemetry anywhere**." This ADR records *why*, because "the founder said so" does not survive a hiring cycle, and the first engineer who reaches for `tracing-opentelemetry` deserves a real answer.

The reasons are structural, not aesthetic:

1. **Token accounting is billing-grade.** Every number Mark 1 quotes to a customer — TVO, coverage bands, the invoice-adjacent usage ledger — derives from `Usage` events. Billing-grade data needs **at-least-once delivery with idempotent dedupe on an application-meaningful key** (`event_id` = UUIDv7 = spool cursor = server dedupe key = ClickHouse ordering component; `idem_key = HMAC_tenant(session_id, message.id, request_id)` as a protocol invariant against the verified ~2.5× streaming overcount). A sampled tracing fabric structurally does not provide this: OTel SDKs shed spans on queue pressure *by design*, samplers are a first-class feature, and exporter delivery is best-effort. You can fight the SDK into reliable delivery, but then you are maintaining a fork of its semantics while carrying all of its surface.
2. **The edge runs on customer laptops, where the dependency surface is a security property.** Mark 1's binaries live on developer machines inside enterprises that will audit them. Binary size, transitive dependency count, and — above all — **egress ambiguity** are procurement questions. An OTel SDK is a large dependency tree whose whole purpose is configurable egress to arbitrary collectors; explaining to a customer's security team that the telemetry library in our binary cannot phone anywhere but our ingest endpoint is a harder conversation than the library not existing. M1P has exactly one destination (`POST /m1p/v1/ingest`), one wire format, and a dependency tree we chose line by line.
3. **`Dropped{}` must be a first-class protocol citizen.** Coverage bands — the honesty mechanism of every TVO report — depend on knowing what was *not* captured: every shed event, CRC loss, or quarantine emits `Dropped{reason, durability_class, quantity}` in the next batch. In OTel, dropped spans are normal and invisible by design; the protocol has no vocabulary for "here is an accounting of what I did not send you," and coverage accounting built on it would be an out-of-band bolt-on.

**The cost of this decision today is genuinely zero.** The estate scan (plan appendix, grounding facts) verified: the only OTel usage anywhere is in `omium-training-plane`, optional and fail-soft (activated by `OTEL_EXPORTER_OTLP_ENDPOINT`), plus a platform OTLP *ingest* endpoint; **no collector is deployed anywhere**, and the observability module explicitly defers logs/traces. There is no investment to abandon, no dashboards to migrate, no team muscle memory to fight.

## Decision

1. **M1P (`m1p.v1`, protobuf, Buf-governed) is the only capture and telemetry fabric**, edge and cloud: typed event families, UUIDv7 `event_id` + per-session monotonic `seq`, at-least-once HTTPS transport with idempotent upsert, M1PL local framing over UDS, per-class spool durability (ADR-0007), and `Dropped{}` accounting as a protocol citizen.
2. **No component may depend on OpenTelemetry, directly or transitively.** Not the SDK, not the API crate, not an OTLP exporter, in any of the three languages.
3. **Correlation replaces trace propagation:** `session_id` / `event_id` / `seq` are the join keys, per `11-observability-and-slo.md`. Self-monitoring is the internal metrics catalog + Prometheus pod-annotation scraping (the estate convention — no ServiceMonitor objects, no OTLP), and `Dropped{}`/coverage accounting is treated as first-class product telemetry, not ops noise.
4. **Mechanical enforcement**, because a rule without a gate rots:
   - Rust: `cargo-deny` `bans` list rejects `opentelemetry*`, `tracing-opentelemetry`, and `opentelemetry-otlp` in any workspace dependency graph.
   - Go: a CI step fails if `go mod graph` for any module matches `go.opentelemetry.io/`.
   - Python: the `uv` lockfile audit fails on any `opentelemetry-*` distribution.
   - Docs: the design-phase verification line "No document references OpenTelemetry as a dependency anywhere" carries forward as a repo lint on `docs/`.
   These land in `omium-mark1`'s own CI per `12`/`13` (the estate CI would not catch them — plan appendix delta 4).

## Alternatives considered

### OpenTelemetry with a custom exporter (v1's position, steelmanned)

The strongest case: OTel is the industry-standard instrumentation surface. Mature SDKs in all three of our languages, auto-instrumentation for HTTP/DB clients, context propagation across process boundaries for free, an enormous ecosystem (Jaeger, Tempo, Grafana, vendor backends) we would never have to build, and every engineer we hire already knows it. A custom exporter could target our ingest endpoint, and OTel's resource/attribute model could carry our event vocabulary.

Why it loses: the exporter is not the problem — the *delivery semantics* are. To make OTel billing-grade we would have to disable sampling everywhere, replace the batch processor's shed-on-pressure behavior, impose our own idempotency key, add durable spooling below the SDK, and invent `Dropped{}` accounting the protocol cannot express. At that point we have written M1P anyway, wrapped in an SDK whose remaining contribution is dependency weight on customer laptops and a semantic vocabulary (spans, traces) that does not match ours (sessions, tasks, verdicts, receipts). We would own all of M1P's hard parts plus OTel's surface area.

### OTel for internal cloud spans only, M1P at the edge

The strongest case: the objections above are edge objections. Cloud pods are ours; dependency weight and egress ambiguity do not apply; distributed tracing across `controld`'s pipeline stages and the Python services is exactly what OTel is good at, and the billing path could stay M1P end to end.

Why it loses on the facts of this estate: there is no collector deployed anywhere, so this option means standing up and operating a second telemetry fabric (collector, storage, dashboards) alongside M1P from day one, for a cloud plane that is deliberately **one Go binary** (`controld`) plus two Python services — a topology where distributed tracing has almost nothing to distribute. The observability doc's `session_id`/`event_id`/`seq` correlation over the ledger covers cross-stage debugging for the pipeline that matters (ingest), because the ledger *is* the trace. If the cloud plane ever grows into a genuine service mesh, this option is the natural revisit — see "How we would know we were wrong."

### Vendor observability SDKs (Datadog, Honeycomb, …)

The strongest case: zero-build observability, excellent dashboards, paged-integrated alerting, someone else's on-call for the telemetry pipeline. Why it loses immediately: a vendor agent phoning home from inside a customer's laptop or VPC is the exact egress-ambiguity conversation-killer described above, now with a third party's DPA attached; and the billing-grade delivery objection applies with less control, not more. Even cloud-side only, it adds a subprocessor for data adjacent to customer usage. Not close.

## Consequences

### What this makes easy
- The procurement/security review of edge binaries: one destination, one wire format, a dependency tree with a stated reason for every node.
- Billing integrity: one identity scheme (`event_id`/`idem_key`) from spool cursor to ClickHouse merge key, designed once, tested with fuzzing and kill -9 drills.
- Honest coverage: `Dropped{}` is in the schema, so every report's coverage band is computable from the ledger, not estimated.

### What this makes hard
- **We give up a large ecosystem**: no Jaeger/Tempo waterfalls, no auto-instrumentation, no off-the-shelf exporters, no OTel-literate hire being productive on our telemetry on day one. Every visualization and every correlation query is ours to build over the ledger.
- **We give up distributed trace propagation for free.** Cross-service causality is reconstructed by joining on `session_id`/`event_id`/`(session_epoch, seq)` — adequate for the current topology, real work if the topology grows.
- Debugging tooling for M1P (batch inspectors, spool dump tools, ledger trace views) is a product cost M1P must pay that OTel shops get from the shelf.

### What we accept
- Owning a wire protocol forever: versioning discipline (`buf breaking` at WIRE_JSON, `m1p.v2` never in place), conformance vectors across three languages, fuzzed decoders — the plan already prices this in.
- That this decision is contrarian and will be questioned by every senior hire; this document is the answer, and re-litigating it requires new facts, not familiarity.

## How we would know we were wrong

**Leading indicator, measurable:** cross-service debugging cost in the cloud plane. Concretely: if, once the cloud plane exceeds ~4 independently deployed services, incident retros show engineers hand-building causality joins that a trace view would give them — operationalized as either (a) median time-to-localize for cross-service incidents exceeding 2× that of single-service incidents over a quarter, or (b) an ad-hoc internal tracing tool appearing in the repo (the surest sign, historically) — the "no OTel in the cloud plane" half of this decision is costing more than it saves.

**Migration path and cost:** the revisit is the second alternative above, *cloud-internal only* — OTel SDK + collector inside Omium's own pods, exporting to a self-hosted backend, with the `bans`/`go mod graph` gates relaxed for cloud-plane modules only. The edge and the billing path stay M1P categorically; no wire change, no schema change, no receipt change. Cost: collector deployment + dashboard setup (days, not weeks) and a carve-out in the CI gates that must be scoped precisely so the edge rule stays absolute. The edge half of this decision has no plausible reversal indicator — the arguments there are structural properties of running on customer hardware, and they do not decay.

## References
- `docs/spec/execution-plan-v2.md` — "Why this is v2" (the rejection), M1P section (schema, identity, transport, `Dropped{}`), grounding fact: "OpenTelemetry in the estate today … Mark 1 taking no OTel dependency costs nothing and breaks nothing"
- `docs/11-observability-and-slo.md` — self-monitoring without OpenTelemetry; `session_id`/`event_id`/`seq` correlation; `Dropped{}`/coverage as product telemetry
- `docs/spec/execution-plan-v2.md` appendix delta 4 — the CI gates (`cargo-deny` etc.) are new in `omium-mark1`, not inherited
- ADR-0007 — spool durability classes (the billing-grade delivery guarantee this fabric exists to carry)
