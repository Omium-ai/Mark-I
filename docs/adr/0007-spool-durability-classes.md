# ADR-0007 — Spool durability classes: billing-grade events block, diagnostics shed, everything is accounted

- **Status:** Accepted
- **Date:** 2026-08-28
- **Deciders:** Anurag Upadhyay (founder), Omium
- **Reversibility:** cheap for the tuning knobs (segment size, cap, fsync cadence — config), expensive for the class semantics — once customers receive coverage-banded, receipt-backed reports, weakening "billing-grade events are never silently shed" retroactively changes what every issued report meant
- **Blocks:** `go/mark1d/internal/spool/` (Phase 1 critical file 3) and the Phase 1 gate's kill -9 drill

## Context

The spool is `mark1d`'s durable buffer between event producers (hookshim, proxy tee, cortexd, tailers — all funneled to the single writer) and the M1P uploader. It is where Mark 1's delivery guarantee physically lives: the plan's shape is Vector-disk-v2 — **64 MiB append-only segments**, records framed `len(bounded) | crc32c | record_id | payload` with the leading 16 bytes of `record_id` being the `event_id` (so **the spool cursor is the wire idempotency key**), an mmap'd ledger, **fsync every 250–500 ms**, **mandatory drain on SessionEnd and shutdown**, a **~2 GiB cap**, and a **95%-disk hard stop**.

Not all events are equal. `Usage` events are the substance of invoices and TVO numerators; `VerdictEvent`s are the labels the corpus moat is made of; `ReceiptCheckpoint`s are links in a witnessed hash chain. A dropped diagnostic is noise; a dropped `Usage` event is a billing dispute. One durability policy for both is wrong in one direction or the other.

The uncomfortable part: the plan's normative posture matrix is **fail-open for availability (capture, hooks), fail-static for policy, fail-closed for legality and secrets**. Blocking producers when the spool is full is a deliberate, localized violation of the fail-open capture posture — the one place Mark 1 chooses integrity over its own availability — and that choice deserves an explicit record.

## Decision

**Per-class durability policy at spool admission:**

1. **`Usage`, `VerdictEvent`, `ReceiptCheckpoint` — block on a full spool.** These classes are billing-grade: they are never shed by Mark 1's own machinery. When the 2 GiB cap is reached, their producers wait for the uploader to drain space.
2. **Diagnostics (and all non-billing classes) — drop-newest on a full spool.** History already spooled is worth more than the newest self-observation; the newest diagnostic describes a system that is visibly unhealthy anyway.
3. **Every shed and every CRC loss emits `Dropped{reason, durability_class, quantity}` in the next uploaded batch.** Loss is permitted only where it is accounted; a silent gap is a bug class, not a policy.
4. **Mechanics as specified:** 64 MiB segments, crc32c per record, mmap'd ledger, fsync cadence 250–500 ms, ~2 GiB cap, 95%-disk hard stop, mandatory drain on SessionEnd/shutdown, decoder fuzzed in CI.
5. **The 95%-disk hard stop outranks everything, including the blocking classes.** At 95% disk, capture stops entirely and the window is receipted as a `CoverageTransition` with its distinct disk-stop reason code — attributably dark, per the coverage design. Mark 1 never fills a developer's disk to preserve its own billing record.

**What a developer actually experiences when billing-grade classes block.** Nothing on the agent's critical path waits on the spool: the hookshim is fire-and-forget under a 50 ms deadline (overflow lands in its sanitized spill ring), the proxy tee is `try_send` and provably cannot hold a client write, and gates fail open on timeout with local hard caps. Blocking happens *inside* `mark1d`'s admission pipeline — capture stops making forward progress, verdicts go stale, and `mark1 status` shows the spool at cap — while the developer's agent keeps streaming, keeps editing, keeps working. The block trades away Mark 1's own observation liveness, never the developer's session. The scenario that produces it is a long ingest outage or an offline laptop *plus* a full 2 GiB of pending billing-grade events; the exit is the uploader draining (backoff capped at 30 min) or the coverage-receipted stop.

**Why billing integrity outweighs capture liveness here.** Every number Mark 1 quotes traces to the ledger, and the sales claim is that the customer can verify it offline. A fabric that quietly sheds `Usage` events under pressure converts "your invoice is a verifiable ledger projection" into "your invoice is our best estimate," and it does so precisely during incidents — when trust is tested. Coverage bands honestly model windows where Mark 1 *was not observing*; they cannot honestly model windows where Mark 1 observed, counted, and then discarded the count. The blast radius of blocking is bounded by design: the 2 GiB cap bounds the disk cost and (at billing-grade event sizes) represents days-to-weeks of disconnected operation, and the 95% stop bounds the worst case at "capture stops, receipted" — never "disk full," never "agent hangs."

**The fsync cadence, in terms of what a crash loses.** A `kill -9` of `mark1d` loses nothing already `write()`-ten — the page cache survives the process, and the Phase 1 gate drills exactly this ("deliberate kill -9 mid-batch loses nothing in the billing-grade classes"). What the fsync window governs is **power loss and kernel crash**: at 250–500 ms cadence, at most half a second of admitted events can vanish, and a torn tail write is caught by crc32c at recovery and emitted as `Dropped{}`. The bracketing alternatives both lose: fsync-per-event serializes every admission on a 1–10 ms device sync — capping throughput near 100–1000 events/s and burning laptop battery for protection against an event (power loss mid-burst) whose cost is already sub-second; a multi-second cadence lets a single power loss swallow an entire model response's usage burst. 250–500 ms is 2–4 syncs/s — negligible on any SSD — with a worst-case hole small enough that the server-side per-session `seq` gap detection localizes it precisely. Events that never reached the page cache are the one honest loss: they cannot emit their own `Dropped{}`, and the `seq` gap plus the coverage machinery is what makes even that hole visible rather than silent.

## Alternatives considered

### Drop-oldest for everything (ring buffer)

The strongest case: it is the classic bounded-buffer answer — never blocks, never grows, trivially predictable memory/disk behavior, and the code is simpler than per-class admission. Telemetry systems overwhelmingly choose it. Why it loses: the oldest records in the spool are exactly the ones next in line to upload — drop-oldest preferentially destroys the *most imminent* billing-grade data, and does it during outages, when the backlog is deepest and the eventual reconciliation matters most. It is the single worst eviction order for an at-least-once billing pipeline.

### Drop-newest for everything

The strongest case: preserves the upload frontier — everything already spooled eventually ships, the cursor never moves backward, and the failure mode is "recent gap" rather than "history rewritten," which coverage bands can band. It is the right policy for diagnostics, which is why this ADR adopts it there. Why it loses for billing-grade classes: the newest events during an outage *are the billing record of the sessions happening right now* — the developer keeps working through the outage (fail-open capture), tokens keep flowing, and drop-newest sheds precisely those tokens' `Usage` events. The result is systematic under-count during every long outage, i.e., a billing gap correlated with infrastructure incidents — indistinguishable, to a skeptical customer, from a vendor that undercounts when its own systems fail.

### Unbounded spool

The strongest case: never sheds and never blocks — the only policy with zero data-loss *and* zero producer back-pressure, and disk is cheap. Why it loses: the spool lives on developer laptops. An unbounded write-path on customer hardware is a product-killing failure waiting for a long vacation plus an offline machine: Mark 1 fills the disk, the developer's *actual work* fails (builds, saves, the agent itself), and the incident report reads "Omium's telemetry bricked my machine." The 95%-disk hard stop exists because filling a customer's disk is strictly worse than any accounting gap; unbounded is that stop's negation.

### Block on nothing; accept billing gaps with honest `Dropped{}` accounting

The strongest steelman of the set: it is philosophically consistent with the rest of the product — Mark 1 already refuses guarantee-grade reports below the coverage floor, already treats `Dropped{}` as a first-class citizen, and already accepts that un-enrolled machines are invisible. Why is a shed `Usage` event with an honest `Dropped{usage, spool_full, n}` record not just one more banded gap? Because coverage bands model *observation* gaps — windows where Mark 1 wasn't looking — and this would create *accounting* gaps: windows where Mark 1 looked, counted, and threw the count away by its own choice. A customer disputing an invoice armed with the vendor's own protocol message saying "we dropped N of your usage events" is an unanswerable position; and the corpus loses verified labels (`VerdictEvent`s) whose entire value is completeness of the (event, outcome) join. The `Dropped{}` mechanism makes loss *honest*; it does not make loss *acceptable* for the classes the product's economics stand on. Blocking — bounded by the cap and the receipted stop — is the cheaper total cost.

## Consequences

### What this makes easy
- The billing and receipt story stays absolute: within any coverage window, billing-grade classes are complete or the window itself is receipted as dark — there is no third state, so reconciliation logic and the offline verifier never model "partial."
- The kill -9 drill in the Phase 1 gate is a real test of a real guarantee, not a demo.
- Diagnostics can be shed aggressively without ceremony, keeping the spool's pressure behavior dominated by data that matters.

### What this makes hard
- Admission is per-class, so every new event family must declare its durability class at schema time — an unclassified event is a design error the proto review must catch.
- The blocking path needs careful liveness engineering inside `mark1d`: bounded producer queues above the spool, and the guarantee that a blocked billing-grade admission can never deadlock the uploader that would unblock it (the uploader must not require admission-path locks).
- Support burden: "Mark 1 stopped capturing" tickets during long outages are by design; `mark1 status` and the disk-stop reason codes must make the state self-explanatory.

### What we accept
- A deliberate, documented exception to the fail-open capture posture, confined to three event classes and bounded by the 2 GiB cap and the 95% stop.
- A sub-second power-loss hole per crash, surfaced via crc32c `Dropped{}` and server-side `seq` gaps rather than eliminated.
- Up to ~2 GiB of customer disk in the worst pending-backlog case, disclosed as a documented resource bound.

## How we would know we were wrong

**Leading indicators, measurable:**
1. **Blocking observed in the wild without an ingest incident:** any occurrence of the spool-cap blocked state on a device while `controld` ingest was healthy (joinable from `CoverageTransition` reason codes vs. server-side ingest SLO windows) means the cap or the drain path is mis-sized for real workloads — the guarantee is firing as friction, not as protection.
2. **Disk-stop frequency:** more than ~1% of active devices hitting the 95% stop in a month says the 2 GiB cap is too generous for real laptops and the stop is doing the cap's job.
3. **Power-loss holes that matter:** if server-side `seq`-gap analysis attributes materially more than the modeled sub-second loss per crash (i.e., fsync cadence is not delivering its promised bound on real filesystems), the cadence or the write path is wrong in implementation, not policy.

**Migration path and cost:** the knobs (cap size, fsync cadence, per-class assignment of *new* families) are bundle/config-tunable — cheap. The expensive reversal is demoting an existing billing-grade class to sheddable: that requires a receipt-visible policy version change (reports issued after it mean something weaker), customer notice, and an update to the verifier's documentation of what completeness claims mean — effectively a product-terms change, which is precisely why the class semantics are the irreversible-ish core of this ADR and the tuning is not.

## References
- `docs/spec/execution-plan-v2.md` — M1P spool section (segments, framing, cap, fsync, per-class policy, `Dropped{}`), posture matrix ("fail-open for availability…"), Phase 1 verification (kill -9 drill), critical file 3
- `docs/design/04-lld-edge.md` — spool internals, backpressure, failure catalog; shim 50 ms deadline and spill ring; tee `try_send`
- `docs/design/10-security-threat-model.md` — §11.5 coverage-window attributability (the disk-stop reason code's role)
- ADR-0005 — why the fabric must carry billing-grade delivery at all
