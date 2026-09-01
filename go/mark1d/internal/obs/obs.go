package obs

import (
	"context"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// EmitEvery is 11 §2.3's device rate limit. Cadence is "one per successful
// uploader cycle" ANDed with this floor, so a busy uploader does not turn
// health into traffic and an idle one still reports every quarter hour.
const EmitEvery = 15 * time.Minute

// spoolSegExt is 07 §6's segment name; the same tally `mark1 status` prints,
// read from the same place, so the two surfaces cannot disagree.
const spoolSegExt = ".m1s"

// Config wires one Health. Admit is capture.Admitter.Admit — the ONLY door to
// the spool (04 §2.0); obs takes the func rather than the type so the emitter
// is testable without a spool, never so a second admission path can exist.
type Config struct {
	EdgeVersion string
	SpoolDir    string
	Admit       func(context.Context, *m1pv1.Event) error
	// BootCount is capture.Admitter.Epoch() — the durable boots-since-enrollment
	// counter that already exists (07 §2). `restarts` is that minus the first
	// boot, so the fleet crash-rate signal needs no second counter, no second
	// state file, and no call site: a process cannot increment a restart counter
	// on the boot where it died.
	BootCount uint32
	Now       func() time.Time // test seam
}

// Health is mark1d's counter/gauge table (11 §3.1) and the EdgeHealth emitter
// (11 §2.3). Every mutator is nil-receiver safe: an unwired daemon must not
// need a branch at each call site, and a missing health table is a missing
// gauge, never a missing gate answer.
type Health struct {
	cfg     Config
	started time.Time

	lastEmit atomic.Int64 // unix nanos; 0 = never emitted

	restarts uint32

	gateReads, gateAllows, gateBlocks, gateTimeouts atomic.Uint64
	gateRead                                        hist

	shimDelivered, shimSpilled atomic.Uint64

	parked, quarantined atomic.Uint32
	lastAckUnix         atomic.Int64
	oldestUnackedMs     atomic.Int64

	bundleSeq     atomic.Uint64
	bundleIssuedS atomic.Int64
	bundleStale   atomic.Bool
}

func New(cfg Config) *Health {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	h := &Health{cfg: cfg, started: cfg.Now()}
	if cfg.BootCount > 0 {
		h.restarts = cfg.BootCount - 1
	}
	return h
}

func (h *Health) now() time.Time { return h.cfg.Now() }

// GateAnswer records one GateQuery→GateVerdict round trip and its latency
// (SLO-7 is judged as the fleet p99 of these).
func (h *Health) GateAnswer(d time.Duration, decision m1pv1.GateDecision) {
	if h == nil {
		return
	}
	h.gateReads.Add(1)
	h.gateRead.observe(d)
	if decision == m1pv1.GateDecision_GATE_DECISION_BLOCK {
		h.gateBlocks.Add(1)
		return
	}
	h.gateAllows.Add(1)
}

// GateTimeout counts the fail-open allows that also emit Dropped{gate_timeout}
// (04 §2.3). It is a subset of the allows GateAnswer counts, not a third bucket.
func (h *Health) GateTimeout() {
	if h == nil {
		return
	}
	h.gateTimeouts.Add(1)
}

// Delivered counts events that reached the daemon over the socket. Counted on
// the daemon side because the shim holds no counters of its own (11 §3.1) —
// `delivered` and `spilled` are the two exits from one shim decision, so both
// have to be tallied at the same end of the wire to be comparable.
func (h *Health) Delivered() {
	if h == nil {
		return
	}
	h.shimDelivered.Add(1)
}

// Spilled counts hookshim events recovered from the sealed spill ring, counted
// at drain (11 §3.1: the shim holds no counters of its own).
func (h *Health) Spilled(n uint64) {
	if h == nil || n == 0 {
		return
	}
	h.shimSpilled.Add(n)
}

// Quarantined counts batches diverted to the quarantine dir.
func (h *Health) Quarantined() {
	if h == nil {
		return
	}
	h.quarantined.Add(1)
}

// Parked tracks the uploader's PARKED state (0/1 for this single-batch
// automaton, which is what `uplink_parked` gauges).
func (h *Health) Parked(parked bool) {
	if h == nil {
		return
	}
	var v uint32
	if parked {
		v = 1
	}
	h.parked.Store(v)
}

// Bundle records the applied policy posture (04 §7.3). issuedAtEpochS is the
// bundle's own issue time, so age_s measures publication age and not how long
// this daemon has been holding it.
func (h *Health) Bundle(seq, issuedAtEpochS uint64, stale bool) {
	if h == nil {
		return
	}
	h.bundleSeq.Store(seq)
	h.bundleIssuedS.Store(int64(issuedAtEpochS)) // #nosec G115 -- epoch seconds
	h.bundleStale.Store(stale)
}

// Cycle is the uploader's report at the end of one automaton cycle: the uplink
// gauges only it can know, then the rate-limited emission. oldestUnacked is
// zero when the spool drained.
//
// The event is diagnostic-class by construction (capture's closed billing set
// is {usage, verdict_event, receipt_checkpoint}), so under spool pressure it
// sheds and the shed is accounted as Dropped{spool_shed, diagnostic} — health
// never blocks a developer's session, and losing health is never silent.
func (h *Health) Cycle(ctx context.Context, lastAck, oldestUnacked time.Time) {
	if h == nil {
		return
	}
	if !lastAck.IsZero() {
		h.lastAckUnix.Store(lastAck.Unix())
	}
	h.oldestUnackedMs.Store(unixMilliOrZero(oldestUnacked))
	h.Emit(ctx)
}

// Emit sends one EdgeHealth if the rate limit allows, and reports nothing to
// the caller: a health event that could not be admitted is already accounted
// in the loss ledger, and an uploader must not change behaviour because its
// own diagnostics were shed.
func (h *Health) Emit(ctx context.Context) {
	if h == nil || h.cfg.Admit == nil {
		return
	}
	now := h.now()
	last := h.lastEmit.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < EmitEvery {
		return
	}
	if !h.lastEmit.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	_ = h.cfg.Admit(ctx, &m1pv1.Event{
		// session_id is deliberately absent: health is per-device, not
		// per-session (11 §2.3's normative privacy rule). tenant_id/device_id
		// are stamped server-side from the token.
		Body: &m1pv1.Event_EdgeHealth{EdgeHealth: h.Snapshot()},
	})
}

// Snapshot renders the current table as an EdgeHealth. The gate latency digest
// is READ-AND-RESET: the field is a per-window p99 the fleet view compares
// cohort-to-cohort (A-14), not a lifetime figure.
//
// Cortexd, Proxy, ProxyLatency, Cortex and DialectRevs stay nil: mark1d
// supervises neither child in this build and owns no dialect table, and the
// proto's own "unset when no proxy is attached" is the honest encoding of a
// process that is not there. A zeroed sub-message would read as a healthy
// idle child.
func (h *Health) Snapshot() *m1pv1.EdgeHealth {
	now := h.now()
	segments, bytesUsed := spoolTally(h.cfg.SpoolDir)
	return &m1pv1.EdgeHealth{
		Mark1D: &m1pv1.ProcessHealth{
			RssBytes: rssBytes(),
			// 11 §2.5: the FACT of a crash reaches Omium as this counter; the
			// content of the crash stays on the machine.
			Restarts: h.restarts,
			UptimeS:  secondsSince(h.started, now),
		},
		Spool: &m1pv1.SpoolHealth{
			Segments:          segments,
			BytesUsed:         bytesUsed,
			OldestUnackedAgeS: ageS(h.oldestUnackedMs.Load(), now.UnixMilli(), 1000),
		},
		Uplink: &m1pv1.UplinkHealth{
			Parked:      h.parked.Load(),
			Quarantined: h.quarantined.Load(),
			LastAckAgeS: ageS(h.lastAckUnix.Load(), now.Unix(), 1),
		},
		Bundle: &m1pv1.BundleHealth{
			Seq:   h.bundleSeq.Load(),
			AgeS:  ageS(h.bundleIssuedS.Load(), now.Unix(), 1),
			Stale: h.bundleStale.Load(),
		},
		Gate: &m1pv1.GateHealth{
			Reads:     h.gateReads.Load(),
			Allows:    h.gateAllows.Load(),
			Blocks:    h.gateBlocks.Load(),
			Timeouts:  h.gateTimeouts.Load(),
			ReadP99Us: h.gateRead.p99AndReset(),
		},
		Shim: &m1pv1.ShimHealth{
			Delivered: h.shimDelivered.Load(),
			Spilled:   h.shimSpilled.Load(),
		},

		EdgeVersion: h.cfg.EdgeVersion,
	}
}

// ageS converts a stored instant to an age in seconds. A zero instant means
// "never happened", which is age 0 rather than "since the epoch"; a negative
// age is a stepped clock, and a negative age is zero age (policy.IsFresh's
// rule, applied to every gauge here).
func ageS(then, now, perSecond int64) uint64 {
	// perSecond is guarded for its own sake, not the linter's: at 0 this
	// divides by zero and takes the daemon down from inside a health gauge.
	if then == 0 || now <= then || perSecond <= 0 {
		return 0
	}
	//nolint:gosec // G115: both conversions are guarded above — now > then, perSecond > 0.
	return uint64(now-then) / uint64(perSecond)
}

func secondsSince(then, now time.Time) uint64 {
	if d := now.Sub(then); d > 0 {
		return uint64(d.Seconds())
	}
	return 0
}

func unixMilliOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// spoolTally is the on-disk occupancy read, byte-for-byte the surface
// `mark1 status` prints (08 §7.3) — the spool exposes no gauge accessor, and a
// second in-process counter would be a second truth to keep in sync.
func spoolTally(dir string) (uint32, uint64) {
	if dir == "" {
		return 0, 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	var n uint32
	var total uint64
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != spoolSegExt {
			continue
		}
		n++
		if fi, err := e.Info(); err == nil && fi.Size() > 0 {
			//nolint:gosec // G115: Size() > 0 is checked on the line above.
			total += uint64(fi.Size())
		}
	}
	return n, total
}

// rssBytes reads the kernel's own accounting. Linux only: /proc is where RSS
// is free and exact. Elsewhere it reports 0 — a gauge that is absent is
// readable as absent, whereas a runtime.MemStats figure would answer a
// different question (Go heap, not resident set) under the same field name.
func rssBytes() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return 0
	}
	//nolint:gosec // G115: os.Getpagesize() is positive on every supported platform.
	return pages * uint64(os.Getpagesize())
}

// hist is a log2-bucketed microsecond digest: bucket i holds the samples whose
// µs value has bit-length i, so the reported quantile is that bucket's upper
// bound. Resolution is a factor of two, which is the honest precision for a
// fleet gauge judged against a 5 ms budget — and it costs one atomic add per
// gate answer, on the path whose whole budget is 5 ms.
//
// ponytail: bucket-upper-bound, not interpolated; if SLO-7 ever needs to
// distinguish 4 ms from 6 ms, that is the day to carry bucket bounds.
type hist struct {
	buckets [48]atomic.Uint64
}

func (g *hist) observe(d time.Duration) {
	us := d.Microseconds()
	if us < 0 {
		us = 0
	}
	//nolint:gosec // G115: us is clamped to >= 0 on the lines above.
	g.buckets[bits.Len64(uint64(us))].Add(1)
}

// p99AndReset returns the 99th-percentile bucket's upper bound in µs and
// clears the window. Reset is per-bucket rather than atomic across the whole
// digest: a sample landing mid-drain is counted in the next window, never
// twice and never in a torn total.
func (g *hist) p99AndReset() uint64 {
	var counts [48]uint64
	var total uint64
	for i := range g.buckets {
		counts[i] = g.buckets[i].Swap(0)
		total += counts[i]
	}
	if total == 0 {
		return 0
	}
	// The smallest rank whose cumulative share reaches 99%.
	target := (total*99 + 99) / 100
	var seen uint64
	for i, c := range counts {
		seen += c
		if seen >= target {
			if i == 0 {
				return 0
			}
			return 1<<uint(i) - 1
		}
	}
	return 0
}
