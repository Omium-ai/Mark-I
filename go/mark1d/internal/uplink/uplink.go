// Package uplink drains the spool over M1P/1 ingest: batching, zstd, and the
// 08 §2.5 retry automaton, exactly as written. States (04 §2.5):
//
//	IDLE → SENDING → (verified 2xx ack) spool.Ack → IDLE
//	              → (net/3xx/5xx/429/unverified 2xx) BACKOFF(n) → SENDING   n ≤ maxAttempts
//	              → (exhausted)   PARKED                    re-queued on restart,
//	                                                        network-change, every 6 h
//	              → (4xx, except 401-with-refresh and 403/426) QUARANTINED
//	              → (403/426)     QUARANTINED + HALT        capture-local-only (08 §2.4)
//
// Retry ONLY on network errors, 5xx and 429; every other 4xx is
// quarantine-and-report, never retried. Park leaves bytes in the spool —
// PARKED is uploader state, not data state — which is what lets billing-grade
// classes survive arbitrarily long outages (08 §2.5). All timers ride Go's
// monotonic clock, so a machine wake never fires a burst of missed retries
// (04 §1.4).
package uplink

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// 08 §2.5, normative and exact.
const (
	backoffBase = 6 * time.Second
	backoffCap  = 30 * time.Minute
	maxAttempts = 10 // give up after the 10th failure
	parkRequeue = 6 * time.Hour
)

// defaultPoll paces the IDLE spool check; a boring cadence, not a doc number
// — the flush barrier covers latency-sensitive drains (07 §6).
const defaultPoll = time.Second

// Store is the spool read/ack surface uplink drives (07 §6): the ack cursor
// advance IS the delete authority — whole-segment ack-then-delete happens
// inside the spool, downstream of Ack. *spool.Spool satisfies it; the seam
// exists so the crash-between-200-and-Ack replay property is testable.
type Store interface {
	Cursors() (ack, write spool.Cursor)
	Records(from spool.Cursor) ([]spool.Record, spool.Cursor, error)
	Ack(through spool.Cursor) error
}

// Config wires one Uplink. Endpoint, Tokens, Store, QuarantineDir and Seal
// are required; the rest default. Seal is the device spill-key seal seam
// (04 §5.4 — main wires spill.Seal over the materialized public half);
// quarantine is an error path 08 §2.5 forbids losing, so there is no
// plaintext fallback.
type Config struct {
	Store         Store
	Drops         []DropSource // spool + capture loss ledgers, drained per batch
	Tokens        TokenSource
	Endpoint      string // full URL of POST /m1p/v1/ingest
	EdgeVersion   string // semver riding X-Mark1-Edge-Version (08 §2.1)
	SDK           *m1pv1.SdkInfo
	QuarantineDir string
	Seal          func(plaintext []byte) ([]byte, error)

	// Health receives the uplink gauges and emits EdgeHealth at the end of a
	// successful cycle (11 §2.3's cadence). nil is legal — an unwired health
	// table costs gauges, never uploads.
	Health *obs.Health

	// NetworkChange re-queues PARKED work when it fires (08 §2.5: wake /
	// network-change signal). nil is legal: restart and the 6 h timer remain.
	NetworkChange <-chan struct{}

	// Checkpoint seals one acked batch into the receipt chain (07's checkpoint
	// model): eventIDs are the batch's Merkle leaves in spool order. nil is
	// legal and is the posture whenever the device has no enrolled key or
	// identity — an unsealed uplink uploads exactly as it did before receipts
	// existed.
	Checkpoint func(ctx context.Context, eventIDs [][]byte)

	// Origin signs quarantine-deletion receipts (retention.go); nil ⇒ unsigned, the same posture as a nil Checkpoint.
	Origin *Origin
	// Admit uploads each signed deletion receipt as a QuarantineDeletion through the capture admitter; nil ⇒ disk only.
	Admit func(ctx context.Context, ev *m1pv1.Event) error

	// Test seams; nil ⇒ production defaults.
	HTTPClient *http.Client
	Log        *slog.Logger
	Now        func() time.Time
	After      func(d time.Duration) <-chan time.Time
	Rand       func() float64 // U(0,1) full-jitter source
	Poll       time.Duration
}

// Uplink owns batching and sending — one goroutine each per 04 §2.5; this
// implementation runs both on the Run goroutine since the spool is the queue
// and nothing buffers between them. NOT safe for concurrent use: Run owns all
// state; call Flush only after Run has returned.
type Uplink struct {
	store         Store
	drops         []DropSource
	tokens        TokenSource
	endpoint      string
	edgeVersion   string
	sdk           *m1pv1.SdkInfo
	quarantineDir string
	seal          func([]byte) ([]byte, error)
	netChange     <-chan struct{}
	checkpoint    func(context.Context, [][]byte)
	origin        *Origin
	admit         func(context.Context, *m1pv1.Event) error
	health        *obs.Health
	lastSweep     time.Time
	// lastAck is the instant of the most recent verified 2xx — Run-owned, like
	// every other field here.
	lastAck time.Time

	client *http.Client
	log    *slog.Logger
	now    func() time.Time
	after  func(time.Duration) <-chan time.Time
	rand   func() float64
	poll   time.Duration

	enc *zstd.Encoder
	// carry holds Dropped rows that must ride the next composed batch:
	// re-credits from failed batches plus quarantine accounting (08 §2.5).
	carry []spool.Dropped
	// quarantined holds the event_ids the 422 remainder flow already wrote
	// quarantine evidence for while their spool window is still unacked (the
	// remainder parked/failed). compose excludes them: quarantine is never
	// auto-retried (08 §2.5), and their Dropped{QUARANTINED} rows entered
	// carry exactly once at quarantine time — a replay must not re-send the
	// events or re-credit the counters.
	// ponytail: process-lifetime memory, grows one entry per 422-named event;
	// a daemon restart before the window acks replays the batch and the named
	// events quarantine again (duplicate evidence + rows, never silence) —
	// dedupe against the quarantine dir at boot is the upgrade if it matters.
	quarantined map[[16]byte]struct{}
}

// New validates the wiring. It does not touch the network.
func New(cfg Config) (*Uplink, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("uplink: Store required")
	case cfg.Tokens == nil:
		return nil, errors.New("uplink: Tokens required")
	case cfg.Endpoint == "":
		return nil, errors.New("uplink: Endpoint required")
	case cfg.EdgeVersion == "":
		return nil, errors.New("uplink: EdgeVersion required (08 §2.1: every edge request carries it)")
	case cfg.QuarantineDir == "":
		return nil, errors.New("uplink: QuarantineDir required (08 §2.5: quarantined data is never discarded)")
	case cfg.Seal == nil:
		return nil, errors.New("uplink: Seal required (04 §2.5: quarantine is encrypted with the device spill key)")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.HTTPClient.CheckRedirect == nil {
		// Never follow a redirect: a 302→200 portal page must surface as the
		// 3xx it is (network-class in post), not as a 2xx that could be
		// mistaken for controld's ack (08 §2.2 — deletion authority comes
		// from the landing write alone).
		cfg.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	if cfg.Poll <= 0 {
		cfg.Poll = defaultPoll
	}
	// Level 3 (SpeedDefault) per 04 §2.5; single-goroutine encoder — the
	// sender is sequential by design (spool order, billing never overtaken).
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	return &Uplink{
		store: cfg.Store, drops: cfg.Drops, tokens: cfg.Tokens,
		endpoint: cfg.Endpoint, edgeVersion: cfg.EdgeVersion, sdk: cfg.SDK,
		quarantineDir: cfg.QuarantineDir, seal: cfg.Seal, netChange: cfg.NetworkChange,
		checkpoint: cfg.Checkpoint, origin: cfg.Origin, admit: cfg.Admit, health: cfg.Health,
		client: cfg.HTTPClient, log: cfg.Log, now: cfg.Now, after: cfg.After,
		rand: cfg.Rand, poll: cfg.Poll, enc: enc,
	}, nil
}

// cycleResult is one batch's terminal automaton outcome.
type cycleResult int

const (
	cycleAdvanced cycleResult = iota // cursor moved: acked, or quarantined+acked
	cycleParked                      // retry budget exhausted; bytes stay spooled
	cycleCtxDone
	// cycleHalt is the 403/426 verdict (08 §2.4): the offending batch is
	// quarantined+acked, then the uplink STOPS — every further batch would
	// meet the same refusal, and grinding the backlog into never-auto-retried
	// quarantine files (08 §2.5) would destroy a recoverable, billing-grade
	// spool. Capture continues; the spool parks until re-enroll/upgrade.
	cycleHalt
)

// Run is the uploader loop: IDLE polls the spool, each composed batch runs
// the automaton, PARKED waits for a re-queue trigger. Returns nil on ctx
// cancellation and on HALT (403/426 — capture-local-only, 08 §2.4); a
// non-nil error is local-durability damage (spool read/ack failure) the
// daemon must restart over.
func (u *Uplink) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		u.maybeSweep(ctx)
		b, err := u.compose()
		if err != nil {
			return err
		}
		if b == nil {
			select {
			case <-ctx.Done():
				return nil
			case <-u.after(u.poll):
			}
			continue
		}
		// The head of the composed window IS the oldest durable-but-unacked
		// record at this instant (spool order), and its record_id leads with
		// the event_id — a UUIDv7, so the backlog age is readable from the
		// identity without decoding the payload (07 §6/§2).
		oldestUnacked := uuidV7Time(recordEventID(b.recs[0]))
		res, err := u.send(ctx, b, 0)
		if err != nil {
			return err
		}
		switch res {
		case cycleAdvanced:
			// 11 §2.3's cadence: one EdgeHealth per successful uploader cycle,
			// rate-limited inside Health to one per 15 minutes per device. It
			// is admitted, not sent — health rides the next batch like every
			// other event, through the one admission chokepoint.
			u.health.Cycle(ctx, u.lastAck, oldestUnacked)
		case cycleCtxDone:
			return nil
		case cycleHalt:
			// 08 §2.4: mark1d drops to capture-local-only. The session keeps
			// capturing and spooling; this goroutine simply stops draining.
			// A daemon restart re-arms the uplink, so after re-enrollment or
			// an edge upgrade the retained spool uploads normally.
			u.log.Error("uplink: halted — capture-local-only; spool retained for re-enroll/upgrade (08 §2.4)")
			return nil
		case cycleParked:
			if !u.park(ctx) {
				return nil
			}
			// Re-queued: recompose from the untouched spool cursor. A fresh
			// batch_id over the same events is safe — the server dedupes
			// per event_id (08 §2.3), the spool is the state that matters.
		}
	}
}

// Flush is the shutdown/SessionEnd drain barrier's upload half (07 §6): one
// best-effort pass, single attempt per batch, no backoff — data that misses
// it stays durably spooled for the next run.
func (u *Uplink) Flush(ctx context.Context) {
	for {
		b, err := u.compose()
		if err != nil || b == nil {
			return
		}
		resp, err := u.post(ctx, b)
		if err != nil || (resp.status != http.StatusOK && resp.status != http.StatusAccepted) {
			u.requeueDropped(b) // rows return to carry; in-memory loss on exit is the counters' documented ceiling
			return
		}
		u.accountServerQuarantine(b, resp.quarantined)
		if u.ackSealed(ctx, b) != nil {
			return
		}
	}
}

// ackSealed is both verified-2xx landings — the automaton's ack and Flush's —
// and only those. The other Ack calls in this file advance the cursor past
// bytes controld REFUSED (quarantine, unsplittable 413, 422 with nothing
// recoverable); sealing there would mint chain evidence for events the server
// rejected, so the split is what makes a checkpoint mean "this landed".
//
// Ack FIRST: a checkpoint attests to bytes controld has already landed, and a
// seal ahead of the ack would attest to a batch a crash could still replay.
func (u *Uplink) ackSealed(ctx context.Context, b *outBatch) error {
	if err := u.store.Ack(b.end); err != nil {
		return err
	}
	if u.checkpoint != nil {
		u.checkpoint(ctx, batchLeaves(b.recs))
	}
	return nil
}

// send runs the 08 §2.5 automaton for one batch. depth guards the two
// content-mutating re-sends (413 split, 422 remainder) against recursion —
// the remainder is re-sent ONCE (08 §2.4), and a split halves at most
// log2(events) times before the single-record floor quarantines.
func (u *Uplink) send(ctx context.Context, b *outBatch, depth int) (cycleResult, error) {
	refreshed := false
	for attempt := 1; ; attempt++ {
		resp, netErr := u.post(ctx, b)
		if netErr != nil && ctx.Err() != nil {
			u.requeueDropped(b)
			return cycleCtxDone, nil
		}
		if netErr == nil {
			switch {
			case resp.status == http.StatusOK || resp.status == http.StatusAccepted:
				// A 2xx only reaches here provenance-checked (post verified
				// the batch_id echo, 08 §2.2/§2.6): the batch can no longer
				// be lost by Omium — the license for ack-then-delete. Ack
				// failure is local ledger damage: fatal, and harmless to
				// durability because a restart re-sends and the server dedupes.
				u.lastAck = u.now()
				u.accountServerQuarantine(b, resp.quarantined)
				if err := u.ackSealed(ctx, b); err != nil {
					return 0, err
				}
				return cycleAdvanced, nil

			case resp.status == http.StatusUnauthorized:
				// The one retryable 4xx, and only AFTER a successful refresh
				// (08 §2.4). A second 401 post-refresh, or no refresh path,
				// parks: auth is not a content problem, quarantine would be.
				if !refreshed {
					if err := u.tokens.Refresh(ctx); err == nil {
						refreshed = true
						continue
					}
				}
				u.requeueDropped(b)
				return cycleParked, nil

			case resp.status == http.StatusRequestEntityTooLarge:
				// Deterministic split, not a backoff retry (08 §2.4).
				return u.split(ctx, b, depth)

			case resp.status == http.StatusUnprocessableEntity && depth == 0:
				// §2.4 remainder flow: quarantine the named events, re-send
				// the rest once. depth>0 falls through to whole-quarantine —
				// the one re-send is spent.
				return u.remainder(ctx, b, resp)

			case resp.status == http.StatusForbidden || resp.status == http.StatusUpgradeRequired:
				// The two halt rows of 08 §2.4. 403: device revoked
				// (M1E-1003) or identity disagreement (M1E-8003) — quarantine
				// THIS batch, then capture-local-only + surface re-enrollment.
				// 426 (M1E-2007): schema window closed — same shape, surface
				// the upgrade. Only the offending batch quarantines: the
				// verdict is about the DEVICE/EDGE, not the next batch's
				// content, so the rest of the spool stays uploadable after
				// the operator acts.
				note := "M1E-1003/M1E-8003: device revoked or identity disagreement — re-enroll to resume uploads (08 §2.4)"
				if resp.status == http.StatusUpgradeRequired {
					note = "M1E-2007: M1P-Schema outside the tenant's accepted window — upgrade mark1d (mark1 doctor, 08 §10.2)"
				}
				if err := u.quarantineBatch(b, resp.status, resp.errCode, note); err != nil {
					u.log.Error("uplink: quarantine write failed; parking", "err", err)
					u.requeueDropped(b)
					return cycleParked, nil
				}
				if err := u.store.Ack(b.end); err != nil {
					return 0, err
				}
				u.log.Error("uplink: halting after terminal verdict", "status", resp.status, "code", resp.errCode, "note", note)
				return cycleHalt, nil

			case resp.status == http.StatusTooManyRequests || resp.status >= 500:
				// The only retryable statuses (08 §2.5) — fall through to
				// backoff; 429's Retry-After is honored below as a floor.

			default:
				// Every other 4xx: quarantine-and-report, never retried
				// (08 §2.5). 409 additionally warns: same batch_id, different
				// bytes — this side re-POSTs byte-identical bodies, so a 409
				// indicates local spool corruption (M1E-2003).
				note := ""
				if resp.status == http.StatusConflict {
					note = "M1E-2003: batch_id landed with different bytes — local spool corruption suspected"
				}
				if err := u.quarantineBatch(b, resp.status, resp.errCode, note); err != nil {
					// Quarantine unwritable ⇒ nothing may advance: parking
					// keeps the bytes durably spooled instead of dropped.
					u.log.Error("uplink: quarantine write failed; parking", "err", err)
					u.requeueDropped(b)
					return cycleParked, nil
				}
				if err := u.store.Ack(b.end); err != nil {
					return 0, err
				}
				return cycleAdvanced, nil
			}
		}
		if attempt >= maxAttempts {
			u.requeueDropped(b)
			return cycleParked, nil
		}
		d := u.backoff(attempt)
		if resp != nil && resp.retryAfter > d {
			d = resp.retryAfter // 08 §2.5: Retry-After is a floor, jitter never undercuts it
		}
		select {
		case <-ctx.Done():
			u.requeueDropped(b)
			return cycleCtxDone, nil
		case <-u.after(d):
		}
	}
}

// backoff is 08 §2.5 verbatim: delay = min(cap, base · 2^(n−1)) · U(0,1) —
// full jitter over the whole capped exponential.
func (u *Uplink) backoff(attempt int) time.Duration {
	exp := float64(backoffBase) * math.Pow(2, float64(attempt-1))
	return time.Duration(math.Min(exp, float64(backoffCap)) * u.rand())
}

// park blocks in PARKED until a re-queue trigger (08 §2.5): the 6 h timer or
// the network-change/wake signal. Restart re-queues by construction — a fresh
// Run starts at the spool cursor. Returns false on ctx cancellation.
func (u *Uplink) park(ctx context.Context) bool {
	u.log.Warn("uplink: parked — retry budget exhausted; spool retains the batch (08 §2.5)")
	u.health.Parked(true)
	defer u.health.Parked(false)
	select {
	case <-ctx.Done():
		return false
	case <-u.after(parkRequeue):
	case <-u.netChange:
	}
	return true
}

// split is the 413 row of 08 §2.4: halve deterministically and re-send both,
// each half acking its own end so the cursor never jumps past unlanded data.
// A single record that still 413s cannot split — it quarantines, keeping the
// queue moving.
func (u *Uplink) split(ctx context.Context, b *outBatch, depth int) (cycleResult, error) {
	if len(b.recs) <= 1 {
		if err := u.quarantineBatch(b, http.StatusRequestEntityTooLarge, "M1E-2004", "single record exceeds batch bound; unsplittable"); err != nil {
			u.requeueDropped(b)
			return cycleParked, nil
		}
		if err := u.store.Ack(b.end); err != nil {
			return 0, err
		}
		return cycleAdvanced, nil
	}
	mid := len(b.recs) / 2
	// The first half inherits the dropped rows (they precede everything in
	// this batch); its end cursor is the second half's first record.
	first, err := u.rebatch(b.recs[:mid], b.dropped, b.recs[mid].Pos)
	if err != nil {
		return 0, err
	}
	if res, err := u.send(ctx, first, depth+1); err != nil || res != cycleAdvanced {
		return res, err
	}
	second, err := u.rebatch(b.recs[mid:], nil, b.end)
	if err != nil {
		return 0, err
	}
	return u.send(ctx, second, depth+1)
}

// remainder is the 422 row of 08 §2.4: the server named invariant-violating
// event_ids — quarantine exactly those, re-send the rest ONCE (as a new batch:
// the content changed, so reusing the batch_id would be the 409 corruption
// signal), report. An empty detail names nothing recoverable (e.g. a
// batch_id_mismatch) — whole-batch quarantine.
func (u *Uplink) remainder(ctx context.Context, b *outBatch, resp *ingestResp) (cycleResult, error) {
	named, rest := splitByEventIDs(b.recs, resp.badEventIDs)
	if len(named) == 0 {
		if err := u.quarantineBatch(b, resp.status, resp.errCode, "422 named no events in this batch"); err != nil {
			u.requeueDropped(b)
			return cycleParked, nil
		}
		if err := u.store.Ack(b.end); err != nil {
			return 0, err
		}
		return cycleAdvanced, nil
	}
	// Quarantine the named events as their own sealed mini-batch so one
	// on-disk quarantine format exists; its id is evidence identity, not wire.
	// Files land BEFORE the ack: the reverse order would let an ack followed
	// by a failed write silently discard them (08 §2.5).
	qb, err := u.rebatch(named, nil, b.end)
	if err != nil {
		return 0, err
	}
	if err := u.quarantine(qb, qb.body, resp.status, resp.errCode,
		"events named by M1E-2006 in batch "+b.id.String()); err != nil {
		u.log.Error("uplink: quarantine write failed; parking", "err", err)
		u.requeueDropped(b)
		return cycleParked, nil
	}
	// Evidence is durable: from here the named events are quarantined EXACTLY
	// once — their ids enter the exclusion set (compose skips them if the
	// remainder fails to ack and the window replays) and their accounting
	// enters carry exactly once, to ride the next successfully-acked batch.
	if u.quarantined == nil {
		u.quarantined = map[[16]byte]struct{}{}
	}
	for _, r := range named {
		var k [16]byte
		copy(k[:], r.ID[:16])
		u.quarantined[k] = struct{}{}
	}
	u.carry = append(u.carry, quarantineRows(named)...)
	if len(rest) == 0 {
		u.requeueDropped(b) // dropped rows never landed; ride the next batch
		if err := u.store.Ack(b.end); err != nil {
			return 0, err
		}
		return cycleAdvanced, nil
	}
	rb, err := u.rebatch(rest, b.dropped, b.end)
	if err != nil {
		return 0, err
	}
	return u.send(ctx, rb, depth1)
}

// depth1 marks the spent 422 re-send: at depth>0 a second 422 quarantines
// whole instead of looping remainder-of-remainder (08 §2.4: "re-send the
// remainder once").
const depth1 = 1

// accountServerQuarantine turns a 202's quarantined[] into
// Dropped{QUARANTINED} rows for the NEXT batch (08 §2.4), classed from the
// spool record identity; an id we cannot match reports class UNSPECIFIED
// rather than a guess.
func (u *Uplink) accountServerQuarantine(b *outBatch, ids []string) {
	if len(ids) == 0 {
		return
	}
	byID := map[[16]byte]spool.Class{}
	for _, r := range b.recs {
		var k [16]byte
		copy(k[:], r.ID[:16])
		byID[k] = r.ID.Class()
	}
	perClass := map[spool.Class]uint64{}
	for _, s := range ids {
		class := spool.ClassUnknown
		if id, err := uuid.Parse(s); err == nil {
			if c, ok := byID[[16]byte(id)]; ok {
				class = c
			}
		}
		perClass[class]++
	}
	for c, q := range perClass {
		u.carry = append(u.carry, spool.Dropped{Reason: dropQuarantined, Class: c, Quantity: q})
	}
	u.log.Warn("uplink: server quarantined events from acked batch (202, 08 §2.4)",
		"batch_id", b.id.String(), "count", len(ids))
}
