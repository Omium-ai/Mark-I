// Package capture owns the single admission pipeline into the spool:
// normalize → redact-admit (fail-closed) → seq-stamp → class-tag → append
// (04 §2.0). New moves the spool write handle in, so no other package can
// obtain one — invariants 1 and 5 made structural — and the class-tag stage
// is the sole owner of the closed billing-grade set {usage, verdict_event,
// receipt_checkpoint} (07 §6).
package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// ErrShed is 04 §2.0's diagnostic outcome under backpressure: the event was
// NOT admitted and the loss is already accounted — never silent.
var ErrShed = errors.New("capture: diagnostic event shed under backpressure")

// ErrQuarantined is the fail-closed redact-admit outcome (04 §2.0): the
// scanner refused or failed, so the event is accounted Dropped{LOCAL_QUARANTINE}
// and never reaches disk raw. Callers keep their connection; the loss ledger
// carries the truth.
var ErrQuarantined = errors.New("capture: event locally quarantined (accounted)")

// Drop reasons beyond the spool's own two, mirroring m1p.v1.DropReason
// numbering (envelope.proto) exactly as spool.DropReason does — the uplink
// translation stays a cast.
const (
	dropLocalQuarantine spool.DropReason = 4 // DROP_REASON_LOCAL_QUARANTINE
)

// maxEventBytes is 07 §6's typed-event admission bound: ingest refuses any
// single event over 1 MiB (05 §2.1), so admission enforces the same bound
// BEFORE spooling — an event the server is contractually bound to refuse must
// not occupy billing-grade spool space and then poison the batch that carries
// it into quarantine. The 4 MiB fabric-frame/spool-record bounds are TRANSPORT
// headroom (decoder allocation safety) and deliberately stay wider.
const maxEventBytes = 1 << 20

// RedactFunc is the admit-to-upload axis seam (04 §2.0): it may rewrite ev in
// place; any error ⇒ quarantine, never admit-raw. The daemon wires
// internal/redact's Scanner.RedactEvent — the Go twin validated bit-identical
// against the Rust mark1-redact crate by conformance/vectors/redact/ — and
// nothing else is a legal production value; the seam exists for tests only.
type RedactFunc func(ev *m1pv1.Event) error

// Config for New. EpochPath is the durable boot-counter file backing
// session_epoch (07 §2): bumped exactly once per Admitter construction,
// fsync'd before any event is stamped with it.
type Config struct {
	EpochPath string
	Redact    RedactFunc // required — there is no flag that disables the stage (04 §2.0)
	Now       func() time.Time
}

// Admitter is the ONLY path to the spool (04 §2.0). One authority for seq
// (R-4) and session_epoch: both are assigned here, at admission, never by a
// writer.
type Admitter struct {
	sp     *spool.Spool
	redact RedactFunc
	now    func() time.Time
	epoch  uint32

	mu    sync.Mutex
	seq   map[[16]byte]uint64 // per-session high-water; next seq is +1
	drops map[spool.DropReason]map[spool.Class]uint64
}

// New reads and bumps the durable boot counter, then takes possession of the
// spool write side. Call once, in cmd/main.go.
func New(sp *spool.Spool, cfg Config) (*Admitter, error) {
	if cfg.Redact == nil {
		return nil, errors.New("capture: Redact is required; the redact-admit stage has no off switch (04 §2.0)")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	epoch, err := bumpEpoch(cfg.EpochPath)
	if err != nil {
		return nil, err
	}
	return &Admitter{
		sp:     sp,
		redact: cfg.Redact,
		now:    cfg.Now,
		epoch:  epoch,
		seq:    map[[16]byte]uint64{},
		drops:  map[spool.DropReason]map[spool.Class]uint64{},
	}, nil
}

// Epoch is the session_epoch every event admitted by this Admitter carries.
func (a *Admitter) Epoch() uint32 { return a.epoch }

// Admit runs the 04 §2.0 pipeline on the caller's goroutine. Billing-grade
// events block under backpressure (the spool's block-on-full propagates to
// fabric read loops by design, 08 §4.4); diagnostics shed to ErrShed.
func (a *Admitter) Admit(ctx context.Context, ev *m1pv1.Event) error {
	// Normalize: identity the rest of the pipeline keys on must hold.
	if ev == nil || ev.GetBody() == nil || len(ev.GetSessionId()) != 16 {
		return a.quarantine(ev, "malformed envelope")
	}
	// The 900-band is server-stamped from verified token claims; a non-empty
	// value here would 403 the WHOLE batch at ingest (07 §2, M1E-8003), so
	// normalize clears it rather than letting one confused writer poison
	// billing-grade drainage for everything batched beside it.
	ev.TenantId = nil
	ev.DeviceId = nil
	ev.ReceivedAt = nil
	ev.ClockSkewMs = 0

	// Redact-admit BEFORE the seq stamp and the append: no pre-redaction
	// bytes ever reach disk (04 §2.0 — stage order is load-bearing).
	if err := a.redact(ev); err != nil {
		return a.quarantine(ev, err.Error())
	}

	class := classOf(ev)

	// Seq stamp + event_id mint under one lock so (session_epoch, seq) pairs
	// are unique and UUIDv7 minting stays per-daemon monotonic (07 §2).
	// ponytail: the session map only grows for the daemon's lifetime — one
	// uint64 per session seen; an eviction sweep if long-lived daemons ever
	// accumulate enough sessions to matter.
	a.mu.Lock()
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	a.seq[sid]++
	ev.Seq = a.seq[sid]
	ev.SessionEpoch = a.epoch
	if len(ev.GetEventId()) != 16 {
		// Minted here (the daemon's monotonic authority); a writer-set 16-byte
		// id is preserved so spill-ring replay stays idempotent server-side.
		id, err := uuid.NewV7()
		if err != nil {
			a.mu.Unlock()
			return a.quarantine(ev, "uuidv7: "+err.Error())
		}
		ev.EventId = id[:]
	}
	var eid [16]byte
	copy(eid[:], ev.GetEventId())
	a.mu.Unlock()

	payload, err := proto.Marshal(ev)
	if err != nil {
		return a.quarantine(ev, "marshal: "+err.Error())
	}
	// 07 §6 admission bound, measured on the exact bytes ingest would decode
	// (post-redaction marshal). Accounted as LOCAL_QUARANTINE: 07 §3's row for
	// an event the edge's own admission chokepoint refused before disk — this
	// ledger already books every such refusal (malformed envelope, marshal
	// failure) under it, and QUARANTINED(6) would falsely claim a batch that
	// left the spool, which this event never entered.
	if len(payload) > maxEventBytes {
		return a.quarantine(ev, fmt.Sprintf("event is %d bytes, over the 1 MiB admission bound (07 §6)", len(payload)))
	}
	err = a.sp.Append(ctx, eid, class, payload)
	if errors.Is(err, spool.ErrDiagnosticShed) {
		return ErrShed // accounted inside the spool's own drop ledger
	}
	return err
}

// AdmitBytes is the fabric-facing door: one M1PL payload (an encoded
// m1p.v1.Event, 07 §5) in, the same pipeline. Undecodable payloads are a
// content failure on an intact framing layer — quarantined and accounted,
// the connection lives on.
func (a *Admitter) AdmitBytes(ctx context.Context, payload []byte) error {
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(payload, ev); err != nil {
		return a.quarantine(nil, "unmarshal: "+err.Error())
	}
	return a.Admit(ctx, ev)
}

// AccountDropped adds an externally-observed loss to capture's ledger — the
// door for edge components that count sheds but own no Batch surface (the
// hookshim's spill ring, 04 §5.4: ring expiry and overflow are accounted at
// mark1d's drain, never vanished). Same read-and-reset ledger as quarantines,
// so uplink drains every edge loss into one Batch.dropped.
func (a *Admitter) AccountDropped(reason spool.DropReason, class spool.Class, quantity uint64) {
	if quantity == 0 {
		return
	}
	a.mu.Lock()
	if a.drops[reason] == nil {
		a.drops[reason] = map[spool.Class]uint64{}
	}
	a.drops[reason][class] += quantity
	a.mu.Unlock()
}

// DrainDropped returns and resets capture's own loss rows (quarantines),
// typed identically to the spool's so uplink drains both into one Batch.dropped.
func (a *Admitter) DrainDropped() []spool.Dropped {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []spool.Dropped
	for reason, byClass := range a.drops {
		for class, q := range byClass {
			out = append(out, spool.Dropped{Reason: reason, Class: class, Quantity: q})
		}
	}
	a.drops = map[spool.DropReason]map[spool.Class]uint64{}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Class < out[j].Class
	})
	return out
}

func (a *Admitter) quarantine(ev *m1pv1.Event, detail string) error {
	class := spool.ClassDiagnostic
	if ev != nil && ev.GetBody() != nil {
		class = classOf(ev)
	}
	a.mu.Lock()
	if a.drops[dropLocalQuarantine] == nil {
		a.drops[dropLocalQuarantine] = map[spool.Class]uint64{}
	}
	a.drops[dropLocalQuarantine][class]++
	a.mu.Unlock()
	return fmt.Errorf("%w: %s", ErrQuarantined, detail)
}

// classOf is the class-tag stage: the billing-grade set is CLOSED at exactly
// these three families (07 §6); widening it changes what a spool full-stop
// does to a developer's keystroke and is a m1p.v2 conversation.
func classOf(ev *m1pv1.Event) spool.Class {
	switch ev.GetBody().(type) {
	case *m1pv1.Event_Usage, *m1pv1.Event_VerdictEvent, *m1pv1.Event_ReceiptCheckpoint:
		return spool.ClassBilling
	default:
		return spool.ClassDiagnostic
	}
}

// bumpEpoch reads, increments and durably persists the per-device boot
// counter (07 §2: session_epoch). Durability is not optional: a lost bump
// re-issues an epoch and re-creates the duplicate-(session_id, seq) corruption
// ENG-04 exists to kill — hence write-tmp, fsync, rename, fsync-dir.
func bumpEpoch(path string) (uint32, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	prev := uint64(0)
	if b, err := os.ReadFile(path); err == nil {
		n, perr := strconv.ParseUint(string(b), 10, 32)
		if perr != nil {
			return 0, fmt.Errorf("capture: corrupt epoch file %s: %w", path, perr)
		}
		prev = n
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	next := prev + 1
	if next > 1<<32-1 {
		return 0, fmt.Errorf("capture: session_epoch exhausted at %d", prev)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	if _, err := f.WriteString(strconv.FormatUint(next, 10)); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return uint32(next), nil
}
