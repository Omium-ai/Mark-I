package obs

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// harness wires the REAL path — spool, then the one admission door — because
// the property under test is "health reaches the spool the way every other
// event does". A fake Admit would pass while obs emitted onto a second path.
func harness(t *testing.T, clock *time.Time) (*Health, *spool.Spool) {
	t.Helper()
	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	// The first boot, constructed for its side effect on the epoch file alone —
	// the handle is deliberately dropped.
	if _, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	// Two Admitters over one epoch file is how capture_test spells "restart";
	// the second boot is the one whose Epoch() must read as restarts=1.
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{
		EdgeVersion: "0.1.0-test",
		SpoolDir:    spoolDir,
		Admit:       adm.Admit,
		BootCount:   adm.Epoch(),
		Now:         func() time.Time { return *clock },
	}), sp
}

func admitted(t *testing.T, sp *spool.Spool) []spool.Record {
	t.Helper()
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func decode(t *testing.T, r spool.Record) *m1pv1.Event {
	t.Helper()
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(r.Payload, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestEdgeHealthIsAdmittedAsDiagnostic pins the three properties 11 §2.3 makes
// normative about the emission itself: it goes through capture (so it is
// spooled, sequenced and shed like everything else), it carries NO session_id
// (health is per-device), and it lands diagnostic-class — the class that sheds
// first and whose shedding is still counted in Dropped{}.
func TestEdgeHealthIsAdmittedAsDiagnostic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h, sp := harness(t, &now)

	h.Delivered()
	h.Spilled(3)
	h.Quarantined()
	h.Parked(true)
	h.Bundle(42, uint64(now.Add(-90*time.Second).Unix()), true)
	h.GateAnswer(200*time.Microsecond, m1pv1.GateDecision_GATE_DECISION_ALLOW)
	h.GateAnswer(300*time.Microsecond, m1pv1.GateDecision_GATE_DECISION_BLOCK)
	h.GateTimeout()

	now = now.Add(time.Minute) // uptime
	h.Cycle(context.Background(), now.Add(-10*time.Second), now.Add(-25*time.Second))

	recs := admitted(t, sp)
	if len(recs) != 1 {
		t.Fatalf("spool holds %d records, want exactly one EdgeHealth", len(recs))
	}
	if recs[0].ID.Class() != spool.ClassDiagnostic {
		t.Fatalf("EdgeHealth landed class %d; health must never be billing-grade (it would then BLOCK a full spool)", recs[0].ID.Class())
	}
	ev := decode(t, recs[0])
	if len(ev.GetSessionId()) != 0 {
		t.Fatalf("EdgeHealth carries a session_id (%x); 11 §2.3 makes health per-device, not per-session", ev.GetSessionId())
	}
	eh := ev.GetEdgeHealth()
	if eh == nil {
		t.Fatalf("admitted body is %T, want EdgeHealth", ev.GetBody())
	}

	if eh.GetEdgeVersion() != "0.1.0-test" {
		t.Fatalf("edge_version = %q — the A-14 cohort key must survive the round trip", eh.GetEdgeVersion())
	}
	if got := eh.GetMark1D(); got.GetRestarts() != 1 || got.GetUptimeS() != 60 {
		t.Fatalf("mark1d = %+v, want restarts 1 uptime 60", got)
	}
	if got := eh.GetShim(); got.GetDelivered() != 1 || got.GetSpilled() != 3 {
		t.Fatalf("shim = %+v, want delivered 1 spilled 3", got)
	}
	if got := eh.GetUplink(); got.GetParked() != 1 || got.GetQuarantined() != 1 || got.GetLastAckAgeS() != 10 {
		t.Fatalf("uplink = %+v, want parked 1 quarantined 1 last_ack_age_s 10", got)
	}
	if got := eh.GetSpool(); got.GetOldestUnackedAgeS() != 25 || got.GetSegments() == 0 || got.GetBytesUsed() == 0 {
		t.Fatalf("spool = %+v, want age 25 and a non-empty on-disk tally", got)
	}
	if got := eh.GetBundle(); got.GetSeq() != 42 || got.GetAgeS() != 150 || !got.GetStale() {
		t.Fatalf("bundle = %+v, want seq 42 age 150 stale — age_s is publication age, not hold time", got)
	}
	// timeouts are a subset of allows, not a third bucket: 2 reads, 1 block.
	if got := eh.GetGate(); got.GetReads() != 2 || got.GetAllows() != 1 || got.GetBlocks() != 1 || got.GetTimeouts() != 1 {
		t.Fatalf("gate = %+v, want reads 2 allows 1 blocks 1 timeouts 1", got)
	}
	// 300 µs has bit-length 9, so the bucket's upper bound is 2^9-1 = 511.
	if got := eh.GetGate().GetReadP99Us(); got != 511 {
		t.Fatalf("read_p99_us = %d, want the 511 µs bucket bound", got)
	}
	// Nothing mark1d does not supervise may be encoded as a zeroed sub-message:
	// that reads as a healthy idle child rather than an absent one.
	if eh.GetCortexd() != nil || eh.GetProxy() != nil || eh.GetProxyLatency() != nil || eh.GetCortex() != nil {
		t.Fatal("an unsupervised child was encoded as a zero-valued ProcessHealth")
	}
}

// TestEmitIsRateLimited pins the other half of the cadence: one per successful
// uploader cycle AND at most one per 15 minutes per device. A busy uploader
// must not turn diagnostics into traffic.
func TestEmitIsRateLimited(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	h, sp := harness(t, &now)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		now = now.Add(time.Minute)
		h.Cycle(ctx, now, time.Time{})
	}
	if n := len(admitted(t, sp)); n != 1 {
		t.Fatalf("5 cycles inside one window emitted %d events, want 1", n)
	}

	now = now.Add(EmitEvery)
	h.Cycle(ctx, now, time.Time{})
	if n := len(admitted(t, sp)); n != 2 {
		t.Fatalf("a cycle a full window later emitted %d events total, want 2", n)
	}

	// The digest is per-window, so the second event must not re-report the
	// first window's latency.
	if p99 := decode(t, admitted(t, sp)[1]).GetEdgeHealth().GetGate().GetReadP99Us(); p99 != 0 {
		t.Fatalf("read_p99_us = %d in a window with no gate reads; the digest is not read-and-reset", p99)
	}
}

// TestNilHealthIsInert is the whole reason every mutator has a nil guard: an
// unwired gauge must never change what the daemon does, and the call sites
// (gate.Answer's defer above all) run before wiring in every test in this repo.
func TestNilHealthIsInert(t *testing.T) {
	var h *Health
	h.Delivered()
	h.Spilled(1)
	h.Quarantined()
	h.Parked(true)
	h.Bundle(1, 1, true)
	h.GateAnswer(time.Millisecond, m1pv1.GateDecision_GATE_DECISION_BLOCK)
	h.GateTimeout()
	h.Cycle(context.Background(), time.Now(), time.Now())
	h.Emit(context.Background())
}

// TestAgeSNeverReportsTheEpoch: a never-set instant is age 0, and a stepped
// clock is age 0 — never "since 1970", which would trip every age alert on a
// device that simply has not acked yet.
func TestAgeSNeverReportsTheEpoch(t *testing.T) {
	if got := ageS(0, time.Now().Unix(), 1); got != 0 {
		t.Fatalf("unset instant reported age %d", got)
	}
	if got := ageS(500, 100, 1); got != 0 {
		t.Fatalf("backwards clock reported age %d", got)
	}
}
