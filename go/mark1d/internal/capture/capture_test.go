package capture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

func passRedact(*m1pv1.Event) error { return nil }

func openSpool(t *testing.T, dir string) *spool.Spool {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	return sp
}

func usageEvent(session byte) *m1pv1.Event {
	sid := make([]byte, 16)
	sid[0] = session
	return &m1pv1.Event{
		SessionId: sid,
		Body:      &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32), OutputTokens: 1}},
	}
}

func toolEvent(session byte) *m1pv1.Event {
	sid := make([]byte, 16)
	sid[0] = session
	return &m1pv1.Event{
		SessionId: sid,
		Body:      &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{}},
	}
}

// TestEpochAndSeq pins 07 §2: session_epoch bumps once per boot from durable
// storage, and (session_epoch, seq) stays unique across a restart that
// re-admits into a still-live session — the ENG-04 corruption.
func TestEpochAndSeq(t *testing.T) {
	dir := t.TempDir()
	epochPath := filepath.Join(dir, "epoch")
	sp := openSpool(t, filepath.Join(dir, "spool"))

	a1, err := New(sp, Config{EpochPath: epochPath, Redact: passRedact})
	if err != nil {
		t.Fatal(err)
	}
	if a1.Epoch() != 1 {
		t.Fatalf("first boot epoch = %d, want 1", a1.Epoch())
	}
	ctx := context.Background()
	evA1, evA2, evB1 := usageEvent(0xA), usageEvent(0xA), usageEvent(0xB)
	for _, ev := range []*m1pv1.Event{evA1, evA2, evB1} {
		if err := a1.Admit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	if evA1.GetSeq() != 1 || evA2.GetSeq() != 2 {
		t.Fatalf("per-session seq = %d,%d, want 1,2", evA1.GetSeq(), evA2.GetSeq())
	}
	if evB1.GetSeq() != 1 {
		t.Fatalf("independent session started at seq %d, want 1", evB1.GetSeq())
	}
	if evA1.GetSessionEpoch() != 1 {
		t.Fatalf("session_epoch = %d, want 1", evA1.GetSessionEpoch())
	}
	if len(evA1.GetEventId()) != 16 || string(evA1.GetEventId()) == string(evA2.GetEventId()) {
		t.Fatal("event_id must be minted, 16 bytes, unique")
	}

	// "Restart": a second Admitter over the same durable counter.
	a2, err := New(sp, Config{EpochPath: epochPath, Redact: passRedact})
	if err != nil {
		t.Fatal(err)
	}
	if a2.Epoch() != 2 {
		t.Fatalf("second boot epoch = %d, want 2", a2.Epoch())
	}
	evA3 := usageEvent(0xA)
	if err := a2.Admit(ctx, evA3); err != nil {
		t.Fatal(err)
	}
	// seq restarts at 1 — the epoch is what keeps (epoch, seq) unique and
	// the (2,1) > (1,2) lexicographic order correct (07 §2 ordering rule).
	if evA3.GetSeq() != 1 || evA3.GetSessionEpoch() != 2 {
		t.Fatalf("post-restart stamp = (%d,%d), want (2,1)", evA3.GetSessionEpoch(), evA3.GetSeq())
	}
}

// TestEventIDsAreMethod1UUIDv7AndBurstMonotonic covers the first two of
// FR-SPINE-001's three acceptance clauses: minted ids parse as RFC 9562
// UUIDv7, and a burst from one daemon is STRICTLY increasing. TestEpochAndSeq
// checks only len==16 and that two ids differ, which a v4 would also satisfy —
// and v4 would quietly break the property 07 §2 rests the whole ordering story
// on, that spool order, id order and the ClickHouse ordering component agree
// by construction rather than by luck.
//
// The third clause ("seq gaps within a session fail the check") is NOT covered
// here: no consumer in this repo reads a seq stream and rejects a hole. That is
// a missing consumer, not a missing test, and the traceability entry says so.
func TestEventIDsAreMethod1UUIDv7AndBurstMonotonic(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, filepath.Join(dir, "spool"))
	a, err := New(sp, Config{EpochPath: filepath.Join(dir, "epoch"), Redact: passRedact})
	if err != nil {
		t.Fatal(err)
	}

	const n = 512
	ctx := context.Background()
	ids := make([][]byte, 0, n)
	before := time.Now()
	for i := 0; i < n; i++ {
		ev := usageEvent(0xC)
		if err := a.Admit(ctx, ev); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ev.GetEventId())
	}
	after := time.Now()

	unixMilli := func(id []byte) int64 {
		var ms int64
		for _, b := range id[:6] {
			ms = ms<<8 | int64(b)
		}
		return ms
	}

	for i, id := range ids {
		if len(id) != 16 {
			t.Fatalf("id %d is %d bytes, want 16", i, len(id))
		}
		if v := id[6] >> 4; v != 7 {
			t.Fatalf("id %d has version nibble %d, want 7 — this is not a UUIDv7", i, v)
		}
		if id[8]&0xC0 != 0x80 {
			t.Fatalf("id %d has variant bits %#02x, want RFC 9562 (0b10xxxxxx)", i, id[8]&0xC0)
		}
		// A v4 read as v7 would put random bytes in the timestamp field, so this
		// is what makes the version nibble above more than a formality.
		//
		// The slack is deliberately a minute and must not be tightened: random
		// bytes in id[:6] land somewhere in a ~280,000-year range, so a minute
		// and a second discriminate identically — but a second does not survive
		// a host clock resync. Observed 2026-08-31 under WSL2 just after a 60 s
		// fuzz run: id 0 carried a wall time 1.44 s past `after` while
		// before..after spanned 1.8 ms, which only a non-monotonic clock can
		// produce. The minter cannot drift that far (google/uuid advances at
		// 1/4096 ms per same-millisecond collision, and 512 ids are minted here).
		ts := time.UnixMilli(unixMilli(id))
		if ts.Before(before.Add(-time.Minute)) || ts.After(after.Add(time.Minute)) {
			t.Fatalf("id %d carries timestamp %s, outside the generation window [%s, %s]",
				i, ts, before, after)
		}
	}

	shared := 0
	for i := 1; i < n; i++ {
		if bytes.Compare(ids[i-1], ids[i]) >= 0 {
			t.Fatalf("ids %d and %d are not strictly increasing (%x then %x); Method-1's "+
				"per-daemon counter is what makes spool order and id order the same order",
				i-1, i, ids[i-1], ids[i])
		}
		if unixMilli(ids[i-1]) == unixMilli(ids[i]) {
			shared++
		}
	}
	if shared == 0 {
		t.Fatalf("no two of %d consecutive admissions shared a millisecond, so the ordering "+
			"above was carried by the clock and the Method-1 counter went unexercised", n)
	}
}

// TestClassTag pins the closed billing-grade set on the spool's class byte
// (07 §6): usage ⇒ 1, everything else ⇒ 2.
func TestClassTag(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, filepath.Join(dir, "spool"))
	a, err := New(sp, Config{EpochPath: filepath.Join(dir, "epoch"), Redact: passRedact})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.Admit(ctx, usageEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := a.Admit(ctx, toolEvent(1)); err != nil {
		t.Fatal(err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("spool holds %d records, want 2", len(recs))
	}
	if recs[0].ID.Class() != spool.ClassBilling || recs[1].ID.Class() != spool.ClassDiagnostic {
		t.Fatalf("class bytes = %d,%d, want 1,2", recs[0].ID.Class(), recs[1].ID.Class())
	}
	// record_id[0..16) IS the event_id (07 §6) — the spool cursor and the
	// wire dedupe key must name the same object.
	var ev m1pv1.Event
	if err := proto.Unmarshal(recs[0].Payload, &ev); err != nil {
		t.Fatal(err)
	}
	if string(recs[0].ID[:16]) != string(ev.GetEventId()) {
		t.Fatal("record_id[0..16) != event_id")
	}
}

// TestClassCensusIsClosedOverEveryBodyType is TestClassTag's missing half.
// That test admits two events and reads two class bytes; classOf's billing arm
// names three families and the oneof has twenty-three, so moving verdict_event
// or receipt_checkpoint into the `default:` arm would shed billing-grade data
// on a full spool with the whole suite green (NFR-DURABILITY-001).
//
// 07 §6 closes the billing set at exactly usage, verdict_event and
// receipt_checkpoint, and says widening it is an m1p.v2 conversation because it
// changes what a full spool does to a developer's keystroke. So the census is
// enumerated from the PROTO's oneof, not from a list of the cases that happen
// to exist here: a new event family arrives with no row and fails this test
// until someone classifies it, rather than inheriting `default: diagnostic` in
// silence — which for a family that ought to be billing-grade is data loss.
func TestClassCensusIsClosedOverEveryBodyType(t *testing.T) {
	want := map[string]spool.Class{
		"Usage":              spool.ClassBilling,
		"VerdictEvent":       spool.ClassBilling,
		"ReceiptCheckpoint":  spool.ClassBilling,
		"SessionStart":       spool.ClassDiagnostic,
		"SessionEnd":         spool.ClassDiagnostic,
		"TaskOpen":           spool.ClassDiagnostic,
		"TaskClose":          spool.ClassDiagnostic,
		"Turn":               spool.ClassDiagnostic,
		"ToolUse":            spool.ClassDiagnostic,
		"ModelRequest":       spool.ClassDiagnostic,
		"ModelResponse":      spool.ClassDiagnostic,
		"CoverageTransition": spool.ClassDiagnostic, // per-event receipted AND diagnostic — 07 §6 names it
		"GuardDecision":      spool.ClassDiagnostic,
		"EdgeHealth":         spool.ClassDiagnostic,
		"AnchorVote":         spool.ClassDiagnostic,
		"JudgeVote":          spool.ClassDiagnostic,
		"RmScore":            spool.ClassDiagnostic,
		"ConsistencyVote":    spool.ClassDiagnostic,
		"CortexInjection":    spool.ClassDiagnostic,
		"MemoryInjection":    spool.ClassDiagnostic,
		"ArtifactOutcome":    spool.ClassDiagnostic,
		"RouteDecision":      spool.ClassDiagnostic,
		"EvidenceExcerpt":    spool.ClassDiagnostic,
	}

	od := (&m1pv1.Event{}).ProtoReflect().Descriptor().Oneofs().ByName("body")
	if od == nil {
		t.Fatal("Event has no `body` oneof — 07 §2's envelope shape changed and this census covers nothing")
	}
	if od.Fields().Len() == 0 {
		t.Fatal("the body oneof enumerated zero arms; this test would pass over nothing")
	}

	seen := map[string]bool{}
	for i := 0; i < od.Fields().Len(); i++ {
		fd := od.Fields().Get(i)
		name := string(fd.Message().Name())
		seen[name] = true
		exp, ok := want[name]
		if !ok {
			t.Errorf("%s is a body arm with no row in this census. Classify it: silence means "+
				"classOf's `default:` arm, i.e. diagnostic, i.e. dropped first when the spool fills", name)
			continue
		}
		ev := &m1pv1.Event{}
		ev.ProtoReflect().Mutable(fd)
		if got := classOf(ev); got != exp {
			t.Errorf("classOf(%s) = %d, want %d", name, got, exp)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s has a census row but is no longer a body arm — the row vouches for nothing", name)
		}
	}
}

// TestSessionExemptionIsClosedOverEveryBodyType is the class census's sibling
// for the OTHER set that must not drift: which bodies may be admitted with no
// session_id. Every event names a session because (session_epoch, seq) is 07
// §2's uniqueness pair; the exempt bodies are the ones reporting on the machine
// instead, and they share the reserved all-zero seq slot. Widening this set
// silently would let a session-scoped family take a device counter — a
// (session_epoch, seq) collision with every other exempt writer on the box —
// and narrowing it would strand the sealer, whose checkpoints are per-device
// and whose batches may contain no session at all.
func TestSessionExemptionIsClosedOverEveryBodyType(t *testing.T) {
	// CoverageTransition joins the two originals because it has nowhere to put a
	// session even if we wanted one: the message carries workspace_id and no
	// session field (proto/m1p/v1/intelligence.proto), and every one of 04 §2.7's
	// seven reason codes names a condition that exists when no session does —
	// `mark1 off`, a hard-stopped disk, a proxy that will not start.
	exempt := map[string]bool{"EdgeHealth": true, "ReceiptCheckpoint": true, "CoverageTransition": true}

	od := (&m1pv1.Event{}).ProtoReflect().Descriptor().Oneofs().ByName("body")
	if od == nil || od.Fields().Len() == 0 {
		t.Fatal("the body oneof enumerated zero arms; this test would pass over nothing")
	}
	seen := map[string]bool{}
	for i := 0; i < od.Fields().Len(); i++ {
		fd := od.Fields().Get(i)
		name := string(fd.Message().Name())
		seen[name] = true
		ev := &m1pv1.Event{}
		ev.ProtoReflect().Mutable(fd)
		if got := deviceScoped(ev); got != exempt[name] {
			t.Errorf("deviceScoped(%s) = %v, want %v", name, got, exempt[name])
		}
	}
	for name := range exempt {
		if !seen[name] {
			t.Errorf("%s is exempted from naming a session but is no longer a body arm", name)
		}
	}
}

// TestQuarantineFailClosed pins 04 §2.0: a redact-admit failure never admits
// raw bytes — the event is dropped, accounted LOCAL_QUARANTINE, and the error
// is typed per-event so the fabric keeps the connection.
func TestQuarantineFailClosed(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, filepath.Join(dir, "spool"))
	boom := errors.New("scanner down")
	a, err := New(sp, Config{
		EpochPath: filepath.Join(dir, "epoch"),
		Redact:    func(*m1pv1.Event) error { return boom },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Admit(context.Background(), usageEvent(1)); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("scanner failure admitted the event: %v", err)
	}
	if err := a.AdmitBytes(context.Background(), []byte{0xff, 0xff, 0xff}); !errors.Is(err, ErrQuarantined) {
		t.Fatal("undecodable payload was not quarantined")
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, write := sp.Cursors()
	if recs, _, _ := sp.Records(ack); len(recs) != 0 {
		t.Fatalf("quarantined event reached disk: %d records at %v..%v", len(recs), ack, write)
	}
	drops := a.DrainDropped()
	if len(drops) != 2 { // one billing-class quarantine, one classless (diagnostic) decode failure
		t.Fatalf("drop ledger rows = %v, want 2", drops)
	}
	for _, d := range drops {
		if d.Reason != spool.DropReason(4) || d.Quantity != 1 {
			t.Fatalf("unexpected drop row %+v", d)
		}
	}
	if len(a.DrainDropped()) != 0 {
		t.Fatal("DrainDropped must reset (read-and-reset contract)")
	}
}

// TestAdmissionBound1MiB pins 07 §6's typed-event bound: a 2 MiB event is
// refused BEFORE spooling with Dropped{LOCAL_QUARANTINE} accounting; a
// 900 KiB event admits — the 4 MiB fabric/spool bounds are transport headroom,
// not event legality.
func TestAdmissionBound1MiB(t *testing.T) {
	dir := t.TempDir()
	sp := openSpool(t, filepath.Join(dir, "spool"))
	a, err := New(sp, Config{EpochPath: filepath.Join(dir, "epoch"), Redact: passRedact})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	big := toolEvent(1)
	big.GetToolUse().ToolName = string(bytes.Repeat([]byte{'x'}, 2<<20))
	if err := a.Admit(ctx, big); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("2 MiB event admitted: %v", err)
	}
	ok := toolEvent(1)
	ok.GetToolUse().ToolName = string(bytes.Repeat([]byte{'x'}, 900<<10))
	if err := a.Admit(ctx, ok); err != nil {
		t.Fatalf("900 KiB event refused: %v", err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || len(recs[0].Payload) < 900<<10 {
		t.Fatalf("spool holds %d records, want exactly the 900 KiB event", len(recs))
	}
	drops := a.DrainDropped()
	if len(drops) != 1 || drops[0].Reason != dropLocalQuarantine ||
		drops[0].Class != spool.ClassDiagnostic || drops[0].Quantity != 1 {
		t.Fatalf("drop ledger = %+v, want one Dropped{LOCAL_QUARANTINE, DIAGNOSTIC, 1}", drops)
	}
}

// TestDiagnosticShed pins the class split under a full spool: diagnostics
// shed to ErrShed (accounted in the spool ledger), never silently.
func TestDiagnosticShed(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool"), SegmentSize: 4096, SpoolCap: 300})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	a, err := New(sp, Config{EpochPath: filepath.Join(dir, "epoch"), Redact: passRedact})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	shed := false
	for i := 0; i < 100; i++ {
		if err := a.Admit(ctx, toolEvent(1)); errors.Is(err, ErrShed) {
			shed = true
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if !shed {
		t.Fatal("full spool never shed a diagnostic")
	}
	found := false
	for _, d := range sp.DrainDropped() {
		if d.Reason == spool.DropSpoolShed && d.Class == spool.ClassDiagnostic && d.Quantity >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatal("shed was not accounted in the spool drop ledger")
	}
}

// TestRedactSubstitutionPreSpool is 12 §3.2's `redact_substitution_pre_spool`
// (F-36) at the capture seam with the REAL Go admit twin wired — the same
// wiring cmd/main.go ships: a planted secret admitted through the pipeline
// must be `⟨redacted:class:hash⟩` in every byte the spool persists.
func TestRedactSubstitutionPreSpool(t *testing.T) {
	dir := t.TempDir()
	sc, err := redact.NewScanner([]byte("capture-test-tenant-key"))
	if err != nil {
		t.Fatal(err)
	}
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(sp, Config{EpochPath: filepath.Join(dir, "epoch"), Redact: sc.RedactEvent})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "AKIAIOSFODNN7EXAMPLE"
	ev := usageEvent(1)
	ev.GetUsage().ServiceTier = "tier " + secret
	if err := a.Admit(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	var sawToken bool
	err = filepath.WalkDir(filepath.Join(dir, "spool"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("pre-redaction plaintext persisted in %s (invariant 5, 04 §0.3)", path)
		}
		if bytes.Contains(raw, []byte("redacted:api_key:")) {
			sawToken = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawToken {
		t.Fatal("no redaction token on disk — the event never landed, so the assertion proved nothing")
	}
}

// TestAllZeroSessionIsNotAdmitted is D-AL at the seq authority: session_id is
// OPTIONAL on the wire, so all-zero is "absent" spelled as present. Admitted, it
// becomes the one seq counter every session-less writer on the box shares, and
// (session_epoch, seq) — 07 §2's uniqueness pair — stops being unique.
func TestAllZeroSessionIsNotAdmitted(t *testing.T) {
	dir := t.TempDir()
	a, err := New(openSpool(t, filepath.Join(dir, "spool")), Config{
		EpochPath: filepath.Join(dir, "epoch"), Redact: passRedact,
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := usageEvent(0) // sid[0]=0 over a zeroed 16-byte array: all-zero
	if err := a.Admit(context.Background(), ev); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("Admit(all-zero session) = %v, want it quarantined and accounted", err)
	}
	if got := a.DrainDropped(); len(got) != 1 || got[0].Quantity != 1 {
		t.Fatalf("loss ledger %+v, want exactly one accounted drop", got)
	}
}
