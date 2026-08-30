package capture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

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
	t.Cleanup(func() { sp.Close() })
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
	t.Cleanup(func() { sp.Close() })
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
