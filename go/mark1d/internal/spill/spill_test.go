package spill

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

var testSession = uuid.MustParse("3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55")

func passRedact(*m1pv1.Event) error { return nil }

// newRig builds a real spool + admitter + drainer over one temp state dir —
// the drain is tested against the actual admission path, never a mock of it.
func newRig(t *testing.T) (*Drainer, *capture.Admitter, *spool.Spool, string) {
	t.Helper()
	stateDir := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(stateDir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(stateDir, "session_epoch"),
		Redact:    passRedact,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(stateDir, adm)
	if err != nil {
		t.Fatal(err)
	}
	d.Settle = 0 // tests write whole records; no in-flight shim to wait for
	return d, adm, sp, stateDir
}

// sealRecord wraps Seal for tests: one ring record, sealed to pub, stamped
// ts. The committed-fixture test below pins the REAL shim's bytes against the
// drain, so the Go Seal twin cannot drift silently.
func sealRecord(t *testing.T, pub, plaintext []byte, ts time.Time) []byte {
	t.Helper()
	rec, err := Seal(pub, plaintext, ts)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// frame builds what the shim actually spills: M1PL(FabricFrame{event}) — the
// output of m1p_wire::encode_frame, which wraps before it frames
// (framing.rs:220). Both layers matter: this helper used to emit M1PL(Event),
// one layer short, and because FabricFrame.event and Event.event_id are both
// field 1 wiretype 2, the missing layer produced no decode error anywhere —
// which is how a drain path that lost 100% of spilled events passed its tests.
func frame(t *testing.T, ev *m1pv1.Event) []byte {
	t.Helper()
	payload, err := proto.Marshal(&m1pv1.FabricFrame{
		Kind: &m1pv1.FabricFrame_Event{Event: ev},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte("M1PL"), 0x01)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload))) // #nosec G115 -- test sizes
	return append(out, payload...)
}

func toolUseEvent(t *testing.T) *m1pv1.Event {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return &m1pv1.Event{
		EventId:   id[:],
		SessionId: testSession[:],
		Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{
			ToolName:  "Bash",
			ToolUseId: "toolu_01SynthSpillTestTTTTT",
		}},
	}
}

func spoolEventIDs(t *testing.T, sp *spool.Spool) [][]byte {
	t.Helper()
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([][]byte, 0, len(recs))
	for _, r := range recs {
		ids = append(ids, append([]byte(nil), r.ID[:16]...))
	}
	return ids
}

func ringPath(stateDir string) string {
	return filepath.Join(stateDir, "spill", "hookshim.ring")
}

// TestDrainReplaysSpilledEventExactlyOnce is the C8 acceptance shape minus
// the shim binary (the committed-fixture test pins the shim's bytes): an
// event sealed to the daemon-minted pubkey lands in the spool exactly once,
// the ring is truncated, and a second drain finds nothing to do.
func TestDrainReplaysSpilledEventExactlyOnce(t *testing.T) {
	d, adm, sp, stateDir := newRig(t)
	pub, err := os.ReadFile(filepath.Join(stateDir, "spill", "spill.pub"))
	if err != nil {
		t.Fatalf("Open must materialize the shim-readable pubkey: %v", err)
	}
	ev := toolUseEvent(t)
	rec := sealRecord(t, pub, frame(t, ev), time.Now())
	if err := os.WriteFile(ringPath(stateDir), rec, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	ids := spoolEventIDs(t, sp)
	if len(ids) != 1 || !bytes.Equal(ids[0], ev.GetEventId()) {
		t.Fatalf("spool holds %d records, want exactly the spilled event once", len(ids))
	}
	if _, err := os.Stat(ringPath(stateDir)); !os.IsNotExist(err) {
		t.Fatal("ring not truncated after a full drain")
	}
	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := spoolEventIDs(t, sp); len(got) != 1 {
		t.Fatalf("second drain duplicated: %d records", len(got))
	}
	if drops := adm.DrainDropped(); len(drops) != 0 {
		t.Fatalf("clean replay accounted losses: %+v", drops)
	}
}

// TestDrainTTLExpiry: entries older than 24 h are swept with receipted expiry
// (08 §4.4) — Dropped{RING_EXPIRED}, never replayed; fresh entries still land.
func TestDrainTTLExpiry(t *testing.T) {
	d, adm, sp, stateDir := newRig(t)
	pub, _ := os.ReadFile(filepath.Join(stateDir, "spill", "spill.pub"))
	now := time.Now()
	stale := sealRecord(t, pub, frame(t, toolUseEvent(t)), now.Add(-TTL-time.Minute))
	fresh := toolUseEvent(t)
	ring := append(stale, sealRecord(t, pub, frame(t, fresh), now)...)
	if err := os.WriteFile(ringPath(stateDir), ring, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	ids := spoolEventIDs(t, sp)
	if len(ids) != 1 || !bytes.Equal(ids[0], fresh.GetEventId()) {
		t.Fatalf("want only the fresh event in the spool, got %d records", len(ids))
	}
	drops := adm.DrainDropped()
	if len(drops) != 1 || drops[0].Reason != dropRingExpired || drops[0].Quantity != 1 {
		t.Fatalf("expired entry not accounted RING_EXPIRED: %+v", drops)
	}
	if _, err := os.Stat(ringPath(stateDir)); !os.IsNotExist(err) {
		t.Fatal("ring not truncated after expiry sweep")
	}
}

// TestDrainShedCounter: the shim's overflow sidecar (one byte per event the
// 64 MiB writer cap refused, spill.rs) converts to Dropped{RING_EVICTED} with
// the exact quantity, and resets.
func TestDrainShedCounter(t *testing.T) {
	d, adm, _, stateDir := newRig(t)
	shed := filepath.Join(stateDir, "spill", "hookshim.ring.shed")
	if err := os.WriteFile(shed, []byte{1, 1, 1}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	drops := adm.DrainDropped()
	if len(drops) != 1 || drops[0].Reason != dropRingEvicted || drops[0].Quantity != 3 {
		t.Fatalf("shed counter not accounted RING_EVICTED×3: %+v", drops)
	}
	if _, err := os.Stat(shed); !os.IsNotExist(err) {
		t.Fatal("shed sidecar not reset after accounting")
	}
	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if drops := adm.DrainDropped(); len(drops) != 0 {
		t.Fatalf("shed counter double-accounted: %+v", drops)
	}
}

// TestDrainQuarantinesUnreadableEntries: an entry the drain cannot unseal or
// unframe is counted (LOCAL_QUARANTINE) and the ring still truncates — the
// drain-side half of spill.rs's "the daemon then quarantines the entry".
func TestDrainQuarantinesUnreadableEntries(t *testing.T) {
	d, adm, sp, stateDir := newRig(t)
	pub, _ := os.ReadFile(filepath.Join(stateDir, "spill", "spill.pub"))
	garbage := sealRecord(t, pub, frame(t, toolUseEvent(t)), time.Now())
	garbage[len(garbage)-1] ^= 0xFF // break the AEAD tag
	ok := toolUseEvent(t)
	ring := append(garbage, sealRecord(t, pub, frame(t, ok), time.Now())...)
	if err := os.WriteFile(ringPath(stateDir), ring, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ids := spoolEventIDs(t, sp); len(ids) != 1 || !bytes.Equal(ids[0], ok.GetEventId()) {
		t.Fatalf("intact entry must still drain around the broken one: %d records", len(ids))
	}
	drops := adm.DrainDropped()
	if len(drops) != 1 || drops[0].Reason != dropLocalQuarantine || drops[0].Quantity != 1 {
		t.Fatalf("broken entry not quarantine-accounted: %+v", drops)
	}
	if _, err := os.Stat(ringPath(stateDir)); !os.IsNotExist(err) {
		t.Fatal("ring not truncated")
	}
}

// TestDrainRustSealedFixture locks the two ends of the ring together across
// languages: testdata/hookshim.ring holds bytes the REAL mark1-hookshim
// binary spilled (generated by running the shim with no daemon against the
// deterministic [7u8;32] device seed — the same seed shim_e2e.rs pins), and
// the drain must replay them through admission. The TTL clock is pinned to
// the fixture's own timestamp so a frozen ring never ages out of the test.
func TestDrainRustSealedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "hookshim.ring"))
	if err != nil {
		t.Fatalf("committed fixture missing (a vacuous pass proves nothing): %v", err)
	}
	stateDir := t.TempDir()
	seed := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(filepath.Join(stateDir, "spill.key"), seed, 0o600); err != nil {
		t.Fatal(err)
	}
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(stateDir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(stateDir, "session_epoch"),
		Redact:    passRedact,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(stateDir, adm)
	if err != nil {
		t.Fatal(err)
	}
	d.Settle = 0
	recs, torn := parseRing(raw)
	if torn || len(recs) != 1 {
		t.Fatalf("fixture drifted: %d records, torn=%v", len(recs), torn)
	}
	d.Now = func() time.Time { return time.Unix(recs[0].unixSecs, 0) }
	if err := os.WriteFile(ringPath(stateDir), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := d.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	spooled, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(spooled) != 1 {
		t.Fatalf("shim-sealed fixture yielded %d spool records, want 1", len(spooled))
	}
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(spooled[0].Payload, ev); err != nil {
		t.Fatal(err)
	}
	tu := ev.GetToolUse()
	if tu.GetToolName() != "Bash" || tu.GetToolUseId() != "toolu_01SynthFixtureTTTTTTTT" {
		t.Fatalf("fixture event decoded to %+v — the two ring ends disagree", ev.GetBody())
	}
	if drops := adm.DrainDropped(); len(drops) != 0 {
		t.Fatalf("shim-sealed entry did not replay cleanly: %+v", drops)
	}
}
