package uplink

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

var t0 = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

// plantQuarantine writes the daemon's own on-disk pair (quarantine.go:59/:74 shape) dated `at`.
func plantQuarantine(t *testing.T, dir, id string, at time.Time, events int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	man, _ := json.Marshal(manifest{BatchID: id, Status: 400, ErrCode: "M1E-2001", EventCount: events, QuarantinedAt: at.UTC().Format(time.RFC3339Nano)})
	for name, body := range map[string][]byte{id + ".m1p.zst.sealed": []byte("sealed-bytes"), id + ".manifest.json": man} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func readReceipt(t *testing.T, dir, id string) (deletionReceipt, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, id+deletionSuffix))
	if err != nil {
		t.Fatalf("deletion receipt missing: %v", err)
	}
	var rec deletionReceipt
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	decoded, err := identity.DecodePayload([]byte(rec.Payload))
	if err != nil {
		t.Fatalf("receipt payload is not canonical JSON: %v", err)
	}
	return rec, decoded.(map[string]any)
}

// TestQuarantineSweepDeletesAtThirtyDaysExactly: 29 d 23 h is kept, 30 d 0 h is deleted and receipted.
func TestQuarantineSweepDeletesAtThirtyDaysExactly(t *testing.T) {
	now := t0
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) { c.Now = func() time.Time { return now } })
	const keep, gone = "0192a1b2-0000-7000-8000-00000000000a", "0192a1b2-0000-7000-8000-00000000000b"
	plantQuarantine(t, qdir, keep, now.Add(-(29*24*time.Hour + 23*time.Hour)), 3)
	plantQuarantine(t, qdir, gone, now.Add(-30*24*time.Hour), 2)

	if n := u.sweepQuarantine(context.Background(), now); n != 1 {
		t.Fatalf("deleted %d, want exactly the 30 d batch", n)
	}
	for _, suffix := range []string{".m1p.zst.sealed", ".manifest.json"} {
		if !exists(t, filepath.Join(qdir, keep+suffix)) {
			t.Fatalf("%s: 29 d 23 h is inside the window and must be kept", keep+suffix)
		}
		if exists(t, filepath.Join(qdir, gone+suffix)) {
			t.Fatalf("%s: 30 d 0 h is at the window and must be deleted", gone+suffix)
		}
	}
	if exists(t, filepath.Join(qdir, keep+deletionSuffix)) {
		t.Fatal("a kept batch must not carry a deletion receipt")
	}
	_, payload := readReceipt(t, qdir, gone)
	want := map[string]any{
		"v": json.Number("1"), "type": "quarantine_deletion", "batch_id": gone, "event_count": json.Number("2"),
		"quarantined_at": now.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano),
		"deleted_at":     now.Format(time.RFC3339Nano), "reason": "retention_30d",
	}
	for k, v := range want {
		if payload[k] != v {
			t.Fatalf("receipt %s = %v, want %v (payload %s)", k, payload[k], v, payload)
		}
	}
	if _, ok := payload["note"]; ok {
		t.Fatalf("a readable manifest needs no provenance note: %v", payload)
	}

	var rec sweepRecord
	raw, err := os.ReadFile(filepath.Join(qdir, sweepRecordFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Deleted != 1 || rec.SweptAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("sweep record %s (%v): want deleted=1 at %s", raw, err, now.Format(time.RFC3339Nano))
	}
}

// TestQuarantineDeletionReceiptIsDeviceSigned: with an enrolled identity the receipt is origin-signed over the
// canonical payload (identity.OriginSign), verifiable under the device key by an offline auditor.
func TestQuarantineDeletionReceiptIsDeviceSigned(t *testing.T) {
	seedPath := filepath.Join(t.TempDir(), "device.key")
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: seedPath})
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := os.ReadFile(seedPath)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) {
		c.Now = func() time.Time { return t0 }
		c.Origin = &Origin{Key: key, TenantID: "9d2b1f0e-1111-4111-8111-111111111111", DeviceID: "9d2b1f0e-2222-4222-8222-222222222222"}
	})
	const id = "0192a1b2-0000-7000-8000-00000000000c"
	plantQuarantine(t, qdir, id, t0.Add(-31*24*time.Hour), 1)
	if n := u.sweepQuarantine(context.Background(), t0); n != 1 {
		t.Fatalf("deleted %d", n)
	}
	rec, payload := readReceipt(t, qdir, id)
	if payload["device_key_id"] != key.KeyID() || payload["tenant_id"] != u.origin.TenantID || payload["device_id"] != u.origin.DeviceID {
		t.Fatalf("identity must ride inside the signed bytes: %v", payload)
	}
	sig, err := hex.DecodeString(rec.DeviceSignature)
	if err != nil {
		t.Fatal(err)
	}
	signed := append([]byte(identity.DomainPrefix), rec.Payload...)
	if !identity.Verify(pub, sig, signed) {
		t.Fatal("device signature does not verify over DomainPrefix || payload")
	}
	if h, _ := identity.ReceiptHash(payload); hex.EncodeToString(h[:]) != rec.ReceiptHash {
		t.Fatalf("receipt_hash %s is not the hash of the signing input", rec.ReceiptHash)
	}
	if canon, _ := identity.CanonicalJSON(payload); canon != rec.Payload {
		t.Fatal("stored payload is not its own canonical serialisation")
	}
	tampered := strings.Replace(rec.Payload, `"reason":"retention_30d"`, `"reason":"operator"`, 1)
	if identity.Verify(pub, sig, append([]byte(identity.DomainPrefix), tampered...)) {
		t.Fatal("signature verified over altered bytes")
	}
}

// TestQuarantineSweepReceiptsOrphansByMtime: a crash between the sealed write and the manifest (quarantine.go:59/:74)
// leaves customer bytes with no date; the sweep dates them by mtime and says so in the receipt.
func TestQuarantineSweepReceiptsOrphansByMtime(t *testing.T) {
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) { c.Now = func() time.Time { return t0 } })
	const orphan, torn = "0192a1b2-0000-7000-8000-00000000000d", "0192a1b2-0000-7000-8000-00000000000e"
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := t0.Add(-40 * 24 * time.Hour)
	for _, name := range []string{orphan + ".m1p.zst.sealed", torn + ".m1p.zst.sealed", torn + ".manifest.json"} {
		if err := os.WriteFile(filepath.Join(qdir, name), []byte(`{"batch_id": "x", "status": 4`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(filepath.Join(qdir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if n := u.sweepQuarantine(context.Background(), t0); n != 2 {
		t.Fatalf("deleted %d, want the orphan and the torn pair", n)
	}
	for _, id := range []string{orphan, torn} {
		if exists(t, filepath.Join(qdir, id+".m1p.zst.sealed")) {
			t.Fatalf("%s: undated customer bytes past the window must still go", id)
		}
		rec, payload := readReceipt(t, qdir, id)
		if payload["quarantined_at"] != old.Format(time.RFC3339Nano) || payload["event_count"] != json.Number("0") || rec.Note != "manifest unreadable; quarantined_at is the file mtime" {
			t.Fatalf("%s receipt must name the mtime fallback: %v %+v", id, payload, rec)
		}
		if _, ok := payload["note"]; ok {
			t.Fatalf("%s: provenance must not enter the signed bytes (controld rebuilds them from the wire): %v", id, payload)
		}
	}
	if exists(t, filepath.Join(qdir, torn+".manifest.json")) {
		t.Fatal("torn manifest left behind")
	}
}

// TestQuarantineSweepIsReceiptFirst: a receipt that cannot be produced keeps the bytes (no receipt, no deletion), and a
// receipt already on disk from an interrupted sweep licenses the deletion without being overwritten.
func TestQuarantineSweepIsReceiptFirst(t *testing.T) {
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) {
		c.Now = func() time.Time { return t0 }
		c.Origin = &Origin{Key: failingKey{}, TenantID: "t", DeviceID: "d"}
	})
	const id = "0192a1b2-0000-7000-8000-00000000000f"
	plantQuarantine(t, qdir, id, t0.Add(-45*24*time.Hour), 4)
	if n := u.sweepQuarantine(context.Background(), t0); n != 0 {
		t.Fatalf("deleted %d with the receipt unsignable; the bytes must stay", n)
	}
	if !exists(t, filepath.Join(qdir, id+".m1p.zst.sealed")) || !exists(t, filepath.Join(qdir, id+".manifest.json")) || exists(t, filepath.Join(qdir, id+deletionSuffix)) {
		t.Fatal("no receipt, no deletion")
	}

	if err := os.WriteFile(filepath.Join(qdir, id+deletionSuffix), []byte(`{"payload":"earlier"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	u.origin = nil
	if n := u.sweepQuarantine(context.Background(), t0); n != 1 {
		t.Fatalf("deleted %d: an existing receipt from an interrupted sweep licenses the deletion", n)
	}
	if raw, _ := os.ReadFile(filepath.Join(qdir, id+deletionSuffix)); string(raw) != `{"payload":"earlier"}` {
		t.Fatalf("the earlier receipt was overwritten: %s", raw)
	}
	if exists(t, filepath.Join(qdir, id+".m1p.zst.sealed")) || exists(t, filepath.Join(qdir, id+".manifest.json")) {
		t.Fatal("bytes survived a licensed deletion")
	}
}

type failingKey struct{}

func (failingKey) Sign([]byte) ([]byte, error) { return nil, errors.New("custody unavailable") }
func (failingKey) KeyID() string               { return "ed25519:0000000000000000" }

// TestQuarantineSweepRunsAtBootAndEveryTwentyFourHours: Run sweeps once on entry and again only after 24 h of wall
// clock, never on every poll.
func TestQuarantineSweepRunsAtBootAndEveryTwentyFourHours(t *testing.T) {
	now := t0
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) { c.Now = func() time.Time { return now } })
	const id = "0192a1b2-0000-7000-8000-000000000010"
	plantQuarantine(t, qdir, id, t0.Add(-(29*24*time.Hour + 12*time.Hour)), 1)

	u.maybeSweep(context.Background())
	if !exists(t, filepath.Join(qdir, sweepRecordFile)) {
		t.Fatal("boot sweep did not run")
	}
	if exists(t, filepath.Join(qdir, id+deletionSuffix)) {
		t.Fatal("29 d 12 h deleted at boot")
	}
	now = t0.Add(23 * time.Hour)
	u.maybeSweep(context.Background())
	if exists(t, filepath.Join(qdir, id+deletionSuffix)) {
		t.Fatal("swept again before 24 h elapsed (batch is now 30 d 11 h and would have gone)")
	}
	now = t0.Add(24 * time.Hour)
	u.maybeSweep(context.Background())
	if !exists(t, filepath.Join(qdir, id+deletionSuffix)) || exists(t, filepath.Join(qdir, id+".m1p.zst.sealed")) {
		t.Fatal("the 24 h sweep did not delete the now-expired batch")
	}
}

// TestRunSweepsQuarantineOnBoot: the sweep is wired into Run's loop head, so a daemon boot with an expired batch on
// disk deletes and receipts it before the first upload cycle needs anything from the network.
func TestRunSweepsQuarantineOnBoot(t *testing.T) {
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) { c.Now = func() time.Time { return t0 } })
	const id = "0192a1b2-0000-7000-8000-000000000011"
	plantQuarantine(t, qdir, id, t0.Add(-30*24*time.Hour), 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- u.Run(ctx) }()
	waitFor(t, "the boot sweep's deletion receipt", func() bool { return exists(t, filepath.Join(qdir, id+deletionSuffix)) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if exists(t, filepath.Join(qdir, id+".m1p.zst.sealed")) || exists(t, filepath.Join(qdir, id+".manifest.json")) {
		t.Fatal("Run receipted the batch but left its bytes")
	}
}

// deletionGolden is the exact canonical payload both halves must agree on: sidefx's reconstruction test in controld pins
// the same string, so a field renamed on either side reds one of the two without a cross-module import.
const deletionGolden = `{"batch_id":"0192a1b2-0000-7000-8000-00000000000b","deleted_at":"2026-09-16T12:00:00.25Z","device_id":"9d2b1f0e-2222-4222-8222-222222222222","device_key_id":"ed25519:0123456789abcdef","event_count":2,"quarantined_at":"2026-08-17T12:00:00Z","reason":"retention_30d","tenant_id":"9d2b1f0e-1111-4111-8111-111111111111","type":"quarantine_deletion","v":1}`

type goldenKey struct{ identity.DeviceKey }

func (goldenKey) KeyID() string { return "ed25519:0123456789abcdef" }

// TestQuarantineDeletionUploadsTheReceiptItWrote: after the files go, exactly one QuarantineDeletion is admitted,
// session-less, carrying the on-disk payload's fields at millisecond precision plus the key id and the signature bytes.
func TestQuarantineDeletionUploadsTheReceiptItWrote(t *testing.T) {
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: filepath.Join(t.TempDir(), "device.key")})
	if err != nil {
		t.Fatal(err)
	}
	var admitted []*m1pv1.Event
	now := t0.Add(250*time.Millisecond + 400*time.Microsecond) // sub-ms clock: the receipt must pin to whole ms
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) {
		c.Now = func() time.Time { return now }
		c.Origin = &Origin{Key: goldenKey{key}, TenantID: "9d2b1f0e-1111-4111-8111-111111111111", DeviceID: "9d2b1f0e-2222-4222-8222-222222222222"}
		c.Admit = func(_ context.Context, ev *m1pv1.Event) error { admitted = append(admitted, ev); return nil }
	})
	const id = "0192a1b2-0000-7000-8000-00000000000b"
	plantQuarantine(t, qdir, id, t0.Add(-30*24*time.Hour), 2)
	if n := u.sweepQuarantine(context.Background(), now); n != 1 {
		t.Fatalf("deleted %d", n)
	}
	rec, _ := readReceipt(t, qdir, id)
	if rec.Payload != deletionGolden {
		t.Fatalf("signed payload drifted from the golden:\n%s\n%s", rec.Payload, deletionGolden)
	}
	if len(admitted) != 1 {
		t.Fatalf("admitted %d events, want exactly one QuarantineDeletion", len(admitted))
	}
	ev := admitted[0]
	qd := ev.GetQuarantineDeletion()
	if qd == nil || len(ev.GetSessionId()) != 0 {
		t.Fatalf("want a session-less QuarantineDeletion body, got %v", ev)
	}
	if got := uuid.UUID(qd.GetBatchId()).String(); got != id {
		t.Fatalf("batch_id %s, want %s", got, id)
	}
	if qd.GetEventCount() != 2 || qd.GetReason() != "retention_30d" || qd.GetDeviceKeyId() != "ed25519:0123456789abcdef" {
		t.Fatalf("fields drifted from the receipt: %v", qd)
	}
	if qd.GetQuarantinedAtMs() != uint64(t0.Add(-30*24*time.Hour).UnixMilli()) || qd.GetDeletedAtMs() != uint64(now.UnixMilli()) {
		t.Fatalf("timestamps %d/%d do not round-trip the receipt's ms rendering", qd.GetQuarantinedAtMs(), qd.GetDeletedAtMs())
	}
	if hex.EncodeToString(qd.GetDeviceSignature()) != rec.DeviceSignature {
		t.Fatal("wire signature is not the on-disk signature")
	}
	if !ev.GetOccurredAt().AsTime().Equal(now.Truncate(time.Millisecond)) {
		t.Fatalf("occurred_at %v, want deleted_at %v", ev.GetOccurredAt().AsTime(), now.Truncate(time.Millisecond))
	}
	// The receipt's own hash still covers DomainPrefix || payload — a verifier needs no wire copy.
	if h := sha256.Sum256(append([]byte(identity.DomainPrefix), rec.Payload...)); hex.EncodeToString(h[:]) != rec.ReceiptHash {
		t.Fatal("receipt_hash is not sha256(DomainPrefix || payload)")
	}
}

// TestQuarantineDeletionStaysOnDiskWhenUnsignedOrUnwired: no admitter, or no enrolled key, uploads nothing; the receipt
// file is still written and the bytes still go.
func TestQuarantineDeletionStaysOnDiskWhenUnsignedOrUnwired(t *testing.T) {
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: filepath.Join(t.TempDir(), "device.key")})
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Config){
		"unsigned": func(c *Config) {
			c.Admit = func(context.Context, *m1pv1.Event) error { t.Fatal("unsigned receipt uploaded"); return nil }
		},
		"unwired": func(c *Config) { c.Origin = &Origin{Key: key, TenantID: "t", DeviceID: "d"} },
	} {
		t.Run(name, func(t *testing.T) {
			u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) { c.Now = func() time.Time { return t0 }; mod(c) })
			const id = "0192a1b2-0000-7000-8000-000000000012"
			plantQuarantine(t, qdir, id, t0.Add(-31*24*time.Hour), 1)
			if n := u.sweepQuarantine(context.Background(), t0); n != 1 {
				t.Fatalf("deleted %d", n)
			}
			if !exists(t, filepath.Join(qdir, id+deletionSuffix)) || exists(t, filepath.Join(qdir, id+".m1p.zst.sealed")) {
				t.Fatal("receipt-then-delete must not depend on the upload")
			}
		})
	}
}

// TestQuarantineDeletionShedIsNotFatal: a shed diagnostic (spool full) leaves the on-disk receipt as the evidence and
// the sweep counts the deletion; an interrupted sweep's pre-existing receipt is what gets uploaded, not a fresh one.
func TestQuarantineDeletionShedIsNotFatal(t *testing.T) {
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: filepath.Join(t.TempDir(), "device.key")})
	if err != nil {
		t.Fatal(err)
	}
	var admitted []*m1pv1.Event
	u, _, qdir := newTestUplink(t, openSpool(t), &fakeIngest{}, func(c *Config) {
		c.Now = func() time.Time { return t0 }
		c.Origin = &Origin{Key: key, TenantID: "9d2b1f0e-1111-4111-8111-111111111111", DeviceID: "9d2b1f0e-2222-4222-8222-222222222222"}
		c.Admit = func(_ context.Context, ev *m1pv1.Event) error {
			admitted = append(admitted, ev)
			return errors.New("shed")
		}
	})
	const id = "0192a1b2-0000-7000-8000-000000000013"
	plantQuarantine(t, qdir, id, t0.Add(-31*24*time.Hour), 1)
	earlier, err := u.receiptDeletion(&quarantined{id: id, since: t0.Add(-45 * 24 * time.Hour), quarantinedAt: MillisString(t0.Add(-45 * 24 * time.Hour)), events: 7}, t0.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n := u.sweepQuarantine(context.Background(), t0); n != 1 {
		t.Fatalf("deleted %d: a shed upload must not block the deletion", n)
	}
	if len(admitted) != 1 {
		t.Fatalf("admitted %d", len(admitted))
	}
	qd := admitted[0].GetQuarantineDeletion()
	if qd.GetEventCount() != 7 || qd.GetDeletedAtMs() != uint64(t0.Add(-time.Hour).UnixMilli()) || hex.EncodeToString(qd.GetDeviceSignature()) != earlier.DeviceSignature {
		t.Fatalf("the upload must mirror the receipt already on disk, not a re-minted one: %v", qd)
	}
}
