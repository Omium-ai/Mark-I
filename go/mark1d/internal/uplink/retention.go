package uplink

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

// Founder ruling 2026-09-16: quarantine retention is 30 days, then delete, with a receipt of the deletion. No knob.
const (
	QuarantineRetention = 30 * 24 * time.Hour
	sweepEvery          = 24 * time.Hour
	sweepRecordFile     = "last-sweep.json"
	deletionSuffix      = ".deleted.json" // ponytail: receipts accumulate in the dir (~600 B each, one per 4xx batch); upload-then-prune once the wire can carry them
)

// Origin is the enrolled identity that signs quarantine-deletion receipts; nil is the unenrolled posture (receipt written, unsigned).
type Origin struct {
	Key      identity.DeviceKey
	TenantID string
	DeviceID string
}

// Note is provenance about how the signed payload was derived, outside the signed bytes on purpose: controld
// rebuilds the payload from the wire fields + verified identity (the checkpoint discipline) and free text never rides.
type deletionReceipt struct {
	Payload         string `json:"payload"`
	ReceiptHash     string `json:"receipt_hash"`
	DeviceSignature string `json:"device_signature,omitempty"`
	Note            string `json:"note,omitempty"`
}

type sweepRecord struct {
	SweptAt string `json:"swept_at"`
	Deleted int    `json:"deleted"`
}

type quarantined struct {
	id            string
	since         time.Time
	quarantinedAt string
	events        int
	note          string
}

// ponytail: wall-clock ages like max_age (04 F-29): a forward jump deletes early but receipted, a backward jump only delays.
func (u *Uplink) maybeSweep(ctx context.Context) {
	now := u.now()
	if !u.lastSweep.IsZero() && now.Sub(u.lastSweep) < sweepEvery {
		return
	}
	u.lastSweep = now
	u.sweepQuarantine(ctx, now)
}

// sweepQuarantine deletes every quarantined batch QuarantineRetention or older, receipt first: no receipt, no deletion.
func (u *Uplink) sweepQuarantine(ctx context.Context, now time.Time) int {
	ents, err := os.ReadDir(u.quarantineDir)
	if err != nil {
		return 0
	}
	batches := map[string]*quarantined{}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".manifest.json")
		if !ok {
			if id, ok = strings.CutSuffix(e.Name(), ".m1p.zst.sealed"); !ok {
				continue
			}
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		b := batches[id]
		if b == nil {
			b = &quarantined{id: id, since: fi.ModTime()}
			batches[id] = b
		}
		if fi.ModTime().Before(b.since) {
			b.since = fi.ModTime()
		}
	}
	deleted := 0
	for _, b := range batches {
		u.dateFromManifest(b)
		if now.Sub(b.since) < QuarantineRetention {
			continue
		}
		rec, err := u.receiptDeletion(b, now)
		if err != nil {
			u.log.Error("uplink: quarantine deletion receipt not written; batch kept", "batch_id", b.id, "err", err)
			continue
		}
		for _, suffix := range []string{".m1p.zst.sealed", ".manifest.json"} {
			if err := os.Remove(filepath.Join(u.quarantineDir, b.id+suffix)); err != nil && !errors.Is(err, os.ErrNotExist) {
				u.log.Error("uplink: quarantine file not removed; next sweep retries", "path", b.id+suffix, "err", err)
			}
		}
		deleted++
		u.log.Info("uplink: quarantined batch deleted at retention, receipted", "batch_id", b.id, "events", b.events, "quarantined_at", b.quarantinedAt)
		u.emitDeletion(ctx, rec)
	}
	rec, _ := json.Marshal(sweepRecord{SweptAt: now.UTC().Format(time.RFC3339Nano), Deleted: deleted})
	if err := os.WriteFile(filepath.Join(u.quarantineDir, sweepRecordFile), rec, 0o600); err != nil {
		u.log.Warn("uplink: sweep record not written", "err", err)
	}
	return deleted
}

// dateFromManifest prefers the manifest's quarantined_at; a torn or missing manifest falls back to the oldest file mtime, said so in the receipt.
func (u *Uplink) dateFromManifest(b *quarantined) {
	var m manifest
	raw, err := os.ReadFile(filepath.Join(u.quarantineDir, b.id+".manifest.json"))
	if err == nil {
		err = json.Unmarshal(raw, &m)
	}
	var at time.Time
	if err == nil {
		at, err = time.Parse(time.RFC3339Nano, m.QuarantinedAt)
	}
	if err != nil {
		b.quarantinedAt = MillisString(b.since)
		b.note = "manifest unreadable; quarantined_at is the file mtime"
		return
	}
	b.since, b.quarantinedAt, b.events = at, MillisString(at), m.EventCount
}

// MillisString pins a receipt timestamp to whole milliseconds: the wire carries unix ms, and controld must rebuild the
// exact signed bytes from it (the IssuedAtString discipline, one rung finer).
func MillisString(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano)
}

// receiptDeletion writes the receipt beside the bytes, or returns the one an interrupted sweep already wrote.
func (u *Uplink) receiptDeletion(b *quarantined, now time.Time) (deletionReceipt, error) {
	payload := map[string]any{
		"v":              1,
		"type":           "quarantine_deletion",
		"batch_id":       b.id,
		"event_count":    b.events,
		"quarantined_at": b.quarantinedAt,
		"deleted_at":     MillisString(now),
		"reason":         "retention_30d",
	}
	rec := deletionReceipt{Note: b.note}
	if u.origin != nil {
		payload["tenant_id"], payload["device_id"], payload["device_key_id"] = u.origin.TenantID, u.origin.DeviceID, u.origin.Key.KeyID()
		signed, err := identity.OriginSign(u.origin.Key, payload)
		if err != nil {
			return rec, err
		}
		rec.Payload, rec.ReceiptHash, rec.DeviceSignature = signed.PayloadText, hex.EncodeToString(signed.ReceiptHash[:]), hex.EncodeToString(signed.DeviceSig)
	} else {
		text, err := identity.CanonicalJSON(payload)
		if err != nil {
			return rec, err
		}
		h, err := identity.ReceiptHash(payload)
		if err != nil {
			return rec, err
		}
		rec.Payload, rec.ReceiptHash = text, hex.EncodeToString(h[:])
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return rec, err
	}
	path := filepath.Join(u.quarantineDir, b.id+deletionSuffix)
	err = writeFileSync(path, raw)
	if errors.Is(err, os.ErrExist) {
		if raw, err = os.ReadFile(path); err == nil {
			err = json.Unmarshal(raw, &rec)
		}
	}
	return rec, err
}

// emitDeletion mirrors the on-disk receipt onto the wire (QuarantineDeletion, envelope arm 23) through the daemon's
// admitter: diagnostic class, device-scoped, so a shed copy costs nothing the receipt file does not still hold.
// Unsigned receipts (no enrolled key) stay on disk only: controld could verify nothing.
func (u *Uplink) emitDeletion(ctx context.Context, rec deletionReceipt) {
	if u.admit == nil || rec.DeviceSignature == "" {
		return
	}
	decoded, err := identity.DecodePayload([]byte(rec.Payload))
	fields, _ := decoded.(map[string]any)
	if err != nil || fields == nil {
		u.log.Warn("uplink: deletion receipt payload unreadable; not uploaded", "err", err)
		return
	}
	str := func(k string) string { v, _ := fields[k].(string); return v }
	batchID, err := uuid.Parse(str("batch_id"))
	sig, serr := hex.DecodeString(rec.DeviceSignature)
	num, _ := fields["event_count"].(json.Number)
	count, cerr := num.Int64()
	qa, qerr := time.Parse(time.RFC3339Nano, str("quarantined_at"))
	da, derr := time.Parse(time.RFC3339Nano, str("deleted_at"))
	if err != nil || serr != nil || cerr != nil || qerr != nil || derr != nil {
		u.log.Warn("uplink: deletion receipt fields unreadable; not uploaded", "batch_id", str("batch_id"))
		return
	}
	err = u.admit(ctx, &m1pv1.Event{
		OccurredAt: timestamppb.New(da),
		Body: &m1pv1.Event_QuarantineDeletion{QuarantineDeletion: &m1pv1.QuarantineDeletion{
			BatchId:         batchID[:],
			EventCount:      uint32(count),          //nolint:gosec // G115: the manifest count is a small non-negative int
			QuarantinedAtMs: uint64(qa.UnixMilli()), //nolint:gosec // G115: post-1970 ms
			DeletedAtMs:     uint64(da.UnixMilli()), //nolint:gosec // G115: post-1970 ms
			Reason:          str("reason"),
			DeviceKeyId:     str("device_key_id"),
			DeviceSignature: sig,
		}},
	})
	if err != nil {
		u.log.Warn("uplink: quarantine deletion not admitted; on-disk receipt remains the evidence", "batch_id", batchID.String(), "err", err)
	}
}
