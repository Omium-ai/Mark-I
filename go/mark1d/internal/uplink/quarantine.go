// Quarantine-and-report, the 4xx rule of 08 §2.5: a refused batch moves OUT
// of the spool to <quarantine-dir> (0600, sealed to the device spill key,
// 04 §2.5) so a poison batch never head-of-line-blocks billing-grade
// drainage — and is never silently discarded and never auto-retried. The
// manifest is the report's durable half; `mark1 status` reads it when that
// surface lands.
package uplink

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// sealChunk bounds one Seal call's plaintext: the device spill seal caps a
// record at one M1PL frame (04 §5.4), so batches larger than a frame are
// sealed as concatenated records — each self-framing via its length prefix.
const sealChunk = 1 << 20

// manifest is the on-disk report row for one quarantined unit. Fields name
// the 08 §2.4 verdict that caused it; event_ids let the 422 partial flow be
// audited without unsealing the payload.
type manifest struct {
	BatchID       string   `json:"batch_id"`
	Status        int      `json:"status"`
	ErrCode       string   `json:"err_code,omitempty"`
	EventIDs      []string `json:"event_ids"`
	EventCount    int      `json:"event_count"`
	QuarantinedAt string   `json:"quarantined_at"`
	Note          string   `json:"note,omitempty"`
}

// quarantine seals raw (a compressed batch body) into <dir>/<id>.m1p.zst.sealed
// and fsyncs both halves BEFORE the caller advances the spool cursor: once
// Ack runs, these files are the only copy — a lost quarantine write after an
// ack would be exactly the silent discard 08 §2.5 forbids.
func (u *Uplink) quarantine(b *outBatch, raw []byte, status int, errCode, note string) error {
	if err := os.MkdirAll(u.quarantineDir, 0o700); err != nil {
		return err
	}
	ids := make([]string, len(b.recs))
	for i, r := range b.recs {
		ids[i] = recordEventID(r).String()
	}
	var sealed []byte
	for off := 0; off < len(raw); off += sealChunk {
		end := min(off+sealChunk, len(raw))
		rec, err := u.seal(raw[off:end])
		if err != nil {
			return err
		}
		sealed = append(sealed, rec...)
	}
	if err := writeFileSync(filepath.Join(u.quarantineDir, b.id.String()+".m1p.zst.sealed"), sealed); err != nil {
		return err
	}
	man, err := json.MarshalIndent(manifest{
		BatchID:       b.id.String(),
		Status:        status,
		ErrCode:       errCode,
		EventIDs:      ids,
		EventCount:    len(b.recs),
		QuarantinedAt: u.now().UTC().Format(time.RFC3339Nano),
		Note:          note,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(u.quarantineDir, b.id.String()+".manifest.json"), man); err != nil {
		return err
	}
	// The report half: the manifest is durable; the log line is the live
	// surface until `mark1 status` grows its quarantine row (04 §2.5).
	u.log.Error("uplink: batch quarantined, never auto-retried (08 §2.5)",
		"batch_id", b.id.String(), "status", status, "code", errCode,
		"events", len(b.recs), "spool_cursor", fmtCursor(b.end), "note", note)
	return nil
}

// quarantineBatch handles the whole-batch 4xx verdicts: files first, then the
// Dropped{QUARANTINED} accounting and the re-credit of the batch's own drained
// rows (they never landed) — both ride the next successful batch.
func (u *Uplink) quarantineBatch(b *outBatch, status int, errCode, note string) error {
	if err := u.quarantine(b, b.body, status, errCode, note); err != nil {
		return err
	}
	u.requeueDropped(b)
	u.carry = append(u.carry, quarantineRows(b.recs)...)
	return nil
}

// splitByEventIDs partitions a batch's records into (named, remainder) for
// the 422 flow (08 §2.4): quarantine the named events, re-send the remainder
// once. Names arrive as uuid strings (M1E-2006 detail.event_ids); matching is
// by the spool record_id's leading 16 bytes — no payload decode.
func splitByEventIDs(recs []spool.Record, names []string) (named, remainder []spool.Record) {
	bad := map[[16]byte]bool{}
	for _, s := range names {
		if id, err := uuid.Parse(s); err == nil {
			bad[[16]byte(id)] = true
		}
	}
	for _, r := range recs {
		var k [16]byte
		copy(k[:], r.ID[:16])
		if bad[k] {
			named = append(named, r)
		} else {
			remainder = append(remainder, r)
		}
	}
	return named, remainder
}

func writeFileSync(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
