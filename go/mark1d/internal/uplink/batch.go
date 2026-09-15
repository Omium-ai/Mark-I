// Batch composition: spool records → one wire-ready m1p.v1.Batch body.
// The spool IS the queue (04 §2.5) — records are taken in spool order from the
// ack cursor and their payloads ride the Batch as-is: each payload already is
// one encoded m1p.v1.Event (07 §6), so events[] is assembled by raw protobuf
// framing (field 5, length-delimited) and never decoded or re-encoded here.
// Byte-preservation is load-bearing: a re-encode could perturb bytes the
// server's landing-object dedupe compares (08 §2.3).
package uplink

import (
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

const (
	// 08 §2.1 caps the decoded batch at 32 MiB and controld stage 1 caps the
	// compressed body at 8 MiB. 4 MiB of raw payload sits well under both even
	// if zstd fails to shrink it (zstd's worst-case overhead is bytes, not
	// megabytes) — a boring target, not a protocol number.
	targetRawBytes = 4 << 20
	// controld stage 5 rejects >10_000 events per batch (05 §2.1); composing
	// past the bound would turn a legal backlog into a 400 quarantine.
	maxBatchEvents = 10_000
	// Event.session_id is field 3 of the Event envelope (envelope.proto).
	eventSessionIDField = 3
	// Event.body's receipt_checkpoint arm is field 21 (envelope.proto).
	eventReceiptCheckpointField = 21
	// Batch.events is field 5 of the Batch envelope (envelope.proto).
	batchEventsField = 5
)

// dropQuarantined mirrors m1p.v1.DropReason numbering exactly as capture and
// spill do — the wire translation stays a cast (envelope.proto).
const dropQuarantined spool.DropReason = 6 // DROP_REASON_QUARANTINED

// DropSource is the read-and-reset loss-ledger seam (04 §8.1): uplink drains
// every edge loss into one Batch.dropped at composition. *spool.Spool and
// *capture.Admitter both satisfy it.
type DropSource interface {
	DrainDropped() []spool.Dropped
}

// outBatch is one composed upload unit. body is built exactly once: 08 §2.3
// makes a re-POST safe only when the same M1P-Batch-Id carries the SAME bytes
// — restamping sent_at per attempt would land Divergent (409) after a lost
// ack, so composition time is the send time the doc's "stamped at send time"
// names.
type outBatch struct {
	id      uuid.UUID
	recs    []spool.Record
	dropped []spool.Dropped
	// end is the exclusive spool cursor one past the last record: what
	// spool.Ack receives on 2xx (07 §6 ack cursor semantics).
	end  spool.Cursor
	body []byte // zstd-compressed Batch bytes, cached across retries
}

// compose reads the unacked window (ack, durable] and takes the bounded
// prefix. nil, nil means the spool is drained. Dropped rows drain here — the
// one reset path the counters have (07 §6) — so they ride exactly the next
// composed batch; carried rows from a failed batch ride before fresh drains.
//
// ponytail: Store.Records loads the whole unacked backlog to slice a prefix
// off it (the frozen spool API has no bounded read); a multi-GiB outage
// backlog pays a copy per compose. A bounded reader on the spool side is the
// upgrade path if that ever shows in memory profiles.
func (u *Uplink) compose() (*outBatch, error) {
	for {
		ack, _ := u.store.Cursors()
		recs, durable, err := u.store.Records(ack)
		if err != nil {
			return nil, err
		}
		if len(recs) == 0 {
			return nil, nil
		}
		take, raw := 0, 0
		for take < len(recs) && take < maxBatchEvents {
			// Always take at least one record: a single oversized record must
			// move (and fail loudly server-side) rather than wedge the queue.
			if take > 0 && raw+len(recs[take].Payload) > targetRawBytes {
				break
			}
			raw += len(recs[take].Payload)
			take++
		}
		end := durable
		if take < len(recs) {
			end = recs[take].Pos
		}
		// Exclude events the 422 remainder flow already quarantined with
		// durable evidence (uplink.go): quarantine is never auto-retried
		// (08 §2.5), so a replayed window re-sends only what never landed.
		kept := recs[:take]
		if len(u.quarantined) > 0 {
			kept = make([]spool.Record, 0, take)
			for _, r := range recs[:take] {
				var k [16]byte
				copy(k[:], r.ID[:16])
				if _, ok := u.quarantined[k]; !ok {
					kept = append(kept, r)
				}
			}
			if len(kept) == 0 {
				// Every record in this window is quarantined-with-evidence and
				// its accounting already sits in carry — acking past it is the
				// same license the remainder's rest-empty path exercises. Loop:
				// the next window may hold live records. (Reached only if the
				// window boundary isolates named events; a defensive branch —
				// encodeBatch cannot frame an empty batch.)
				if err := u.store.Ack(end); err != nil {
					return nil, err
				}
				continue
			}
		}
		dropped := u.carry
		u.carry = nil
		for _, src := range u.drops {
			dropped = append(dropped, src.DrainDropped()...)
		}
		return u.rebatch(kept, mergeDropped(dropped), end)
	}
}

// rebatch mints a fresh batch identity over a record subset — used by compose
// and by the 413-split / 422-remainder paths (08 §2.4), where the content
// changed and reusing the old batch_id would be the 409 corruption signal.
func (u *Uplink) rebatch(recs []spool.Record, dropped []spool.Dropped, end spool.Cursor) (*outBatch, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	b := &outBatch{id: id, recs: recs, dropped: dropped, end: end}
	if b.body, err = u.encodeBatch(b); err != nil {
		return nil, err
	}
	return b, nil
}

// encodeBatch marshals the envelope head, then appends each opaque event
// payload as a raw field-5 frame — valid protobuf by concatenation, zero
// event decodes — and zstd-compresses the result (level 3, 04 §2.5).
func (u *Uplink) encodeBatch(b *outBatch) ([]byte, error) {
	head := &m1pv1.Batch{
		BatchId: b.id[:],
		// Batch.session_id is envelope-advisory: every admitted event carries
		// its own (capture normalizes it in, and controld's projection reads
		// the event's first). Stamped from the first rider so the envelope
		// stays honest for single-session batches — the overwhelming case —
		// without decoding anything but one field tag.
		SessionId: sessionIDOf(b.recs[0].Payload),
		Sdk:       u.sdk,
		SentAt:    timestamppb.New(u.now()),
		Dropped:   droppedToProto(b.dropped),
	}
	raw, err := proto.Marshal(head)
	if err != nil {
		return nil, err
	}
	for _, r := range b.recs {
		raw = protowire.AppendTag(raw, batchEventsField, protowire.BytesType)
		raw = protowire.AppendBytes(raw, r.Payload)
	}
	return u.enc.EncodeAll(raw, make([]byte, 0, len(raw)/2)), nil
}

// topLevelBytes walks the top-level wire fields of one encoded Event for the
// first length-delimited field numbered num — a tag scan, not a decode,
// honoring the opaque-payload rule. ok is false when absent or malformed.
func topLevelBytes(payload []byte, num protowire.Number) (v []byte, ok bool) {
	b := payload
	for len(b) > 0 {
		n, typ, m := protowire.ConsumeTag(b)
		if m < 0 {
			return nil, false
		}
		b = b[m:]
		if n == num && typ == protowire.BytesType {
			v, m = protowire.ConsumeBytes(b)
			return v, m >= 0
		}
		if m = protowire.ConsumeFieldValue(n, typ, b); m < 0 {
			return nil, false
		}
		b = b[m:]
	}
	return nil, false
}

// sessionIDOf reads session_id (field 3). Absent/odd shapes return nil: the
// field is advisory (see encodeBatch).
func sessionIDOf(payload []byte) []byte {
	v, ok := topLevelBytes(payload, eventSessionIDField)
	if !ok || len(v) != 16 {
		return nil
	}
	return v
}

// isCheckpoint reports whether the encoded Event's body is a ReceiptCheckpoint
// (field 21 present; an embedded message is length-delimited even when empty).
func isCheckpoint(payload []byte) bool {
	_, ok := topLevelBytes(payload, eventReceiptCheckpointField)
	return ok
}

// mergeDropped collapses rows by (reason, class): the counters are additive
// and controld caps dropped[] at 1_000 entries — merged rows can never
// approach it (reasons × classes is tens).
func mergeDropped(rows []spool.Dropped) []spool.Dropped {
	if len(rows) == 0 {
		return nil
	}
	sum := map[[2]int32]uint64{}
	for _, d := range rows {
		sum[[2]int32{int32(d.Reason), int32(d.Class)}] += d.Quantity
	}
	out := make([]spool.Dropped, 0, len(sum))
	for k, q := range sum {
		out = append(out, spool.Dropped{Reason: spool.DropReason(k[0]), Class: spool.Class(k[1]), Quantity: q})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Class < out[j].Class
	})
	return out
}

// droppedToProto is the cast the mirrored numbering exists for (spool.go,
// capture.go: "the uplink translation stays a cast").
func droppedToProto(rows []spool.Dropped) []*m1pv1.Dropped {
	out := make([]*m1pv1.Dropped, len(rows))
	for i, d := range rows {
		out[i] = &m1pv1.Dropped{
			Reason:          m1pv1.DropReason(d.Reason),
			DurabilityClass: m1pv1.DurabilityClass(d.Class),
			Quantity:        d.Quantity,
		}
	}
	return out
}

// requeueDropped re-credits a failed batch's drained rows so they ride the
// next composed batch instead of vanishing with the failure — "silence is the
// one failure the ledger can't price" (04 §8.1 via spool).
func (u *Uplink) requeueDropped(b *outBatch) {
	u.carry = append(u.carry, b.dropped...)
}

// quarantineRows accounts a set of records leaving the upload path as
// Dropped{QUARANTINED} per class, to ride the next successful batch (08 §2.5).
func quarantineRows(recs []spool.Record) []spool.Dropped {
	perClass := map[spool.Class]uint64{}
	for _, r := range recs {
		perClass[r.ID.Class()]++
	}
	out := make([]spool.Dropped, 0, len(perClass))
	for c, q := range perClass {
		out = append(out, spool.Dropped{Reason: dropQuarantined, Class: c, Quantity: q})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// recordEventID recovers the wire idempotency key from the spool identity:
// record_id[0..16) IS the event_id (07 §6) — no decode needed to name an event.
func recordEventID(r spool.Record) uuid.UUID {
	var id uuid.UUID
	copy(id[:], r.ID[:16])
	return id
}

// batchLeaves is the checkpoint's Merkle leaf set: every event_id in the batch
// EXCEPT ReceiptCheckpoint records, in spool order.
//
// The rule is the server's (controld ingest/sidefx/sidefx.go Apply): "every
// non-checkpoint landed event is a leaf of the device's NEXT checkpoint; the
// checkpoint announcement itself is sealed AFTER its tree and is deliberately
// not a leaf of any tree." A checkpoint's attestation is its own chain row, so
// a tree that counted it would claim one leaf more than controld holds pending
// and be refused, and its orphaned leaf would wedge every later honest seal
// into merkle_mismatch. Order is load-bearing — controld's EffectsFromBatch
// walks the decoded batch in the same order, so the tree it rebuilds is this
// tree. A batch of only checkpoints yields no leaves, and the sealer seals
// nothing over nothing — that is the termination rule.
func batchLeaves(recs []spool.Record) [][]byte {
	leaves := make([][]byte, 0, len(recs))
	for _, r := range recs {
		if isCheckpoint(r.Payload) {
			continue
		}
		id := recordEventID(r)
		leaves = append(leaves, id[:])
	}
	return leaves
}

func fmtCursor(c spool.Cursor) string { return fmt.Sprintf("(%d,%d)", c.Seq, c.Off) }

// uuidV7Time reads RFC 9562's 48-bit big-endian millisecond prefix — the half
// of a trace span an event_id already gives us (11 §0.3: "the ID *is* a coarse
// timestamp"). A non-v7 id has no such prefix and reports the zero time rather
// than a number from another layout.
func uuidV7Time(id uuid.UUID) time.Time {
	if id.Version() != 7 {
		return time.Time{}
	}
	//nolint:gosec // G115: >>16 leaves 48 bits, which always fits in int64.
	ms := int64(binary.BigEndian.Uint64(id[0:8]) >> 16)
	return time.UnixMilli(ms)
}
