// Server-originated per-event receipts: the four classes in m1_002's
// `ck_m1_receipts_record_shape` arm that carry a subject_id and no device
// signature (noise_certificate, memory_admission, bundle_publication,
// corpus_export).
//
// WHY IT IS TX-SCOPED. A bundle publication must be ONE transaction (05 §4.1):
// the catalog row, the transparency-log leaf and this receipt either all
// commit or none do, because a published bundle with no receipt is a policy
// change with no evidence and a receipt with no bundle is evidence of nothing.
// So the caller owns the transaction and hands it in; m1_receipts still has
// exactly one writer, which is this package.

package receipts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// ServerRecordTypes is the closed set this path may write. Not a passthrough:
// the three device-originated classes are excluded here so a caller cannot
// mint a "checkpoint" with no device signature by picking a string, and
// `discontinuity` is excluded because it carries no subject.
var ServerRecordTypes = map[string]bool{
	"noise_certificate":  true,
	"memory_admission":   true,
	"bundle_publication": true,
	"corpus_export":      true,
}

// reservedPayloadKeys are the chain fields this function owns. A class-specific
// field that shadowed one of them would put a caller-chosen seq or tenant_id
// inside the signed bytes while the row carried the real one.
var reservedPayloadKeys = map[string]bool{
	"v": true, "type": true, "tenant_id": true, "seq": true,
	"prev_receipt_hash": true, "issued_at": true, "subject_id": true,
}

// ServerRecord is one server act to be receipted. Fields carries the
// class-specific evidence; the chain fields are added here.
type ServerRecord struct {
	RecordType string
	SubjectID  uuid.UUID
	IssuedAt   time.Time
	Fields     map[string]any
}

// AppendServerRecordTx takes the tenant's receipt head lock inside tx, builds
// and signs the payload at seq+1, inserts the receipt and advances the head.
// tx MUST already have app.tenant_id set for tenant (i.e. it came from
// TenantDB.WithTenant), or RLS makes the head row invisible and the insert
// fails -- which is the correct failure, not a silent cross-tenant write.
func (s *Store) AppendServerRecordTx(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, rec ServerRecord) (Appended, error) {
	if !ServerRecordTypes[rec.RecordType] {
		return Appended{}, fmt.Errorf("receipts: %q is not a server-originated record class", rec.RecordType)
	}
	if rec.SubjectID == uuid.Nil {
		// ck_m1_receipts_record_shape would reject it anyway; naming it here
		// makes the cause readable without a constraint name lookup.
		return Appended{}, fmt.Errorf("receipts: %s needs a subject_id (m1_002 record shape)", rec.RecordType)
	}
	for k := range rec.Fields {
		if reservedPayloadKeys[k] {
			return Appended{}, fmt.Errorf("receipts: field %q is a chain field and cannot be supplied by the caller", k)
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO m1_receipt_chain_head (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`,
		tenant.UUID()); err != nil {
		return Appended{}, err
	}
	var headSeq, headCkpt int64
	var headHash []byte
	if err := tx.QueryRow(ctx,
		`SELECT seq, head_hash, checkpoint_seq FROM m1_receipt_chain_head
		  WHERE tenant_id = $1 FOR UPDATE`, tenant.UUID()).
		Scan(&headSeq, &headHash, &headCkpt); err != nil {
		return Appended{}, err
	}

	seq := headSeq + 1
	issued := IssuedAtString(rec.IssuedAt)
	payload := map[string]any{
		"v":                 1,
		"type":              rec.RecordType,
		"tenant_id":         tenant.String(),
		"seq":               seq,
		"prev_receipt_hash": hex.EncodeToString(headHash),
		"issued_at":         issued,
		"subject_id":        rec.SubjectID.String(),
	}
	for k, v := range rec.Fields {
		payload[k] = v
	}
	text, err := CanonicalJSON(payload)
	if err != nil {
		return Appended{}, err
	}
	signingInput := append([]byte(DomainPrefix), text...)
	serverSig, err := s.signer.Sign(signingInput)
	if err != nil {
		return Appended{}, err
	}
	hash := sha256.Sum256(signingInput)

	var receiptID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO m1_receipts
		  (tenant_id, seq, prev_receipt_hash, receipt_hash, payload, record_type, issued_at,
		   server_key_id, server_signature, subject_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		tenant.UUID(), seq, headHash, hash[:], text, rec.RecordType,
		rec.IssuedAt.UTC().Truncate(time.Second),
		s.signer.KeyID(), serverSig, rec.SubjectID).Scan(&receiptID); err != nil {
		return Appended{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE m1_receipt_chain_head SET seq = $2, head_hash = $3, updated_at = now()
		 WHERE tenant_id = $1`, tenant.UUID(), seq, hash[:]); err != nil {
		return Appended{}, err
	}
	return Appended{ReceiptID: receiptID, Seq: seq, CheckpointSeq: headCkpt, ReceiptHash: hash, PayloadText: text}, nil
}
