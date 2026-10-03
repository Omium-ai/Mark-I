// Server-originated per-event receipts: the classes in m1_002's
// `ck_m1_receipts_record_shape` arm that carry a subject_id and no device
// signature (noise_certificate, memory_admission, bundle_publication,
// corpus_export, and m1_068's key_rotation).
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
	"errors"
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
	"noise_certificate":   true,
	"memory_admission":    true,
	"bundle_publication":  true,
	"corpus_export":       true,
	"key_rotation":        true,
	"verifier_promotion":  true,
	"quarantine_deletion": true, // m1_080: subject = batch_id; origin edge (device-verified at stage 11) or cloud (the sweep)
}

// reservedPayloadKeys are the chain fields this function owns. A class-specific
// field that shadowed one of them would put a caller-chosen seq or tenant_id
// inside the signed bytes while the row carried the real one.
var reservedPayloadKeys = map[string]bool{
	"v": true, "type": true, "tenant_id": true, "seq": true,
	"prev_receipt_hash": true, "issued_at": true, "subject_id": true,
	"hosts": true, "arrests_acted": true, "arrests_recommended": true, // ADR-0017
}

// ServerRecord is one server act to be receipted. Fields carries the
// class-specific evidence; the chain fields are added here.
type ServerRecord struct {
	RecordType string
	SubjectID  uuid.UUID
	IssuedAt   time.Time
	Fields     map[string]any
	// IdempotencyKey is the caller's attempt identity (m1_072); a row fact, never signed. Empty = none.
	IdempotencyKey string
}

// Validate is AppendServerRecordTx's store-free half, so a handler can refuse before opening a tx.
func (r ServerRecord) Validate() error {
	if !ServerRecordTypes[r.RecordType] {
		return fmt.Errorf("receipts: %q is not a server-originated record class", r.RecordType)
	}
	if r.SubjectID == uuid.Nil {
		// ck_m1_receipts_record_shape would reject it anyway; naming it here
		// makes the cause readable without a constraint name lookup.
		return fmt.Errorf("receipts: %s needs a subject_id (m1_002 record shape)", r.RecordType)
	}
	for k := range r.Fields {
		if reservedPayloadKeys[k] {
			return fmt.Errorf("receipts: field %q is a chain field and cannot be supplied by the caller", k)
		}
	}
	return nil
}

// AppendServerRecordTx takes the tenant's receipt head lock inside tx, builds
// and signs the payload at seq+1, inserts the receipt and advances the head.
// tx MUST already have app.tenant_id set for tenant (i.e. it came from
// TenantDB.WithTenant), or RLS makes the head row invisible and the insert
// fails -- which is the correct failure, not a silent cross-tenant write.
func (s *Store) AppendServerRecordTx(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, rec ServerRecord) (Appended, error) {
	if err := rec.Validate(); err != nil {
		return Appended{}, err
	}
	if s.retiring != nil {
		if err := s.crossOver(ctx, tx, tenant); err != nil {
			return Appended{}, err
		}
	}
	return s.appendSigned(ctx, tx, tenant, s.signer, rec)
}

// crossOver appends the ADR-0004 rotation record when this tenant's head was
// countersigned by the retiring key: the retiring key's LAST receipt names
// the successor, then the successor signs everything after. A tenant whose
// head is already under the successor (or is empty) crosses nothing.
func (s *Store) crossOver(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID) error {
	var headKey, headType string
	err := tx.QueryRow(ctx, `
		SELECT r.server_key_id, r.record_type FROM m1_receipts r
		  JOIN m1_receipt_chain_head h ON h.tenant_id = r.tenant_id AND h.seq = r.seq
		 WHERE r.tenant_id = $1`, tenant.UUID()).Scan(&headKey, &headType)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (headKey != s.retiring.KeyID() || headType == "key_rotation")) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.appendSigned(ctx, tx, tenant, s.retiring, ServerRecord{
		RecordType: "key_rotation",
		SubjectID:  KeySubjectID(s.signer.KeyID()),
		IssuedAt:   time.Now(),
		Fields:     map[string]any{"successor_key_id": s.signer.KeyID()},
	})
	return err
}

// KeySubjectID names a key as a receipt subject: UUIDv5 over its derived id,
// so the rotation record needs no row to exist first.
func KeySubjectID(keyID string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("urn:mark1:key:"+keyID))
}

func (s *Store) appendSigned(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, signer SignerLike, rec ServerRecord) (Appended, error) {
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
	serverSig, err := signer.Sign(signingInput)
	if err != nil {
		return Appended{}, err
	}
	hash := sha256.Sum256(signingInput)

	var receiptID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO m1_receipts
		  (tenant_id, seq, prev_receipt_hash, receipt_hash, payload, record_type, issued_at,
		   server_key_id, server_signature, subject_id, idempotency_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''))
		RETURNING id`,
		tenant.UUID(), seq, headHash, hash[:], text, rec.RecordType,
		rec.IssuedAt.UTC().Truncate(time.Second),
		signer.KeyID(), serverSig, rec.SubjectID, rec.IdempotencyKey).Scan(&receiptID); err != nil {
		return Appended{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE m1_receipt_chain_head SET seq = $2, head_hash = $3, updated_at = now()
		 WHERE tenant_id = $1`, tenant.UUID(), seq, hash[:]); err != nil {
		return Appended{}, err
	}
	return Appended{ReceiptID: receiptID, Seq: seq, CheckpointSeq: headCkpt, ReceiptHash: hash, PayloadText: text}, nil
}
