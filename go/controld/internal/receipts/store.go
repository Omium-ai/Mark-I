// The server-side receipt writer — the countersignature half of the
// dual-signed chain (m1_002; 07 §"The checkpoint model": "controld verifies
// the device signature against the enrolled key, countersigns the same
// canonical bytes, takes the tenant's head lock, and appends the checkpoint
// receipt at seq+1/checkpoint_seq+1").
//
// SIGNING-INPUT RECONSTRUCTION, stated once. Both signatures cover ONE
// signing input: DomainPrefix || canonical(payload), where the payload
// carries seq/prev_receipt_hash INSIDE (the frozen vectors; m1_002's column
// comment). The ReceiptCheckpoint wire event deliberately carries no payload
// text (artifacts.proto: "a checkpoint announcement is about the batch"), so
// the server REBUILDS the payload here from the verified claims, the wire
// fields, and the locked head — via the same Checkpoint builder the vectors
// freeze — and verifies the device's origin_signature over that
// reconstruction. A device whose view of the head (seq, prev, tenant
// checkpoint counter) is stale therefore fails verification and is REFUSED;
// it re-seals against the fresh head (08 §3.4 serves it; 03 §7.g: "a
// checkpoint that cannot be signed correctly is not emitted at all" —
// fail-closed on integrity, never a server-side repair). NOTE: artifacts
// .proto's field comment reads "over the domain-prefixed root"; the vectors
// commit (normative where prose delegated construction, vectors README) and
// m1_002 fix the input as the full payload, and this file follows them — the
// wire shape itself (64 signature bytes) is unchanged either way.
//
// Key-role binding is the table split: device origin keys are looked up in
// m1_device_keys ONLY (tenant-scoped by RLS), the server chain key never
// appears there — so a server key answering an origin claim (the vectors' S1,
// `server_key_as_device_origin`) is structurally an unknown key.

package receipts

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
)

// DB is the WithTenant-shaped seam (05 §7.2); *pg.TenantDB satisfies it and
// tests fake it.
type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

var _ DB = (*pg.TenantDB)(nil)

// RefusalError is a checkpoint the chain will not accept — a statement about
// the REQUEST, distinct from infrastructure errors, because the two demand
// different responses: a refusal is final for these bytes (the device must
// re-seal), an error is retryable as-is. Code uses the vectors' defect
// vocabulary where one names the failure exactly.
type RefusalError struct {
	Code   Defect
	Detail string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("receipts: checkpoint refused (%s): %s", e.Code, e.Detail)
}

// AsRefusal unwraps a RefusalError if err carries one.
func AsRefusal(err error) (*RefusalError, bool) {
	var r *RefusalError
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}

// CheckpointEvent is the wire-side half the ingest pipeline hands over: the
// ReceiptCheckpoint body plus the envelope facts the payload reconstruction
// needs. Identity (tenant, device) comes from verified claims, never the
// event (08 §2.1).
type CheckpointEvent struct {
	EventID     uuid.UUID
	DeviceID    uuid.UUID
	DeviceKeyID string // ReceiptCheckpoint.key_id — a lookup hint; trust comes from the signature
	// ClaimedCheckpointSeq is the event's per-device counter claim. It must
	// equal the tenant counter the head lock assigns, or the origin signature
	// cannot verify anyway — checked first so the refusal names the real
	// cause (stale head) instead of a bare bad_signature.
	ClaimedCheckpointSeq int64
	MerkleRoot           [32]byte
	LeafCount            int
	OriginSig            []byte
	// IssuedAt is the envelope's device-stamped occurred_at. The payload's
	// issued_at string is its RFC 3339 UTC seconds rendering — pinned here
	// because the device must produce the identical bytes when it signs.
	IssuedAt time.Time
}

// Appended reports the chain position a checkpoint landed at.
type Appended struct {
	ReceiptID     uuid.UUID
	Seq           int64
	CheckpointSeq int64
	ReceiptHash   [32]byte
	PayloadText   string
}

// Store appends to m1_receipts under the tenant GUC. ONE writer estate-wide:
// every append flows through controld, which holds the head lock and the
// server chain key (m1_002 §5).
type Store struct {
	db     DB
	signer SignerLike
	// retiring is the predecessor chain key during a rotation window
	// (ADR-0004): it signs exactly one more receipt per tenant, the
	// key_rotation record naming signer, and nothing else.
	retiring SignerLike
}

func NewStore(db DB, signer SignerLike) *Store {
	return &Store{db: db, signer: signer}
}

// WithRetiring installs the predecessor for the rotation window. Wiring it is
// deploy-time (a second seed or KMS alias); until then no chain crosses over.
func (s *Store) WithRetiring(prev SignerLike) *Store {
	s.retiring = prev
	return s
}

// Signer exposes the chain key (module routes publish its public half).
func (s *Store) Signer() SignerLike { return s.signer }

// IssuedAtString is the pinned rendering of a checkpoint payload's issued_at:
// RFC 3339, UTC, whole seconds. One rule, one place — the device-side sealer
// and this reconstruction must emit identical bytes or every checkpoint reads
// as forged.
func IssuedAtString(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// AppendCheckpoint runs the whole 07 §checkpoint-model server half in ONE
// transaction under the tenant GUC: lock the head row, rebuild the payload at
// seq+1/checkpoint_seq+1, verify the device origin signature over the signing
// input, countersign the SAME input, INSERT the receipt, advance the head.
// `sealed`, when non-nil, runs inside the same tx after the insert — the seam
// for side effects that need the receipt id to exist (coverage_transitions,
// m1_043's NOT NULL receipt_id).
//
// The head lock (SELECT ... FOR UPDATE) is the serialization point: two
// concurrent appends for one tenant queue on the row, so seq is gap-free by
// construction and a gap MEANS deletion (m1_002 header). This is retry
// semantics, not an optimization — do not replace the lock with a sequence.
func (s *Store) AppendCheckpoint(ctx context.Context, tenant querychoke.TenantID, ev CheckpointEvent, sealed func(tx pgx.Tx, r Appended) error) (Appended, error) {
	// The rotation record commits in its OWN transaction first: a device that
	// sealed against the pre-rotation head is refused below and re-seals, and
	// a refusal must not roll the announcement back with it.
	if s.retiring != nil {
		if err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error { return s.crossOver(ctx, tx, tenant) }); err != nil {
			return Appended{}, err
		}
	}
	var out Appended
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		// Genesis rule: the head row is created 0-with-genesis-hash on first
		// touch so the first append has no special case (m1_002 §3). The
		// INSERT is a no-op forever after; the SELECT takes the lock.
		if _, err := tx.Exec(ctx,
			`INSERT INTO m1_receipt_chain_head (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`,
			tenant.UUID()); err != nil {
			return err
		}
		var headSeq, headCkpt int64
		var headHash []byte
		if err := tx.QueryRow(ctx,
			`SELECT seq, head_hash, checkpoint_seq FROM m1_receipt_chain_head
			  WHERE tenant_id = $1 FOR UPDATE`, tenant.UUID()).
			Scan(&headSeq, &headHash, &headCkpt); err != nil {
			return err
		}

		// The device origin key: m1_device_keys IS the device-origin role set
		// (RLS already scopes it to this tenant). key_id → the wrong table's
		// key, a revoked key, or another device's key are all refusals with
		// their own names — a bare signature failure would hide which control
		// fired.
		var pub []byte
		var keyDevice uuid.UUID
		var revokedAt *time.Time
		switch err := tx.QueryRow(ctx,
			`SELECT public_key, device_id, revoked_at FROM m1_device_keys WHERE key_id = $1`,
			ev.DeviceKeyID).Scan(&pub, &keyDevice, &revokedAt); {
		case errors.Is(err, pgx.ErrNoRows):
			return &RefusalError{Code: DefectUnknownKey,
				Detail: fmt.Sprintf("key_id %q is not a device origin key for this tenant (key-class split, 05 §4.5)", ev.DeviceKeyID)}
		case err != nil:
			return err
		}
		if keyDevice != ev.DeviceID {
			// A valid key used by the WRONG device is an impersonation
			// attempt, not a stale-key accident.
			return &RefusalError{Code: DefectUnknownKey,
				Detail: fmt.Sprintf("key_id %q belongs to device %s, not the authenticated device", ev.DeviceKeyID, keyDevice)}
		}
		if revokedAt != nil {
			// Verification of PAST receipts still uses the key; nothing NEW
			// signed under it is accepted (m1_001's column comment).
			return &RefusalError{Code: DefectUnknownKey,
				Detail: fmt.Sprintf("key_id %q was revoked at %s; it signs nothing new", ev.DeviceKeyID, revokedAt.UTC().Format(time.RFC3339))}
		}

		seq := headSeq + 1
		ckptSeq := headCkpt + 1
		if ev.ClaimedCheckpointSeq != ckptSeq {
			// The device sealed against a stale head; its signature covers
			// the wrong counter and can never verify here. Name the real
			// cause so the edge's re-seal is a deterministic next step.
			return &RefusalError{Code: DefectBrokenLink,
				Detail: fmt.Sprintf("checkpoint_seq %d does not extend the tenant chain (next is %d); re-seal against the current head (08 §3.4)", ev.ClaimedCheckpointSeq, ckptSeq)}
		}

		cp := Checkpoint{
			TenantID:        tenant.String(),
			DeviceID:        ev.DeviceID.String(),
			Seq:             seq,
			PrevReceiptHash: [32]byte(headHash),
			IssuedAt:        IssuedAtString(ev.IssuedAt),
			CheckpointSeq:   ckptSeq,
			MerkleRoot:      ev.MerkleRoot,
			LeafCount:       ev.LeafCount,
		}
		text, err := CanonicalJSON(cp.Payload(ev.DeviceKeyID))
		if err != nil {
			return err
		}
		signingInput := append([]byte(DomainPrefix), text...)
		if !Verify(ed25519.PublicKey(pub), ev.OriginSig, signingInput) {
			return &RefusalError{Code: DefectBadSignature,
				Detail: "origin signature does not verify over the reconstructed signing input; tampered event, or the device sealed against a stale head"}
		}
		// Countersign the SAME signing input — never a re-serialisation
		// (m1_002's column comment: one canonicalisation, two public keys).
		serverSig, err := s.signer.Sign(signingInput)
		if err != nil {
			return err
		}
		// receipt_hash covers the signing input, prefix included (vectors
		// README) — the same bytes both signatures just covered.
		hash := sha256.Sum256(signingInput)

		var receiptID uuid.UUID
		if err := tx.QueryRow(ctx, `
			INSERT INTO m1_receipts
			  (tenant_id, seq, prev_receipt_hash, receipt_hash, payload, record_type, issued_at,
			   server_key_id, server_signature, device_key_id, device_signature,
			   checkpoint_seq, merkle_root, event_count)
			VALUES ($1, $2, $3, $4, $5, 'checkpoint', $6, $7, $8, $9, $10, $11, $12, $13)
			RETURNING id`,
			// issued_at column = the payload's issued_at, verbatim to the
			// second (estate rule: the column restates the signed claim).
			tenant.UUID(), seq, headHash, hash[:], text, ev.IssuedAt.UTC().Truncate(time.Second),
			s.signer.KeyID(), serverSig, ev.DeviceKeyID, ev.OriginSig,
			ckptSeq, ev.MerkleRoot[:], ev.LeafCount).Scan(&receiptID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE m1_receipt_chain_head
			   SET seq = $2, head_hash = $3, checkpoint_seq = $4, updated_at = now()
			 WHERE tenant_id = $1`,
			tenant.UUID(), seq, hash[:], ckptSeq); err != nil {
			return err
		}
		out = Appended{ReceiptID: receiptID, Seq: seq, CheckpointSeq: ckptSeq, ReceiptHash: hash, PayloadText: text}
		if sealed != nil {
			return sealed(tx, out)
		}
		return nil
	})
	if err != nil {
		return Appended{}, err
	}
	return out, nil
}

// AlreadyAppended reports whether an origin-signed checkpoint already sits in
// the tenant chain. Ed25519 is deterministic — one key, one signing input,
// one signature — and the signing input carries seq/prev_hash/root, so the
// origin signature bytes identify exactly one sealed checkpoint. This is the
// dedupe fact sidefx needs: at-least-once ingest and 05 §2.5 S3 replay both
// re-deliver checkpoints the chain already holds, and re-delivery must read
// as "duplicate", never as staleness or tampering.
// ponytail: unindexed scan on m1_receipts.device_signature — it runs only on
// refusal/mismatch paths (cold); index it if replaying large chains shows up.
func (s *Store) AlreadyAppended(ctx context.Context, tenant querychoke.TenantID, originSig []byte) (bool, error) {
	if len(originSig) == 0 {
		return false, nil
	}
	found := false
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var one int
		scanErr := tx.QueryRow(ctx,
			`SELECT 1 FROM m1_receipts WHERE record_type = 'checkpoint' AND device_signature = $1 LIMIT 1`,
			originSig).Scan(&one)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		found = scanErr == nil
		return scanErr
	})
	return found, err
}

// Head returns the tenant's current chain head (0, genesis when the chain is
// empty) — what the export response's chain_head reports (08 §3.4) and what
// a device re-seals against after a refusal.
func (s *Store) Head(ctx context.Context, tenant querychoke.TenantID) (seq int64, hash [32]byte, checkpointSeq int64, err error) {
	hash = GenesisHash
	err = s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var h []byte
		scanErr := tx.QueryRow(ctx,
			`SELECT seq, head_hash, checkpoint_seq FROM m1_receipt_chain_head WHERE tenant_id = $1`,
			tenant.UUID()).Scan(&seq, &h, &checkpointSeq)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil // empty chain: 0 + genesis, m1_002 §3's no-special-case shape
		}
		if scanErr == nil {
			hash = [32]byte(h)
		}
		return scanErr
	})
	return seq, hash, checkpointSeq, err
}

// Execer is the boot-time seam for the global (non-RLS)
// m1_server_signing_keys table; *pgxpool.Pool satisfies it. Request-path code
// never touches it — everything tenant-scoped rides WithTenant.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// RegisterServerKey publishes the chain key's public half so m1_receipts'
// server_key_id FK holds and verifiers can fetch it. Idempotent (key_id is
// derived, so re-registering the same key is a no-op); keys are NEVER deleted
// or unpublished — rotation stamps retired_at instead (m1_002 §1: a receipt
// under an unpublished key is one nobody can verify, i.e. one we never
// issued).
func RegisterServerKey(ctx context.Context, db Execer, signer SignerLike) error {
	_, err := db.Exec(ctx, `
		INSERT INTO m1_server_signing_keys (key_id, public_key)
		VALUES ($1, $2) ON CONFLICT (key_id) DO NOTHING`,
		signer.KeyID(), []byte(signer.Public()))
	return err
}

// RegisterSuccessorKey is the rotation ceremony's server-chain step
// (ADR-0004): the retiring key cross-signs the successor, the successor is
// published WITH that endorsement, and the retiring key is stamped retired.
// Idempotent; a successor already registered bare (boot's RegisterServerKey)
// gains its cross-signature rather than keeping none.
func RegisterSuccessorKey(ctx context.Context, db Execer, retiring, successor SignerLike) error {
	sig, err := CrossSign(retiring, RoleServerChain, successor.Public())
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO m1_server_signing_keys (key_id, public_key, cross_signed_by, cross_signature)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (key_id) DO UPDATE SET cross_signed_by = EXCLUDED.cross_signed_by,
		                                   cross_signature = EXCLUDED.cross_signature
		 WHERE m1_server_signing_keys.cross_signed_by IS NULL`,
		successor.KeyID(), []byte(successor.Public()), retiring.KeyID(), sig); err != nil {
		return err
	}
	_, err = db.Exec(ctx, `UPDATE m1_server_signing_keys SET retired_at = now()
		 WHERE key_id = $1 AND retired_at IS NULL`, retiring.KeyID())
	return err
}
