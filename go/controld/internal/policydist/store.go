// The Postgres half: publication, catalog serving, ACK intake, ACK coverage.
//
// PUBLICATION IS ONE TRANSACTION (05 §4.1). Catalog row, transparency-log
// leaf, signed log head and the `bundle_publication` receipt commit together
// or not at all. A published bundle with no log leaf is invisible to
// split-view detection; a leaf with no catalog row is a promise about bytes
// nobody can fetch.
//
// THE MONOTONICITY IS NOT ENFORCED HERE. m1_042's trigger owns it: seq must be
// head+1 and prev_hash must chain, checked under a row lock the trigger takes
// itself. This file computes the same values and would be redundant if the
// trigger did not exist -- which is the point. If the two ever disagree the
// INSERT fails, and a failed publish is the safe direction. Rollback is a
// forward publication at seq+1; there is no unpublish verb in this package
// because there is none in the system.

package policydist

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/pg"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

// Counters cross one impedance boundary in this file: uint64 on the wire (CBOR
// has no signed form for a counter) and bigint in Postgres. Every value that
// crosses it was read out of a bigint column, or derived from one, inside the
// same transaction -- so the range is int64's to begin with and the conversion
// cannot lose information. These two exist so that argument is made once here
// rather than restated at eight call sites.
//
//nolint:gosec // G115: see above.
func i64(v uint64) int64 { return int64(v) }

//nolint:gosec // G115: callers guard non-negativity (head_seq, tree_size, max_age).
func u64(v int64) uint64 { return uint64(v) }

// DB is the WithTenant-shaped seam (05 §7.2). *pg.TenantDB satisfies it.
type DB interface {
	WithTenant(ctx context.Context, t querychoke.TenantID, fn func(pgx.Tx) error) error
}

var _ DB = (*pg.TenantDB)(nil)

// ReceiptAppender is the receipts package's tx-scoped server-record seam.
type ReceiptAppender interface {
	AppendServerRecordTx(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, rec receipts.ServerRecord) (receipts.Appended, error)
}

// ErrNoChannel is 08 §3.2's only server-side 3xxx: the tenant has no bundle on
// this channel. HTTP 404 / M1E-3004.
var ErrNoChannel = errors.New("policydist: no bundle published on this channel")

type Store struct {
	db       DB
	receipts ReceiptAppender
	// ring and headSigner are nil when no bundle key is configured: this
	// process then SERVES and takes ACKs but cannot publish. Publish refuses
	// loudly rather than the module failing to mount, because publication has
	// no public route and an unmounted module takes the poll down with it.
	ring *Keyring
	// headSigner is the log key class (05 §4.4), never a bundle section key.
	// In practice it is the server CHAIN key: that key is already the log-class
	// key of this service and is already the FK target in
	// m1_server_signing_keys, and the domain prefixes make a receipt signature
	// and a log-head signature non-interchangeable.
	headSigner SectionSigner
}

func NewStore(db DB, r ReceiptAppender, ring *Keyring, headSigner SectionSigner) *Store {
	return &Store{db: db, receipts: r, ring: ring, headSigner: headSigner}
}

// Draft is what the policy compiler submits: a channel, a fail-static age
// bound, and the canonical CBOR of the six-section map. No seq, no prev_hash,
// no signatures -- those are the server's to assign, and a caller that could
// choose them could choose a regression.
type Draft struct {
	Channel      string
	MaxAge       time.Duration
	SectionsCBOR []byte
	// FirstOnly publishes only as the channel's seq 1: a channel that already has a head is left untouched (ErrChannelHasHead), under the same row lock, so two enrollments cannot both bootstrap.
	FirstOnly bool
}

// ErrChannelHasHead is a FirstOnly draft meeting a channel that already published.
var ErrChannelHasHead = errors.New("policydist: channel already has a head; FirstOnly draft not published")

// Published reports where a bundle landed.
type Published struct {
	Channel    string
	Seq        int64
	BodySHA256 [32]byte
	TLogIndex  int64
	TreeSize   int64
	RootHash   [32]byte
	ReceiptID  uuid.UUID
	ETag       string
	Body       []byte // the served bytes: canonical body PLUS inclusion
}

// Publish runs the whole publication transaction.
func (s *Store) Publish(ctx context.Context, tenant querychoke.TenantID, d Draft) (Published, error) {
	if s.ring == nil || s.headSigner == nil {
		return Published{}, errors.New("policydist: no bundle signing key configured (BUNDLE_SECTION_ED25519_SEED); this process serves and ACKs but does not publish")
	}
	if err := ident("channel", d.Channel); err != nil {
		return Published{}, err
	}
	if d.MaxAge < time.Second {
		// max_age is the fail-static floor: past it the edge falls to
		// conservative built-in defaults. Zero would mean "stale on arrival".
		return Published{}, reject("M1E-2001", "max_age must be at least one second, got %s", d.MaxAge)
	}
	// THE GATE. Decode + validate + canonicality, before a seq is reserved and
	// before anything is signed. 05 §4.1: "a compiler bug that emits one must
	// die here, at publish, not at ten thousand edges."
	sections, err := DecodeSections(d.SectionsCBOR)
	if err != nil {
		return Published{}, err
	}
	secBytes, err := sectionBytes(sections)
	if err != nil {
		return Published{}, err
	}

	var out Published
	err = s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO bundle_channel_heads (tenant_id, channel) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			tenant.UUID(), d.Channel); err != nil {
			return err
		}
		var headSeq int64
		var headHash []byte
		if err := tx.QueryRow(ctx,
			`SELECT head_seq, head_hash FROM bundle_channel_heads
			  WHERE tenant_id = $1 AND channel = $2 FOR UPDATE`,
			tenant.UUID(), d.Channel).Scan(&headSeq, &headHash); err != nil {
			return err
		}
		if d.FirstOnly && headSeq != 0 {
			return ErrChannelHasHead
		}
		if headSeq < 0 {
			// Unreachable while the CHECK on bundle_channel_heads holds. If it
			// ever is reachable, a negative head becomes a colossal uint64 seq
			// that no later publication can exceed -- the channel would be
			// bricked at the edge's anti-rollback check, permanently.
			return fmt.Errorf("policydist: channel %q head_seq is negative (%d)", d.Channel, headSeq)
		}

		tid := tenant.UUID()
		b := &Bundle{
			Schema: SchemaID, TenantID: tid[:], Channel: d.Channel,
			Seq: u64(headSeq + 1), IssuedAt: IssuedAtNow(),
			MaxAge: u64(int64(d.MaxAge / time.Second)), PrevHash: headHash,
			Sections: sections,
		}
		sigs, err := s.ring.SignSections(b, secBytes)
		if err != nil {
			return err
		}
		b.Signatures = sigs

		body, err := CanonicalBody(b)
		if err != nil {
			return err
		}
		bodyHash := sha256.Sum256(body)

		incl, treeSize, err := s.appendLeaf(ctx, tx, tenant, LeafKindPolicyBundle, bodyHash)
		if err != nil {
			return err
		}
		b.Inclusion = incl

		served, err := Marshal(b)
		if err != nil {
			return err
		}

		// The publication receipt. subject_id is derived from the body hash so
		// it is stable and needs no row to exist first -- policy_bundles'
		// receipt_id is NOT NULL, so the receipt must precede the catalog row,
		// and a subject_id pointing at the catalog row would be circular.
		app, err := s.receipts.AppendServerRecordTx(ctx, tx, tenant, receipts.ServerRecord{
			RecordType: "bundle_publication",
			SubjectID:  BundleSubjectID(bodyHash),
			IssuedAt:   b.IssuedAt,
			Fields: map[string]any{
				"channel":        d.Channel,
				"bundle_seq":     b.Seq,
				"body_sha256":    hex.EncodeToString(bodyHash[:]),
				"bundle_prev":    hex.EncodeToString(headHash),
				"max_age_s":      b.MaxAge,
				"tlog_index":     incl.LeafIndex,
				"tlog_tree_size": incl.TreeSize,
				"tlog_root":      hex.EncodeToString(incl.RootHash),
				"signing_key_id": s.ring.PrimaryKeyID(),
			},
		})
		if err != nil {
			return err
		}

		proofJSON, err := inclusionJSON(incl)
		if err != nil {
			return err
		}
		sigJSON, err := signaturesJSON(sigs)
		if err != nil {
			return err
		}
		// body_cbor is the SERVED bytes (inclusion included) -- m1_042: "the
		// exact signed bytes ... storing anything but those bytes invites a
		// canonicalization mismatch between what we signed and what we serve".
		// body_sha256 is over the body MINUS inclusion, because that is what
		// prev_hash and the log leaf commit to (08 §3.2). The two therefore
		// differ by design; sha256(body_cbor) is not body_sha256.
		if _, err := tx.Exec(ctx, `
			INSERT INTO policy_bundles
			  (tenant_id, channel, seq, body_cbor, body_sha256, prev_hash, max_age,
			   signatures, signing_key_id, tlog_index, tlog_proof, receipt_id)
			VALUES ($1, $2, $3, $4, $5, $6, make_interval(secs => $7), $8, $9, $10, $11, $12)`,
			tenant.UUID(), d.Channel, i64(b.Seq), served, bodyHash[:], headHash,
			float64(b.MaxAge), sigJSON, s.ring.PrimaryKeyID(),
			i64(incl.LeafIndex), proofJSON, app.ReceiptID); err != nil {
			return err
		}

		out = Published{
			Channel: d.Channel, Seq: i64(b.Seq), BodySHA256: bodyHash,
			TLogIndex: i64(incl.LeafIndex), TreeSize: treeSize,
			RootHash: [32]byte(incl.RootHash), ReceiptID: app.ReceiptID,
			ETag: ETag(tenant, d.Channel, i64(b.Seq)), Body: served,
		}
		return nil
	})
	if err != nil {
		return Published{}, err
	}
	return out, nil
}

// BundleSubjectID derives the receipt's subject from the body hash. UUIDv5
// over a URN keeps it deterministic (a retried publication of identical bytes
// names the same subject) without inventing a namespace constant.
func BundleSubjectID(bodyHash [32]byte) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("urn:mark1:policy-bundle:"+hex.EncodeToString(bodyHash[:])))
}

// appendLeaf adds one leaf to the tenant's log, recomputes the root, signs the
// new head, and returns the inclusion proof for the leaf just added.
//
// ponytail: recomputes the whole tree from the leaf table on every append --
// O(n) hashes per publication. At Mark 1 volumes (a few publications a day per
// tenant) that is microseconds. Upgrade path when a tenant's log gets long:
// keep the RFC 6962 "tree head state" (the ~log n right-hand fringe hashes)
// in tlog_heads and fold the new leaf in, which is what makes appends O(log n)
// -- the tree functions above already take that shape.
func (s *Store) appendLeaf(ctx context.Context, tx pgx.Tx, tenant querychoke.TenantID, kind string, leaf [32]byte) (*Inclusion, int64, error) {
	if _, err := tx.Exec(ctx,
		`INSERT INTO tlog_heads (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, tenant.UUID()); err != nil {
		return nil, 0, err
	}
	var size int64
	if err := tx.QueryRow(ctx,
		`SELECT tree_size FROM tlog_heads WHERE tenant_id = $1 FOR UPDATE`, tenant.UUID()).Scan(&size); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO tlog_leaves (tenant_id, leaf_index, kind, leaf_hash) VALUES ($1, $2, $3, $4)`,
		tenant.UUID(), size, kind, leaf[:]); err != nil {
		return nil, 0, err
	}

	rows, err := tx.Query(ctx,
		`SELECT leaf_hash FROM tlog_leaves WHERE tenant_id = $1 ORDER BY leaf_index`, tenant.UUID())
	if err != nil {
		return nil, 0, err
	}
	var leaves [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return nil, 0, err
		}
		leaves = append(leaves, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	newSize := int64(len(leaves))
	if newSize != size+1 {
		// The dense-index trigger already refuses gaps; this catches the other
		// direction -- a leaf the tenant GUC hid from this read would produce
		// a proof against a tree the log does not have.
		return nil, 0, fmt.Errorf("policydist: log read %d leaves after appending index %d", newSize, size)
	}

	root, err := MerkleRoot(leaves)
	if err != nil {
		return nil, 0, err
	}
	path, err := InclusionProof(leaves, len(leaves)-1)
	if err != nil {
		return nil, 0, err
	}
	// Verify our own proof before committing: a tree bug becomes a failed
	// publication instead of a fleet-wide M1E-3003.
	if !VerifyInclusion(leaf[:], u64(size), u64(newSize), path, root) {
		return nil, 0, fmt.Errorf("policydist: freshly built inclusion proof does not verify (leaf %d of %d)", size, newSize)
	}

	input, err := TLogHeadSigningInput(tenant.UUID(), u64(newSize), root)
	if err != nil {
		return nil, 0, err
	}
	sig, err := s.headSigner.Sign(input)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tlog_signed_heads (tenant_id, tree_size, root_hash, key_id, signature)
		VALUES ($1, $2, $3, $4, $5)`,
		tenant.UUID(), newSize, root[:], s.headSigner.KeyID(), sig); err != nil {
		return nil, 0, err
	}
	return &Inclusion{
		TreeSize: u64(newSize), LeafIndex: u64(size), AuditPath: path, RootHash: root[:],
	}, newSize, nil
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

// Served is one catalog row, ready for the wire.
type Served struct {
	Seq       int64
	Body      []byte
	ETag      string
	SigHeader string // X-Mark1-Bundle-Sig: echo of the in-map sigs (08 §3.2)
	Proof     string // X-Mark1-Tlog-Proof: echo of the in-map inclusion proof
}

// Latest reads the head bundle for (tenant, channel). ErrNoChannel when the
// tenant has never published there.
func (s *Store) Latest(ctx context.Context, tenant querychoke.TenantID, channel string) (Served, error) {
	var out Served
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		var sigJSON, proofJSON []byte
		scanErr := tx.QueryRow(ctx, `
			SELECT seq, body_cbor, signatures::text, tlog_proof::text
			  FROM policy_bundles
			 WHERE tenant_id = $1 AND channel = $2
			 ORDER BY seq DESC LIMIT 1`, tenant.UUID(), channel).
			Scan(&out.Seq, &out.Body, &sigJSON, &proofJSON)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return ErrNoChannel
		}
		if scanErr != nil {
			return scanErr
		}
		out.ETag = ETag(tenant, channel, out.Seq)
		out.SigHeader = base64.StdEncoding.EncodeToString(sigJSON)
		out.Proof = base64.StdEncoding.EncodeToString(proofJSON)
		return nil
	})
	if err != nil {
		return Served{}, err
	}
	return out, nil
}

// SignedHead is the tenant's signed head at treeSize (05 §4.4), newest when 0: a bundle's proof targets the head at ITS tree_size, and the log keeps growing past it.
func (s *Store) SignedHead(ctx context.Context, tenant querychoke.TenantID, treeSize int64) (SignedHead, error) {
	var out SignedHead
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tree_size, root_hash, key_id, signature FROM tlog_signed_heads
			 WHERE tenant_id = $1 AND ($2 = 0 OR tree_size = $2)
			 ORDER BY tree_size DESC LIMIT 1`, tenant.UUID(), treeSize).
			Scan(&out.TreeSize, &out.Root, &out.KeyID, &out.Signature)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SignedHead{}, ErrNoHead
	}
	return out, err
}

// SignedHead is a tlog_signed_heads row.
type SignedHead struct {
	TreeSize  int64
	Root      []byte
	KeyID     string
	Signature []byte
}

// ErrNoHead: the tenant's log has no signed head at that size (or none at all).
var ErrNoHead = errors.New("policydist: no signed tlog head")

// ETag is 05 §4.2's `"t<n>-<channel>-<seq06>"`.
//
// DOC GAP, resolved and reported: neither 05 nor 08 defines `<n>`. It is
// derived here as the first 8 hex of SHA-256(tenant uuid) -- stable per
// tenant, and not the tenant UUID itself, because an ETag rides in proxy logs
// and caches where 08 §3.5's "nothing tenant-identifying" discipline applies.
// The value is opaque to the client either way: 08 §3.2 makes headers
// "transport-level echoes ... a header participates in NO verification step",
// so the only operation performed on it is equality against one we minted.
func ETag(tenant querychoke.TenantID, channel string, seq int64) string {
	t := tenant.UUID()
	h := sha256.Sum256(t[:])
	return fmt.Sprintf("\"t%s-%s-%06d\"", hex.EncodeToString(h[:4]), channel, seq)
}

// ---------------------------------------------------------------------------
// ACK intake
// ---------------------------------------------------------------------------

// Ack is 08 §3.2's POST body, already parsed and vocabulary-checked. device_id
// and tenant_id are absent by design -- both come from verified claims.
type Ack struct {
	Channel         string
	Seq             int64
	BundleHash      [32]byte
	Result          string
	SectionsSkipped []string
	RejectCode      *string
	EdgeVersion     string
}

// RecordAck inserts one ACK. ON CONFLICT DO NOTHING, not an upsert: the ledger
// role holds INSERT and no UPDATE (m1_060), and the first ACK for a
// (device, channel, seq) is the one the canary must believe. A device that
// rejected a bundle and then restarts and reports 'applied' for the same seq
// cannot erase the rejection -- that is the fail-closed direction, and 05
// §4.3's halt arithmetic depends on it.
//
// Returns false when the row already existed (a retry, not an error).
func (s *Store) RecordAck(ctx context.Context, tenant querychoke.TenantID, deviceID uuid.UUID, a Ack) (bool, error) {
	inserted := false
	// sections_skipped is NOT NULL DEFAULT '{}'; a nil Go slice binds as SQL
	// NULL, not as the empty array, so an 'applied' ACK (which skips nothing)
	// would violate the column on every single insert.
	skipped := a.SectionsSkipped
	if skipped == nil {
		skipped = []string{}
	}
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO bundle_acks
			  (tenant_id, channel, seq, device_id, result, bundle_hash,
			   sections_skipped, reject_code, edge_version)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id, channel, device_id, seq) DO NOTHING`,
			tenant.UUID(), a.Channel, a.Seq, deviceID, a.Result, a.BundleHash[:],
			skipped, a.RejectCode, a.EdgeVersion)
		if err != nil {
			return err
		}
		inserted = tag.RowsAffected() == 1
		return nil
	})
	return inserted, err
}

// ---------------------------------------------------------------------------
// ACK coverage -- m1_042's canary query, parameterised by channel.
// ---------------------------------------------------------------------------

// Coverage is the rollout picture for one channel at one instant.
type Coverage struct {
	HeadSeq       int64
	ActiveDevices int64 // seen in the last 24h; a dark device cannot ACK and must not count against the rollout
	OnHead        int64 // latest ACK is the head AND applied
	Rejected      int64
	Partial       int64
	CommandString int64 // ACKs carrying M1E-3005 -- 05 §4.3(a), one is too many
}

// HeadRatio is the promotion numerator over the active denominator. Zero
// active devices reads as 0.0, never 1.0: an empty fleet has not adopted
// anything, and dividing by nothing must not widen a rollout.
func (c Coverage) HeadRatio() float64 {
	if c.ActiveDevices == 0 {
		return 0
	}
	return float64(c.OnHead) / float64(c.ActiveDevices)
}

// AckCoverage runs m1_042's canary query. `partial` is deliberately absent
// from the numerator: 05 §4.3(b) makes a skipped section count as
// NON-adoption, so a partial ACK must not widen a rollout even though it is a
// successful verify.
//
// All three adoption counters are scoped to head_seq, because every one of them
// is an answer to the same question -- what happened to THIS bundle. Earlier,
// only `applied` was scoped, so a device whose newest ACK rejected a superseded
// seq counted as Rejected against the current head and, being active but no
// longer ACKing, blocked widening permanently. Fail-closed in direction, but
// indistinguishable from a hung rollout in production.
//
// CommandString is the deliberate exception and is NOT seq-scoped: 05 §4.3(a)
// makes one M1E-3005 too many, and a command string that reached a device in a
// superseded bundle still happened. It reads the full ACK history rather than
// the latest-per-device CTE, which could only ever have seen the most recent
// one anyway.
func (s *Store) AckCoverage(ctx context.Context, tenant querychoke.TenantID, channel string) (Coverage, error) {
	var c Coverage
	err := s.db.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx, `
			WITH latest AS (
			  SELECT DISTINCT ON (a.device_id) a.device_id, a.seq, a.result, a.reject_code
			    FROM bundle_acks a
			   WHERE a.tenant_id = $1 AND a.channel = $2
			   ORDER BY a.device_id, a.acked_at DESC
			)
			SELECT h.head_seq,
			       count(d.id),
			       count(l.device_id) FILTER (WHERE l.seq = h.head_seq AND l.result = 'applied'),
			       count(l.device_id) FILTER (WHERE l.seq = h.head_seq AND l.result = 'rejected'),
			       count(l.device_id) FILTER (WHERE l.seq = h.head_seq AND l.result = 'partial'),
			       -- $1/$2 rather than h.tenant_id/h.channel: identical in value
			       -- (the WHERE pins both), but a correlated reference to an
			       -- ungrouped outer column is a planner error, not a preference.
			       (SELECT count(DISTINCT a.device_id) FROM bundle_acks a
			         WHERE a.tenant_id = $1 AND a.channel = $2
			           AND a.reject_code = 'M1E-3005')
			  FROM bundle_channel_heads h
			  JOIN m1_devices d ON d.tenant_id = h.tenant_id
			                   AND d.revoked_at IS NULL
			                   AND d.last_seen_at > now() - interval '24 hours'
			  LEFT JOIN latest l ON l.device_id = d.id
			 WHERE h.tenant_id = $1 AND h.channel = $2
			 GROUP BY h.head_seq`, tenant.UUID(), channel).
			Scan(&c.HeadSeq, &c.ActiveDevices, &c.OnHead, &c.Rejected, &c.Partial, &c.CommandString)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// No head row, or no device seen in 24h. Both mean "nothing to
			// widen on", and both must read as zero coverage rather than as
			// an error the caller might treat as transient and retry into a
			// widen decision.
			return nil
		}
		return scanErr
	})
	return c, err
}

// inclusionJSON / signaturesJSON render the two jsonb columns. Hex, not
// base64: the receipt payloads and every other hash column in this estate are
// hex, and one encoding for one kind of value keeps operator queries joinable.
//
// encoding/json, NOT receipts.CanonicalBytes: these are jsonb columns, and
// Postgres re-canonicalises jsonb on storage anyway. The receipt canonicaliser
// would prepend its signing-domain prefix, which is not JSON at all -- these
// bytes are never signed, so borrowing a signing helper for them would put a
// domain prefix inside a column and refuse every float and []string on the way.
func inclusionJSON(i *Inclusion) ([]byte, error) {
	path := make([]string, len(i.AuditPath))
	for n, h := range i.AuditPath {
		path[n] = hex.EncodeToString(h)
	}
	// Key names mirror the CBOR wire exactly so an operator diffing this column
	// against a captured bundle is comparing like with like. The head's key_id
	// and signature are not duplicated here: they live in tlog_signed_heads,
	// joinable on (tenant_id, tree_size).
	return json.Marshal(map[string]any{
		"tree_size":  i64(i.TreeSize),
		"leaf_index": i64(i.LeafIndex),
		"path":       path,
		"root":       hex.EncodeToString(i.RootHash),
	})
}

func signaturesJSON(sigs map[string]Signature) ([]byte, error) {
	m := make(map[string]any, len(sigs))
	for name, s := range sigs {
		m[name] = map[string]any{"key_id": s.KeyID, "sig": hex.EncodeToString(s.Sig)}
	}
	return json.Marshal(m)
}
