// Package receipt is the edge PRODUCER of the receipt chain (07's checkpoint
// model): every acked upload batch is Merkle-hashed over its event_ids,
// origin-signed with the device key, and admitted as a ReceiptCheckpoint
// event. controld's receipts.AppendCheckpoint is the authority every byte here
// is written against — it rebuilds the payload from the tenant's locked chain
// head and refuses anything that does not reproduce byte-for-byte.
//
// The consequence that shapes this whole package: the device-signed payload
// carries `seq` and `prev_receipt_hash`, which are per-TENANT server facts a
// device cannot know locally. So a seal is always head-fetch → sign → admit,
// never sign-from-local-state. That is the frozen wire format
// (conformance/vectors/receipt/), not a design choice available here.
package receipt

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

// headBodyLimit bounds the chain-head read: the response is one receipt row
// plus the head, never data — an oversized one is a broken or hostile server.
const headBodyLimit = 1 << 20

// maxPendingLeaves caps the carry-forward set (see retain). Leaves are 16 bytes,
// so the ceiling is ~1.6 MB — ten full batches, since compose caps a batch at
// 10_000 records. Past it the OLDEST leaves are dropped and reported orphaned:
// an unbounded buffer would turn a long outage into an OOM, which loses the
// whole spool rather than the head of one carry-forward set.
const maxPendingLeaves = 100_000

// Config wires one Sealer. Every field is required except the test seams.
type Config struct {
	Key identity.DeviceKey
	// TenantID/DeviceID must be the canonical UUID strings enrollment issued:
	// the server rebuilds the payload from `tenant.String()` / `device.String()`
	// off verified token claims (store.go:206), so a different rendering of the
	// same id is a signature over different bytes and refuses bad_signature.
	TenantID string
	DeviceID string
	// HeadURL is 08 §3.4's GET /api/v1/receipts — see HeadURL().
	HeadURL string
	Token   func(context.Context) (string, error)
	Admit   func(context.Context, *m1pv1.Event) error

	// Test seams; nil ⇒ production defaults.
	HTTPClient *http.Client
	Log        *slog.Logger
	Now        func() time.Time
}

// Sealer holds the device identity and the set of checkpoints it has emitted.
// NOT safe for concurrent use: uplink's Run goroutine is the sole caller, and
// Flush runs only after Run has returned (uplink.Uplink's own contract).
type Sealer struct {
	key      identity.DeviceKey
	keyID    string
	tenantID string
	deviceID string
	headURL  string
	token    func(context.Context) (string, error)
	admit    func(context.Context, *m1pv1.Event) error

	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	// mine holds the event_ids of the checkpoints THIS process admitted — the
	// termination fact, see allMine.
	// ponytail: process-lifetime memory, one 16-byte entry per acked batch.
	// Bounded in practice by how deep a backlog gets drained before the tail of
	// checkpoints is uploaded; evict-on-sight if a long-lived daemon ever shows
	// it in a heap profile.
	mine map[[16]byte]struct{}

	// pending holds leaves whose seal was refused by an I/O path that can clear.
	// See retain. Capped at maxPendingLeaves.
	pending [][]byte
}

// New validates the wiring. It does not touch the network.
func New(cfg Config) (*Sealer, error) {
	switch {
	case cfg.Key == nil:
		return nil, errors.New("receipt: Key required")
	case cfg.TenantID == "" || cfg.DeviceID == "":
		return nil, errors.New("receipt: TenantID and DeviceID required (they ride inside the signed payload)")
	case cfg.HeadURL == "":
		return nil, errors.New("receipt: HeadURL required (the chain head is a server fact, 08 §3.4)")
	case cfg.Token == nil:
		return nil, errors.New("receipt: Token required")
	case cfg.Admit == nil:
		return nil, errors.New("receipt: Admit required (a checkpoint reaches the wire only through capture, 04 §2.0)")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Sealer{
		key: cfg.Key, keyID: cfg.Key.KeyID(),
		tenantID: cfg.TenantID, deviceID: cfg.DeviceID,
		headURL: cfg.HeadURL, token: cfg.Token, admit: cfg.Admit,
		client: cfg.HTTPClient, log: cfg.Log, now: cfg.Now,
		mine: map[[16]byte]struct{}{},
	}, nil
}

// OpenKey loads the enrolled device key, and only loads it.
// identity.NewDeviceKey MINTS one on ErrNoKey — right for the self-issued
// spill key, wrong here: a key controld never enrolled is not in
// m1_device_keys, so every checkpoint signed under it refuses unknown_key
// (store.go:177). An absent key means sealing stays off, which is why the
// error is returned rather than resolved.
func OpenKey(path string) (identity.DeviceKey, error) {
	c := identity.FileCustody{Path: path}
	if _, err := c.Load(); err != nil {
		return nil, err
	}
	return identity.NewDeviceKey(c)
}

// HeadURL derives 08 §3.4's chain-head endpoint from the ingest URL the daemon
// already has. controld serves both, so its origin is the one fact needed —
// a second flag would only be a way to point them at different servers.
func HeadURL(ingestURL string) (string, error) {
	u, err := url.Parse(ingestURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("receipt: %q is not an absolute ingest URL", ingestURL)
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/api/v1/receipts"}).String(), nil
}

// Seal turns one acked upload batch into a checkpoint: leaves are the batch's
// event_ids in spool order (= the order the tree is built in, mirrored by
// controld's EffectsFromBatch).
//
// The checkpoint is admitted session-lessly. `checkpoint_seq` is per-DEVICE and
// controld's CheckpointEvent has no session field, so there is no session this
// is a fact about — a batch spans whatever sessions uploaded together, and a
// batch of purely device-scoped events has none at all.
//
// No error return, deliberately: nothing upstream can act on a failed seal —
// the batch has already landed and the spool cursor has already moved. A
// refusal is either carried into the next seal (retain) or reported orphaned.
func (s *Sealer) Seal(ctx context.Context, leaves [][]byte) {
	// Leaves a previous seal could not place come first: they are older, so this
	// keeps first_event_id/last_event_id a true range over the combined tree.
	leaves = append(s.pending, leaves...)
	if len(leaves) == 0 || s.allMine(leaves) {
		return
	}
	root, err := identity.MerkleRoot(leaves)
	if err != nil {
		// PERMANENT. A leaf that is not LeafSize will not be next time either,
		// and carrying it would fail every future seal at this same line — one
		// malformed leaf would end the device's chain outright. Drop the set.
		s.pending = nil
		s.orphaned(leaves, err)
		return
	}
	head, err := s.head(ctx)
	if err != nil {
		s.retain(leaves, err)
		return
	}
	// One instant, used twice: the payload's issued_at string and the envelope's
	// occurred_at. The server rebuilds the string from the envelope with its own
	// IssuedAtString (store.go:129, sidefx.go:142) — RFC 3339, UTC, whole
	// seconds — and truncating here as well leaves nothing for the two
	// renderings to disagree about.
	issuedAt := s.now().UTC().Truncate(time.Second)
	cp := identity.Checkpoint{
		TenantID:        s.tenantID,
		DeviceID:        s.deviceID,
		Seq:             head.seq + 1,
		PrevReceiptHash: head.hash,
		IssuedAt:        issuedAt.Format(time.RFC3339),
		CheckpointSeq:   head.checkpointSeq + 1,
		MerkleRoot:      root,
		LeafCount:       len(leaves),
	}
	signed, err := identity.OriginSign(s.key, cp.Payload(s.keyID))
	if err != nil {
		// PERMANENT for the same reason: the key is the key. A signer that
		// cannot sign this payload cannot sign a larger one either.
		s.pending = nil
		s.orphaned(leaves, err)
		return
	}
	ev := &m1pv1.Event{
		OccurredAt: timestamppb.New(issuedAt),
		Body: &m1pv1.Event_ReceiptCheckpoint{ReceiptCheckpoint: &m1pv1.ReceiptCheckpoint{
			//nolint:gosec // G115: checkpoint_seq is head+1, always ≥ 1.
			CheckpointSeq: uint64(cp.CheckpointSeq),
			MerkleRoot:    root[:],
			//nolint:gosec // G115: compose caps a batch at 10_000 records (batch.go).
			LeafCount:       uint32(len(leaves)),
			FirstEventId:    leaves[0],
			LastEventId:     leaves[len(leaves)-1],
			OriginSignature: signed.DeviceSig,
			KeyId:           s.keyID,
		}},
	}
	if err := s.admit(ctx, ev); err != nil {
		// The event is well-formed by construction here, so the reachable cause
		// is the spool refusing the write — transient. If it is not, pending
		// grows to the cap and sheds, which is the old behaviour with a ceiling.
		s.retain(leaves, err)
		return
	}
	s.pending = nil
	s.mine[[16]byte(ev.GetEventId())] = struct{}{}
	s.log.Info("receipt: batch sealed",
		"checkpoint_seq", cp.CheckpointSeq, "seq", cp.Seq, "leaves", len(leaves),
		"merkle_root", hex.EncodeToString(root[:]))
}

// retain carries a refused batch's leaves into the NEXT seal instead of losing
// them. Both callers are I/O — the chain-head GET and spool admission — and a
// laptop that sleeps, roams networks or drops a connection hits them routinely;
// the old behaviour put a whole batch outside the receipt chain forever for the
// duration of one failed request.
//
// This is legal because controld does not rebuild the tree from the batch it
// received: sidefx.EffectsFromBatch reads merkle_root and leaf_count off the
// checkpoint event and store.AppendCheckpoint verifies only the signature over
// them. A checkpoint whose tree spans two uploads is as valid as one that does
// not, and every leaf still appears under exactly one root.
//
// STILL OPEN: a checkpoint the SERVER refuses — a stale head, if another device
// in the tenant sealed between our GET and ingest — is refused asynchronously
// and is invisible from here. Nothing re-seals that. This closes the local half.
func (s *Sealer) retain(leaves [][]byte, err error) {
	if drop := len(leaves) - maxPendingLeaves; drop > 0 {
		s.orphaned(leaves[:drop], fmt.Errorf("carry-forward set full at %d leaves: %w", maxPendingLeaves, err))
		leaves = leaves[drop:]
	}
	s.pending = leaves
	s.log.Warn("receipt: batch not sealed, leaves carried into the next seal",
		"leaves", len(leaves), "err", err)
}

// orphaned is the permanent refusal path: the named events have already left
// the spool and nothing will re-seal them — they are outside the chain for
// good. This ERROR line is the entire record that it happened, so it must never
// be downgraded to a debug line or swallowed.
func (s *Sealer) orphaned(leaves [][]byte, err error) {
	s.log.Error("receipt: batch NOT sealed — these events are outside the receipt chain and will not be re-sealed",
		"leaves", len(leaves), "err", err)
}

// allMine reports whether a batch is made up ENTIRELY of checkpoints this
// process emitted — the termination rule. A checkpoint is admitted as an event,
// so it rides the next batch; sealing that batch would emit another checkpoint,
// forever. A checkpoint's attestation is its own chain row and needs no Merkle
// inclusion, so a batch with nothing else in it is already fully attested and
// gets no new seal. A batch with even one other event still seals, and covers
// the checkpoints riding beside it.
//
// A restart empties the set, so the first batch of pre-restart checkpoints
// seals ONE extra checkpoint; the batch after that is all-ours again and the
// loop closes. Bounded by construction — no persistent state needed.
func (s *Sealer) allMine(leaves [][]byte) bool {
	for _, l := range leaves {
		if len(l) != identity.LeafSize {
			return false
		}
		if _, ok := s.mine[[16]byte(l)]; !ok {
			return false
		}
	}
	return true
}

// chainHead is the tenant's chain position as 08 §3.4 reports it.
type chainHead struct {
	seq           int64
	hash          [32]byte
	checkpointSeq int64
}

// head fetches the CURRENT chain head, fresh, before every seal — never cached.
// seq is per-TENANT: it advances from other devices and from server-written
// receipt kinds, so a cached head is stale the moment anything else in the
// tenant writes a receipt, and a stale head signs the wrong counter (refused
// broken_link, store.go:201). The honest cost is one extra GET per checkpoint.
func (s *Sealer) head(ctx context.Context) (chainHead, error) {
	tok, err := s.token(ctx)
	if err != nil {
		return chainHead{}, err
	}
	// limit=1 is the smallest legal page (module.go defaults limit<=0 to 500);
	// the rows are unwanted, only chain_head is read.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.headURL+"?since_seq=0&limit=1", nil)
	if err != nil {
		return chainHead{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := s.client.Do(req)
	if err != nil {
		return chainHead{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return chainHead{}, fmt.Errorf("receipt: chain head GET answered %d", resp.StatusCode)
	}
	var body struct {
		ChainHead *struct {
			Seq  int64  `json:"seq"`
			Hash string `json:"hash"`
			// A POINTER, and that is the whole point: absent means a controld
			// predating the additive field (module.go §handleList). Defaulting it
			// to 0 would sign the wrong counter on every non-empty chain, so an
			// absent field is a refusal to seal, not a guess.
			CheckpointSeq *int64 `json:"checkpoint_seq"`
		} `json:"chain_head"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, headBodyLimit)).Decode(&body); err != nil {
		return chainHead{}, fmt.Errorf("receipt: chain head body is not controld's JSON: %w", err)
	}
	if body.ChainHead == nil {
		return chainHead{}, errors.New("receipt: response carries no chain_head")
	}
	if body.ChainHead.CheckpointSeq == nil {
		return chainHead{}, errors.New("receipt: chain_head carries no checkpoint_seq — this controld is too old to seal against; refusing to guess the counter the origin signature covers")
	}
	raw, err := hex.DecodeString(body.ChainHead.Hash)
	if err != nil || len(raw) != 32 {
		return chainHead{}, fmt.Errorf("receipt: chain_head.hash %q is not a 32-byte hex hash", body.ChainHead.Hash)
	}
	return chainHead{seq: body.ChainHead.Seq, hash: [32]byte(raw), checkpointSeq: *body.ChainHead.CheckpointSeq}, nil
}
