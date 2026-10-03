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
	"os"
	"path/filepath"
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
	// Session resolves a session to its host binding for ADR-0017's v2
	// payload; nil, or a batch with no bound session, seals the v1 payload.
	Session func(session [16]byte) identity.SessionBinding
	// StateDir is mark1d's state root; `last` is persisted under it (see
	// Sealer.lastPath) so the head race Seal reconciles does not re-open across
	// a restart with a pre-restart checkpoint still in the spool. Empty ⇒
	// process-lifetime only, with a warning: sealing fails SOFT throughout.
	StateDir string

	// Test seams; nil ⇒ production defaults.
	HTTPClient *http.Client
	Log        *slog.Logger
	Now        func() time.Time
}

// Sealer holds the device identity and the chain position of the newest
// checkpoint it has emitted. NOT safe for concurrent use: uplink's Run
// goroutine is the sole caller, and Flush runs only after Run has returned
// (uplink.Uplink's own contract).
// raceOver: the server's head has sat behind `last` WITHOUT MOVING for headRace. A moving head is the server catching up (the race); a head that has not advanced while the edge kept sealing is a refused seal — measured from the first sighting, not the newest seal, or a device that seals every few seconds would never notice.
func (s *Sealer) raceOver(head chainHead) bool {
	now := s.now()
	if s.lagSince.IsZero() || head.checkpointSeq > s.lagHead {
		s.lagSince, s.lagHead = now, head.checkpointSeq
		return false
	}
	return now.Sub(s.lagSince) >= headRace
}

// headRace bounds how long the edge trusts its own last seal over the server's head: controld applies a checkpoint post-ack within a second or two; past this the seal was refused.
const headRace = 15 * time.Second

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

	// last is the head the newest checkpoint this DEVICE admitted will leave
	// behind once controld applies it: its seq, its receipt hash (= the server's
	// head_hash, store.go "hash := sha256.Sum256(signingInput)"), its
	// checkpoint_seq. Zero until the first admit ever. See Seal for why it can
	// outrank a freshly fetched head. Persisted at lastPath after every admit
	// and loaded by New: a checkpoint admitted just before a restart is still
	// in the spool, still ahead of the server, and still the head the first
	// post-restart seal must chain to.
	last   chainHead
	lastAt time.Time // when last was sealed
	// lagSince is when the server's head was first seen behind `last` without moving since: the head race is over once that has lasted headRace, whatever the edge sealed meanwhile.
	lagSince time.Time
	lagHead  int64
	lastPath string

	// pending holds leaves whose seal was refused by an I/O path that can clear.
	// See retain. Capped at maxPendingLeaves.
	pending      [][]byte
	pendingFacts identity.BatchFacts // the pending leaves' facts, merged into the next seal
	session      func([16]byte) identity.SessionBinding
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
	s := &Sealer{
		key: cfg.Key, keyID: cfg.Key.KeyID(),
		tenantID: cfg.TenantID, deviceID: cfg.DeviceID,
		headURL: cfg.HeadURL, token: cfg.Token, admit: cfg.Admit, session: cfg.Session,
		client: cfg.HTTPClient, log: cfg.Log, now: cfg.Now,
	}
	if cfg.StateDir == "" {
		s.log.Warn("receipt: StateDir unset — the last-sealed head is process-lifetime only; a restart with a checkpoint still in the spool may re-mint its checkpoint_seq")
		return s, nil
	}
	s.lastPath = filepath.Join(cfg.StateDir, "receipt", "last-head")
	s.last = s.loadLast()
	return s, nil
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
// non-checkpoint event_ids in spool order (= the order the tree is built in,
// mirrored by controld's EffectsFromBatch). A ReceiptCheckpoint is never a
// leaf — uplink's batchLeaves drops them, the rule controld enforces
// (sidefx.go Apply) — so a batch of only checkpoints arrives here as no leaves
// and seals nothing, which is what ends the checkpoint-of-a-checkpoint chain.
//
// The checkpoint is admitted session-lessly. `checkpoint_seq` is per-DEVICE and
// controld's CheckpointEvent has no session field, so there is no session this
// is a fact about — a batch spans whatever sessions uploaded together, and a
// batch of purely device-scoped events has none at all.
//
// No error return, deliberately: nothing upstream can act on a failed seal —
// the batch has already landed and the spool cursor has already moved. A
// refusal is either carried into the next seal (retain) or reported orphaned.
func (s *Sealer) Seal(ctx context.Context, leaves [][]byte, facts identity.BatchFacts) {
	// Leaves a previous seal could not place come first: they are older, so this
	// keeps first_event_id/last_event_id a true range over the combined tree.
	leaves = append(s.pending, leaves...)
	facts = s.pendingFacts.Merge(facts)
	if len(leaves) == 0 {
		return
	}
	root, err := identity.MerkleRoot(leaves)
	if err != nil {
		// PERMANENT. A leaf that is not LeafSize will not be next time either,
		// and carrying it would fail every future seal at this same line — one
		// malformed leaf would end the device's chain outright. Drop the set.
		s.pending, s.pendingFacts = nil, identity.BatchFacts{}
		s.orphaned(leaves, err)
		return
	}
	head, err := s.head(ctx)
	if err != nil {
		s.retain(leaves, facts, err)
		return
	}
	if head.checkpointSeq < s.last.checkpointSeq && !s.raceOver(head) {
		// The head race: controld applies a batch's checkpoint POST-ack, on a
		// per-device queue (sidefx.Enqueue/Apply), so the head read right after
		// the ack may predate the checkpoint that rode in that very batch — or
		// one still in the spool behind this seal. Chaining to the stale row
		// would re-mint its checkpoint_seq and be refused broken_link once the
		// earlier one lands (store.go AppendCheckpoint). The edge knows exactly
		// what that checkpoint leaves as the head — it signed it — so chain to
		// that. Correct iff it lands before this one, which spool order and the
		// server's in-order queue give; if it is refused instead, no head the
		// edge could pick makes this seal right (its leaves sit behind the
		// refused set, see retain's STILL OPEN). A head at or past `last` is the
		// server's newer truth (our checkpoint applied, or another device's
		// seal outran it) and wins as before.
		head = s.last
	} else if head.checkpointSeq < s.last.checkpointSeq {
		// The race is long over and the server still has not applied `last`: it refused it post-ack (a merkle
		// mismatch, a stale head of its own) and said nothing the edge could hear. Chaining to `last` again would
		// claim a seq the chain will never reach — the founder's device sat at checkpoint_seq 1314 against a
		// server head of 6, every seal refused broken_link, every receipt "Server pending". The server's head is
		// the truth; the refused seal's leaves stay unreceipted, which is what they are.
		s.log.Warn("receipt: last seal never landed; chaining to the server's head", "last_checkpoint_seq", s.last.checkpointSeq, "server_checkpoint_seq", head.checkpointSeq)
		s.last = head
		s.lagSince = time.Time{}
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
		// ADR-0017: nil Hosts (no lookup, or no bound session in the batch) keeps v1.
		Hosts: facts.Bind(s.session), ArrestsActed: facts.ArrestsActed, ArrestsRecommended: facts.ArrestsRecommended,
	}
	signed, err := identity.OriginSign(s.key, cp.Payload(s.keyID))
	if err != nil {
		// PERMANENT for the same reason: the key is the key. A signer that
		// cannot sign this payload cannot sign a larger one either.
		s.pending, s.pendingFacts = nil, identity.BatchFacts{}
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
	if cp.Hosts != nil {
		rc := ev.GetReceiptCheckpoint()
		rc.PayloadVersion, rc.Hosts = 2, hostsProto(cp.Hosts)
		rc.ArrestsActed, rc.ArrestsRecommended = cp.ArrestsActed, cp.ArrestsRecommended
	}
	if err := s.admit(ctx, ev); err != nil {
		// The event is well-formed by construction here, so the reachable cause
		// is the spool refusing the write — transient. If it is not, pending
		// grows to the cap and sheds, which is the old behaviour with a ceiling.
		s.retain(leaves, facts, err)
		return
	}
	s.pending, s.pendingFacts = nil, identity.BatchFacts{}
	s.last = chainHead{seq: cp.Seq, hash: signed.ReceiptHash, checkpointSeq: cp.CheckpointSeq}
	s.lastAt = s.now()
	if err := s.saveLast(); err != nil {
		// The seal already happened; this only narrows what a restart knows.
		s.log.Warn("receipt: last-sealed head not persisted — a restart before the server applies it may re-mint its checkpoint_seq",
			"path", s.lastPath, "err", err)
	}
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
func (s *Sealer) retain(leaves [][]byte, facts identity.BatchFacts, err error) {
	if drop := len(leaves) - maxPendingLeaves; drop > 0 {
		s.orphaned(leaves[:drop], fmt.Errorf("carry-forward set full at %d leaves: %w", maxPendingLeaves, err))
		leaves = leaves[drop:]
	}
	s.pending, s.pendingFacts = leaves, facts
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

// chainHead is the tenant's chain position as 08 §3.4 reports it.
type chainHead struct {
	seq           int64
	hash          [32]byte
	checkpointSeq int64
}

// lastHeadFile is chainHead on disk: one JSON object, hash as the same hex
// controld's chain_head.hash uses, so the file reads like the GET it stands in
// for.
type lastHeadFile struct {
	Seq           int64  `json:"seq"`
	Hash          string `json:"hash"`
	CheckpointSeq int64  `json:"checkpoint_seq"`
	SealedAt      string `json:"sealed_at,omitempty"` // RFC 3339; absent in files older than headRace ⇒ the race is treated as over
}

// loadLast reads lastPath. Absent ⇒ zero, silently (first boot). Unreadable or
// unparseable ⇒ zero WITH a warning, never a boot refusal: the worst outcome
// is the head race being open for one seal, which is where every device was
// before the file existed — a refusal to boot would cost capture to protect a
// receipt.
func (s *Sealer) loadLast() chainHead {
	b, err := os.ReadFile(s.lastPath)
	if errors.Is(err, os.ErrNotExist) {
		return chainHead{}
	}
	var f lastHeadFile
	if err == nil {
		err = json.Unmarshal(b, &f)
	}
	var raw []byte
	if err == nil {
		raw, err = hex.DecodeString(f.Hash)
		if err == nil && len(raw) != 32 {
			err = fmt.Errorf("hash %q is not a 32-byte hex hash", f.Hash)
		}
	}
	if err != nil {
		s.log.Warn("receipt: last-sealed head unreadable, ignored — the first seal chains to the server's head as before",
			"path", s.lastPath, "err", err)
		return chainHead{}
	}
	if at, aerr := time.Parse(time.RFC3339Nano, f.SealedAt); aerr == nil {
		s.lastAt = at
	}
	return chainHead{seq: f.Seq, hash: [32]byte(raw), checkpointSeq: f.CheckpointSeq}
}

// saveLast persists `last` the way capture persists session_epoch: write-tmp,
// fsync, rename, fsync-dir. The spool's A/B slot exists for a value republished
// on every fsync tick through one open fd; this is written once per seal, so
// a rename per write is free and the idiom is the ~20 lines the tree already
// uses for its other small state files. Mode 0600 like the rest of the state
// dir — the hash is public, but the file is still a chain fact.
func (s *Sealer) saveLast() error {
	if s.lastPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.lastPath), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(lastHeadFile{
		Seq: s.last.seq, Hash: hex.EncodeToString(s.last.hash[:]), CheckpointSeq: s.last.checkpointSeq,
		SealedAt: s.lastAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	tmp := s.lastPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.lastPath); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.lastPath)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// head fetches the CURRENT chain head, fresh, before every seal — never cached.
// seq is per-TENANT: it advances from other devices and from server-written
// receipt kinds, so a cached head is stale the moment anything else in the
// tenant writes a receipt, and a stale head signs the wrong counter (refused
// broken_link, store.go:201). The honest cost is one extra GET per checkpoint.
// The one thing the fetch can lag is this device's own just-acked checkpoint,
// which Seal reconciles against `last`.
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

// hostsProto is the payload's host block on the wire (ReceiptCheckpoint.hosts),
// field for field, so controld rebuilds the same v2 bytes.
func hostsProto(hs []identity.HostBinding) []*m1pv1.HostBinding {
	out := make([]*m1pv1.HostBinding, 0, len(hs))
	for _, h := range hs {
		pb := &m1pv1.HostBinding{SessionId: h.SessionID[:], Transport: h.Transport, HostId: h.HostID, HostVersion: h.HostVersion, ProfileHash: h.ProfileHash[:], HostCorrelationId: h.HostCorrelationID}
		for _, t := range h.Tasks {
			pb.Tasks = append(pb.Tasks, &m1pv1.TaskBinding{TaskId: t.TaskID[:], IdentityHash: t.IdentityHash})
		}
		out = append(out, pb)
	}
	return out
}
