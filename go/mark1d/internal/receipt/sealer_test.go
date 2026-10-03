// The sealer is driven against a REAL spool + REAL capture admitter and a fake
// chain-head endpoint speaking controld's exact JSON (module.go handleList).
// Nothing here is mocked that can be run.
package receipt

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// The head the fake server reports, and therefore the head controld would have
// held under its FOR UPDATE lock. Non-zero on both counters so a sealer that
// defaulted either one is visible.
const (
	headSeq  = int64(41)
	headCkpt = int64(7)
)

var headHashHex = "aa" + hex.EncodeToString(make([]byte, 31))

const (
	testTenant = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	testDevice = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
)

type harness struct {
	sealer *Sealer
	cfg    Config // as wired; restart re-runs New over it
	sp     *spool.Spool
	pub    ed25519.PublicKey
	heads  int // chain-head GETs served
}

// restart is a daemon restart from the sealer's point of view: a NEW Sealer
// over the same state dir, spool and server, with no process memory.
func (h *harness) restart(t *testing.T) {
	t.Helper()
	s, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.sealer = s
}

// newHarness wires a sealer over a real spool + admitter. headBody, when
// non-nil, overrides the chain_head JSON so the too-old-server case is
// reachable.
func newHarness(t *testing.T, headBody func(w http.ResponseWriter)) *harness {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "session_epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "device.key")
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	// The public half as enrollment would have published it into m1_device_keys:
	// re-derived from the stored seed, never from the signer under test.
	seed, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{sp: sp, pub: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("chain head GET carried Authorization %q", got)
		}
		h.heads++
		w.Header().Set("Content-Type", "application/json")
		if headBody != nil {
			headBody(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipts": []any{},
			"chain_head": map[string]any{
				"seq": headSeq, "hash": headHashHex, "checkpoint_seq": headCkpt,
			},
		})
	}))
	t.Cleanup(srv.Close)

	h.cfg = Config{
		Key: key, TenantID: testTenant, DeviceID: testDevice,
		HeadURL:  srv.URL + "/api/v1/receipts",
		Token:    func(context.Context) (string, error) { return "tok", nil },
		Admit:    adm.Admit,
		StateDir: dir,
		Now:      func() time.Time { return time.Unix(1767225600, 123456789) },
	}
	h.sealer, err = New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// checkpoints reads back every ReceiptCheckpoint the sealer admitted. Records
// are invisible below the durable cursor, hence the Sync (07 §6).
func (h *harness) checkpoints(t *testing.T) []*m1pv1.Event {
	t.Helper()
	if err := h.sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := h.sp.Cursors()
	recs, _, err := h.sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	var out []*m1pv1.Event
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatal(err)
		}
		if ev.GetReceiptCheckpoint() != nil {
			if r.ID.Class() != spool.ClassBilling {
				t.Errorf("checkpoint spooled class %d, want billing (07 §6)", r.ID.Class())
			}
			out = append(out, ev)
		}
	}
	return out
}

func leaf(b byte) []byte {
	l := make([]byte, identity.LeafSize)
	l[0], l[15] = b, b
	return l
}

// TestSealVerifiesAsControldWould is the contract test. It RECONSTRUCTS the
// verification controld's receipts.Store.AppendCheckpoint performs — rebuild
// the Checkpoint at (headSeq+1, headHash, headCkpt+1), CanonicalJSON its
// Payload(key_id), prepend DomainPrefix, verify the origin signature — using
// the EDGE module's copy of those primitives.
//
// It therefore proves the sealer agrees with identity/, not that it agrees with
// controld: the two are separate Go modules and this test cannot import the
// server's code. The real cross-binary binding is conformance/vectors/receipt/,
// which both sides are pinned against; this test is the edge-side half.
func TestSealVerifiesAsControldWould(t *testing.T) {
	h := newHarness(t, nil)
	leaves := [][]byte{leaf(1), leaf(2), leaf(3)}
	h.sealer.Seal(context.Background(), leaves, identity.BatchFacts{})

	cps := h.checkpoints(t)
	if len(cps) != 1 {
		t.Fatalf("sealed %d checkpoints, want 1", len(cps))
	}
	ev := cps[0]
	cp := ev.GetReceiptCheckpoint()

	// Refused with DefectBrokenLink unless the claim equals headCkpt+1
	// (store.go:197) — checked before the signature, so check it first here too.
	if cp.GetCheckpointSeq() != uint64(headCkpt+1) {
		t.Errorf("checkpoint_seq %d, want %d — controld refuses broken_link", cp.GetCheckpointSeq(), headCkpt+1)
	}
	wantRoot, err := identity.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cp.GetMerkleRoot()) != hex.EncodeToString(wantRoot[:]) {
		t.Errorf("merkle_root %x, want %x", cp.GetMerkleRoot(), wantRoot)
	}
	if cp.GetLeafCount() != 3 ||
		hex.EncodeToString(cp.GetFirstEventId()) != hex.EncodeToString(leaves[0]) ||
		hex.EncodeToString(cp.GetLastEventId()) != hex.EncodeToString(leaves[2]) {
		t.Errorf("leaf range: count=%d first=%x last=%x", cp.GetLeafCount(), cp.GetFirstEventId(), cp.GetLastEventId())
	}
	if cp.GetKeyId() != identity.DeriveKeyID(h.pub) {
		t.Errorf("key_id %q does not name the device public key", cp.GetKeyId())
	}

	// --- the server's reconstruction ---
	headHash, err := hex.DecodeString(headHashHex)
	if err != nil {
		t.Fatal(err)
	}
	var root [32]byte
	copy(root[:], cp.GetMerkleRoot())
	rebuilt := identity.Checkpoint{
		TenantID:        testTenant,
		DeviceID:        testDevice,
		Seq:             headSeq + 1,
		PrevReceiptHash: [32]byte(headHash),
		// store.go's IssuedAtString over the envelope's occurred_at, which is
		// the only issued_at input the server has (sidefx.go:142).
		IssuedAt:      ev.GetOccurredAt().AsTime().UTC().Truncate(time.Second).Format(time.RFC3339),
		CheckpointSeq: int64(cp.GetCheckpointSeq()),
		MerkleRoot:    root,
		LeafCount:     int(cp.GetLeafCount()),
	}
	text, err := identity.CanonicalJSON(rebuilt.Payload(cp.GetKeyId()))
	if err != nil {
		t.Fatal(err)
	}
	signingInput := append([]byte(identity.DomainPrefix), text...)
	if !identity.Verify(h.pub, cp.GetOriginSignature(), signingInput) {
		t.Fatalf("origin signature does not verify over the reconstructed signing input — controld would refuse bad_signature.\nreconstructed: %s", text)
	}
}

// TestSealTerminates: the checkpoint-of-a-checkpoint loop ends at the leaf
// rule, not here — a ReceiptCheckpoint is never a leaf (uplink batchLeaves;
// controld sidefx.go Apply), so a batch of only checkpoints reaches the sealer
// as no leaves at all. Nothing over nothing: no seal, and no head GET either.
func TestSealTerminates(t *testing.T) {
	h := newHarness(t, nil)
	h.sealer.Seal(context.Background(), nil, identity.BatchFacts{})
	if got := len(h.checkpoints(t)); got != 0 {
		t.Fatalf("an empty batch sealed %d checkpoints — the chain does not terminate", got)
	}
	if h.heads != 0 {
		t.Errorf("chain head fetched %d times for an empty batch, want 0", h.heads)
	}
}

// TestSealerDoesNotReMintACheckpointSeqAfterAStaleHead: controld appends the
// checkpoint riding in a batch AFTER acking it (sidefx worker), so the head
// read for the next seal can still show the counter BEFORE the checkpoint this
// process just minted. Re-minting that counter is refused broken_link once the
// earlier one lands (store.go AppendCheckpoint) — and its leaves are then
// outside the chain for good. The sealer must chain to the checkpoint it last
// sent: seq+1, checkpoint_seq+1, prev_receipt_hash = THAT checkpoint's receipt
// hash, exactly the head controld will hold when it verifies this one.
func TestSealerDoesNotReMintACheckpointSeqAfterAStaleHead(t *testing.T) {
	// The fake head is frozen at (headSeq, headHash, headCkpt): every GET after
	// the first is stale by construction.
	h := newHarness(t, nil)
	ctx := context.Background()

	h.sealer.Seal(ctx, [][]byte{leaf(1)}, identity.BatchFacts{})
	h.sealer.Seal(ctx, [][]byte{leaf(2)}, identity.BatchFacts{})
	cps := h.checkpoints(t)
	if len(cps) != 2 {
		t.Fatalf("sealed %d checkpoints, want 2", len(cps))
	}
	if h.heads != 2 {
		t.Fatalf("chain head fetched %d times, want 2 — the head is still read fresh every seal", h.heads)
	}
	first, second := cps[0].GetReceiptCheckpoint(), cps[1].GetReceiptCheckpoint()
	if first.GetCheckpointSeq() != uint64(headCkpt+1) {
		t.Fatalf("first checkpoint_seq %d, want %d", first.GetCheckpointSeq(), headCkpt+1)
	}
	if second.GetCheckpointSeq() != uint64(headCkpt+2) {
		t.Fatalf("second checkpoint_seq %d, want %d — the stale head re-minted the counter (broken_link on the server)",
			second.GetCheckpointSeq(), headCkpt+2)
	}

	// --- the server's reconstruction of the SECOND seal, after the first landed.
	h.verifySecondChainedToFirst(t, cps[0], cps[1])

	// A head at or past our own is the server's newer truth (our checkpoint
	// applied, or another device's seal outran it) and wins outright.
	h.sealer.last = chainHead{seq: 1, checkpointSeq: headCkpt - 1}
	h.sealer.Seal(ctx, [][]byte{leaf(3)}, identity.BatchFacts{})
	cps = h.checkpoints(t)
	if got := cps[2].GetReceiptCheckpoint().GetCheckpointSeq(); got != uint64(headCkpt+1) {
		t.Errorf("third checkpoint_seq %d, want %d — a fresh head that is not stale must be followed", got, headCkpt+1)
	}
}

// rebuild is the server's reconstruction of one checkpoint's signed payload
// at a head it holds: (seq, prev) are the head's, the rest is read off the
// event as sidefx.EffectsFromBatch does.
func rebuild(ev *m1pv1.Event, seq int64, prev [32]byte) identity.Checkpoint {
	cp := ev.GetReceiptCheckpoint()
	var root [32]byte
	copy(root[:], cp.GetMerkleRoot())
	return identity.Checkpoint{
		TenantID: testTenant, DeviceID: testDevice,
		Seq: seq, PrevReceiptHash: prev,
		IssuedAt:      ev.GetOccurredAt().AsTime().UTC().Truncate(time.Second).Format(time.RFC3339),
		CheckpointSeq: int64(cp.GetCheckpointSeq()),
		MerkleRoot:    root, LeafCount: int(cp.GetLeafCount()),
	}
}

// verifySecondChainedToFirst is the server's check of the SECOND seal after
// the first landed on the frozen fake head: head = (headSeq+1,
// receipt_hash(first), headCkpt+1), so second must verify over (headSeq+2,
// receipt_hash(first), headCkpt+2). receipt_hash is sha256 over the signing
// input, prefix included (store.go, vectors README).
func (h *harness) verifySecondChainedToFirst(t *testing.T, first, second *m1pv1.Event) {
	t.Helper()
	headHash, err := hex.DecodeString(headHashHex)
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := identity.ReceiptHash(rebuild(first, headSeq+1, [32]byte(headHash)).Payload(first.GetReceiptCheckpoint().GetKeyId()))
	if err != nil {
		t.Fatal(err)
	}
	signingInput, err := identity.CanonicalBytes(rebuild(second, headSeq+2, firstHash).Payload(second.GetReceiptCheckpoint().GetKeyId()))
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Verify(h.pub, second.GetReceiptCheckpoint().GetOriginSignature(), signingInput) {
		t.Fatal("second seal does not verify over (seq+1, receipt_hash(first), checkpoint_seq+1) — controld would refuse bad_signature")
	}
}

// TestSealerLastHeadSurvivesRestart: the stale-head reconciliation above lived
// in process memory, so a restart with a pre-restart checkpoint still in the
// spool re-opened the race for the first post-restart seal — it read the
// frozen head, re-minted checkpoint_seq, and was refused broken_link once the
// spooled one landed. `last` is now on disk: a NEW sealer over the same state
// dir must chain to the checkpoint the old one admitted.
func TestSealerLastHeadSurvivesRestart(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	h.sealer.Seal(ctx, [][]byte{leaf(1)}, identity.BatchFacts{})
	if fi, err := os.Stat(h.sealer.lastPath); err != nil {
		t.Fatalf("last-head not written after the first seal: %v", err)
	} else if got := fi.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Errorf("last-head mode %04o, want 0600 (NFR-SECURITY-007: state files owner-only)", got)
	}
	h.restart(t)
	h.sealer.Seal(ctx, [][]byte{leaf(2)}, identity.BatchFacts{})

	cps := h.checkpoints(t)
	if len(cps) != 2 {
		t.Fatalf("sealed %d checkpoints, want 2", len(cps))
	}
	if got := cps[1].GetReceiptCheckpoint().GetCheckpointSeq(); got != uint64(headCkpt+2) {
		t.Fatalf("first post-restart checkpoint_seq %d, want %d — the stale head re-minted the counter across the restart",
			got, headCkpt+2)
	}
	h.verifySecondChainedToFirst(t, cps[0], cps[1])
}

// TestSealerIgnoresACorruptLastHead: the file is an optimisation over the
// server's head, not a source of truth. Garbage in it costs one warning and
// puts the device back where it was before the file existed — never a boot
// refusal, because that would cost capture to protect a receipt.
func TestSealerIgnoresACorruptLastHead(t *testing.T) {
	h := newHarness(t, nil)
	if err := os.MkdirAll(filepath.Dir(h.sealer.lastPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.sealer.lastPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	h.sealer.Seal(context.Background(), [][]byte{leaf(1)}, identity.BatchFacts{})
	cps := h.checkpoints(t)
	if len(cps) != 1 {
		t.Fatalf("sealed %d checkpoints, want 1", len(cps))
	}
	if got := cps[0].GetReceiptCheckpoint().GetCheckpointSeq(); got != uint64(headCkpt+1) {
		t.Errorf("checkpoint_seq %d, want %d — a corrupt last-head must yield to the server's head", got, headCkpt+1)
	}
}

// TestSealRefusesHeadWithoutCheckpointSeq: a controld predating the additive
// chain_head.checkpoint_seq field cannot be sealed against. Guessing 0 would
// sign the wrong counter on every non-empty chain, so the sealer must emit
// NOTHING rather than a checkpoint that reads as forged.
func TestSealRefusesHeadWithoutCheckpointSeq(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipts":   []any{},
			"chain_head": map[string]any{"seq": headSeq, "hash": headHashHex},
		})
	})
	h.sealer.Seal(context.Background(), [][]byte{leaf(1)}, identity.BatchFacts{})
	if h.heads != 1 {
		t.Fatalf("chain head fetched %d times, want 1", h.heads)
	}
	if got := len(h.checkpoints(t)); got != 0 {
		t.Fatalf("sealed %d checkpoints against a head with no checkpoint_seq, want 0", got)
	}
}

// TestSealFetchesHeadEveryTime: seq and prev_receipt_hash are per-TENANT server
// facts that advance from other devices and from server-written receipt kinds,
// so a cached head is stale the moment anything else in the tenant writes.
func TestSealFetchesHeadEveryTime(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	h.sealer.Seal(ctx, [][]byte{leaf(1)}, identity.BatchFacts{})
	h.sealer.Seal(ctx, [][]byte{leaf(2)}, identity.BatchFacts{})
	if h.heads != 2 {
		t.Fatalf("chain head fetched %d times for 2 seals, want 2", h.heads)
	}
}

// TestSealAdmitsTheCheckpointDeviceScoped: a checkpoint names NO session, and
// capture has to accept it that way. checkpoint_seq is per-DEVICE and
// controld's CheckpointEvent carries no session field, so the only session a
// checkpoint could name is one it is not a fact about — and a batch of purely
// device-scoped events has none to borrow at all, which under the old rule left
// its landed events with no chain evidence. capture.deviceScoped is what makes
// this legal; narrow it again and every test in this file fails at the spool
// read, because the quarantined checkpoint never becomes a record.
func TestSealAdmitsTheCheckpointDeviceScoped(t *testing.T) {
	h := newHarness(t, nil)
	h.sealer.Seal(context.Background(), [][]byte{leaf(1)}, identity.BatchFacts{})
	cps := h.checkpoints(t)
	if len(cps) != 1 {
		t.Fatalf("sealed %d checkpoints, want 1", len(cps))
	}
	if sid := cps[0].GetSessionId(); len(sid) != 0 {
		t.Errorf("checkpoint carries session_id %x — a per-device chain fact filed under one arbitrary session", sid)
	}
}

// TestSealCarriesRefusedLeavesIntoTheNextSeal: a failed chain-head GET used to
// put a whole batch outside the receipt chain permanently — and the GET is the
// one step here that fails for ordinary reasons (a sleeping laptop, a roamed
// network). The leaves must reappear under the next checkpoint's root, oldest
// first, so that "every landed event is covered by some checkpoint" survives a
// transient network fault rather than only a quiet one.
func TestSealCarriesRefusedLeavesIntoTheNextSeal(t *testing.T) {
	calls := 0
	h := newHarness(t, func(w http.ResponseWriter) {
		if calls++; calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipts": []any{},
			"chain_head": map[string]any{
				"seq": headSeq, "hash": headHashHex, "checkpoint_seq": headCkpt,
			},
		})
	})
	ctx := context.Background()

	h.sealer.Seal(ctx, [][]byte{leaf(1)}, identity.BatchFacts{})
	if got := len(h.checkpoints(t)); got != 0 {
		t.Fatalf("sealed %d checkpoints against a failed head fetch, want 0", got)
	}

	h.sealer.Seal(ctx, [][]byte{leaf(2), leaf(3)}, identity.BatchFacts{})
	cps := h.checkpoints(t)
	if len(cps) != 1 {
		t.Fatalf("sealed %d checkpoints after the head recovered, want 1", len(cps))
	}
	cp := cps[0].GetReceiptCheckpoint()
	if cp.GetLeafCount() != 3 {
		t.Errorf("leaf_count %d, want 3 — the refused batch was not carried", cp.GetLeafCount())
	}
	// Oldest first, and the root must be over the combined tree in that order:
	// a checkpoint whose count says 3 but whose root covers 2 verifies against
	// nothing.
	want, err := identity.MerkleRoot([][]byte{leaf(1), leaf(2), leaf(3)})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cp.GetMerkleRoot()) != hex.EncodeToString(want[:]) {
		t.Errorf("merkle_root %x is not the tree over all three leaves in order", cp.GetMerkleRoot())
	}
	if hex.EncodeToString(cp.GetFirstEventId()) != hex.EncodeToString(leaf(1)) ||
		hex.EncodeToString(cp.GetLastEventId()) != hex.EncodeToString(leaf(3)) {
		t.Errorf("leaf range first=%x last=%x, want %x..%x", cp.GetFirstEventId(), cp.GetLastEventId(), leaf(1), leaf(3))
	}

	// And the carry-forward set is cleared, or the next seal double-counts.
	h.sealer.Seal(ctx, [][]byte{leaf(4)}, identity.BatchFacts{})
	cps = h.checkpoints(t)
	if len(cps) != 2 {
		t.Fatalf("sealed %d checkpoints total, want 2", len(cps))
	}
	if got := cps[1].GetReceiptCheckpoint().GetLeafCount(); got != 1 {
		t.Errorf("second checkpoint covered %d leaves, want 1 — pending was not cleared on success", got)
	}
}

// TestSealDropsALeafItCanNeverPlace is the other half of the carry-forward
// rule, and the reason it is not "retry everything": a leaf that is not
// LeafSize fails MerkleRoot every time, so carrying it would fail every FUTURE
// seal at the same line and end the device's chain outright. The malformed set
// is dropped and the next honest batch seals normally.
func TestSealDropsALeafItCanNeverPlace(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	h.sealer.Seal(ctx, [][]byte{{1, 2, 3}}, identity.BatchFacts{})
	if got := len(h.checkpoints(t)); got != 0 {
		t.Fatalf("sealed %d checkpoints over a malformed leaf, want 0", got)
	}
	if h.heads != 0 {
		t.Errorf("chain head fetched %d times, want 0 — the tree is built before the GET", h.heads)
	}

	h.sealer.Seal(ctx, [][]byte{leaf(1)}, identity.BatchFacts{})
	cps := h.checkpoints(t)
	if len(cps) != 1 {
		t.Fatalf("sealed %d checkpoints after a malformed batch, want 1 — the bad leaf stalled the chain", len(cps))
	}
	if got := cps[0].GetReceiptCheckpoint().GetLeafCount(); got != 1 {
		t.Errorf("leaf_count %d, want 1 — the malformed leaf was carried forward", got)
	}
}

// TestCarryForwardIsCapped: an outage must not grow the carry-forward set
// without bound. Past the cap the OLDEST leaves are dropped — losing the head
// of one set is survivable, losing the process to an OOM takes the whole spool.
func TestCarryForwardIsCapped(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) })
	const over = 5
	big := make([][]byte, maxPendingLeaves+over)
	for i := range big {
		l := make([]byte, identity.LeafSize)
		l[0], l[1], l[2] = byte(i), byte(i>>8), byte(i>>16)
		big[i] = l
	}
	h.sealer.Seal(context.Background(), big, identity.BatchFacts{})

	if got := len(h.sealer.pending); got != maxPendingLeaves {
		t.Fatalf("carried %d leaves, want the cap %d", got, maxPendingLeaves)
	}
	if hex.EncodeToString(h.sealer.pending[0]) != hex.EncodeToString(big[over]) {
		t.Errorf("the surviving head is %x, want %x — the NEWEST leaves were dropped instead of the oldest",
			h.sealer.pending[0], big[over])
	}
}

func TestHeadURL(t *testing.T) {
	got, err := HeadURL("https://api.example.com/m1p/v1/ingest")
	if err != nil || got != "https://api.example.com/api/v1/receipts" {
		t.Fatalf("HeadURL = %q, %v", got, err)
	}
	if _, err := HeadURL("/m1p/v1/ingest"); err == nil {
		t.Fatal("a relative ingest URL yielded a head URL")
	}
}

// The head race has a clock on it: inside headRace the edge chains to its own last seal (the server applies post-ack); past it, a server head still behind `last` means that seal was refused and the edge rechains to the server's head — the founder's device sat at checkpoint_seq 1314 against a server head of 6, every seal refused broken_link.
func TestSealerRechainsToTheServerHeadOnceTheRaceIsOver(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil) // the fake server's head never moves: checkpoint_seq headCkpt
	clock := time.Unix(1767225600, 0)
	h.sealer.now = func() time.Time { return clock }
	h.sealer.Seal(ctx, [][]byte{leaf(1)}, identity.BatchFacts{})
	first := h.sealer.last.checkpointSeq
	if first != headCkpt+1 {
		t.Fatalf("first seal claims %d, want %d", first, headCkpt+1)
	}
	clock = clock.Add(headRace / 2)
	h.sealer.Seal(ctx, [][]byte{leaf(2)}, identity.BatchFacts{})
	if got := h.sealer.last.checkpointSeq; got != first+1 {
		t.Fatalf("inside the race the edge chains to its own last seal: got %d, want %d", got, first+1)
	}
	// seals every few seconds must not restart the clock: the head has not moved since the first sighting
	var claims []int64
	for i := 0; i < 4; i++ {
		clock = clock.Add(headRace / 3)
		h.sealer.Seal(ctx, [][]byte{leaf(byte(10 + i))}, identity.BatchFacts{})
		claims = append(claims, h.sealer.last.checkpointSeq)
	}
	rechained := false
	for _, c := range claims {
		rechained = rechained || c == headCkpt+1
	}
	if !rechained {
		t.Fatalf("past the race with the server head still behind, the edge must rechain to it: claims %v, want one at %d", claims, headCkpt+1)
	}
}
