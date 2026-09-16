//go:build chaos

package uplink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	_ "unsafe"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/bundle"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// google/uuid mints UUIDv7 off its own package clock; this is the only way to skew it.
//
//go:linkname uuidTimeNow github.com/google/uuid.timeNow
var uuidTimeNow func() time.Time

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

const (
	skewTenant  = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	skewDevice  = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
	skewHeadSeq = int64(41)
	skewHeadCk  = int64(7)
)

var skewHeadHash = "aa" + hex.EncodeToString(make([]byte, 31))

// skewControld adds the receipts head and 08 §3.2 policy routes to partitionIngest.
type skewControld struct {
	*partitionIngest
	mu    sync.Mutex
	acks  int
	body  []byte
	heads int
}

func newSkewControld(t *testing.T, stateDir string) (*skewControld, string) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "..", "conformance", "vectors", "bundle")
	body, err := os.ReadFile(filepath.Join(root, "bundle_zero.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Keys map[string]struct {
			PublicHex string `json:"public_hex"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var trust struct {
		Keys []map[string]string `json:"bundle_section_keys"`
	}
	for s, k := range m.Keys {
		trust.Keys = append(trust.Keys, map[string]string{"section": s, "pubkey_hex": k.PublicHex})
	}
	tj, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "policy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "policy", "keys.json"), tj, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &skewControld{partitionIngest: &partitionIngest{}, body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /m1p/v1/ingest", s.handler())
	mux.HandleFunc("GET /api/v1/receipts", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		s.heads++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipts":   []any{},
			"chain_head": map[string]any{"seq": skewHeadSeq, "hash": skewHeadHash, "checkpoint_seq": skewHeadCk},
		})
	})
	mux.HandleFunc("GET /api/v1/policy/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"t7-local-000000"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("ETag", `"t7-local-000000"`)
		w.Header().Set("X-Mark1-Bundle-Seq", "0")
		_, _ = w.Write(s.body)
	})
	mux.HandleFunc("GET /.well-known/mark1-keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tlog":{}}`))
	})
	mux.HandleFunc("POST /api/v1/policy/ack", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		s.mu.Lock()
		s.acks++
		s.mu.Unlock()
		_, _ = w.Write([]byte(`{"recorded":true}`))
	})
	mux.HandleFunc("GET /api/v1/policy/stream", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		<-r.Context().Done()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func idemKey() []byte {
	id := uuid.Must(uuid.NewV7())
	return bytes.Repeat(id[:], 2)
}

type wireEvent struct {
	batch  int
	sentAt time.Time
	ev     *m1pv1.Event
}

func TestChaosClockSkewAndSleepWake(t *testing.T) {
	clk := &fakeClock{now: time.Now().Add(time.Hour).Truncate(time.Second)}
	uuidTimeNow = clk.Now
	t.Cleanup(func() { uuidTimeNow = time.Now })

	dir := t.TempDir()
	sp, err := spool.Open(spool.Config{
		Dir: filepath.Join(dir, "spool"), SegmentSize: 16 << 10, Now: clk.Now,
		DiskUsage: func(string) (float64, error) { return 0.10, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "session_epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
		Now:       clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	cp, origin := newSkewControld(t, dir)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	keyPath := filepath.Join(dir, "device.key")
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	sealer, err := receipt.New(receipt.Config{
		Key: key, TenantID: skewTenant, DeviceID: skewDevice,
		HeadURL:  origin + "/api/v1/receipts",
		Token:    func(context.Context) (string, error) { return "tok", nil },
		Admit:    adm.Admit,
		StateDir: dir,
		Log:      quiet,
		Now:      clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	var appliedMu sync.Mutex
	var applied []verdict.BundleMatrices
	bc, err := bundle.New(bundle.Config{
		StateDir: dir, BaseURL: origin, Channel: "local", Token: "tok", EdgeVersion: "1.4.2",
		Log: quiet, Now: clk.Now, Rand: func() float64 { return 0.5 },
		Poll: 100 * time.Millisecond, FreshEvery: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	bc.Apply = func(m verdict.BundleMatrices) {
		appliedMu.Lock()
		defer appliedMu.Unlock()
		applied = append(applied, m)
	}
	postureIs := func(stale bool, verifiers int) func() bool {
		return func() bool {
			appliedMu.Lock()
			defer appliedMu.Unlock()
			if len(applied) == 0 {
				return false
			}
			last := applied[len(applied)-1]
			return last.Stale == stale && len(last.Verifiers) == verifiers
		}
	}

	dl := &delayLog{blockPark: true}
	netChange := make(chan struct{})
	u, err := New(Config{
		Store: sp, Drops: []DropSource{sp, adm}, Tokens: StaticToken("tok"),
		Endpoint: origin + "/m1p/v1/ingest", EdgeVersion: "1.4.2",
		SDK:           &m1pv1.SdkInfo{Name: "mark1d", Version: "1.4.2", Os: "linux", Arch: "amd64", Agent: "claudecode"},
		QuarantineDir: filepath.Join(dir, "quarantine"),
		Seal:          func(p []byte) ([]byte, error) { return p, nil },
		Checkpoint:    sealer.Seal,
		HTTPClient:    &http.Client{Timeout: 300 * time.Millisecond},
		Log:           quiet, Now: clk.Now, After: dl.After,
		Rand:          func() float64 { return 0.5 },
		NetworkChange: netChange, Poll: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var loops sync.WaitGroup
	loops.Add(2)
	runErr := make(chan error, 1)
	go func() { defer loops.Done(); runErr <- u.Run(ctx) }()
	go func() { defer loops.Done(); bc.Run(ctx) }()

	waitFor(t, "bundle_zero applied fresh (3 verifiers) under the injected clock", postureIs(false, 3))

	s1, s2 := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	var minted [][16]byte
	admitUsage := func(session uuid.UUID, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			ev := &m1pv1.Event{SessionId: session[:], Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
				IdemKey: idemKey(), Model: "claude-chaos",
			}}}
			if err := adm.Admit(context.Background(), ev); err != nil {
				t.Fatal(err)
			}
			minted = append(minted, [16]byte(ev.GetEventId()))
			clk.Jump(time.Second)
		}
		if err := sp.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	landedCount := func() int {
		_, landed := cp.snapshot()
		return len(landed)
	}
	waitLanded := func(what string) {
		t.Helper()
		before := landedCount()
		waitFor(t, what, func() bool { return landedCount() > before })
	}

	// Phase A: baseline, the clock ticking one second per event.
	admitUsage(s1, 10)
	admitUsage(s2, 5)
	waitLanded("the baseline batch")

	// Phase B: +26 h.
	clk.Jump(26 * time.Hour)
	admitUsage(s1, 10)
	waitLanded("the batch after the +26 h jump")

	// Phase C: back below every timestamp minted so far.
	highWater := minted[len(minted)-1]
	clk.Jump(-29 * time.Hour)
	admitUsage(s1, 5)
	admitUsage(s2, 5)
	if first := minted[len(minted)-10]; bytes.Compare(first[:], highWater[:]) <= 0 {
		t.Fatalf("UUIDv7 regressed across a -29 h wall-clock jump: %x after %x", first, highWater)
	}
	waitLanded("the batch after the -29 h jump")

	// Phase D: max_age is a wall-clock fact (F-29): a jump past it is stale, the correction restores it.
	if postureIs(true, 0)() {
		t.Fatal("bundle already stale before the max_age jump")
	}
	clk.Jump(400 * 24 * time.Hour)
	waitFor(t, "built-ins flagged stale_cert once the clock passes max_age (M1E-3006)", postureIs(true, 0))
	clk.Jump(-400 * 24 * time.Hour)
	waitFor(t, "the bundle back in force once the clock returns inside max_age", postureIs(false, 3))

	// Phase E: sleep — the network is gone and the wall clock stops; then wake.
	cp.setHole(true)
	holeAt := len(minted)
	for i := 0; i < 10; i++ {
		ev := &m1pv1.Event{SessionId: s1[:], Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
			IdemKey: idemKey(), Model: "claude-chaos",
		}}}
		if err := adm.Admit(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
		minted = append(minted, [16]byte(ev.GetEventId()))
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	for i := holeAt + 1; i < len(minted); i++ {
		if bytes.Compare(minted[i][:], minted[i-1][:]) <= 0 {
			t.Fatalf("UUIDv7 did not advance under a frozen clock: %x then %x", minted[i-1], minted[i])
		}
	}
	waitFor(t, "the uploader to park while asleep", func() bool { return dl.parkEntries() == 1 })
	if holed, _ := cp.snapshot(); holed != maxAttempts {
		t.Fatalf("%d attempts swallowed before PARKED, want %d", holed, maxAttempts)
	}
	clk.Jump(10 * time.Minute)
	cp.setHole(false)
	netChange <- struct{}{}
	waitLanded("the wake re-queue to land")
	// Every landed batch with a leaf seals one checkpoint, which rides a later batch.
	waitFor(t, "every acked leaf batch to be sealed and its checkpoint to land", func() bool {
		_, landed := cp.snapshot()
		leafBatches, checkpoints := 0, 0
		for _, body := range landed {
			b, _ := decodeBody(t, body)
			leaves := 0
			for _, ev := range b.GetEvents() {
				if ev.GetReceiptCheckpoint() != nil {
					checkpoints++
				} else {
					leaves++
				}
			}
			if leaves > 0 {
				leafBatches++
			}
		}
		return leafBatches >= 4 && checkpoints == leafBatches
	})
	cancel()
	loops.Wait()
	if err := <-runErr; err != nil {
		t.Fatalf("Run = %v", err)
	}

	// Grade.
	_, landed := cp.snapshot()
	var wire []wireEvent
	for i, body := range landed {
		b, _ := decodeBody(t, body)
		if len(b.GetDropped()) != 0 {
			t.Fatalf("batch %d carries Dropped%v: nothing was shed", i, b.GetDropped())
		}
		for _, ev := range b.GetEvents() {
			wire = append(wire, wireEvent{batch: i, sentAt: b.GetSentAt().AsTime(), ev: ev})
		}
	}
	byID := map[[16]byte]int{}
	byIdem := map[string]int{}
	lastSeq := map[[16]byte]uint64{}
	var checkpoints []*m1pv1.Event
	sentAtRegressed := false
	for i, w := range wire {
		id := [16]byte(w.ev.GetEventId())
		byID[id]++
		if i > 0 && w.sentAt.Before(wire[i-1].sentAt) {
			sentAtRegressed = true
		}
		if u := w.ev.GetUsage(); u != nil {
			byIdem[string(u.GetIdemKey())]++
			var sid [16]byte
			copy(sid[:], w.ev.GetSessionId())
			if w.ev.GetSeq() <= lastSeq[sid] {
				t.Fatalf("session %x: seq %d after %d in wire order — causal order lost to the clock", sid, w.ev.GetSeq(), lastSeq[sid])
			}
			lastSeq[sid] = w.ev.GetSeq()
		}
		if w.ev.GetReceiptCheckpoint() != nil {
			// Sealed on one goroutine, so wire order is mint order for these.
			if n := len(checkpoints); n > 0 && bytes.Compare(id[:], checkpoints[n-1].GetEventId()) <= 0 {
				t.Fatalf("checkpoint event_id %x does not exceed the previous seal's %x — the monotonic counter regressed", id, checkpoints[n-1].GetEventId())
			}
			checkpoints = append(checkpoints, w.ev)
		}
	}
	for i, id := range minted {
		if byID[id] != 1 {
			t.Fatalf("Usage %x on the wire %d times, want exactly once", id, byID[id])
		}
		if i > 0 && bytes.Compare(id[:], minted[i-1][:]) <= 0 {
			t.Fatalf("mint %d: event_id %x does not exceed its predecessor %x across the clock jumps", i, id, minted[i-1])
		}
	}
	for k, n := range byIdem {
		if n != 1 {
			t.Fatalf("idem_key %x on the wire %d times: a duplicate Usage across sleep/wake", k, n)
		}
	}
	if len(byIdem) != len(minted) {
		t.Fatalf("%d idem_keys on the wire for %d Usage events", len(byIdem), len(minted))
	}
	if !sentAtRegressed {
		t.Fatal("no batch's sent_at is earlier than its predecessor's: the wall clock never visibly went backwards, so the ordering claims above were not tested against a regression")
	}
	if len(checkpoints) < 4 {
		t.Fatalf("%d receipt checkpoints on the wire, want one per acked batch across every phase", len(checkpoints))
	}
	prevHash, err := hex.DecodeString(skewHeadHash)
	if err != nil {
		t.Fatal(err)
	}
	prev := [32]byte(prevHash)
	var lastIssued time.Time
	issuedRegressed := false
	for i, ev := range checkpoints {
		cpb := ev.GetReceiptCheckpoint()
		if cpb.GetCheckpointSeq() != uint64(skewHeadCk)+uint64(i)+1 {
			t.Fatalf("checkpoint %d has checkpoint_seq %d, want %d", i, cpb.GetCheckpointSeq(), skewHeadCk+int64(i)+1)
		}
		var root [32]byte
		copy(root[:], cpb.GetMerkleRoot())
		issued := ev.GetOccurredAt().AsTime().UTC().Truncate(time.Second)
		if i > 0 && issued.Before(lastIssued) {
			issuedRegressed = true
		}
		lastIssued = issued
		rebuilt := identity.Checkpoint{
			TenantID: skewTenant, DeviceID: skewDevice,
			Seq: skewHeadSeq + int64(i) + 1, PrevReceiptHash: prev,
			IssuedAt: issued.Format(time.RFC3339), CheckpointSeq: int64(cpb.GetCheckpointSeq()),
			MerkleRoot: root, LeafCount: int(cpb.GetLeafCount()),
		}
		payload := rebuilt.Payload(cpb.GetKeyId())
		input, err := identity.CanonicalBytes(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !identity.Verify(pub, cpb.GetOriginSignature(), input) {
			t.Fatalf("checkpoint %d does not verify over (seq %d, prev %x): the chain broke across the clock jumps", i, rebuilt.Seq, prev[:4])
		}
		if prev, err = identity.ReceiptHash(payload); err != nil {
			t.Fatal(err)
		}
	}
	if !issuedRegressed {
		t.Fatal("no checkpoint's issued_at precedes its predecessor's: the chain was never sealed across a backward jump")
	}
	if heads := func() int { cp.mu.Lock(); defer cp.mu.Unlock(); return cp.heads }(); heads < len(checkpoints) {
		t.Fatalf("%d chain-head fetches for %d seals: a seal signed without asking the server", heads, len(checkpoints))
	}
	t.Logf("chaos_clock_skew: %d Usage exactly once over %d batches across +26h/-29h/+400d/-400d jumps and a 10-minute sleep; "+
		"event_id monotone throughout, %d checkpoints chained, sent_at regressed on the wire as wall time should",
		len(minted), len(landed), len(checkpoints))
}
