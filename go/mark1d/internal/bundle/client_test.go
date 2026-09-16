// Client tests drive the REAL frozen bundle vectors through a real httptest
// server speaking 08 §3.2. Nothing here hand-rolls a bundle: the fixtures are
// conformance/vectors/bundle, so a test that passes is a test that moved bytes
// the Rust twin also agrees on.
//
// The names deliberately avoid the `ConfVectors` prefix: conformance_crosslang.sh
// counts the bundle family by that token, and these are wiring tests, not vector
// tests — inflating the family count would make the gate report coverage it does
// not have.
package bundle

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const vectorsDir = "../../../../conformance/vectors/bundle"

type vecHead struct {
	RootHex  string `json:"root_hex"`
	TreeSize uint64 `json:"tree_size"`
}

type vector struct {
	Name     string   `json:"name"`
	File     string   `json:"file"`
	Expect   string   `json:"expect"`
	Code     string   `json:"code"`
	TlogHead *vecHead `json:"tlog_head"`
	Summary  *struct {
		Seq     uint64 `json:"seq"`
		Channel string `json:"channel"`
		MaxAgeS uint64 `json:"max_age_s"`
	} `json:"summary"`
}

type manifest struct {
	Keys map[string]struct {
		PublicHex string `json:"public_hex"`
	} `json:"keys"`
	Vectors []vector `json:"vectors"`
}

func loadManifest(t *testing.T) *manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading vector manifest: %v", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing vector manifest: %v", err)
	}
	// Tripwire: every case below looks a vector up BY NAME, so a manifest that
	// lost its accept or reject half would leave this file passing while
	// exercising nothing. Assert the family is the frozen one.
	accepts, rejects := 0, 0
	for _, v := range m.Vectors {
		switch v.Expect {
		case "accept":
			accepts++
		case "reject":
			rejects++
		}
	}
	// (writeTrust separately fatals unless the manifest publishes a key for
	// every section class, so the key ring needs no count here.)
	if accepts < 3 || rejects < 15 {
		t.Fatalf("not the frozen bundle vector family: accept=%d reject=%d", accepts, rejects)
	}
	return &m
}

func (m *manifest) vec(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range m.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("vector %q is not in the frozen manifest", name)
	return vector{}
}

// writeTrust publishes the manifest's section keys as the edge's LOCAL pinned
// custody — the same material the vectors were signed with.
func writeTrust(t *testing.T, stateDir string, m *manifest) {
	t.Helper()
	dir := filepath.Join(stateDir, "policy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var tf trustFile
	for _, s := range policy.AllSections() {
		k, ok := m.Keys[s.Name()]
		if !ok {
			t.Fatalf("manifest has no key for section %s", s.Name())
		}
		if b, err := hex.DecodeString(k.PublicHex); err != nil || len(b) != ed25519.PublicKeySize {
			t.Fatalf("manifest key for %s is not a 32-byte hex public key", s.Name())
		}
		tf.BundleSectionKeys = append(tf.BundleSectionKeys, pinnedKey{Section: s.Name(), PubkeyHex: k.PublicHex})
	}
	raw, err := json.Marshal(tf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keysFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// cp is a fake control plane implementing 08 §3.2 + §3.5. It counts every route
// so a test can assert the network layer actually ran.
type cp struct {
	mu sync.Mutex

	body []byte // what GET /bundle serves
	etag string //   under this ETag
	seq  string //   and this X-Mark1-Bundle-Seq echo
	head *vecHead

	bundleStatus int    // non-zero ⇒ GET /bundle fails with it
	keysStatus   int    // non-zero ⇒ GET /.well-known/mark1-keys fails with it
	ackFail      bool   // ⇒ POST /ack 503s
	keysDoc      []byte // the manifest's key lists served beside tlog (rotation tests)

	acks     []ackBody
	getN     int
	notModN  int
	headN    int
	ackN     int
	condSeen []string // If-None-Match values observed, in order
}

func (s *cp) set(fn func(*cp)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

type counts struct{ get, notMod, head, ack int }

func (s *cp) snapshot() ([]ackBody, counts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ackBody(nil), s.acks...), counts{s.getN, s.notModN, s.headN, s.ackN}
}

func (s *cp) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(pathBundle, func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.getN++
		s.condSeen = append(s.condSeen, r.Header.Get("If-None-Match"))
		if s.bundleStatus != 0 {
			w.WriteHeader(s.bundleStatus)
			return
		}
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == s.etag {
			s.notModN++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("ETag", s.etag)
		w.Header().Set("X-Mark1-Bundle-Seq", s.seq)
		_, _ = w.Write(s.body)
	})
	mux.HandleFunc(pathKeys, func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.headN++
		if s.keysStatus != 0 {
			w.WriteHeader(s.keysStatus)
			return
		}
		out := map[string]any{"tlog": map[string]any{}}
		if s.keysDoc != nil {
			_ = json.Unmarshal(s.keysDoc, &out)
		}
		if s.head != nil {
			out["tlog"] = map[string]any{"head": map[string]any{"size": s.head.TreeSize, "root": s.head.RootHex}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc(pathAck, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var a ackBody
		if err := json.Unmarshal(body, &a); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.ackFail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		s.ackN++
		s.acks = append(s.acks, a)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"recorded":true}`))
	})
	return mux
}

// harness is a client wired to a fake control plane on a fixed clock.
type harness struct {
	t     *testing.T
	m     *manifest
	cp    *cp
	srv   *httptest.Server
	state string
	now   time.Time

	appliedMu sync.Mutex
	applied   []verdict.BundleMatrices
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	m := loadManifest(t)
	state := t.TempDir()
	writeTrust(t, state, m)
	s := &cp{}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	// 1787961600 is every vector's issued_at; the fixed clock keeps each bundle
	// inside its own max_age until a test deliberately moves it.
	return &harness{t: t, m: m, cp: s, srv: srv, state: state, now: time.Unix(1787961600, 0).UTC()}
}

// serve points GET /bundle at a named vector, with the head that vector's
// inclusion proof targets.
func (h *harness) serve(name, etag, seq string) {
	h.t.Helper()
	v := h.m.vec(h.t, name)
	raw, err := os.ReadFile(filepath.Join(vectorsDir, v.File))
	if err != nil {
		h.t.Fatalf("reading vector %s: %v", name, err)
	}
	h.cp.set(func(s *cp) { s.body, s.etag, s.seq, s.head = raw, etag, seq, v.TlogHead })
}

func (h *harness) client() *Client {
	h.t.Helper()
	c, err := New(Config{
		StateDir:   h.state,
		BaseURL:    h.srv.URL,
		Channel:    "stable",
		Token:      "dev",
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTPClient: h.srv.Client(),
		Now:        func() time.Time { return h.now },
		Rand:       func() float64 { return 0.5 },
		Poll:       time.Hour, // tests drive tick() directly; no timer racing
	})
	if err != nil {
		h.t.Fatalf("New: %v", err)
	}
	c.Apply = func(m verdict.BundleMatrices) {
		h.appliedMu.Lock()
		defer h.appliedMu.Unlock()
		h.applied = append(h.applied, m)
	}
	return c
}

func (h *harness) applies() []verdict.BundleMatrices {
	h.appliedMu.Lock()
	defer h.appliedMu.Unlock()
	return append([]verdict.BundleMatrices(nil), h.applied...)
}

func (h *harness) lastApplied() verdict.BundleMatrices {
	h.t.Helper()
	a := h.applies()
	if len(a) == 0 {
		h.t.Fatal("nothing was ever published to the verdict plane")
	}
	return a[len(a)-1]
}

// applyChain walks a client from nothing through the frozen seq-1 → seq-2 pair.
// minimal.prev_hash == full.body_sha256, so this is a real chain and exercises
// callerChecks' linkage rule on the accepting side.
func (h *harness) applyChain(c *Client) {
	h.t.Helper()
	for _, step := range []struct{ name, etag, seq string }{
		{"full", `"t7-stable-000001"`, "1"},
		{"minimal", `"t7-stable-000002"`, "2"},
	} {
		h.serve(step.name, step.etag, step.seq)
		if !c.tick(context.Background()) {
			h.t.Fatalf("tick reported a retryable failure serving %s", step.name)
		}
		if c.lkg == nil || fmt.Sprint(c.lkg.b.Seq) != step.seq {
			h.t.Fatalf("%s did not apply", step.name)
		}
	}
}

// TestClientAppliesChainAndAcks is the happy path end to end: two real bundles,
// a real prev_hash chain, matrices swapped into the verdict plane, custody on
// disk, ACKs in the ledger.
func TestClientAppliesChainAndAcks(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	if m := c.Matrices(); !m.Stale || len(m.Verifiers) != 0 {
		t.Fatal("a client with no custody must boot on built-ins (FR-POLICY-005)")
	}
	h.applyChain(c)

	acks, n := h.cp.snapshot()
	if n.get != 2 || n.ack != 2 || n.head != 2 {
		t.Fatalf("the network layer did not run as expected: %+v", n)
	}
	for i, wantSeq := range []string{"1", "2"} {
		got := acks[i]
		if got.Seq != wantSeq || got.Result != "applied" || got.RejectCode != "" {
			t.Fatalf("ack[%d] = %+v, want seq %s applied with no reject_code", i, got, wantSeq)
		}
		if got.Channel != "stable" || !strings.HasPrefix(got.BundleHash, "sha256:") || len(got.BundleHash) != len("sha256:")+64 {
			t.Fatalf("ack[%d] = %+v, want 08 §3.2's channel plus a prefixed 32-byte hash", i, got)
		}
	}

	// Custody: bytes at 0600 plus metadata naming the head it was verified
	// against, without which a reboot could not re-verify it.
	fi, err := os.Stat(filepath.Join(h.state, "policy", lkgFile))
	if err != nil {
		t.Fatalf("last-known-good was not persisted: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("last-known-good mode is %v, want 0600", fi.Mode().Perm())
	}
	metaRaw, err := os.ReadFile(filepath.Join(h.state, "policy", metaFile))
	if err != nil {
		t.Fatal(err)
	}
	var meta lkgMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Seq != 2 || meta.ETag != `"t7-stable-000002"` || meta.HeadTreeSize != 3 {
		t.Fatalf("lkg metadata = %+v, want seq 2 / the serving ETag / tree_size 3", meta)
	}
}

// TestClientRejectionsKeepLastKnownGood is FR-POLICY-004's negative row: apply
// seq N, feed hostile bytes, assert seq N still runs. Each vector's code is
// asserted only where the verification ORDER makes it deterministic under a
// standing anti-rollback floor (verify.go checks size → canonical → signatures
// → seq → inclusion → decode).
func TestClientRejectionsKeepLastKnownGood(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	h.applyChain(c)
	good := c.lkg
	appliesBefore := len(h.applies())

	for _, tc := range []struct{ vector, code, why string }{
		{"seq_replay", "M1E-3002", "seq 1 under an applied seq 2 is the anti-rollback rule itself"},
		{"bad_section_sig", "M1E-3001", "the signature check precedes the seq check"},
		{"non_canonical", "M1E-3001", "canonical form is checked before anything else"},
		{"too_large", "M1E-3001", "the size ceiling is the first check, over a 4 MiB body"},
	} {
		t.Run(tc.vector, func(t *testing.T) {
			_, before := h.cp.snapshot()
			h.serve(tc.vector, `"t7-stable-hostile"`, "9")
			if !c.tick(context.Background()) {
				t.Fatal("a fetched-and-refused bundle is a successful tick, not a transport failure")
			}
			if c.lkg != good {
				t.Fatalf("FAIL-STATIC VIOLATED: %s replaced the applied bundle", tc.vector)
			}
			acks, after := h.cp.snapshot()
			if after.ack != before.ack+1 {
				t.Fatalf("a rejection must ACK exactly once: %d → %d", before.ack, after.ack)
			}
			got := acks[len(acks)-1]
			if got.Result != "rejected" || got.RejectCode != tc.code {
				t.Fatalf("ack = %+v, want rejected/%s (%s)", got, tc.code, tc.why)
			}
			if got.Seq != "9" {
				t.Fatalf("a reject ACK names the seq the SERVER filed the bytes under, got %q", got.Seq)
			}
		})
	}
	if n := len(h.applies()); n != appliesBefore {
		t.Fatalf("the verdict plane was republished %d times across the rejection sweep", n-appliesBefore)
	}
	if c.lkg.b.Seq != 2 {
		t.Fatalf("applied seq is %d after the sweep, want 2", c.lkg.b.Seq)
	}
}

// TestClientRejectionsOnVirginEdge covers the codes that only surface with no
// anti-rollback floor in force — with an LKG the seq check fires first, since
// inclusion and decode are the LAST two verification steps.
func TestClientRejectionsOnVirginEdge(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	for _, tc := range []struct{ vector, code string }{
		{"command_string", "M1E-3005"},        // CON-009: never executable content
		{"forged_inclusion_root", "M1E-3003"}, // proof does not target the pinned head
		{"tlog_head_missing", "M1E-3003"},     // D-S: no pinned head at seq > 0
		{"inclusion_missing", "M1E-3003"},
	} {
		t.Run(tc.vector, func(t *testing.T) {
			_, before := h.cp.snapshot()
			h.serve(tc.vector, `"t7-stable-hostile"`, "7")
			if !c.tick(context.Background()) {
				t.Fatal("tick reported a transport failure")
			}
			if c.lkg != nil {
				t.Fatalf("%s applied on a virgin edge", tc.vector)
			}
			acks, after := h.cp.snapshot()
			if after.ack != before.ack+1 {
				t.Fatalf("expected exactly one ACK, %d → %d", before.ack, after.ack)
			}
			if got := acks[len(acks)-1]; got.Result != "rejected" || got.RejectCode != tc.code {
				t.Fatalf("ack = %+v, want rejected/%s", got, tc.code)
			}
		})
	}
	if m := c.Matrices(); !m.Stale {
		t.Fatal("nothing applied ⇒ still built-ins")
	}
}

// TestClientRejectsForeignChannel: seq is monotonic per (tenant, CHANNEL), so
// applying another channel's bundle would raise our anti-rollback floor against
// a sequence that is not ours and lock out our own channel's next publication.
func TestClientRejectsForeignChannel(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	if got := h.m.vec(t, "bundle_zero").Summary.Channel; got != "local" {
		t.Fatalf("vector premise moved: bundle_zero channel is %q, expected one this client does not poll", got)
	}
	h.serve("bundle_zero", `"t7-local-000000"`, "0")
	if !c.tick(context.Background()) {
		t.Fatal("tick reported a transport failure")
	}
	if c.lkg != nil {
		t.Fatal("a foreign channel's bundle must not apply")
	}
	acks, _ := h.cp.snapshot()
	if len(acks) != 1 || acks[0].RejectCode != "M1E-3001" {
		t.Fatalf("acks = %+v, want one M1E-3001", acks)
	}
}

// TestClientMaxAgeFallsToBuiltins is FR-POLICY-005's clock half: past max_age
// the verdict plane runs conservative built-ins flagged stale_cert, the
// transition is announced by a publish rather than left silent, and the applied
// bundle is retained so a clock correction restores it.
func TestClientMaxAgeFallsToBuiltins(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	// `full` carries 3 verifiers, so its live matrices are distinguishable from
	// built-ins; `minimal` carries none and is Stale by construction.
	h.serve("full", `"t7-stable-000001"`, "1")
	if !c.tick(context.Background()) {
		t.Fatal("seq 1 did not apply")
	}
	if live := h.lastApplied(); live.Stale || len(live.Verifiers) == 0 {
		t.Fatalf("a fresh bundle must publish live matrices: stale=%v verifiers=%d", live.Stale, len(live.Verifiers))
	}
	_, beforeAck := h.cp.snapshot()

	// One second past issued_at + max_age; the boundary itself is still fresh,
	// which policy.Bundle.IsFresh owns.
	h.now = h.now.Add(time.Duration(c.lkg.b.MaxAgeS)*time.Second + time.Second)
	c.publish()
	stale := h.lastApplied()
	if !stale.Stale || len(stale.Verifiers) != 0 {
		t.Fatalf("past max_age the edge must run built-ins flagged stale_cert: %+v", stale)
	}
	if c.lkg == nil {
		t.Fatal("staleness must not DISCARD the last-known-good")
	}
	// The freshness ticker calls publish() every 30 s forever; an unchanged
	// posture must not keep swapping the verdict plane's pointer.
	pubs := len(h.applies())
	c.publish()
	if len(h.applies()) != pubs {
		t.Fatal("publish is not idempotent on an unchanged posture")
	}
	// M1E-3006 is a status condition, not a verdict on a bundle: ACKing
	// `rejected` for a bundle we did apply would corrupt the canary
	// controller's adoption denominator (05 §4.3).
	if _, n := h.cp.snapshot(); n.ack != beforeAck.ack {
		t.Fatalf("staleness emitted an ACK (%d → %d)", beforeAck.ack, n.ack)
	}

	// And back: the clock returning inside the window restores the bundle.
	h.now = h.now.Add(-2 * time.Second)
	c.publish()
	if back := h.lastApplied(); back.Stale || len(back.Verifiers) == 0 {
		t.Fatalf("a bundle back inside max_age must be republished live: %+v", back)
	}
}

// TestClientBootsOnLastKnownGoodWithControlPlaneDown is FR-POLICY-005's
// blackhole: custody survives a restart, re-verifies against the head it was
// applied under, and boots with no control plane at all.
func TestClientBootsOnLastKnownGoodWithControlPlaneDown(t *testing.T) {
	h := newHarness(t)
	h.applyChain(h.client())

	h.srv.Close() // the control plane is now gone
	c2 := h.client()
	if c2.lkg == nil || c2.lkg.b.Seq != 2 {
		t.Fatal("the daemon must boot on its persisted last-known-good with the control plane down")
	}
	if c2.tick(context.Background()) {
		t.Fatal("a dead control plane must report a retryable tick failure")
	}
	if c2.lkg.b.Seq != 2 {
		t.Fatal("FAIL-STATIC VIOLATED: an unreachable control plane changed the applied bundle")
	}
}

// TestClientIgnoresTamperedCustody: the 0700 custody dir is a boundary, not a
// proof. Bytes nobody signed must not become policy on the next boot.
func TestClientIgnoresTamperedCustody(t *testing.T) {
	h := newHarness(t)
	h.applyChain(h.client())
	path := filepath.Join(h.state, "policy", lkgFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	if c.lkg != nil {
		t.Fatal("a tampered last-known-good must not load")
	}
	if m := c.Matrices(); !m.Stale || len(m.Verifiers) != 0 {
		t.Fatal("an unverifiable last-known-good falls to built-ins, not to its own contents")
	}
}

// TestClientWithoutPinnedKeysNeverFetches: with no local signing material
// nothing can ever be verified, so nothing is fetched. A client that downloaded
// bundles it could not check would be theatre with a bandwidth bill.
func TestClientWithoutPinnedKeysNeverFetches(t *testing.T) {
	h := newHarness(t)
	if err := os.Remove(filepath.Join(h.state, "policy", keysFile)); err != nil {
		t.Fatal(err)
	}
	c := h.client()
	h.serve("full", `"t7-stable-000001"`, "1")
	if !c.tick(context.Background()) {
		t.Fatal("a keyless client must report a healthy no-op tick")
	}
	if _, n := h.cp.snapshot(); n.get != 0 {
		t.Fatalf("a keyless client fetched %d times", n.get)
	}
	if m := c.Matrices(); !m.Stale {
		t.Fatal("no keys ⇒ built-ins")
	}
}

// TestClientConditionalPoll: after an apply the poll is ETag-conditional, a 304
// is a no-op, and a server that re-serves identical bytes (our ETag lost) does
// NOT produce a spurious anti-rollback ACK — which the canary halt rule counts.
func TestClientConditionalPoll(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	h.applyChain(c)

	if !c.tick(context.Background()) {
		t.Fatal("conditional poll failed")
	}
	acks, n := h.cp.snapshot()
	if n.notMod != 1 {
		t.Fatalf("expected one 304, got %d", n.notMod)
	}
	if n.ack != 2 {
		t.Fatalf("a 304 must ACK nothing: %+v", acks)
	}
	h.cp.mu.Lock()
	sent := h.cp.condSeen[len(h.cp.condSeen)-1]
	h.cp.mu.Unlock()
	if sent != `"t7-stable-000002"` {
		t.Fatalf("If-None-Match = %q, want the applied bundle's ETag", sent)
	}

	// ETag lost (fresh proxy, cleared cache): the same bytes come back 200.
	c.lkg.etag = ""
	if !c.tick(context.Background()) {
		t.Fatal("unconditional re-fetch failed")
	}
	acks, n = h.cp.snapshot()
	if n.ack != 2 {
		t.Fatalf("re-serving the applied bundle must not ACK: %+v", acks)
	}
	if c.lkg.etag != `"t7-stable-000002"` {
		t.Fatalf("the re-serve must re-learn the ETag, got %q", c.lkg.etag)
	}
}

// TestClientHeadFetchFailureDefersApply: an unreachable head is a missing
// INPUT, not evidence against the bundle. Rejecting on it would spend M1E-3003
// — and a canary halt — on a network blip.
func TestClientHeadFetchFailureDefersApply(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	h.serve("full", `"t7-stable-000001"`, "1")
	h.cp.set(func(s *cp) { s.keysStatus = http.StatusBadGateway })
	if c.tick(context.Background()) {
		t.Fatal("a failed head fetch must report a retryable tick failure")
	}
	if c.lkg != nil {
		t.Fatal("no head ⇒ no apply")
	}
	if _, n := h.cp.snapshot(); n.ack != 0 {
		t.Fatalf("a head fetch failure must ACK nothing, got %d", n.ack)
	}
	// Heal it and the very same bundle applies.
	h.cp.set(func(s *cp) { s.keysStatus = 0 })
	if !c.tick(context.Background()) || c.lkg == nil || c.lkg.b.Seq != 1 {
		t.Fatal("the deferred bundle did not apply once the head came back")
	}
}

// TestClientRetriesOwedAck: 05 §4.3 widens on ACK COVERAGE, so an ACK lost to a
// blip must be re-offered rather than dropped.
func TestClientRetriesOwedAck(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	h.cp.set(func(s *cp) { s.ackFail = true })
	h.serve("full", `"t7-stable-000001"`, "1")
	if !c.tick(context.Background()) {
		t.Fatal("a refused ACK must not fail the tick — the bundle did apply")
	}
	if c.pending == nil || c.pending.Seq != "1" {
		t.Fatalf("a refused ACK must stay owed, got %+v", c.pending)
	}
	if _, n := h.cp.snapshot(); n.ack != 0 {
		t.Fatalf("the ledger recorded %d acks through a broken route", n.ack)
	}
	// Heal the route: the next tick pays the debt before anything else.
	h.cp.set(func(s *cp) { s.ackFail = false })
	if !c.tick(context.Background()) {
		t.Fatal("post-heal tick failed")
	}
	acks, _ := h.cp.snapshot()
	if len(acks) != 1 || acks[0].Seq != "1" || acks[0].Result != "applied" {
		t.Fatalf("the owed ACK was never paid: %+v", acks)
	}
	if c.pending != nil {
		t.Fatalf("a paid ACK must clear, got %+v", c.pending)
	}
}

// TestClientBackoffIsBoundedAndJittered: no retry storm. The base is the poll
// interval, so the first failure never retries sooner than a healthy poll, and
// the cap holds however long the outage runs.
func TestClientBackoffIsBoundedAndJittered(t *testing.T) {
	c := &Client{poll: 5 * time.Minute, rand: func() float64 { return 1.0 }}
	prev := time.Duration(0)
	for n := 1; n <= 20; n++ {
		d := c.backoff(n)
		if d > backoffCap {
			t.Fatalf("backoff(%d) = %v exceeds the cap %v", n, d, backoffCap)
		}
		if d < prev {
			t.Fatalf("backoff went backwards at attempt %d: %v < %v", n, d, prev)
		}
		prev = d
	}
	if prev != backoffCap {
		t.Fatalf("backoff never reached the cap: %v", prev)
	}
	if c.backoff(1) != c.poll {
		t.Fatalf("the first retry is %v, want the poll interval %v", c.backoff(1), c.poll)
	}
	c.rand = func() float64 { return 0 }
	if c.backoff(5) != 0 {
		t.Fatal("jitter is not applied to the exponential")
	}
}

// TestClientSSEHintTriggersFetch: the stream is the LATENCY path. It carries no
// bundle and applies nothing — it only wakes the poll, and one queued wake is
// the in-flight bound.
func TestClientSSEHintTriggersFetch(t *testing.T) {
	h := newHarness(t)
	mux := http.NewServeMux()
	mux.Handle("/", h.cp.handler())
	mux.HandleFunc(pathStream, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// `ping` and `revocation` must NOT wake the poll; only `bundle` does.
		_, _ = fmt.Fprint(w, "event: ping\ndata: {}\n\nevent: revocation\ndata: {}\n\nevent: bundle\ndata: {\"seq\":\"1\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := h.client()
	c.baseURL = srv.URL
	c.http = srv.Client()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.stream(ctx)

	select {
	case <-c.hint:
	case <-time.After(10 * time.Second):
		t.Fatal("an `event: bundle` block did not wake the poll loop")
	}
	c.nudge()
	c.nudge()
	if len(c.hint) > 1 {
		t.Fatalf("the fetch queue is unbounded: %d wakes queued", len(c.hint))
	}
}

// TestClientRunDoesNotBlockStartup: whatever the control plane is doing, Run is
// a goroutine that returns on cancellation and nothing more.
func TestClientRunDoesNotBlockStartup(t *testing.T) {
	h := newHarness(t)
	h.cp.set(func(s *cp) { s.bundleStatus = http.StatusInternalServerError })
	c := h.client()
	c.freshEvery = 5 * time.Millisecond
	c.poll = time.Millisecond // force real fetch attempts, and real backoff
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return on cancellation")
	}
	if _, n := h.cp.snapshot(); n.get == 0 {
		t.Fatal("Run never attempted a fetch — the loop is not wired to the poll timer")
	}
}

// TestClientGatesFollowsFreshness: Gates() is the applied bundle's gates
// section under Matrices' posture -- `full` carries {enabled, mcb 3, hourly
// 20}; past max_age it is the zero section (stop gate open, FR-POLICY-005),
// and a clock back inside the window restores it. No bundle at all is the
// zero section too.
// TestClientApplyRankerFollowsBundleAndFreshness: an applied bundle's cortex
// learned_ranker reaches the hook decoded; a bundle without the key, or the
// clock passing max_age, publishes nil — the removal side of the ranker file.
func TestClientApplyRankerFollowsBundleAndFreshness(t *testing.T) {
	h := newHarness(t)
	if got := h.m.vec(t, "cortex_learned_ranker").Summary.Channel; got != "local" {
		t.Fatalf("vector premise moved: cortex_learned_ranker channel is %q", got)
	}
	c, err := New(Config{
		StateDir: h.state, BaseURL: h.srv.URL, Channel: "local", Token: "dev",
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTPClient: h.srv.Client(),
		Now:        func() time.Time { return h.now },
		Rand:       func() float64 { return 0.5 },
		Poll:       time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var seen []*policy.LearnedRanker
	c.ApplyRanker = func(r *policy.LearnedRanker) { seen = append(seen, r) }
	h.serve("cortex_learned_ranker", `"t7-local-000000"`, "0")
	if !c.tick(context.Background()) || c.lkg == nil {
		t.Fatal("cortex_learned_ranker did not apply")
	}
	want := policy.LearnedRanker{Stage: policy.RankerShadow, Weight: 0.5, Bias: 0.05, Coefficients: [4]float64{0.6, 0.25, -0.1, 0.15}}
	if len(seen) != 1 || seen[0] == nil || *seen[0] != want {
		t.Fatalf("apply must publish the decoded ranker once: %+v", seen)
	}
	h.now = h.now.Add(time.Duration(c.lkg.b.MaxAgeS)*time.Second + time.Second)
	c.publish()
	if len(seen) != 2 || seen[1] != nil {
		t.Fatalf("past max_age the ranker must be withdrawn: %+v", seen)
	}
	h.now = h.now.Add(-2 * time.Second)
	c.publish()
	if len(seen) != 3 || seen[2] == nil || *seen[2] != want {
		t.Fatalf("back inside max_age the ranker must return: %+v", seen)
	}

	// A bundle that lacks the key publishes nil on apply, not a stale ranker.
	h2 := newHarness(t)
	c2 := h2.client()
	c2.ApplyRanker = func(r *policy.LearnedRanker) { seen = append(seen, r) }
	h2.serve("full", `"t7-stable-000001"`, "1")
	if !c2.tick(context.Background()) {
		t.Fatal("full did not apply")
	}
	if len(seen) != 4 || seen[3] != nil {
		t.Fatalf("a bundle without learned_ranker must publish nil: %+v", seen)
	}
}

func TestClientGatesFollowsFreshness(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	if g := c.Gates(); g != (policy.GatesSection{}) {
		t.Fatalf("no bundle: Gates() = %+v, want the zero section", g)
	}
	h.serve("full", `"t7-stable-000001"`, "1")
	if !c.tick(context.Background()) {
		t.Fatal("seq 1 did not apply")
	}
	want := policy.GatesSection{StopGateEnabled: true, MaxConsecutiveBlocks: 3, HourlyBlockCeiling: 20}
	if g := c.Gates(); g != want {
		t.Fatalf("fresh: Gates() = %+v, want %+v", g, want)
	}
	h.now = h.now.Add(time.Duration(c.lkg.b.MaxAgeS)*time.Second + time.Second)
	if g := c.Gates(); g != (policy.GatesSection{}) {
		t.Fatalf("past max_age: Gates() = %+v, want the zero section (gates open)", g)
	}
	h.now = h.now.Add(-2 * time.Second)
	if g := c.Gates(); g != want {
		t.Fatalf("back inside max_age: Gates() = %+v, want %+v", g, want)
	}
}
