//go:build chaos && unix

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// fakeControld is ingest + policy distribution behind one origin, with a hole
// that resets every new request so the daemon meets the fault on both planes.
type fakeControld struct {
	t    *testing.T
	url  string
	tap  *wireTap
	body []byte
	etag string

	hole      atomic.Bool
	holeHits  map[string]int
	notMod    int
	applied   int
	streamMu  sync.Mutex
	streams   []http.Flusher
	streamsRW []http.ResponseWriter
	mu        sync.Mutex
}

const bundleZeroETag = `"t7-local-000000"`

func newFakeControld(t *testing.T, tap *wireTap, stateDir string) *fakeControld {
	t.Helper()
	root := filepath.Join("..", "..", "..", "conformance", "vectors", "bundle")
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
	type pinned struct {
		Section   string `json:"section"`
		PubkeyHex string `json:"pubkey_hex"`
	}
	var trust struct {
		BundleSectionKeys []pinned `json:"bundle_section_keys"`
	}
	for s, k := range m.Keys {
		trust.BundleSectionKeys = append(trust.BundleSectionKeys, pinned{Section: s, PubkeyHex: k.PublicHex})
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

	f := &fakeControld{t: t, tap: tap, body: body, etag: bundleZeroETag, holeHits: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /m1p/v1/ingest", f.guard("ingest", tap.serve))
	mux.HandleFunc("GET /api/v1/policy/bundle", f.guard("bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == f.etag {
			f.mu.Lock()
			f.notMod++
			f.mu.Unlock()
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("ETag", f.etag)
		w.Header().Set("X-Mark1-Bundle-Seq", "0")
		_, _ = w.Write(f.body)
	}))
	mux.HandleFunc("GET /.well-known/mark1-keys", f.guard("keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tlog":{}}`))
	}))
	mux.HandleFunc("POST /api/v1/policy/ack", f.guard("ack", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if bytes.Contains(b, []byte(`"applied"`)) {
			f.mu.Lock()
			f.applied++
			f.mu.Unlock()
		}
		_, _ = w.Write([]byte(`{"recorded":true}`))
	}))
	mux.HandleFunc("GET /api/v1/policy/stream", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: bundle\ndata: {}\n\n")
		fl.Flush()
		f.streamMu.Lock()
		f.streams = append(f.streams, fl)
		f.streamsRW = append(f.streamsRW, w)
		f.streamMu.Unlock()
		<-r.Context().Done()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// guard resets the connection while the hole is open: the request arrived and got no reply.
func (f *fakeControld) guard(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !f.hole.Load() {
			next(w, r)
			return
		}
		f.mu.Lock()
		f.holeHits[name]++
		f.mu.Unlock()
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
			}
		}
	}
}

// hint pushes one SSE bundle hint so the client polls now instead of in five minutes.
func (f *fakeControld) hint() {
	f.streamMu.Lock()
	defer f.streamMu.Unlock()
	for i, fl := range f.streams {
		_, _ = io.WriteString(f.streamsRW[i], "event: bundle\ndata: {}\n\n")
		fl.Flush()
	}
}

func (f *fakeControld) counts() (hits map[string]int, notMod, applied int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hits = map[string]int{}
	for k, v := range f.holeHits {
		hits[k] = v
	}
	return hits, f.notMod, f.applied
}

func (f *fabricConn) usage(session [16]byte, outputTokens uint64) {
	f.t.Helper()
	f.event(session, &m1pv1.Event{Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{
		IdemKey: bytes.Repeat([]byte{byte(outputTokens)}, 32), OutputTokens: outputTokens, Model: "claude-chaos",
	}}})
}

func (w *wireTap) usageTokens() map[uint64]int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[uint64]int{}
	for _, b := range w.batches {
		for _, ev := range b.GetEvents() {
			if u := ev.GetUsage(); u != nil {
				out[u.GetOutputTokens()]++
			}
		}
	}
	return out
}

func (w *wireTap) turns() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, b := range w.batches {
		for _, ev := range b.GetEvents() {
			if ev.GetTurn() != nil {
				n++
			}
		}
	}
	return n
}

func TestChaosNetworkPartitionDaemon(t *testing.T) {
	tap := newWireTap(t)
	stateDir, spoolDir, socket := uplinkPaths(t)
	cp := newFakeControld(t, tap, stateDir)

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: &logBuf, mu: &logMu}, nil))
	stop := runDaemonLog(t, config{
		stateDir:      stateDir,
		spoolDir:      spoolDir,
		socket:        socket,
		ingestURL:     cp.url + "/m1p/v1/ingest",
		policyURL:     cp.url,
		policyChannel: "local",
		deviceToken:   "tok-test",
		offPoll:       10 * time.Millisecond,
	}, log)
	stopped := false
	stopOnce := func() {
		if !stopped {
			stopped = true
			stop()
		}
	}
	defer stopOnce()
	waitFor(t, "fabric socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})
	waitUpTo(t, 20*time.Second, "bundle_zero applied and ACKed (policy plane live before the fault)", func() bool {
		_, _, applied := cp.counts()
		return applied == 1
	})

	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.prompt(session)
	c.usage(session, 1)
	waitUpTo(t, 20*time.Second, "the pre-fault Usage on the wire (ingest live before the fault)", func() bool {
		return tap.usageTokens()[1] == 1
	})

	cp.hole.Store(true)
	cp.hint()
	const holeUsages = 8
	var gateMax time.Duration
	for i := uint64(2); i < 2+holeUsages; i++ {
		c.prompt(session)
		c.usage(session, i)
		started := time.Now()
		v := c.gate()
		gateMax = max(gateMax, time.Since(started))
		// A task with no votes is a cache miss: M1E-5001 allow + Dropped{gate_timeout}, partition or not.
		if v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || !strings.Contains(v.GetReason(), "M1E-5001") {
			t.Fatalf("gate under the partition answered %v (%s), want the M1E-5001 fail-open allow", v.GetDecision(), v.GetReason())
		}
	}
	if gateMax > 240*time.Millisecond {
		t.Fatalf("slowest gate answer under the partition took %v, over the 240 ms shim deadline", gateMax)
	}
	if n := c.flush().GetDrained(); n < 2*holeUsages {
		t.Fatalf("FlushAck drained %d, want >= %d: capture stalled behind the partition", n, 2*holeUsages)
	}
	waitUpTo(t, 30*time.Second, "the uplink and the policy client to each hit the hole", func() bool {
		hits, _, _ := cp.counts()
		return hits["ingest"] >= 1 && hits["bundle"] >= 1
	})
	hitsAtHeal, _, _ := cp.counts()
	if tap.usageTokens()[2] != 0 {
		t.Fatal("a Usage crossed a reset connection: the tap recorded a batch nobody acked")
	}

	cp.hole.Store(false)
	cp.hint()
	waitUpTo(t, 20*time.Second, "a conditional poll answered 304 (the client kept its last-known-good ETag)", func() bool {
		_, notMod, _ := cp.counts()
		return notMod >= 1
	})
	waitUpTo(t, 90*time.Second, "every Usage sent through the partition to land after the heal", func() bool {
		got := tap.usageTokens()
		for i := uint64(1); i < 2+holeUsages; i++ {
			if got[i] == 0 {
				return false
			}
		}
		return true
	})
	stopOnce()

	for i := uint64(1); i < 2+holeUsages; i++ {
		if n := tap.usageTokens()[i]; n != 1 {
			t.Errorf("Usage %d on the wire %d times, want exactly once", i, n)
		}
	}
	if n := tap.turns(); n != 1+holeUsages {
		t.Errorf("%d Turn events on the wire, want %d: a diagnostic was lost without a Dropped row", n, 1+holeUsages)
	}
	tap.mu.Lock()
	for _, b := range tap.batches {
		for _, d := range b.GetDropped() {
			if d.GetReason() != m1pv1.DropReason_DROP_REASON_GATE_TIMEOUT {
				t.Errorf("Dropped%v on the wire: nothing was shed, so the partition was accounted as a loss it was not", d)
			}
		}
	}
	tap.mu.Unlock()
	if n := tap.dropped(m1pv1.DropReason_DROP_REASON_GATE_TIMEOUT, m1pv1.DurabilityClass_DURABILITY_CLASS_DIAGNOSTIC); n != holeUsages {
		t.Errorf("Dropped{GATE_TIMEOUT} on the wire = %d, want exactly the %d cache-miss gate answers given under the hole", n, holeUsages)
	}
	_, _, applied := cp.counts()
	if applied != 1 {
		t.Errorf("%d applied ACKs, want 1: the client re-applied or re-fetched across the partition", applied)
	}
	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logs, "last-known-good stays in force") {
		t.Error("the policy client never logged the fail-static hold — the hole did not reach a fetch")
	}
	if strings.Contains(logs, "past max_age") || strings.Contains(logs, "rejected") {
		t.Error("the partition moved the policy posture: a fetch failure is not a bundle verdict")
	}
	t.Logf("chaos_network_partition (daemon): hole hits %v, %d Usage + %d Turn exactly once after heal, slowest gate under the hole %v",
		hitsAtHeal, 1+holeUsages, 1+holeUsages, gateMax)
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
