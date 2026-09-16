//go:build soak

package soak

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/bundle"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/uplink"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const vectorsDir = "../../../../conformance/vectors/bundle"

// 08 §2.5 literals, written from the doc so an edited constant in uplink reds here.
const (
	docBackoffBase  = 6 * time.Second
	docBackoffCap   = 30 * time.Minute
	docMaxAttempts  = 10
	docParkRequeue  = 6 * time.Hour
	docSpoolCap     = 2 << 30
	docMark1dRSSCap = 200 << 20
	// 04 §2.6: the freshness re-evaluation cadence the max_age edge is observed on.
	freshEvery = 30 * time.Second
)

var errBlackhole = errors.New("soak: control plane blackholed")

// blackhole fails every request at the transport while dark: 08 §2.5's network-error row, never a status.
type blackhole struct {
	dark  atomic.Bool
	mu    sync.Mutex
	posts int
	gets  int
}

func (b *blackhole) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.dark.Load() {
		b.mu.Lock()
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ingest") {
			b.posts++
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/bundle") {
			b.gets++
		}
		b.mu.Unlock()
		return nil, errBlackhole
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (b *blackhole) counts() (posts, gets int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.posts, b.gets
}

type vecHead struct {
	RootHex  string `json:"root_hex"`
	TreeSize uint64 `json:"tree_size"`
}

type manifest struct {
	Keys map[string]struct {
		PublicHex string `json:"public_hex"`
	} `json:"keys"`
	Vectors []struct {
		Name     string   `json:"name"`
		File     string   `json:"file"`
		TlogHead *vecHead `json:"tlog_head"`
		Summary  *struct {
			Seq            uint64 `json:"seq"`
			IssuedAtEpochS uint64 `json:"issued_at_epoch_s"`
			MaxAgeS        uint64 `json:"max_age_s"`
		} `json:"summary"`
	} `json:"vectors"`
}

type served struct {
	body []byte
	etag string
	seq  string
	head *vecHead
}

type ackBody struct {
	Channel    string `json:"channel"`
	Seq        string `json:"seq"`
	BundleHash string `json:"bundle_hash"`
	Result     string `json:"result"`
	RejectCode string `json:"reject_code,omitempty"`
}

// controlPlane fakes 08 §2 ingest and 08 §3.2/§3.5 policy distribution, recording every landed event_id and Dropped row.
type controlPlane struct {
	mu      sync.Mutex
	bundle  served
	acks    []ackBody
	landed  map[uuid.UUID]int
	dropped map[[2]int32]uint64
	batches int
	dec     *zstd.Decoder
}

func (cp *controlPlane) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy/bundle", func(w http.ResponseWriter, r *http.Request) {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == cp.bundle.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("ETag", cp.bundle.etag)
		w.Header().Set("X-Mark1-Bundle-Seq", cp.bundle.seq)
		_, _ = w.Write(cp.bundle.body)
	})
	mux.HandleFunc("/.well-known/mark1-keys", func(w http.ResponseWriter, _ *http.Request) {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		out := map[string]any{"tlog": map[string]any{}}
		if h := cp.bundle.head; h != nil {
			out["tlog"] = map[string]any{"head": map[string]any{"size": h.TreeSize, "root": h.RootHex}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/api/v1/policy/ack", func(w http.ResponseWriter, r *http.Request) {
		var a ackBody
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&a); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		cp.mu.Lock()
		cp.acks = append(cp.acks, a)
		cp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"recorded":true}`))
	})
	mux.HandleFunc("/m1p/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ingest body: %v", err)
		}
		plain, err := cp.dec.DecodeAll(raw, nil)
		if err != nil {
			t.Errorf("ingest body is not zstd: %v", err)
		}
		var batch m1pv1.Batch
		if err := proto.Unmarshal(plain, &batch); err != nil {
			t.Errorf("ingest body is not a m1p.v1.Batch: %v", err)
		}
		cp.mu.Lock()
		cp.batches++
		for _, ev := range batch.GetEvents() {
			id, err := uuid.FromBytes(ev.GetEventId())
			if err != nil {
				t.Errorf("event_id is not 16 bytes: %v", err)
			}
			cp.landed[id]++
		}
		for _, d := range batch.GetDropped() {
			cp.dropped[[2]int32{int32(d.GetReason()), int32(d.GetDurabilityClass())}] += d.GetQuantity()
		}
		cp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"batch_id": r.Header.Get("M1P-Batch-Id"), "accepted": len(batch.GetEvents()), "quarantined": []string{},
		})
	})
	return mux
}

func (cp *controlPlane) serve(t *testing.T, m *manifest, name, etag, seq string) {
	t.Helper()
	for _, v := range m.Vectors {
		if v.Name != name {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(vectorsDir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		cp.mu.Lock()
		cp.bundle = served{body: raw, etag: etag, seq: seq, head: v.TlogHead}
		cp.mu.Unlock()
		return
	}
	t.Fatalf("vector %q is not in the frozen manifest", name)
}

func loadManifest(t *testing.T) *manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

func (m *manifest) summary(t *testing.T, name string) (seq, issued, maxAge uint64) {
	t.Helper()
	for _, v := range m.Vectors {
		if v.Name == name && v.Summary != nil {
			return v.Summary.Seq, v.Summary.IssuedAtEpochS, v.Summary.MaxAgeS
		}
	}
	t.Fatalf("vector %q has no summary", name)
	return 0, 0, 0
}

// writeTrust pins the manifest's section keys as local custody in the 08 §3.5 bundle_section_keys shape.
func writeTrust(t *testing.T, stateDir string, m *manifest) {
	t.Helper()
	type pinned struct {
		Section   string `json:"section"`
		PubkeyHex string `json:"pubkey_hex"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
	}
	var keys []pinned
	for section, k := range m.Keys {
		keys = append(keys, pinned{Section: section, PubkeyHex: k.PublicHex})
	}
	raw, err := json.Marshal(map[string]any{"bundle_section_keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(stateDir, "policy")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

type event struct {
	id      uuid.UUID
	class   spool.Class
	payload []byte
}

func newEvent(t *testing.T, session uuid.UUID, seq uint64, class spool.Class) event {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	ev := &m1pv1.Event{EventId: id[:], Seq: seq, SessionId: session[:], SessionEpoch: 1}
	if class == spool.ClassBilling {
		ev.Body = &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32)}}
	} else {
		ev.Body = &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claudecode", AgentVersion: strings.Repeat("v", 1024)}}
	}
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return event{id: id, class: class, payload: payload}
}

// sleeps pairs each requested wait with the jitter draw that preceded it, so 08 §2.5 is checkable draw by draw.
type sleeps struct {
	mu     sync.Mutex
	rng    *rand.Rand
	draws  int
	last   float64
	seen   int
	ds     []time.Duration
	drawOf []float64
}

func (s *sleeps) rand() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = s.rng.Float64()
	s.draws++
	return s.last
}

func (s *sleeps) after(c *clock) func(time.Duration) <-chan time.Time {
	return func(d time.Duration) <-chan time.Time {
		s.mu.Lock()
		s.ds = append(s.ds, d)
		draw := math.NaN()
		if s.draws > s.seen {
			s.seen = s.draws
			draw = s.last
		}
		s.drawOf = append(s.drawOf, draw)
		s.mu.Unlock()
		return c.After(d)
	}
}

func (s *sleeps) list() ([]time.Duration, []float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.ds...), append([]float64(nil), s.drawOf...)
}

func docDelay(attempt int) time.Duration {
	if d := docBackoffBase << (attempt - 1); d < docBackoffCap {
		return d
	}
	return docBackoffCap
}

func spoolBytes(t *testing.T, dir string) (total, largest int64) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".m1s") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		largest = max(largest, info.Size())
	}
	return total, largest
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		runtime.Gosched()
		time.Sleep(50 * time.Microsecond)
	}
	t.Fatalf("soak: timed out waiting for %s", what)
}

var (
	soakSession = uuid.MustParse("0192f000-0000-7000-8000-00000000aa01")
	soakTask    = verdict.TaskID{0x5a}
	soakVotes   = []verdict.AnchorVote{
		{AnchorID: "anchor.syntactic", Vote: m1pv1.Verdict_VERDICT_VIOLATED},
		{AnchorID: "anchor.test_suite", Vote: m1pv1.Verdict_VERDICT_VIOLATED},
	}
)

type probe struct {
	at       time.Time
	decision m1pv1.GateDecision
	reason   string
}

func TestSoakSevenDayBlackhole(t *testing.T) {
	if testing.Short() {
		t.Skip("soak: 7 simulated days")
	}
	m := loadManifest(t)
	fullSeq, issued, maxAge := m.summary(t, "full")
	minimalSeq, _, _ := m.summary(t, "minimal")
	if fullSeq != 1 || minimalSeq != 2 || maxAge != 86400 {
		t.Fatalf("not the frozen chain: full seq %d (max_age %d s), minimal seq %d", fullSeq, maxAge, minimalSeq)
	}
	if spool.DefaultCap != docSpoolCap {
		t.Fatalf("spool.DefaultCap = %d, 07 §6 says %d", spool.DefaultCap, docSpoolCap)
	}

	t0 := time.Unix(int64(issued), 0).UTC()
	day := 24 * time.Hour
	boundary := t0.Add(time.Duration(maxAge) * time.Second)
	darkAt := t0.Add(12 * time.Minute)
	diskFullAt, diskFreeAt := t0.Add(3*day), t0.Add(3*day+2*time.Hour)
	returnAt := t0.Add(7 * day)
	captureEnd := returnAt.Add(7 * time.Hour)
	end := returnAt.Add(8 * time.Hour)

	// Five sleepers park on the clock: spool fsync loop, uplink Run, bundle Run (poll + freshness), bundle SSE stream.
	clk := newClock(t, t0, 5)
	hole := &blackhole{}
	cp := &controlPlane{landed: map[uuid.UUID]int{}, dropped: map[[2]int32]uint64{}}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	cp.dec = dec
	srv := httptest.NewServer(cp.handler(t))
	defer srv.Close()
	cp.serve(t, m, "full", `"t7-stable-000001"`, "1")
	httpClient := &http.Client{Transport: hole, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	state := t.TempDir()
	writeTrust(t, state, m)
	if err := os.MkdirAll(filepath.Dir(fabric.OptInPath(state)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fabric.OptInPath(state), []byte(`{"stop_gate":true,"ts":"2026-09-16T00:00:00Z","user":"soak"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 07 §6's operational sizes shrunk (the byte format never varies with them) so the cap is reached inside the outage.
	var diskUsed atomic.Uint64
	diskUsed.Store(50)
	const spoolCap, segSize = 4 << 20, 256 << 10
	spoolDir := filepath.Join(state, "spool")
	sp, err := spool.Open(spool.Config{
		Dir: spoolDir, SegmentSize: segSize, SpoolCap: spoolCap,
		Now: clk.Now, After: clk.After,
		DiskUsage: func(string) (float64, error) { return float64(diskUsed.Load()) / 100, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	type edge struct {
		at      time.Time
		entered bool
	}
	var hardStops []edge
	sp.SetHardStopHook(func(entered bool) { hardStops = append(hardStops, edge{clk.Now(), entered}) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Day 0 boots on PERSISTED last-known-good: a first client applies seq 1 under real time, the soak's re-verifies custody.
	newClient := func(after func(time.Duration) <-chan time.Time, poll time.Duration) *bundle.Client {
		c, err := bundle.New(bundle.Config{
			StateDir: state, BaseURL: srv.URL, Channel: "stable", Token: "dev", EdgeVersion: "1.4.2", Log: quiet,
			HTTPClient: httpClient, Now: clk.Now, After: after, Rand: func() float64 { return 0.5 },
			Poll: poll, FreshEvery: freshEvery,
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	seed := newClient(nil, 10*time.Millisecond)
	if !seed.Matrices().Stale {
		t.Fatal("a virgin edge must boot on built-ins (FR-POLICY-005)")
	}
	seedCtx, seedCancel := context.WithCancel(context.Background())
	seedDone := make(chan struct{})
	go func() { seed.Run(seedCtx); close(seedDone) }()
	waitFor(t, "seq 1 applied and acked", func() bool {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		return len(cp.acks) == 1 && cp.acks[0].Seq == "1" && cp.acks[0].Result == "applied"
	})
	seedCancel()
	<-seedDone

	blocks := verdict.NewBlocks()
	bs := &sleeps{rng: rand.New(rand.NewPCG(1, 1))}
	bc := newClient(bs.after(clk), 0)
	if boot := bc.Matrices(); boot.Stale || boot.Seq != fullSeq || len(boot.Verifiers) == 0 {
		t.Fatalf("day 0 boot must be live on persisted seq %d: stale=%v seq=%d verifiers=%d", fullSeq, boot.Stale, boot.Seq, len(boot.Verifiers))
	}
	eng := verdict.NewEngine(bc.Matrices(), blocks, clk.Now)
	type swap struct {
		at time.Time
		m  verdict.BundleMatrices
	}
	var swaps []swap
	bc.Apply = func(m verdict.BundleMatrices) {
		swaps = append(swaps, swap{clk.Now(), m})
		eng.SetBundle(m)
	}
	go eng.Run(ctx)
	gate := fabric.NewGate(eng.Reader(), blocks, state)
	gate.ApplyGates(bc.Gates())
	gate.Now = clk.Now
	gate.TaskFor = func(session, want [16]byte) ([16]byte, bool) { return want, session == soakSession }

	up := &sleeps{rng: rand.New(rand.NewPCG(7, 7))}
	ul, err := uplink.New(uplink.Config{
		Store: sp, Drops: []uplink.DropSource{sp}, Tokens: uplink.StaticToken("dev"),
		Endpoint: srv.URL + "/m1p/v1/ingest", EdgeVersion: "1.4.2",
		QuarantineDir: filepath.Join(state, "quarantine"),
		Seal:          func(p []byte) ([]byte, error) { return p, nil },
		HTTPClient:    httpClient, Log: quiet, Now: clk.Now, After: up.after(clk), Rand: up.rand,
	})
	if err != nil {
		t.Fatal(err)
	}
	runErr := make(chan error, 2)
	go func() { runErr <- ul.Run(ctx) }()
	go func() { bc.Run(ctx); runErr <- nil }()

	// A pre-cancelled ctx makes a full spool answer ctx.Err() instead of blocking the driver: F-17 observed, event kept upstream (04 §8.2).
	tryCtx, tryCancel := context.WithCancel(context.Background())
	tryCancel()
	type burstResult struct {
		at                   time.Time
		admitted, held, shed int
		pending              int
	}
	var (
		produced       = map[uuid.UUID]spool.Class{}
		pendingBilling []event
		shed           int
		burstLog       []burstResult
		peakHeap       uint64
		seq            uint64
		gateLog        []probe
	)
	tryAppend := func(ev event) error {
		return sp.Append(tryCtx, [16]byte(ev.id), ev.class, ev.payload)
	}
	burst := func() {
		now := clk.Now()
		r := burstResult{at: now}
		var keep []event
		for _, ev := range pendingBilling {
			if len(keep) > 0 {
				keep = append(keep, ev)
				continue
			}
			if err := tryAppend(ev); err != nil {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("%v: pending billing append: %v", now, err)
				}
				keep = append(keep, ev)
			} else {
				r.admitted++
			}
		}
		pendingBilling = keep
		for i := range 8 {
			seq++
			class := spool.ClassDiagnostic
			if i < 3 {
				class = spool.ClassBilling
			}
			ev := newEvent(t, soakSession, seq, class)
			produced[ev.id] = class
			err := tryAppend(ev)
			switch {
			case err == nil:
				r.admitted++
			case class == spool.ClassBilling && errors.Is(err, context.Canceled):
				pendingBilling = append(pendingBilling, ev)
				r.held++
			case class == spool.ClassDiagnostic && errors.Is(err, spool.ErrDiagnosticShed):
				shed++
				r.shed++
				delete(produced, ev.id)
			default:
				t.Fatalf("%v: append class %d: %v (a billing-grade record was refused, or a diagnostic failed without accounting)", now, class, err)
			}
		}
		r.pending = len(pendingBilling)
		burstLog = append(burstLog, r)
		if got, seg := spoolBytes(t, spoolDir); got > spoolCap || seg > segSize {
			t.Fatalf("%v: spool holds %d bytes (cap %d), largest segment %d (limit %d)", now, got, spoolCap, seg, segSize)
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		peakHeap = max(peakHeap, ms.HeapInuse)
	}
	for at := t0.Add(5 * time.Minute); at.Before(captureEnd); at = at.Add(10 * time.Minute) {
		clk.at(at, burst)
	}

	gateProbe := func() {
		now := clk.Now()
		eng.Recompute(soakTask, soakVotes, 2)
		waitFor(t, "engine publish", func() bool {
			e, ok := eng.Reader().Get(soakTask)
			return ok && e.ComputedAt.Equal(now)
		})
		v := gate.Answer(&m1pv1.GateQuery{TaskId: soakTask[:], Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: 5000}, soakSession)
		gateLog = append(gateLog, probe{now, v.GetDecision(), v.GetReason()})
	}
	clk.at(t0.Add(time.Minute), gateProbe)
	for at := t0.Add(time.Hour); at.Before(end); at = at.Add(time.Hour) {
		clk.at(at, gateProbe)
	}
	for d := -90 * time.Second; d <= 90*time.Second; d += freshEvery {
		clk.at(boundary.Add(d), gateProbe)
	}

	var ackAtDark, ackAtReturn, writeAtReturn spool.Cursor
	clk.at(darkAt, func() {
		ackAtDark, _ = sp.Cursors()
		hole.dark.Store(true)
	})
	clk.at(diskFullAt, func() { diskUsed.Store(96) })
	clk.at(diskFreeAt, func() { diskUsed.Store(50) })
	clk.at(returnAt, func() {
		ackAtReturn, writeAtReturn = sp.Cursors()
		cp.serve(t, m, "minimal", `"t7-stable-000002"`, "2")
		hole.dark.Store(false)
	})
	var drainedByRequeue bool
	clk.at(returnAt.Add(docParkRequeue+time.Minute), func() {
		ack, write := sp.Cursors()
		drainedByRequeue = ack == write
	})

	start := time.Now()
	clk.runUntil(end)
	select {
	case err := <-runErr:
		t.Fatalf("a Run loop exited during the soak: %v", err)
	default:
	}

	// (1) capture, burst by burst: free, the 95 % disk window (F-19), then at cap (F-17/F-18); billing never refused.
	var capAt time.Time
	inDisk := func(at time.Time) bool { return !at.Before(diskFullAt) && at.Before(diskFreeAt) }
	for _, r := range burstLog {
		switch {
		case inDisk(r.at):
			if r.held != 3 || r.shed != 5 || r.admitted != 0 {
				t.Fatalf("%v inside the disk hard stop: admitted %d held %d shed %d, want 0/3/5 (02 §8.2: every class stops)", r.at, r.admitted, r.held, r.shed)
			}
		case capAt.IsZero() && r.shed > 0:
			capAt = r.at
			if r.held != 0 {
				t.Fatalf("%v reached the cap: a billing record was held while a diagnostic still fitted", r.at)
			}
		case !capAt.IsZero() && r.at.Before(returnAt):
			if r.shed != 5 || r.admitted+r.held < 3 {
				t.Fatalf("%v at cap: admitted %d held %d shed %d, want every diagnostic shed and every billing record admitted or held", r.at, r.admitted, r.held, r.shed)
			}
		case !capAt.IsZero():
			if r.held != 0 && r.at.After(returnAt.Add(docParkRequeue+time.Minute)) {
				t.Fatalf("%v after the drain: %d billing records still held", r.at, r.held)
			}
		default:
			if r.held != 0 || r.shed != 0 {
				t.Fatalf("%v before the cap: held %d shed %d, want everything admitted", r.at, r.held, r.shed)
			}
		}
	}
	if capAt.IsZero() || capAt.Before(diskFreeAt) || !capAt.Before(returnAt) {
		t.Fatalf("the spool cap was reached at %v; want inside the outage and after the disk window (%v)", capAt, diskFreeAt)
	}
	for _, r := range burstLog {
		if r.at.After(diskFreeAt) && r.at.Before(capAt) && r.pending != 0 {
			t.Fatalf("%v: %d billing records still held after the disk window cleared", r.at, r.pending)
		}
	}
	if len(pendingBilling) != 0 {
		t.Fatalf("%d billing-grade events still held upstream after the drain freed the spool", len(pendingBilling))
	}
	if !drainedByRequeue {
		t.Fatalf("the spool was not drained within one park re-queue (%v) of the control plane returning", docParkRequeue)
	}
	if len(hardStops) != 2 || !hardStops[0].entered || hardStops[1].entered ||
		hardStops[0].at.Before(diskFullAt) || hardStops[0].at.After(diskFullAt.Add(time.Second)) ||
		hardStops[1].at.Before(diskFreeAt) || hardStops[1].at.After(diskFreeAt.Add(time.Second)) {
		t.Fatalf("disk hard stop edges %+v, want entered within a cadence of %v and left within a cadence of %v", hardStops, diskFullAt, diskFreeAt)
	}
	if got, _ := spoolBytes(t, spoolDir); got > spoolCap {
		t.Fatalf("spool holds %d bytes at end, cap %d", got, spoolCap)
	}
	if peakHeap > docMark1dRSSCap {
		t.Fatalf("peak heap %d exceeds 04 §1.3's %d", peakHeap, docMark1dRSSCap)
	}

	// (2) the gate served the last-known-good bundle for exactly max_age, inclusive, then built-ins.
	sawFresh := false
	for _, p := range gateLog {
		stale := strings.Contains(p.reason, fabric.CodeStaleCert)
		switch {
		case !p.at.After(boundary):
			sawFresh = true
			if stale || p.decision != m1pv1.GateDecision_GATE_DECISION_BLOCK {
				t.Fatalf("%v: inside max_age (boundary %v) the gate must block from the applied bundle, got %v %q", p.at, boundary, p.decision, p.reason)
			}
		default:
			if !stale || p.decision != m1pv1.GateDecision_GATE_DECISION_ALLOW {
				t.Fatalf("%v: past max_age (boundary %v) the gate must answer allow+stale_cert from built-ins, got %v %q", p.at, boundary, p.decision, p.reason)
			}
		}
	}
	if !sawFresh {
		t.Fatal("no probe observed the fresh bundle")
	}
	var lastFresh, firstStale time.Time
	for _, p := range gateLog {
		if p.decision == m1pv1.GateDecision_GATE_DECISION_BLOCK {
			lastFresh = p.at
		}
		if firstStale.IsZero() && p.at.After(boundary) {
			firstStale = p.at
		}
	}
	if !lastFresh.Equal(boundary) || !firstStale.Equal(boundary.Add(freshEvery)) {
		t.Fatalf("transition: last fresh answer %v, first stale %v; want exactly %v (inclusive boundary) and %v (one freshness cadence later)", lastFresh, firstStale, boundary, boundary.Add(freshEvery))
	}
	// The verdict-plane pointer moved exactly twice: built-ins one cadence past max_age, then seq 2's aged-out posture on return.
	if len(swaps) != 2 || !swaps[0].at.Equal(boundary.Add(freshEvery)) || !swaps[0].m.Stale ||
		swaps[1].at.Before(returnAt) || !swaps[1].m.Stale || len(swaps[1].m.Verifiers) != 0 {
		t.Fatalf("verdict-plane swaps %+v: want [built-ins at %v, seq-2 built-ins after %v]", swaps, boundary.Add(freshEvery), returnAt)
	}

	// (3) uploader: the 08 §2.5 automaton verbatim, then a complete drain with zero duplicates.
	ds, draws := up.list()
	parks, backoffs, run := 0, 0, 0
	for i, d := range ds {
		switch {
		case d == docParkRequeue:
			parks++
			if run != docMaxAttempts-1 {
				t.Fatalf("park %d followed %d backoff sleeps, want %d", parks, run, docMaxAttempts-1)
			}
			run = 0
		case math.IsNaN(draws[i]):
			if d != time.Second {
				t.Fatalf("sleep %d = %v drew no jitter and is not the idle poll", i, d)
			}
			if run != 0 {
				t.Fatalf("an idle poll interrupted a backoff run of %d", run)
			}
		default:
			run++
			backoffs++
			ceiling := docDelay(run)
			if want := time.Duration(float64(ceiling) * draws[i]); d != want || d < 0 || d > ceiling {
				t.Fatalf("backoff %d (attempt %d, draw %v) slept %v, want %v within [0, %v]", i, run, draws[i], d, want, ceiling)
			}
			if run > docMaxAttempts-1 {
				t.Fatalf("backoff run reached %d sleeps without parking", run)
			}
		}
	}
	// One cycle is 6 h parked plus 0-51 min of jittered backoff, over 6 d 23 h 48 min dark.
	if parks < 24 || parks > 28 {
		t.Fatalf("%d park entries over the outage, want 24-28 from a 6 h re-queue cadence", parks)
	}
	darkPosts, darkGets := hole.counts()
	if darkPosts != backoffs+parks {
		t.Fatalf("%d ingest POSTs hit the blackhole, want %d (one per backoff sleep plus one per park)", darkPosts, backoffs+parks)
	}
	if ack, write := sp.Cursors(); ack != write {
		t.Fatalf("spool not drained after return: ack %v write %v", ack, write)
	}
	if ackAtReturn != ackAtDark || ackAtReturn == writeAtReturn {
		t.Fatalf("ack cursor moved during the outage (%v → %v) or no backlog was waiting at return (write %v)", ackAtDark, ackAtReturn, writeAtReturn)
	}
	cp.mu.Lock()
	landed, dropped, batches := cp.landed, cp.dropped, cp.batches
	cp.mu.Unlock()
	if len(landed) != len(produced) {
		t.Fatalf("%d distinct events landed, %d were admitted", len(landed), len(produced))
	}
	for id, n := range landed {
		if n != 1 {
			t.Fatalf("event %s landed %d times: the idempotent key did not hold", id, n)
		}
		if _, ok := produced[id]; !ok {
			t.Fatalf("event %s landed but was never admitted", id)
		}
	}
	if q := dropped[[2]int32{int32(spool.DropSpoolShed), int32(spool.ClassDiagnostic)}]; q != uint64(shed) {
		t.Fatalf("Dropped{SPOOL_SHED, diagnostic} landed %d, %d diagnostics were shed", q, shed)
	}
	for k, q := range dropped {
		if k[1] == int32(spool.ClassBilling) {
			t.Fatalf("Dropped row for a billing-grade class landed: reason %d quantity %d", k[0], q)
		}
		if k[0] != int32(spool.DropSpoolShed) {
			t.Fatalf("unexpected Dropped row reason %d class %d quantity %d", k[0], k[1], q)
		}
	}
	if rest := sp.DrainDropped(); len(rest) != 0 {
		t.Fatalf("loss ledger still holds %v after the drain", rest)
	}
	if ents, _ := os.ReadDir(filepath.Join(state, "quarantine")); len(ents) != 0 {
		t.Fatal("the outage quarantined a batch; a blackhole is network-class and must never quarantine (08 §2.5)")
	}
	if batches < 2 {
		t.Fatalf("%d acked batches; the drain plus post-return uploads must produce more", batches)
	}

	// The bundle client: fail-static across every failed tick, then FETCHED → RUNNING_NEW on return.
	cp.mu.Lock()
	acks := append([]ackBody(nil), cp.acks...)
	cp.mu.Unlock()
	if len(acks) != 2 || acks[0].Seq != "1" || acks[0].Result != "applied" || acks[1].Seq != "2" || acks[1].Result != "applied" {
		t.Fatalf("bundle ACKs %+v, want exactly [seq 1 applied, seq 2 applied]", acks)
	}
	// At draw 0.5 the poll backoff sits at half the 30 min cap for the outage: polled no faster (04 §2.6), no slower.
	wantGets := int(returnAt.Sub(darkAt) / (docBackoffCap / 2))
	if darkGets < wantGets-4 || darkGets > wantGets+4 {
		t.Fatalf("%d bundle polls hit the blackhole, want %d±4 from a capped backoff held for the outage", darkGets, wantGets)
	}
	bds, _ := bs.list()
	var maxSleep time.Duration
	for _, d := range bds {
		if d == freshEvery {
			continue
		}
		if d > docBackoffCap || d < 30*time.Second {
			t.Fatalf("bundle client slept %v; want inside [poll-derived floor, %v]", d, docBackoffCap)
		}
		maxSleep = max(maxSleep, d)
	}
	if maxSleep != docBackoffCap/2 {
		t.Fatalf("bundle client's longest sleep %v; at draw 0.5 the cap gives %v, so the ladder never reached it", maxSleep, docBackoffCap/2)
	}
	t.Logf("soak: %v virtual in %v wall; %d bursts, cap at %v, %d diagnostics shed, %d parks, %d backoff sleeps, %d dark POSTs, %d dark bundle GETs, %d acked batches, peak heap %d MiB",
		end.Sub(t0), time.Since(start), len(burstLog), capAt.Sub(t0), shed, parks, backoffs, darkPosts, darkGets, batches, peakHeap>>20)
	raw, err := os.ReadFile(filepath.Join(state, "policy", "lkg.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Seq uint64 `json:"seq"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Seq != minimalSeq {
		t.Fatalf("custody after return: seq %d err %v, want %d", meta.Seq, err, minimalSeq)
	}
}
