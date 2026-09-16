package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
)

const (
	planted   = "Exit code 1\nFAIL test_retry_backoff: expected 3 attempts, saw 1"
	near      = "Exit code 1\nFAIL test_retry_backoff: expected 3 attempts, saw none"
	pitfallID = "0195a000-0000-7000-8000-000000000001"
	fixID     = "0195a000-0000-7000-8000-000000000002"
	invID     = "0195a000-0000-7000-8000-000000000003"
	prefID    = "0195a000-0000-7000-8000-000000000004"
	hintID    = "0195a000-0000-7000-8000-000000000005"
	fix2ID    = "0195a000-0000-7000-8000-000000000006"
	fix3ID    = "0195a000-0000-7000-8000-000000000007"
)

var (
	session = [16]byte{0xAA, 1}
	task    = [16]byte{0xBB, 1}
)

func plantedSet() []Artifact {
	return []Artifact{
		{ID: fixID, Kind: "fix_pattern", Trigger: "flaky retries", Guidance: "use exponential backoff", LCB: 0.9},
		{ID: prefID, Kind: "preference", Trigger: "lint", Guidance: "route lint to haiku", LCB: 0.8},
		{ID: hintID, Kind: "routing_hint", Trigger: "any", Guidance: "never inject me", LCB: 0.7},
		{ID: invID, Kind: "invariant", Trigger: "config", Guidance: "config lives in yaml", LCB: 0.6},
		{ID: fix2ID, Kind: "fix_pattern", Trigger: "second", Guidance: "second pattern", LCB: 0.5},
		{ID: fix3ID, Kind: "fix_pattern", Trigger: "third", Guidance: "third pattern", LCB: 0.4},
		{ID: pitfallID, Kind: "pitfall", Trigger: planted, Guidance: "run the retry test with --attempts 3", LCB: 0.3,
			SigDigest: SignatureDigest(NormalizeSignature(planted))},
	}
}

type retrievalServer struct {
	*httptest.Server
	mu      sync.Mutex
	arts    []Artifact
	match   []Artifact
	lists   int
	matches int
	lastErr string
	down    bool
	auth    string
}

func newRetrievalServer(t *testing.T, arts []Artifact) *retrievalServer {
	t.Helper()
	rs := &retrievalServer{arts: arts}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		rs.auth = r.Header.Get("Authorization")
		if rs.down {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		switch r.URL.Path {
		case pathArtifacts:
			rs.lists++
			_ = json.NewEncoder(w).Encode(map[string]any{"artifacts": rs.arts})
		case pathMatch:
			rs.matches++
			var body struct {
				Error string `json:"error"`
				Limit int    `json:"limit"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			rs.lastErr = body.Error
			if body.Limit != MInject {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"artifacts": rs.match})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(rs.Close)
	return rs
}

type sink struct {
	mu     sync.Mutex
	events []*m1pv1.Event
	fail   error
}

func (s *sink) admit(_ context.Context, ev *m1pv1.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.events = append(s.events, proto.CloneOf(ev))
	return nil
}

func (s *sink) injections() []*m1pv1.MemoryInjection {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*m1pv1.MemoryInjection
	for _, ev := range s.events {
		if mi := ev.GetMemoryInjection(); mi != nil {
			if !bytes.Equal(ev.GetSessionId(), session[:]) || !bytes.Equal(ev.GetTaskId(), task[:]) {
				panic("injection event not scoped to the session/task")
			}
			out = append(out, mi)
		}
	}
	return out
}

func (s *sink) outcomes() []*m1pv1.ArtifactOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*m1pv1.ArtifactOutcome
	for _, ev := range s.events {
		if ao := ev.GetArtifactOutcome(); ao != nil {
			out = append(out, ao)
		}
	}
	return out
}

func newCache(t *testing.T, rs *retrievalServer, sk *sink, verdict m1pv1.Verdict) *Cache {
	t.Helper()
	cfg := Config{
		StateDir: t.TempDir(), Token: "device-token", EdgeVersion: "test",
		Admit:   sk.admit,
		TaskFor: func(s, _ [16]byte) ([16]byte, bool) { return task, s == session },
		Verdict: func([16]byte) (*m1pv1.VerdictEvent, bool) {
			return &m1pv1.VerdictEvent{Verdict: verdict}, verdict != m1pv1.Verdict_VERDICT_UNSPECIFIED
		},
	}
	if rs != nil {
		cfg.BaseURL = rs.URL
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func idOf(s string) []byte {
	b, _ := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return b
}

func query(ch m1pv1.InjectionChannel, errText string) fabric.ContextQuery {
	return fabric.ContextQuery{Channel: uint32(ch), ToolName: "Bash", Error: errText, DeadlineMs: 1490}
}

func TestReactivePitfallInjectsExactlyOnceWithBudgetAccounting(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_SATISFIED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rs.auth != "Bearer device-token" {
		t.Fatalf("sync carried %q, want the device token", rs.auth)
	}
	ctx := context.Background()

	text := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted+"\nline 3 differs"), session)
	if !strings.Contains(text, "run the retry test with --attempts 3") {
		t.Fatalf("no remedy injected: %q", text)
	}
	inj := sk.injections()
	if len(inj) != 1 {
		t.Fatalf("%d MemoryInjection events, want exactly one", len(inj))
	}
	if len(inj[0].ArtifactIds) != 1 || !bytes.Equal(inj[0].ArtifactIds[0], idOf(pitfallID)) {
		t.Fatalf("artifact_ids %x, want the planted pitfall", inj[0].ArtifactIds)
	}
	if inj[0].Channel != m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL {
		t.Fatalf("channel %v", inj[0].Channel)
	}
	if inj[0].TokensUsed != Tokens(text) || inj[0].TokensUsed == 0 {
		t.Fatalf("tokens_used %d, want ceil(%d/4)", inj[0].TokensUsed, len(text))
	}
	if rs.matches != 0 {
		t.Fatalf("exact digest tier hit the server %d times", rs.matches)
	}
	// Same failure again in the same task: nothing, and no second event.
	if again := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted), session); again != "" {
		t.Fatalf("re-injected within the task: %q", again)
	}
	if len(sk.injections()) != 1 {
		t.Fatal("dedupe failed: a second MemoryInjection was emitted")
	}
	c.OnClose(task)
	out := sk.outcomes()
	if len(out) != 1 || !bytes.Equal(out[0].ArtifactId, idOf(pitfallID)) || out[0].TaskVerdict != m1pv1.Verdict_VERDICT_SATISFIED {
		t.Fatalf("outcomes %v", out)
	}
	c.OnClose(task)
	if len(sk.outcomes()) != 1 {
		t.Fatal("a second close re-emitted outcomes")
	}
}

func TestPackInjectsAllowlistedKindsOnlyWithinBudgets(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_VIOLATED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	text := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session)
	for _, banned := range []string{"route lint to haiku", "never inject me", "--attempts 3"} {
		if strings.Contains(text, banned) {
			t.Fatalf("pack carries a non-injectable artifact: %q", text)
		}
	}
	inj := sk.injections()
	if len(inj) != 1 || inj[0].Channel != m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT {
		t.Fatalf("injections %v", inj)
	}
	want := [][]byte{idOf(fixID), idOf(invID), idOf(fix2ID)}
	if len(inj[0].ArtifactIds) != MInject {
		t.Fatalf("%d ids, want m_inject=%d", len(inj[0].ArtifactIds), MInject)
	}
	for i, id := range inj[0].ArtifactIds {
		if !bytes.Equal(id, want[i]) {
			t.Fatalf("id %d = %x, want LCB order %x", i, id, want[i])
		}
	}
	if inj[0].TokensUsed != Tokens(text) || uint64(inj[0].TokensUsed) > defaultPackTokens {
		t.Fatalf("tokens_used %d over budget %d", inj[0].TokensUsed, defaultPackTokens)
	}
	if c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session) != "" {
		t.Fatal("pack injected twice for one task")
	}
	// The task's MInject room is spent: a matching failure now injects nothing.
	if got := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted), session); got != "" {
		t.Fatalf("m_inject exceeded: %q", got)
	}
	c.OnClose(task)
	out := sk.outcomes()
	if len(out) != MInject {
		t.Fatalf("%d outcomes, want one per injected artifact", len(out))
	}
	for i, o := range out {
		if !bytes.Equal(o.ArtifactId, want[i]) || o.TaskVerdict != m1pv1.Verdict_VERDICT_VIOLATED {
			t.Fatalf("outcome %d: %v", i, o)
		}
	}
}

func TestPackRespectsTheBundleTokenBudget(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	c.cfg.PackTokensMax = uint64(Tokens(packHeader)) + 12
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session)
	if strings.Contains(text, "exponential backoff") || !strings.Contains(text, "config lives in yaml") {
		t.Fatalf("budget did not skip the line that does not fit: %q", text)
	}
	if uint64(Tokens(text)) > c.cfg.PackTokensMax {
		t.Fatalf("pack %d tokens over %d", Tokens(text), c.cfg.PackTokensMax)
	}
	// Room is left under MInject, and still no second pack for the same task.
	if got := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session); got != "" {
		t.Fatalf("pack repeated with room left: %q", got)
	}
	if len(sk.injections()) != 1 {
		t.Fatal("a second pack event was emitted")
	}
	c.cfg.PackTokensMax = 1
	c2 := newCache(t, rs, &sink{}, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	c2.cfg.PackTokensMax = 1
	_ = c2.Sync(context.Background())
	if got := c2.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session); got != "" {
		t.Fatalf("a budget nothing fits under still injected: %q", got)
	}
}

func TestPackNeverCarriesPitfalls(t *testing.T) {
	arts := plantedSet()
	rs := newRetrievalServer(t, []Artifact{arts[6], arts[0]})
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session)
	if strings.Contains(text, "--attempts 3") || !strings.Contains(text, "exponential backoff") {
		t.Fatalf("pitfalls are reactive, never packed: %q", text)
	}
	inj := sk.injections()
	if len(inj) != 1 || len(inj[0].ArtifactIds) != 1 || !bytes.Equal(inj[0].ArtifactIds[0], idOf(fixID)) {
		t.Fatalf("injections %v", inj)
	}
}

func TestFuzzTierAsksTheServerAndFailsOpen(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	rs.match = []Artifact{
		{ID: prefID, Kind: "preference", Guidance: "leaked routing hint"},
		{ID: pitfallID, Kind: "pitfall", Guidance: "run the retry test with --attempts 3"},
	}
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	text := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, near), session)
	if !strings.Contains(text, "--attempts 3") || strings.Contains(text, "leaked") {
		t.Fatalf("fuzz tier: %q", text)
	}
	if rs.matches != 1 || rs.lastErr != near {
		t.Fatalf("server saw %d match calls, last error %q", rs.matches, rs.lastErr)
	}
	inj := sk.injections()
	if len(inj) != 1 || !bytes.Equal(inj[0].ArtifactIds[0], idOf(pitfallID)) {
		t.Fatalf("injections %v", inj)
	}

	rs.mu.Lock()
	rs.down = true
	rs.mu.Unlock()
	sk2 := &sink{}
	c2 := newCache(t, rs, sk2, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	c2.mu.Lock()
	c2.lkg = custody{SyncedAt: time.Now(), Artifacts: keep(plantedSet())}
	c2.mu.Unlock()
	if got := c2.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, near), session); got != "" {
		t.Fatalf("server down must inject nothing: %q", got)
	}
	if len(sk2.injections()) != 0 {
		t.Fatal("an undelivered injection was recorded")
	}
	if got := c2.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted), session); got == "" {
		t.Fatal("the exact tier must keep serving from last-known-good while the server is down")
	}
}

func TestNoInjectionWithoutTaskInterruptOrEmptyError(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	other := [16]byte{0xCC}
	if got := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), other); got != "" {
		t.Fatalf("no task resolved yet injected: %q", got)
	}
	q := query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted)
	q.IsInterrupt = true
	if got := c.Context(ctx, q, session); got != "" {
		t.Fatalf("a user interrupt is not a pitfall: %q", got)
	}
	if got := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, "  \n"), session); got != "" {
		t.Fatalf("empty error injected: %q", got)
	}
	if got := c.Context(ctx, query(m1pv1.InjectionChannel_INJECTION_CHANNEL_UNSPECIFIED, planted), session); got != "" {
		t.Fatalf("unspecified channel injected: %q", got)
	}
	if len(sk.injections()) != 0 || rs.matches != 0 {
		t.Fatalf("%d injections, %d server calls", len(sk.injections()), rs.matches)
	}
	c.OnClose(task)
	if len(sk.outcomes()) != 0 {
		t.Fatal("outcomes without injections")
	}
}

func TestAdmitFailureDeliversNothing(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	sk := &sink{fail: io.ErrClosedPipe}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted), session); got != "" {
		t.Fatalf("delivered without a ledger record: %q", got)
	}
	c.OnClose(task)
	if len(sk.events) != 0 {
		t.Fatal("events recorded past a failed admit")
	}
}

func TestCacheIsFailStaticAndFreshnessBounded(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	dir := t.TempDir()
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	cfg := Config{StateDir: dir, BaseURL: rs.URL, Now: func() time.Time { return now }}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.artifacts(); got != nil {
		t.Fatalf("unsynced cache served %d artifacts", len(got))
	}
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.artifacts(); len(got) != 5 {
		t.Fatalf("served %d, want the 5 allowlisted of 7 (preference and routing_hint dropped at load)", len(got))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "memory", cacheFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "routing_hint") || strings.Contains(string(raw), `"preference"`) {
		t.Fatal("non-injectable kinds persisted")
	}
	if st, _ := os.Stat(filepath.Join(dir, "memory", cacheFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %v", st.Mode().Perm())
	}

	rs.mu.Lock()
	rs.down = true
	rs.mu.Unlock()
	if err := c.Sync(context.Background()); err == nil {
		t.Fatal("a 502 sync reported success")
	}
	if got := c.artifacts(); len(got) != 5 {
		t.Fatalf("outage lowered the cache to %d", len(got))
	}
	c2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := c2.artifacts(); len(got) != 5 {
		t.Fatalf("boot on last-known-good served %d", len(got))
	}
	now = now.Add(defaultMaxAge + time.Second)
	if got := c2.artifacts(); got != nil {
		t.Fatalf("a cache past max age served %d", len(got))
	}
	now = now.Add(-2 * time.Second)
	c2.Purge()
	if got := c2.artifacts(); got != nil {
		t.Fatal("purge left artifacts in memory")
	}
	if _, err := os.Stat(filepath.Join(dir, "memory", cacheFile)); !os.IsNotExist(err) {
		t.Fatal("purge left the cache file")
	}
	c3, _ := New(Config{StateDir: dir})
	if got := c3.artifacts(); got != nil {
		t.Fatal("purge did not survive a restart")
	}
}

// The end-to-end path a shim exercises: Hello, then a hand-encoded ContextQuery frame through
// fabric.Server into the cache, and the ContextReply bytes back.
func TestContextQueryOverTheFabricInjectsThePlantedRemedy(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_UNSPECIFIED)
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := fabric.NewServer(func(context.Context, []byte) error { return nil }, nil)
	srv.SetContextHandler(c)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(context.Background(), l) //nolint:errcheck // closed by cleanup
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	hello, _ := proto.Marshal(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{Component: "mark1-hookshim", Pid: 1, SessionId: session[:]}}})
	if err := fabric.WriteFrame(conn, hello); err != nil {
		t.Fatal(err)
	}
	ack := &m1pv1.FabricFrame{}
	if err := proto.Unmarshal(readRaw(t, conn), ack); err != nil || !ack.GetHelloAck().GetAccepted() {
		t.Fatalf("handshake: %v %v", ack, err)
	}
	inner := protowire.AppendTag(nil, 1, protowire.VarintType)
	inner = protowire.AppendVarint(inner, uint64(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL))
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendString(inner, "Bash")
	inner = protowire.AppendTag(inner, 3, protowire.BytesType)
	inner = protowire.AppendString(inner, planted)
	inner = protowire.AppendTag(inner, 4, protowire.VarintType)
	inner = protowire.AppendVarint(inner, 1490)
	frame := protowire.AppendTag(nil, 8, protowire.BytesType)
	frame = protowire.AppendBytes(frame, inner)
	if err := fabric.WriteFrame(conn, frame); err != nil {
		t.Fatal(err)
	}
	reply := readRaw(t, conn)
	num, typ, n := protowire.ConsumeTag(reply)
	if num != 9 || typ != protowire.BytesType {
		t.Fatalf("reply arm %d/%d", num, typ)
	}
	body, _ := protowire.ConsumeBytes(reply[n:])
	num, _, n = protowire.ConsumeTag(body)
	text, _ := protowire.ConsumeString(body[n:])
	if num != 1 || !strings.Contains(text, "--attempts 3") {
		t.Fatalf("reply text %q (field %d)", text, num)
	}
	inj := sk.injections()
	if len(inj) != 1 || !bytes.Equal(inj[0].ArtifactIds[0], idOf(pitfallID)) || inj[0].TokensUsed != Tokens(text) {
		t.Fatalf("injections %v", inj)
	}
}

func readRaw(t *testing.T, c net.Conn) []byte {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatal(err)
	}
	n := int(uint32(hdr[5]) | uint32(hdr[6])<<8 | uint32(hdr[7])<<16 | uint32(hdr[8])<<24)
	payload := make([]byte, n)
	if _, err := io.ReadFull(c, payload); err != nil {
		t.Fatal(err)
	}
	return payload
}
