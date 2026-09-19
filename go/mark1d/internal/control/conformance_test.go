package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// The desktop app (Mark1-GUI) is built against desktop/mock; this test holds the daemon to the same shapes.
const mockDir = "../../../../desktop/mock"

// skippedFixtures are the local-*.json files no route exercises, each with its reason.
var skippedFixtures = map[string]string{
	"local-events": "SSE replay format {delayMs,event,data}, not a route; TestEventFramesMatchDesktopFixture holds each row's data to the hub's frame",
}

var routeRe = regexp.MustCompile(`\['(GET|POST|PUT|DELETE)', '(/v1/[^']+)', '(local-[^']+)'\]`)

// localRoutes reads LOCAL_ROUTES out of server.mjs, so the mapping under test is the mock's own.
func localRoutes(t *testing.T) [][3]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(mockDir, "server.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start, end := strings.Index(src, "LOCAL_ROUTES"), strings.Index(src, "CLOUD_ROUTES")
	if start < 0 || end < start {
		t.Fatal("server.mjs: LOCAL_ROUTES block not found")
	}
	var out [][3]string
	for _, m := range routeRe.FindAllStringSubmatch(src[start:end], -1) {
		out = append(out, [3]string{m[1], m[2], m[3]})
	}
	if len(out) < 10 {
		t.Fatalf("server.mjs: parsed only %d local routes", len(out))
	}
	return out
}

func writeFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}

type seeded struct {
	s                   *Server
	dir                 string
	repoA, repoB, repoC string
	keyID, controld     string
}

// seedConformance builds one daemon state every route has data for: two enabled roots, a live Claude Code session attributed to repoA, a published anchor catalog, a provisioned fragment, a sealed head, an enrollment key.
func seedConformance(t *testing.T) seeded {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs for claude and the verifier")
	}
	bin, home := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(bin, "claude"), []byte("#!/bin/sh\necho '2.1.251 (Claude Code)'\n"), 0o700)
	t.Setenv("PATH", bin)
	t.Setenv("HOME", home)
	s, dir := newServer(t)
	repoA, _ := canonical(t.TempDir())
	repoB, _ := canonical(t.TempDir())
	repoC, _ := canonical(t.TempDir())
	writeFile(t, anchors.RepoOptInPath(repoA), []byte(`{"tests":true}`), 0o600)
	writeFile(t, filepath.Join(repoA, ".mark1ignore"), []byte("node_modules/\n"), 0o600)
	ws := workspacesFile{Version: 1, Workspaces: []workspaceEntry{{Path: repoA, EnabledAt: time.Now().UTC()}, {Path: repoB, EnabledAt: time.Now().UTC()}}}
	if err := s.saveWorkspaces(ws); err != nil {
		t.Fatal(err)
	}

	sid := [16]byte{1}
	txDir, err := (&claudecode.Adapter{}).TranscriptDir(repoA)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(txDir, uuid.UUID(sid).String()+".jsonl"), []byte(`{"type":"user","cwd":`+jsonString(repoA)+`}`+"\n"), 0o600)
	hub := s.Hub()
	hub.Publish(sessionEvent(1, &m1pv1.SessionStart{Agent: "claudecode", AgentVersion: "2.1.251"}))
	hub.Publish(sessionEvent(1, &m1pv1.Usage{InputTokens: 10, OutputTokens: 5}))
	stamp := func(ev *m1pv1.Event, seq uint64) *m1pv1.Event {
		id := uuid.New()
		ev.EventId, ev.Seq, ev.SessionEpoch, ev.OccurredAt = id[:], seq, 3, timestamppb.Now()
		ev.TaskId = bytes.Repeat([]byte{9}, 16)
		return ev
	}
	hub.Arrest(sid, [16]byte{9}, verdict.KneeState{N: 3, PLCB: 0.18, VTask: 6000, CostN: 2900, CostBasis: "usd", Stop: true, Evaluable: true}, "ev_task_401_3")
	hub.Publish(stamp(sessionEvent(1, &m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED, Verdict: m1pv1.Verdict_VERDICT_SATISFIED, Posterior: []float64{0.8, 0.1, 0.05, 0.05}, NoiseCertId: "cert_5591", BundleSeq: 4, VoteCount: 2, Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_CERTIFIED}), 7))
	hub.Publish(stamp(sessionEvent(1, &m1pv1.AnchorVote{AnchorId: "ruff@cat-1", Vote: m1pv1.Verdict_VERDICT_SATISFIED, Integrity: &m1pv1.AnchorIntegrity{Tamper: true}}), 9))
	hub.Publish(stamp(&m1pv1.Event{Body: &m1pv1.Event_ReceiptCheckpoint{ReceiptCheckpoint: &m1pv1.ReceiptCheckpoint{CheckpointSeq: 4, MerkleRoot: bytes.Repeat([]byte{0xab}, 32), LeafCount: 87, KeyId: "ed25519:a1cf5c00b2784f6e"}}}, 1))

	e := catalogEntry()
	derived := map[string][]anchors.CatalogEntry{repoA: {e}}
	publish := func() {
		consented, err := anchors.LoadConsent(anchors.ConsentPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if err := anchors.PublishCandidates(anchors.CandidatesPath(dir), consented, derived, anchors.SandboxStatus{Available: true}); err != nil {
			t.Fatal(err)
		}
	}
	publish()
	var offset int64
	s.SetReconcile(func() {
		off, _, err := anchors.ApplyApprovals(anchors.ConsentPath(dir), anchors.ApprovalsPath(dir), offset, derived, time.Now(), slog.Default())
		if err != nil {
			t.Error(err)
		}
		offset = off
		publish()
	})

	s.SetShutdown(func() {})
	writeFile(t, fabric.OptInPath(dir), []byte(`{"stop_gate":true,"ts":"2026-09-16T00:00:00Z","user":"test"}`), 0o600)
	writeFile(t, filepath.Join(dir, "spool", "seg-0000000000000001.m1s"), make([]byte, 64), 0o600)
	writeFile(t, filepath.Join(dir, "receipt", "last-head"), []byte(`{"seq":92,"hash":"`+strings.Repeat("ab", 32)+`","checkpoint_seq":4}`), 0o600)
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, []byte(`{"model": "opus"}`), 0o600)
	if _, err := claudecode.ApplyFragment(settings, dir, ""); err != nil {
		t.Fatal(err)
	}
	// The plan sources: ~/.claude.json's oauthAccount (never .credentials.json) and one status-line record in the vendor's published shape (https://code.claude.com/docs/en/statusline).
	writeFile(t, filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount":{"organizationRateLimitTier":"default_claude_max_20x","organizationType":"claude_max","billingType":"stripe_subscription","hasExtraUsageEnabled":false,"profileFetchedAt":1789501965151}}`), 0o600)
	writeFile(t, claudecode.RateLimitsPath(dir), []byte(`{"received_at":1789562800,"rate_limits":{"five_hour":{"used_percentage":23.5,"resets_at":1789575600},"seven_day":{"used_percentage":41.2,"resets_at":1789893600}},"model":{"id":"claude-opus-5","display_name":"Opus"},"context_window":{"total_input_tokens":15500,"total_output_tokens":1200,"context_window_size":200000,"used_percentage":8,"remaining_percentage":92,"current_usage":{"input_tokens":8500,"output_tokens":1200,"cache_creation_input_tokens":5000,"cache_read_input_tokens":2000}},"prompt_cache":{"warm":true,"caching_observed":true,"ttl":"1h","expires_at":1789566400,"requests":14,"misses":2,"expected_rebuilds":1,"hit_ratio":0.91,"cache_write_tokens":352000,"miss_recache_tokens":310200,"last_miss_at":1789562630,"last_miss_cause":{"causes":["tools_changed"],"tools_added":2,"tools_removed":0},"miss_causes":{"tools_changed":2},"recache_tokens_if_cold":45000}}`+"\n"), 0o600)
	// The verifier's own Report (tools/verifier/src/lib.rs), which the route relays verbatim — after checking it was handed the export and key manifest the stub controld below serves.
	verifier := filepath.Join(bin, "mark1-verifier")
	writeFile(t, verifier, []byte("#!/bin/sh\nread -r c < \"$3\"; read -r k < \"$5\"\ncase \"$c\" in *'\"seq\":1'*) ;; *) echo no-chain >&2; exit 1;; esac\ncase \"$k\" in *pubkey_hex*) ;; *) echo no-keys >&2; exit 1;; esac\necho '{\"ok\":true,\"checked\":{\"receipts\":3,\"checkpoints\":1,\"inclusion_proofs\":3,\"witness_heads\":0},\"intact_prefix_seq\":92,\"intact_prefix_hash\":\"ab\",\"last_good_seq\":92,\"last_good_hash\":\"ab\",\"defects\":[]}'\n"), 0o700)
	t.Setenv("MARK1_VERIFIER", verifier)
	controld := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/receipts/export":
			if r.URL.Query().Get("since_seq") == "0" {
				_, _ = w.Write([]byte(`{"seq":1,"kind":"checkpoint"}` + "\n"))
			}
		case "/api/v1/receipts/keys":
			_, _ = w.Write([]byte(`{"device_keys":[{"key_id":"k","pubkey_hex":"00"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(controld.Close)

	var kg struct {
		KeyID string `json:"key_id"`
	}
	resp, body := call(t, s, http.MethodPost, "/v1/enroll/keygen", nil)
	want(t, resp, body, http.StatusOK, "")
	decodeTo(t, body, &kg)
	sd := seeded{s: s, dir: dir, repoA: repoA, repoB: repoB, repoC: repoC, keyID: kg.KeyID, controld: controld.URL}
	resp, body = call(t, s, http.MethodPost, "/v1/enroll", sd.body(http.MethodPost, "/v1/enroll"))
	want(t, resp, body, http.StatusOK, "")
	return sd
}

func (sd seeded) body(method, path string) any {
	switch method + " " + path {
	case "POST /v1/projects", "DELETE /v1/projects":
		return map[string]string{"path": sd.repoC}
	case "POST /v1/anchors/consent":
		return map[string]any{"id": "ruff@cat-1", "consented": true}
	case "PUT /v1/optins":
		return map[string]any{"stop_gate": true, "tests_by_project": map[string]bool{sd.repoA: true}}
	case "POST /v1/enroll":
		active := activeFor(tenantA, deviceA, sd.keyID)
		active["endpoints"] = map[string]string{"ingest": sd.controld + "/m1p/v1/ingest"}
		return active
	}
	return nil
}

func TestControlAPIMatchesDesktopFixtures(t *testing.T) {
	sd := seedConformance(t)
	fixtures := filepath.Join(mockDir, "fixtures", "active")
	routes := localRoutes(t)
	covered := map[string]bool{}
	for _, r := range routes {
		method, path, name := r[0], r[1], r[2]
		covered[name] = true
		raw, err := os.ReadFile(filepath.Join(fixtures, name+".json"))
		if err != nil {
			t.Errorf("%s %s: %v", method, path, err)
			continue
		}
		var wantShape, gotShape any
		if err := json.Unmarshal(raw, &wantShape); err != nil {
			t.Fatalf("%s.json: %v", name, err)
		}
		resp, body := call(t, sd.s, method, path, sd.body(method, path))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, body)
			continue
		}
		if err := json.Unmarshal(body, &gotShape); err != nil {
			t.Errorf("%s %s: not JSON: %v: %s", method, path, err, body)
			continue
		}
		if diffs := shapeDiff("$", wantShape, gotShape); len(diffs) > 0 {
			t.Errorf("%s %s (%s.json) diverges from the daemon:\n  %s\ndaemon: %s", method, path, name, strings.Join(diffs, "\n  "), body)
		}
	}
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !strings.HasPrefix(name, "local-") || covered[name] {
			continue
		}
		if why, skipped := skippedFixtures[name]; skipped {
			t.Logf("skipped %s.json: %s", name, why)
			continue
		}
		t.Errorf("%s.json has no LOCAL_ROUTES entry in server.mjs and is not in skippedFixtures", name)
	}
}

// records are objects whose keys are data (a path → bool map), compared by their first value's shape like arrays.
var records = map[string]bool{"$.tests_by_project": true}

// shapeDiff compares JSON structure, never values: key sets per object (recursively), the JSON type per key, arrays by their first element. A null in the fixture accepts anything; a null from the daemon where the fixture has a value is a divergence.
func shapeDiff(path string, want, got any) []string {
	if want == nil {
		return nil
	}
	if kind(want) != kind(got) {
		return []string{fmt.Sprintf("%s: fixture %s, daemon %s", path, kind(want), kind(got))}
	}
	var out []string
	switch w := want.(type) {
	case map[string]any:
		g := got.(map[string]any)
		if records[path] {
			if len(w) > 0 && len(g) > 0 {
				out = shapeDiff(path+"[*]", w[slices.Sorted(maps.Keys(w))[0]], g[slices.Sorted(maps.Keys(g))[0]])
			}
			break
		}
		keys := slices.Sorted(func(yield func(string) bool) {
			seen := map[string]bool{}
			for k := range w {
				seen[k] = true
				if !yield(k) {
					return
				}
			}
			for k := range g {
				if !seen[k] && !yield(k) {
					return
				}
			}
		})
		for _, k := range keys {
			wv, inW := w[k]
			gv, inG := g[k]
			switch {
			case !inG:
				out = append(out, fmt.Sprintf("%s.%s: missing from the daemon", path, k))
			case !inW:
				out = append(out, fmt.Sprintf("%s.%s: daemon-only key", path, k))
			default:
				out = append(out, shapeDiff(path+"."+k, wv, gv)...)
			}
		}
	case []any:
		g := got.([]any)
		if len(w) > 0 && len(g) > 0 {
			out = append(out, shapeDiff(path+"[0]", w[0], g[0])...)
		}
	}
	sort.Strings(out)
	return out
}

func kind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// TestEventFramesMatchDesktopFixture holds every family the hub streams to the active scenario's local-events.json rows: the same frame shape (ids as dashed UUIDs, the protojson body under its family key; arrest the verify-events row) the app's SSE readers are built against.
func TestEventFramesMatchDesktopFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(mockDir, "fixtures", "active", "local-events.json"))
	if err != nil {
		t.Fatal(err)
	}
	var script []struct {
		Event string         `json:"event"`
		Data  map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &script); err != nil {
		t.Fatal(err)
	}
	hub := NewHub()
	ch, cancel := hub.subscribe()
	defer cancel()
	at := timestamppb.New(time.Date(2026, 9, 16, 13, 52, 0, 0, time.UTC))
	full := func(body any) *m1pv1.Event {
		ev := sessionEvent(1, body)
		ev.EventId, ev.TaskId, ev.OccurredAt = bytes.Repeat([]byte{5}, 16), bytes.Repeat([]byte{3}, 16), at
		return ev
	}
	published := []*m1pv1.Event{
		full(&m1pv1.SessionStart{Agent: "claudecode", AgentVersion: "2.1.0", CapturePaths: []m1pv1.CapturePath{m1pv1.CapturePath_CAPTURE_PATH_HOOKS}}),
		full(&m1pv1.Turn{TurnIndex: 1, Initiator: m1pv1.Initiator_INITIATOR_HUMAN}),
		full(&m1pv1.ToolUse{ToolName: "Edit", ToolUseId: "toolu_01", DurationMs: 120, Status: m1pv1.ToolStatus_TOOL_STATUS_OK}),
		full(&m1pv1.Usage{Model: "claude-sonnet-4-5", InputTokens: 1800, OutputTokens: 620, CacheReadInputTokens: 4100}),
		full(&m1pv1.VerdictEvent{Stage: m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL, Verdict: m1pv1.Verdict_VERDICT_VIOLATED, Posterior: []float64{0.2, 0.7, 0.05, 0.05}, Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_BOOTSTRAPPING}),
		full(&m1pv1.MemoryInjection{ArtifactIds: [][]byte{bytes.Repeat([]byte{7}, 16)}, Channel: m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, TokensUsed: 180}),
		full(&m1pv1.RouteDecision{DecisionId: bytes.Repeat([]byte{4}, 16), Action: "claude-haiku-4-5", Candidates: []string{"claude-haiku-4-5", "claude-sonnet-4-5"}, Propensity: 0.97, Fidelity: m1pv1.RouteFidelity_ROUTE_FIDELITY_WIRE_ENFORCED, BundleSeq: 1042}),
		full(&m1pv1.CoverageTransition{Kind: m1pv1.CoverageKind_COVERAGE_KIND_ENABLE, ReasonCode: "project_enable"}),
	}
	published[0].TaskId = nil
	published[len(published)-1].TaskId = nil
	for _, ev := range published {
		hub.Publish(ev)
	}
	hub.Arrest([16]byte{1}, [16]byte{3}, verdict.KneeState{N: 3, PLCB: 0.18, VTask: 6000, CostN: 2900, Stop: true, Evaluable: true}, "ev_task_401_3")
	got := map[string]any{}
	for len(got) < len(published)+1 {
		select {
		case f := <-ch:
			var data any
			if err := json.Unmarshal(f.data, &data); err != nil {
				t.Fatal(err)
			}
			got[f.family] = data
		case <-time.After(time.Second):
			t.Fatalf("hub streamed %d families, want %d", len(got), len(published)+1)
		}
	}
	for _, row := range script {
		frame, ok := got[row.Event]
		if !ok {
			t.Errorf("fixture family %q is not one the hub streams", row.Event)
			continue
		}
		if diffs := shapeDiff("$", row.Data, frame); len(diffs) > 0 {
			t.Errorf("event %s diverges from the hub's frame:\n  %s", row.Event, strings.Join(diffs, "\n  "))
		}
		if id, _ := frame.(map[string]any)["session_id"].(string); uuid.Validate(id) != nil {
			t.Errorf("event %s: session_id %q is not a dashed UUID", row.Event, id)
		}
	}
}
