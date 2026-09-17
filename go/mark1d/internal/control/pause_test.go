package control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
)

// TestPerAgentPauseIsTheAgentsOffSwitch: POST /v1/agents/{name}/pause pauses ONE
// agent — its sessions' gate answers allow agent_paused through a real
// fabric.Gate resolving agents through the hub, its tailer emit (off.Unless)
// admits nothing, /v1/agents and status.agents_live say so — while another
// agent still blocks; resume restores it; each transition (and no repeat)
// journals an agent-scoped coverage row the drain receipts device-wide; the
// global switch is untouched and still wins.
func TestPerAgentPauseIsTheAgentsOffSwitch(t *testing.T) {
	fakeHome(t)
	s, dir := newServer(t)
	if err := writeAtomic(fabric.OptInPath(dir), []byte(`{"stop_gate":true,"ts":"2026-09-16T00:00:00Z","user":"test"}`)); err != nil {
		t.Fatal(err)
	}
	hub := s.Hub()
	hub.Publish(sessionEvent(1, &m1pv1.SessionStart{Agent: "codex"}))
	hub.Publish(sessionEvent(2, &m1pv1.SessionStart{Agent: "claudecode"}))
	codexSession, claudeSession := [16]byte{1}, [16]byte{2}
	g := blockableGate(dir)
	g.AgentFor = hub.AgentFor
	task := make([]byte, 16)
	task[0] = 1
	q := &m1pv1.GateQuery{TaskId: task, Gate: m1pv1.GateKind_GATE_KIND_STOP, DeadlineMs: 5000}
	if v := g.Answer(q, codexSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("precondition: gate must BLOCK before pause, got %v %q", v.GetDecision(), v.GetReason())
	}
	var admitted []string
	emit := off.Unless(dir, "codex", func(_ context.Context, ev *m1pv1.Event) error {
		admitted = append(admitted, ev.GetSessionStart().GetAgent())
		return nil
	})
	usage := func() { _ = emit(context.Background(), sessionEvent(1, &m1pv1.SessionStart{Agent: "codex"})) }
	usage()

	resp, body := call(t, s, http.MethodPost, "/v1/agents/codex/pause", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"agent":"codex","paused":true,"receipted_transition_id":null}` {
		t.Fatalf("pause %s", body)
	}
	if !off.AgentOff(dir, "codex") || off.AgentOff(dir, "claudecode") || off.Off(dir) {
		t.Fatalf("codex=%v claudecode=%v global=%v: only codex is paused", off.AgentOff(dir, "codex"), off.AgentOff(dir, "claudecode"), off.Off(dir))
	}
	if v := g.Answer(q, codexSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW || v.GetReason() != "agent_paused" {
		t.Fatalf("paused codex gate answered %v %q, want allow agent_paused", v.GetDecision(), v.GetReason())
	}
	if v := g.Answer(q, claudeSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("claudecode gate answered %v %q while only codex is paused", v.GetDecision(), v.GetReason())
	}
	usage()
	if len(admitted) != 1 {
		t.Fatalf("a paused agent's tailer emit reached admission: %v", admitted)
	}
	var marker struct {
		Agent     string `json:"agent"`
		WrittenAt string `json:"written_at"`
	}
	b, _ := os.ReadFile(off.AgentMarker(dir, "codex"))
	decodeTo(t, b, &marker)
	if marker.Agent != "codex" || marker.WrittenAt == "" {
		t.Fatalf("marker %s", b)
	}
	if _, body := call(t, s, http.MethodPost, "/v1/agents/codex/pause", nil); strings.TrimSpace(string(body)) != `{"agent":"codex","paused":true,"receipted_transition_id":null}` {
		t.Fatalf("pause twice %s", body)
	}

	var agents []map[string]any
	_, body = call(t, s, http.MethodGet, "/v1/agents", nil)
	decodeTo(t, body, &agents)
	paused := map[string]any{}
	for _, row := range agents {
		paused[row["name"].(string)] = row["paused"]
	}
	if paused["codex"] != true || paused["claudecode"] != false || paused["crush"] != false {
		t.Fatalf("GET /v1/agents paused = %v", paused)
	}
	var status struct {
		Paused     bool `json:"paused"`
		AgentsLive []struct {
			Agent  string `json:"agent"`
			Paused bool   `json:"paused"`
		} `json:"agents_live"`
	}
	_, body = call(t, s, http.MethodGet, "/v1/status", nil)
	decodeTo(t, body, &status)
	live := map[string]bool{}
	for _, l := range status.AgentsLive {
		live[l.Agent] = l.Paused
	}
	if status.Paused || len(live) != 2 || !live["codex"] || live["claudecode"] {
		t.Fatalf("status paused=%v agents_live=%v", status.Paused, live)
	}

	resp, body = call(t, s, http.MethodPost, "/v1/agents/codex/resume", nil)
	want(t, resp, body, http.StatusOK, "")
	if strings.TrimSpace(string(body)) != `{"agent":"codex","paused":false,"receipted_transition_id":null}` || off.AgentOff(dir, "codex") {
		t.Fatalf("resume %s paused=%v", body, off.AgentOff(dir, "codex"))
	}
	if v := g.Answer(q, codexSession); v.GetDecision() != m1pv1.GateDecision_GATE_DECISION_BLOCK {
		t.Fatalf("resumed codex must gate again, got %v %q", v.GetDecision(), v.GetReason())
	}
	usage()
	if len(admitted) != 2 {
		t.Fatalf("resumed agent's emit must admit again: %v", admitted)
	}
	if _, body := call(t, s, http.MethodPost, "/v1/agents/codex/resume", nil); strings.TrimSpace(string(body)) != `{"agent":"codex","paused":false,"receipted_transition_id":null}` {
		t.Fatalf("resume twice %s", body)
	}
	resp, body = call(t, s, http.MethodPost, "/v1/agents/crush/pause", nil)
	want(t, resp, body, http.StatusNotFound, "M1E-2001")
	resp, _ = call(t, s, http.MethodPost, "/v1/agents/../OFF/pause", nil)
	if resp.StatusCode == http.StatusOK || off.Off(dir) {
		t.Fatalf("a path escape answered %d and global off=%v", resp.StatusCode, off.Off(dir))
	}

	rec := &recorder{}
	cov := coverage.New(rec.admit, []byte("k"))
	if n, err := cov.DrainJournal(context.Background(), dir); err != nil || n != 2 {
		t.Fatalf("drain %d %v (pause, resume — repeats journal nothing)", n, err)
	}
	var got []string
	for _, ev := range rec.events {
		ct := ev.GetCoverageTransition()
		if !bytes.Equal(ct.GetWorkspaceId(), coverage.DeviceWide()) {
			t.Fatalf("an agent pause lands device-wide, like mark1 off --all: %v", ct)
		}
		got = append(got, ct.GetKind().String()+"/"+ct.GetReasonCode())
	}
	if strings.Join(got, " ") != "COVERAGE_KIND_DISABLE/agent_pause COVERAGE_KIND_ENABLE/agent_resume" {
		t.Fatalf("transitions %v", got)
	}
	lines, _ := os.ReadFile(coverage.JournalPath(dir))
	for _, l := range bytes.Split(bytes.TrimSpace(lines), []byte("\n")) {
		var row struct {
			Agent string `json:"agent"`
			Scope string `json:"scope"`
		}
		if err := json.Unmarshal(l, &row); err != nil || row.Agent != "codex" || row.Scope != "all" {
			t.Fatalf("journal line %s must name the agent and stay device-scoped", l)
		}
	}

	// Global pause still wins over a resumed agent, and over a paused one's reason.
	call(t, s, http.MethodPost, "/v1/agents/codex/pause", nil)
	call(t, s, http.MethodPost, "/v1/pause", nil)
	for _, sid := range [][16]byte{codexSession, claudeSession} {
		if v := g.Answer(q, sid); v.GetReason() != "mark1_off" {
			t.Fatalf("global off must precede the per-agent check, got %q", v.GetReason())
		}
	}
	call(t, s, http.MethodPost, "/v1/resume", nil)
	if v := g.Answer(q, codexSession); v.GetReason() != "agent_paused" {
		t.Fatalf("a global resume must not lift an agent's own pause, got %q", v.GetReason())
	}
}
