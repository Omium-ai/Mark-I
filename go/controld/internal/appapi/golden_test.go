package appapi

// The desktop app (Mark1-GUI) parses every desktop/mock/fixtures/controld/cloud-*.json through its endpoint schemas (src/renderer/test/contract.test.ts). This test writes those files from the real handlers with -update and otherwise holds the checked-in goldens to the handlers' current shape, so a drift on either side fails a CI run in its own repo.

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var update = flag.Bool("update", false, "rewrite desktop/mock/fixtures/controld/cloud-*.json from the handlers")

const goldenDir = "../../../../desktop/mock/fixtures/controld"

// goldenRig seeds one tenant with every row family the app-facing handlers read: two sessions, a task with a verdict trail and an arrest, a route with a real choice, an injection, a rollup day (so trend carries a point) and an arrested task with no verdict yet (verdict "").
func goldenRig(t *testing.T) (*rig, uuid.UUID) {
	t.Helper()
	r := newRig(t)
	at := time.Now().UTC().Add(-3 * time.Hour)
	session, other := v7(), v7()
	task1, task2 := uuid.New(), uuid.New()
	cert, decision := uuid.New(), v7()
	conf := float32(0.91)
	r.run.add("app_sessions", r.tenantA,
		sessionRowFor(session, "claudecode", projA, []string{"CAPTURE_PATH_HOOKS", "CAPTURE_PATH_PROXY"}, at),
		sessionRowFor(other, "codex", "", []string{"CAPTURE_PATH_TRANSCRIPT"}, at.Add(-time.Hour)),
	)
	r.run.add("app_session_events", r.tenantA,
		eventRow(session, task1, 1, at, "TaskOpen", 0, `{"task_seg_version":"task_seg.v1","task_class":"edit.small"}`, nil),
		eventRow(session, task1, 2, at, "Usage", 100, `{"model":"claude-sonnet-4-5"}`, nil),
		eventRow(session, task1, 3, at, "VerdictEvent", 0, `{"certification":"CERTIFICATION_STATUS_BOOTSTRAPPING","bundle_seq":"7"}`, map[string]any{"verdict": "violated", "verdict_stage": "provisional"}),
		eventRow(session, task1, 4, at, "AnchorVote", 0, `{"anchor_id":"ruff@1","vote":"VERDICT_VIOLATED","evidence":{"tool":"ruff","diagnostic_code":"E501","category":"EVIDENCE_CATEGORY_LINT","counts":{"errors":2},"path_role":"PATH_ROLE_SRC"},"integrity":{"tamper":false}}`, nil),
		eventRow(session, task1, 5, at, "GuardDecision", 0, `{"decision":"block","tokens_saved_estimate":1200}`, map[string]any{"bundle_seq": uint64(7)}),
		eventRow(session, task1, 6, at, "MemoryInjection", 0, `{"artifact_ids":["`+b64(uuid.New())+`"],"channel":"INJECTION_CHANNEL_HOOK_CONTEXT","tokens_used":12}`, nil),
		eventRow(session, task1, 7, at, "VerdictEvent", 0, `{"certification":"CERTIFICATION_STATUS_CERTIFIED"}`, map[string]any{"verdict": "satisfied", "verdict_stage": "certified", "noise_cert_id": cert}),
		eventRow(session, task1, 8, at, "TaskClose", 0, `{"resolution":"RESOLUTION_VERDICT"}`, nil),
		eventRow(session, task2, 9, at, "TaskOpen", 0, `{"task_seg_version":"task_seg.v1"}`, nil),
		eventRow(session, task2, 10, at, "GuardDecision", 0, `{"decision":"block","tokens_saved_estimate":900}`, map[string]any{"bundle_seq": uint64(7)}),
		eventRow(session, uuid.Nil, 11, at, "ReceiptCheckpoint", 0, `{}`, map[string]any{"checkpoint_seq": uint64(9)}),
	)
	now := time.Now().UTC()
	moment := func(at time.Time, eventType, payload string, extra map[string]any) map[string]any {
		row := map[string]any{"event_id": v7(), "occurred_at": at, "session_id": session, "task_id": task1, "agent": "claudecode",
			"event_type": eventType, "propensity": float64(1), "fidelity": "", "bundle_seq": uint64(0), "payload": payload}
		for k, v := range extra {
			row[k] = v
		}
		return row
	}
	r.run.add("app_moments", r.tenantA,
		moment(now.Add(-1*time.Minute), "RouteDecision", `{"action":"claude-haiku-4-5","candidates":["claude-haiku-4-5","claude-sonnet-4-5"]}`, map[string]any{"fidelity": "wire_enforced", "bundle_seq": uint64(483), "propensity": float64(0.97)}),
		moment(now.Add(-2*time.Minute), "MemoryInjection", `{"artifact_ids":["AAEC"],"channel":"INJECTION_CHANNEL_MCP_PULL","tokens_used":40}`, map[string]any{"task_id": uuid.Nil}),
		moment(now.Add(-3*time.Minute), "GuardDecision", `{"decision":"block","tokens_saved_estimate":900}`, map[string]any{"bundle_seq": uint64(483)}),
	)
	r.run.add("ope_route_decisions", r.tenantA,
		map[string]any{"decision_id": decision, "task_id": task1, "session_id": session, "session_epoch": uint32(1), "seq": uint64(6), "agent": "claudecode",
			"action": "claude-haiku-4-5", "candidates": []string{"claude-haiku-4-5", "claude-sonnet-4-5"}, "propensity": float64(0.97), "fidelity": "wire_enforced", "bundle_seq": uint64(483),
			"served_model": "claude-haiku-4-5", "verdict": "satisfied", "verdict_stage": "certified", "label_confidence": &conf},
	)
	r.run.add("interventions", r.tenantA,
		map[string]any{"task_id": task1, "tokens_saved_estimate": uint64(1200), "arrests": uint64(1), "verdict": "satisfied", "bundle_seq": uint64(7)},
		map[string]any{"task_id": task2, "tokens_saved_estimate": uint64(900), "arrests": uint64(1), "verdict": "", "bundle_seq": uint64(7)},
	)
	return r, session
}

// goldens are the app-facing 200 bodies the storeless rig can produce, named as the app's fixtureFile() spells them; the PG- and intel-backed routes (me, team, certificates, bundle, memory artifacts/outcomes/actions, receipts) have no rows here.
func goldens(session uuid.UUID) []struct{ file, path, schema string } {
	return []struct{ file, path, schema string }{
		{"cloud-sessions", "/api/v1/sessions?window=7d", "sessions.json"},
		{"cloud-sessions-detail", "/api/v1/sessions/" + session.String(), "session_detail.json"},
		{"cloud-moments", "/api/v1/moments", "moments.json"},
		{"cloud-route-decisions", "/api/v1/route/decisions?window=7d", "route_decisions.json"},
		{"cloud-memory-injections", "/api/v1/memory/injections?window=7d", "memory_injections.json"},
		{"cloud-reports-tvo", "/api/v1/reports/tvo?window=7d", ""},
		{"cloud-reports-interventions", "/api/v1/reports/interventions?window=7d", ""},
	}
}

func TestAppAPIMatchesDesktopFixtures(t *testing.T) {
	r, session := goldenRig(t)
	for _, g := range goldens(session) {
		w := r.get(g.path, r.tokenA)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", g.path, w.Code, w.Body.String())
		}
		if g.schema != "" {
			r.schemas.Validate(g.schema, w.Body.Bytes())
		}
		var live any
		if err := json.Unmarshal(w.Body.Bytes(), &live); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(goldenDir, g.file+".json")
		if *update {
			pretty, _ := json.MarshalIndent(live, "", "  ")
			if err := os.MkdirAll(goldenDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, append(pretty, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v (run with -update)", g.file, err)
		}
		var want any
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("%s: %v", g.file, err)
		}
		if g.schema != "" {
			r.schemas.Validate(g.schema, raw)
		}
		if diffs := shapeDiff("$", want, live); len(diffs) > 0 {
			t.Errorf("%s.json diverges from GET %s (run with -update if the handler is right):\n  %s", g.file, g.path, strings.Join(diffs, "\n  "))
		}
	}
	// The cases the app's schemas were wrong about (b-contracts audit): a rollup day in the trend, an arrest with no verdict yet, the boolean grade with its joined refusal.
	var tvo struct {
		Trend          []map[string]any `json:"trend"`
		GuaranteeGrade bool             `json:"guarantee_grade"`
		Refusal        string           `json:"refusal"`
	}
	if err := json.Unmarshal(r.get("/api/v1/reports/tvo?window=7d", r.tokenA).Body.Bytes(), &tvo); err != nil {
		t.Fatal(err)
	}
	if len(tvo.Trend) != 1 || tvo.Trend[0]["day"] == nil || tvo.Trend[0]["tvo"] == nil || tvo.GuaranteeGrade || tvo.Refusal == "" {
		t.Fatalf("tvo golden must carry [{day,tvo}], a false grade and its refusal: %+v", tvo)
	}
	var iv struct {
		KneeArrests []map[string]any `json:"knee_arrests"`
	}
	if err := json.Unmarshal(r.get("/api/v1/reports/interventions?window=7d", r.tokenA).Body.Bytes(), &iv); err != nil {
		t.Fatal(err)
	}
	if len(iv.KneeArrests) != 2 || iv.KneeArrests[1]["verdict"] != "" {
		t.Fatalf("interventions golden must carry an arrest with verdict \"\": %+v", iv.KneeArrests)
	}
}

// shapeDiff compares JSON structure, never values: key sets per object (recursively), the JSON type per key, arrays by their first element. A null on either side accepts anything (nullable fields flip with the data).
func shapeDiff(path string, want, got any) []string {
	if want == nil || got == nil {
		return nil
	}
	if kind(want) != kind(got) {
		return []string{fmt.Sprintf("%s: golden %s, handler %s", path, kind(want), kind(got))}
	}
	switch w := want.(type) {
	case map[string]any:
		g := got.(map[string]any)
		var diffs []string
		keys := map[string]bool{}
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			wv, inW := w[k]
			gv, inG := g[k]
			switch {
			case !inG:
				diffs = append(diffs, path+"."+k+": missing from the handler")
			case !inW:
				diffs = append(diffs, path+"."+k+": handler-only key")
			default:
				diffs = append(diffs, shapeDiff(path+"."+k, wv, gv)...)
			}
		}
		return diffs
	case []any:
		g := got.([]any)
		if len(w) == 0 || len(g) == 0 {
			return nil
		}
		return shapeDiff(path+"[0]", w[0], g[0])
	}
	return nil
}

func kind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64, json.Number:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}
