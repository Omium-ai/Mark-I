package appapi

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type sessionRow struct {
	SessionID        string   `json:"session_id"`
	Agent            string   `json:"agent"`
	Project          string   `json:"project"`
	StartedAt        string   `json:"started_at"`
	EndedAt          string   `json:"ended_at"`
	Tokens           tokens   `json:"tokens"`
	Tasks            uint64   `json:"tasks"`
	VerifiedOutcomes uint64   `json:"verified_outcomes"`
	Arrests          uint64   `json:"arrests"`
	Blocks           uint64   `json:"blocks"`
	TokensSaved      uint64   `json:"tokens_saved"` // the edge's estimate over the session's arrests and blocks
	Injections       uint64   `json:"injections"`
	RouteDecisions   uint64   `json:"route_decisions"`
	Coverage         coverage `json:"coverage"`
	CheckpointSeq    uint64   `json:"checkpoint_seq"`
	HistoryImport    bool     `json:"history_import"` // imported from transcript history on first tail, not captured live
}

type tokens struct {
	Input       uint64 `json:"input"`
	Output      uint64 `json:"output"`
	CacheRead   uint64 `json:"cache_read"`
	CacheCreate uint64 `json:"cache_create"`
}

// coverage is the session's own capture posture (desktop spec §5.2: was the proxy in the path, was the transcript tailed) plus its billing-grade loss.
type coverage struct {
	CapturePaths     []string `json:"capture_paths"`
	ProxyInPath      bool     `json:"proxy_in_path"`
	TranscriptTailed bool     `json:"transcript_tailed"`
	DroppedBilling   uint64   `json:"dropped_billing"`
}

func sessionFromRow(row map[string]any) sessionRow {
	paths := []string{}
	for _, p := range asStrings(row["capture_paths"]) {
		paths = append(paths, enumSuffix(p, "CAPTURE_PATH_"))
	}
	sort.Strings(paths)
	return sessionRow{
		SessionID: asStr(row["session_id"]),
		Agent:     asStr(row["agent"]),
		Project:   strings.ToLower(asStr(row["project"])),
		StartedAt: asTime(row["started_at"]).Format(time.RFC3339Nano),
		EndedAt:   asTime(row["ended_at"]).Format(time.RFC3339Nano),
		Tokens: tokens{
			Input: asU64(row["tokens_in"]), Output: asU64(row["tokens_out"]),
			CacheRead: asU64(row["tokens_cache_read"]), CacheCreate: asU64(row["tokens_cache_create"]),
		},
		Tasks:            asU64(row["tasks"]),
		VerifiedOutcomes: asU64(row["tasks_verified"]),
		Arrests:          asU64(row["arrests"]),
		Blocks:           asU64(row["blocks"]),
		TokensSaved:      asU64(row["tokens_saved"]),
		Injections:       asU64(row["injections"]),
		RouteDecisions:   asU64(row["route_decisions"]),
		Coverage: coverage{
			CapturePaths:     paths,
			ProxyInPath:      contains(paths, "proxy"),
			TranscriptTailed: contains(paths, "transcript"),
			DroppedBilling:   asU64(row["dropped_billing"]),
		},
		CheckpointSeq: asU64(row["checkpoint_seq"]),
		HistoryImport: asU64(row["history_import"]) != 0,
	}
}

// Session detail: the per-task attempt timeline, verdict trail and typed evidence

type task struct {
	TaskID         string      `json:"task_id"`
	TaskSegVersion string      `json:"task_seg_version"`
	TaskClass      string      `json:"task_class"`
	OpenedAt       *string     `json:"opened_at"`
	ClosedAt       *string     `json:"closed_at"`
	Resolution     string      `json:"resolution"`
	Attempts       []attempt   `json:"attempts"`
	VerdictTrail   []trailStep `json:"verdict_trail"`
	Evidence       []evidence  `json:"evidence"`
	Injections     []injection `json:"injections"`
	Arrests        []arrest    `json:"arrests"`
	Blocks         []arrest    `json:"blocks"`
}

type attempt struct {
	N            int     `json:"n"`
	Tokens       uint64  `json:"tokens"`
	CostUSD      float64 `json:"cost_usd"`
	Verdict      string  `json:"verdict"`
	VerdictStage string  `json:"verdict_stage"`
}

type trailStep struct {
	At            string  `json:"at"`
	EventID       string  `json:"event_id"`
	Stage         string  `json:"stage"`
	Verdict       string  `json:"verdict"`
	Certification string  `json:"certification"`
	CertificateID *string `json:"certificate_id"`
	BundleSeq     uint64  `json:"bundle_seq"`
}

// evidence is EvidenceRecord's typed fields only (07 §4): tool, code, category, counts, path role. No path, no excerpt, no digest.
type evidence struct {
	At             string `json:"at"`
	EventID        string `json:"event_id"`
	AnchorID       string `json:"anchor_id"`
	Vote           string `json:"vote"`
	Tool           string `json:"tool"`
	DiagnosticCode string `json:"diagnostic_code"`
	Category       string `json:"category"`
	Counts         counts `json:"counts"`
	PathRole       string `json:"path_role"`
	Tamper         bool   `json:"tamper"`
}

type counts struct {
	Errors        uint32 `json:"errors"`
	Warnings      uint32 `json:"warnings"`
	FilesAffected uint32 `json:"files_affected"`
}

type injection struct {
	At            string `json:"at"`
	EventID       string `json:"event_id"`
	Channel       string `json:"channel"`
	TokensUsed    uint32 `json:"tokens_used"`
	ArtifactCount int    `json:"artifact_count"`
}

type arrest struct {
	At                  string `json:"at"`
	EventID             string `json:"event_id"`
	BundleSeq           uint64 `json:"bundle_seq"`
	TokensSavedEstimate uint64 `json:"tokens_saved_estimate"`
	Attempt             uint32 `json:"attempt"`
}

type anchorVotePayload struct {
	AnchorID string `json:"anchor_id"`
	Vote     string `json:"vote"`
	Evidence struct {
		Tool           string `json:"tool"`
		DiagnosticCode string `json:"diagnostic_code"`
		Category       string `json:"category"`
		Counts         counts `json:"counts"`
		PathRole       string `json:"path_role"`
	} `json:"evidence"`
	Integrity struct {
		Tamper bool `json:"tamper"`
	} `json:"integrity"`
}

type taskOpenPayload struct {
	TaskSegVersion string `json:"task_seg_version"`
	TaskClass      string `json:"task_class"`
}

type taskClosePayload struct {
	Resolution string `json:"resolution"`
}

type verdictPayload struct {
	Certification string `json:"certification"`
	BundleSeq     uint64 `json:"bundle_seq,string"`
}

type injectionPayload struct {
	ArtifactIDs []string `json:"artifact_ids"`
	Channel     string   `json:"channel"`
	TokensUsed  uint32   `json:"tokens_used"`
}

type guardPayload struct {
	TokensSavedEstimate uint64 `json:"tokens_saved_estimate"`
	ReasonCode          string `json:"reason_code"`
	Attempt             uint32 `json:"attempt"`
}

func isFinal(stage string) bool { return stage == "certified" || stage == "revised" }

// foldTasks narrows the window's rows to one session (rows arrive in (session_id, session_epoch, seq) order) and folds each task: attempt_n = least(1 + stage-final verdicts before the row, greatest(1, stage-final verdicts in the task)) — tvo_task_window's rule, so the tail after the last verdict folds into the last attempt.
func foldTasks(rows []map[string]any, sid uuid.UUID) []task {
	want := sid.String()
	byTask := map[string]*task{}
	var order []string
	finals := map[string]int{}
	for _, row := range rows {
		if asStr(row["session_id"]) != want || asStr(row["event_type"]) != "VerdictEvent" {
			continue
		}
		if isFinal(asStr(row["verdict_stage"])) {
			finals[asStr(row["task_id"])]++
		}
	}
	seen := map[string]int{}
	for _, row := range rows {
		if asStr(row["session_id"]) != want {
			continue
		}
		id := asStr(row["task_id"])
		if id == uuid.Nil.String() {
			continue
		}
		t, ok := byTask[id]
		if !ok {
			t = &task{TaskID: id, Attempts: []attempt{}, VerdictTrail: []trailStep{}, Evidence: []evidence{}, Injections: []injection{}, Arrests: []arrest{}, Blocks: []arrest{}}
			byTask[id] = t
			order = append(order, id)
		}
		at := asTime(row["occurred_at"]).Format(time.RFC3339Nano)
		eventID := asStr(row["event_id"])
		payload := asStr(row["payload"])
		n := min(1+seen[id], max(1, finals[id]))
		for len(t.Attempts) < n {
			t.Attempts = append(t.Attempts, attempt{N: len(t.Attempts) + 1})
		}
		a := &t.Attempts[n-1]
		a.Tokens += asU64(row["tokens"])
		a.CostUSD += asF64(row["cost_usd"])
		switch asStr(row["event_type"]) {
		case "TaskOpen":
			var p taskOpenPayload
			_ = json.Unmarshal([]byte(payload), &p)
			t.TaskSegVersion, t.TaskClass, t.OpenedAt = p.TaskSegVersion, p.TaskClass, &at
		case "TaskClose":
			var p taskClosePayload
			_ = json.Unmarshal([]byte(payload), &p)
			t.Resolution, t.ClosedAt = enumSuffix(p.Resolution, "RESOLUTION_"), &at
		case "VerdictEvent":
			verdict, stage := asStr(row["verdict"]), asStr(row["verdict_stage"])
			var p verdictPayload
			_ = json.Unmarshal([]byte(payload), &p)
			step := trailStep{At: at, EventID: eventID, Stage: stage, Verdict: verdict, Certification: enumSuffix(p.Certification, "CERTIFICATION_STATUS_"), BundleSeq: p.BundleSeq}
			if cert := asStr(row["noise_cert_id"]); cert != uuid.Nil.String() {
				step.CertificateID = &cert
			}
			t.VerdictTrail = append(t.VerdictTrail, step)
			if verdict != "" {
				a.Verdict, a.VerdictStage = verdict, stage
			}
			if isFinal(stage) {
				seen[id]++
			}
		case "AnchorVote":
			var p anchorVotePayload
			_ = json.Unmarshal([]byte(payload), &p)
			t.Evidence = append(t.Evidence, evidence{
				At: at, EventID: eventID, AnchorID: p.AnchorID, Vote: enumSuffix(p.Vote, "VERDICT_"),
				Tool: p.Evidence.Tool, DiagnosticCode: p.Evidence.DiagnosticCode,
				Category: enumSuffix(p.Evidence.Category, "EVIDENCE_CATEGORY_"), Counts: p.Evidence.Counts,
				PathRole: enumSuffix(p.Evidence.PathRole, "PATH_ROLE_"), Tamper: p.Integrity.Tamper,
			})
		case "MemoryInjection":
			var p injectionPayload
			_ = json.Unmarshal([]byte(payload), &p)
			t.Injections = append(t.Injections, injection{At: at, EventID: eventID, Channel: enumSuffix(p.Channel, "INJECTION_CHANNEL_"), TokensUsed: p.TokensUsed, ArtifactCount: len(p.ArtifactIDs)})
		case "GuardDecision":
			var p guardPayload
			_ = json.Unmarshal([]byte(payload), &p)
			row := arrest{At: at, EventID: eventID, BundleSeq: asU64(row["bundle_seq"]), TokensSavedEstimate: p.TokensSavedEstimate, Attempt: p.Attempt}
			switch p.ReasonCode {
			case "stop_gate_block":
				t.Blocks = append(t.Blocks, row)
			default:
				t.Arrests = append(t.Arrests, row)
			}
		}
	}
	out := make([]task, 0, len(order))
	for _, id := range order {
		out = append(out, *byTask[id])
	}
	return out
}

// Moments: one feed, three kinds

type moment struct {
	Kind      string        `json:"kind"`
	At        time.Time     `json:"at"`
	EventID   string        `json:"event_id"`
	SessionID string        `json:"session_id"`
	TaskID    *string       `json:"task_id"`
	Agent     string        `json:"agent"`
	Arrest    *arrestDetail `json:"arrest,omitempty"`
	Block     *arrestDetail `json:"block,omitempty"`
	Injection *injection    `json:"injection,omitempty"`
	Route     *routeDetail  `json:"route,omitempty"`
}

type arrestDetail struct {
	BundleSeq           uint64 `json:"bundle_seq"`
	TokensSavedEstimate uint64 `json:"tokens_saved_estimate"`
	Attempt             uint32 `json:"attempt"`
}

type routeDetail struct {
	Action     string   `json:"action"`
	Candidates []string `json:"candidates"`
	Propensity float64  `json:"propensity"`
	Fidelity   string   `json:"fidelity"`
	BundleSeq  uint64   `json:"bundle_seq"`
}

type routePayload struct {
	Action     string   `json:"action"`
	Candidates []string `json:"candidates"`
}

func momentFromRow(row map[string]any, since time.Time) (moment, bool) {
	at := asTime(row["occurred_at"])
	if !at.After(since) {
		return moment{}, false
	}
	mo := moment{At: at, EventID: asStr(row["event_id"]), SessionID: asStr(row["session_id"]), Agent: asStr(row["agent"])}
	if id := asStr(row["task_id"]); id != uuid.Nil.String() {
		mo.TaskID = &id
	}
	payload := []byte(asStr(row["payload"]))
	switch asStr(row["event_type"]) {
	case "GuardDecision":
		var p guardPayload
		_ = json.Unmarshal(payload, &p)
		d := &arrestDetail{BundleSeq: asU64(row["bundle_seq"]), TokensSavedEstimate: p.TokensSavedEstimate, Attempt: p.Attempt}
		if p.ReasonCode == "stop_gate_block" {
			mo.Kind, mo.Block = "block", d
		} else {
			mo.Kind, mo.Arrest = "arrest", d
		}
	case "MemoryInjection":
		var p injectionPayload
		_ = json.Unmarshal(payload, &p)
		mo.Kind, mo.Injection = "injection", &injection{At: at.Format(time.RFC3339Nano), EventID: mo.EventID, Channel: enumSuffix(p.Channel, "INJECTION_CHANNEL_"), TokensUsed: p.TokensUsed, ArtifactCount: len(p.ArtifactIDs)}
	case "RouteDecision":
		var p routePayload
		_ = json.Unmarshal(payload, &p)
		if p.Candidates == nil {
			p.Candidates = []string{}
		}
		mo.Kind, mo.Route = "route", &routeDetail{Action: p.Action, Candidates: p.Candidates, Propensity: asF64(row["propensity"]), Fidelity: asStr(row["fidelity"]), BundleSeq: asU64(row["bundle_seq"])}
	default:
		return moment{}, false
	}
	return mo, true
}

// Route decisions: ope_route_decisions rows, `at` derived from the UUIDv7 decision id

type routeDecision struct {
	DecisionID      string   `json:"decision_id"`
	At              *string  `json:"at"`
	TaskID          string   `json:"task_id"`
	SessionID       string   `json:"session_id"`
	Agent           string   `json:"agent"`
	Action          string   `json:"action"`
	Candidates      []string `json:"candidates"`
	Propensity      float64  `json:"propensity"`
	Fidelity        string   `json:"fidelity"`
	BundleSeq       uint64   `json:"bundle_seq"`
	ServedModel     string   `json:"served_model"`
	Verdict         string   `json:"verdict"`
	VerdictStage    string   `json:"verdict_stage"`
	LabelConfidence *float64 `json:"label_confidence"`
}

func routeDecisionFromRow(row map[string]any) routeDecision {
	d := routeDecision{
		DecisionID: asStr(row["decision_id"]), TaskID: asStr(row["task_id"]), SessionID: asStr(row["session_id"]),
		Agent: asStr(row["agent"]), Action: asStr(row["action"]), Candidates: asStrings(row["candidates"]),
		Propensity: asF64(row["propensity"]), Fidelity: asStr(row["fidelity"]), BundleSeq: asU64(row["bundle_seq"]),
		ServedModel: asStr(row["served_model"]), Verdict: asStr(row["verdict"]), VerdictStage: asStr(row["verdict_stage"]),
	}
	if d.Candidates == nil {
		d.Candidates = []string{}
	}
	if v, ok := asNullableF64(row["label_confidence"]); ok {
		d.LabelConfidence = &v
	}
	if id, err := uuid.Parse(d.DecisionID); err == nil && id.Version() == 7 {
		sec, nsec := id.Time().UnixTime()
		at := time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
		d.At = &at
	}
	return d
}

// Row-value coercion: the runner hands back concrete ClickHouse scan types.

func asU64(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case uint8:
		return uint64(x)
	case int64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case int:
		if x < 0 {
			return 0
		}
		return uint64(x)
	}
	return 0
}

func asF64(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case *float64:
		if x != nil {
			return *x
		}
	}
	return 0
}

func asNullableF64(v any) (float64, bool) {
	switch x := v.(type) {
	case *float64:
		if x == nil {
			return 0, false
		}
		return *x, true
	case *float32:
		if x == nil {
			return 0, false
		}
		return float64(*x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	}
	return 0, false
}

func asStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func asStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, asStr(e))
		}
		return out
	}
	return nil
}

func asTime(v any) time.Time {
	if t, ok := v.(time.Time); ok {
		return t.UTC()
	}
	return time.Time{}
}

func enumSuffix(name, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(name, prefix))
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
