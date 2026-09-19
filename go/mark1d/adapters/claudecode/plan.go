package claudecode

// Plan tier and rate-limit windows from what the unmodified Claude Code binary writes locally: ~/.claude.json's oauthAccount (never ~/.claude/.credentials.json) and the shim's status-line feed; no token read, nothing sent to Anthropic.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"
)

// PlanNote is the docs sentence every plan response carries verbatim.
const PlanNote = "Mark 1 never reads, stores, or transmits your Claude account token and never calls Anthropic on your behalf; your plan tier and usage limits are read from the files and status-line data that the unmodified Claude Code binary writes on your own machine, so Claude Code remains the only program that uses your subscription."

// RateLimitsPath is the shim's `statusline` append log (rust/mark1-hookshim/src/statusline.rs).
func RateLimitsPath(stateDir string) string {
	return filepath.Join(stateDir, "claude", "ratelimits.jsonl")
}

// tierLabels maps organizationRateLimitTier to a display name; an unmapped id is shown raw.
var tierLabels = map[string]string{
	"claude_pro":             "Pro",
	"default_claude_pro":     "Pro",
	"default_claude_max_5x":  "Max 5x",
	"default_claude_max_20x": "Max 20x",
}

type Tier struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	FetchedAt        string `json:"fetched_at"`
	OrganizationType string `json:"organization_type"`
	BillingType      string `json:"billing_type"`
	ExtraUsage       bool   `json:"extra_usage_enabled"`
}

type Window struct {
	UsedPercentage float64 `json:"used_percentage"`
	ResetsAt       string  `json:"resets_at"`
	ObservedAt     string  `json:"observed_at"`
}

type Plan struct {
	Agent   string `json:"agent"`
	Tier    *Tier  `json:"tier"`
	Windows struct {
		FiveHour *Window `json:"five_hour"`
		SevenDay *Window `json:"seven_day"`
	} `json:"windows"`
	Model         *string         `json:"model"`
	ContextWindow json.RawMessage `json:"context_window"`
	PromptCache   json.RawMessage `json:"prompt_cache"`
	Source        string          `json:"source"`
	Note          string          `json:"note"`
}

// PlanTier reads ~/.claude.json; nil when the file, the object or the tier id is absent. Field names are local observation, so every read is tolerant.
func PlanTier(home string) *Tier {
	b, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		return nil
	}
	var doc struct {
		OAuth map[string]any `json:"oauthAccount"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	id, _ := doc.OAuth["organizationRateLimitTier"].(string)
	if id == "" {
		return nil
	}
	t := &Tier{ID: id, Label: id}
	if l, ok := tierLabels[id]; ok {
		t.Label = l
	}
	t.OrganizationType, _ = doc.OAuth["organizationType"].(string)
	t.BillingType, _ = doc.OAuth["billingType"].(string)
	t.ExtraUsage, _ = doc.OAuth["hasExtraUsageEnabled"].(bool)
	if ms, ok := doc.OAuth["profileFetchedAt"].(float64); ok && ms > 0 {
		t.FetchedAt = time.UnixMilli(int64(ms)).UTC().Format(time.RFC3339)
	}
	return t
}

// statusLineTail bounds the read of the newest record: a line is ~1-2 KiB.
const statusLineTail = 64 << 10

// ReadPlan is GET /v1/plan: the tier plus the newest status-line record, null-shaped when either is missing.
func ReadPlan(home, stateDir string) (Plan, error) {
	p := Plan{Agent: "claudecode", Tier: PlanTier(home), Source: "none", Note: PlanNote}
	line, err := lastLine(RateLimitsPath(stateDir))
	if err != nil || len(line) == 0 {
		return p, err
	}
	var rec struct {
		ReceivedAt int64 `json:"received_at"`
		RateLimits map[string]struct {
			UsedPercentage float64 `json:"used_percentage"`
			ResetsAt       int64   `json:"resets_at"`
		} `json:"rate_limits"`
		Model struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"model"`
		ContextWindow json.RawMessage `json:"context_window"`
		PromptCache   json.RawMessage `json:"prompt_cache"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return p, nil // a torn tail is no data, not a failure
	}
	p.Source = "statusline"
	observed := time.Unix(rec.ReceivedAt, 0).UTC().Format(time.RFC3339)
	window := func(name string) *Window {
		w, ok := rec.RateLimits[name]
		if !ok {
			return nil
		}
		return &Window{UsedPercentage: w.UsedPercentage, ResetsAt: time.Unix(w.ResetsAt, 0).UTC().Format(time.RFC3339), ObservedAt: observed}
	}
	p.Windows.FiveHour, p.Windows.SevenDay = window("five_hour"), window("seven_day")
	if m := rec.Model.ID; m != "" || rec.Model.DisplayName != "" {
		if m == "" {
			m = rec.Model.DisplayName
		}
		p.Model = &m
	}
	if len(rec.ContextWindow) > 0 && !bytes.Equal(rec.ContextWindow, []byte("null")) {
		p.ContextWindow = rec.ContextWindow
	}
	if len(rec.PromptCache) > 0 && !bytes.Equal(rec.PromptCache, []byte("null")) {
		p.PromptCache = rec.PromptCache
	}
	return p, nil
}

// lastLine returns the newest complete line of an append log, or nil when the file is absent or empty.
func lastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > statusLineTail {
		if _, err := f.Seek(-statusLineTail, io.SeekEnd); err != nil {
			return nil, err
		}
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\n")
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	return b, nil
}
