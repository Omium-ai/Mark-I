package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// userStatusLine is a settings.json whose user already runs their own status line, with a display option the chained command must keep.
const userStatusLine = `{
  "model": "opus",
  "statusLine": { "type": "command", "command": "~/.claude/statusline.sh", "padding": 2 },
  "permissions": { "allow": ["Bash(ls:*)"] }
}
`

const userStatusLineRaw = `{ "type": "command", "command": "~/.claude/statusline.sh", "padding": 2 }`

func statusLineOf(t *testing.T, path string) map[string]any {
	t.Helper()
	sl, ok := readJSON(t, path)["statusLine"].(map[string]any)
	if !ok {
		t.Fatalf("no statusLine object in %s", path)
	}
	return sl
}

func TestStatusLineTakesAnEmptySlot(t *testing.T) {
	path, state := provisioned(t, userSettings)
	sl := statusLineOf(t, path)
	if sl["type"] != "command" || sl["command"] != DefaultShimPath+" statusline" || sl["_mark1"] != "v1" || len(sl) != 3 {
		t.Fatalf("status line entry: %#v", sl)
	}
	if _, err := os.Stat(StatusLinePrevPath(state)); !os.IsNotExist(err) {
		t.Fatalf("an empty slot must record no previous command: %v", err)
	}
	if res, err := Revert(state); err != nil || res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("revert: %+v %v", res, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != userSettings {
		t.Fatalf("revert left the slot changed:\n%s", after)
	}
}

func TestStatusLineChainsTheUsersCommandAndRevertsByteEqual(t *testing.T) {
	path, state := provisioned(t, userStatusLine)
	sl := statusLineOf(t, path)
	if sl["command"] != DefaultShimPath+" statusline" || sl["padding"].(float64) != 2 || sl["_mark1"] != "v1" {
		t.Fatalf("ours must take the slot and keep their display options: %#v", sl)
	}
	prev, err := os.ReadFile(StatusLinePrevPath(state))
	if err != nil || string(prev) != userStatusLineRaw {
		t.Fatalf("sidecar must hold their entry verbatim: %q %v", prev, err)
	}
	if res, err := ApplyFragment(path, state, ""); err != nil || res.Changed {
		t.Fatalf("re-apply over our own slot: %+v %v", res, err)
	}
	if st, err := Inspect(state); err != nil || st.State != StateOK || st.Lines[len(st.Lines)-1].Pointer != "/statusLine" {
		t.Fatalf("doctor must list the slot: %+v %v", st, err)
	}

	if res, err := Revert(state); err != nil || res.Kind != "verbatim" || !res.ByteEquality {
		t.Fatalf("revert: %+v %v", res, err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != userStatusLine {
		t.Fatalf("off did not restore the user's bytes:\n%s", after)
	}
	if _, err := os.Stat(StatusLinePrevPath(state)); !os.IsNotExist(err) {
		t.Fatalf("sidecar survived revert: %v", err)
	}
}

func TestStatusLineSurgicalRevertRestoresTheirEntry(t *testing.T) {
	path, state := provisioned(t, userStatusLine)
	b, _ := os.ReadFile(path)
	edited := strings.Replace(string(b), `"model": "opus"`, `"model": "sonnet"`, 1)
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := Revert(state); err != nil || res.Kind != "surgical" {
		t.Fatalf("revert: %+v %v", res, err)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), `"statusLine": `+userStatusLineRaw) || strings.Contains(string(after), entryTag) {
		t.Fatalf("their entry must come back verbatim and ours must go:\n%s", after)
	}
	if readJSON(t, path)["model"] != "sonnet" {
		t.Fatal("the user's post-apply edit was reverted away")
	}
}

func TestStatusLineReplacedByHandIsDamagedAndLeftAlone(t *testing.T) {
	path, state := provisioned(t, userStatusLine)
	b, _ := os.ReadFile(path)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	doc["statusLine"] = json.RawMessage(`{"type":"command","command":"/usr/bin/theirs.sh"}`)
	moved, _ := json.Marshal(doc)
	if err := os.WriteFile(path, moved, 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := Inspect(state); st.State != StateDamaged {
		t.Fatalf("a replaced slot is damage, got %s", st.State)
	}
	if _, err := Revert(state); err != nil {
		t.Fatal(err)
	}
	if got := statusLineOf(t, path)["command"]; got != "/usr/bin/theirs.sh" {
		t.Fatalf("revert overwrote the entry the user chose after us: %v", got)
	}
}

func TestPlanTierReadsClaudeJSONOnly(t *testing.T) {
	home := t.TempDir()
	if PlanTier(home) != nil {
		t.Fatal("no file must be no tier, not an error")
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount":{"organizationRateLimitTier":"default_claude_max_20x","organizationType":"claude_max","billingType":"stripe_subscription","hasExtraUsageEnabled":false,"profileFetchedAt":1789501965151}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := PlanTier(home)
	if got == nil || got.Label != "Max 20x" || got.ID != "default_claude_max_20x" || got.FetchedAt != "2026-09-15T19:52:45Z" || got.OrganizationType != "claude_max" {
		t.Fatalf("tier: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount":{"organizationRateLimitTier":"default_claude_team"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := PlanTier(home); got == nil || got.Label != "default_claude_team" || got.FetchedAt != "" {
		t.Fatalf("an unmapped tier shows its raw id: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if PlanTier(home) != nil {
		t.Fatal("no tier id must be no tier")
	}
}

func TestReadPlanUsesTheNewestStatusLineRecord(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	p, err := ReadPlan(home, state)
	if err != nil || p.Source != "none" || p.Tier != nil || p.Windows.FiveHour != nil || p.Model != nil || p.ContextWindow != nil {
		t.Fatalf("first run must be honest nulls: %+v %v", p, err)
	}
	b, _ := json.Marshal(p)
	for _, want := range []string{`"tier":null`, `"five_hour":null`, `"seven_day":null`, `"model":null`, `"context_window":null`, `"prompt_cache":null`, `"note":"Mark 1 never reads`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("plan JSON lacks %s: %s", want, b)
		}
	}
	lines := `{"received_at":1758240000,"rate_limits":{"five_hour":{"used_percentage":10,"resets_at":1758250000}},"model":{"id":"claude-opus-5"},"context_window":null,"prompt_cache":null}
{"received_at":1758243600,"rate_limits":{"five_hour":{"used_percentage":23.5,"resets_at":1758250000},"seven_day":{"used_percentage":41.2,"resets_at":1758700000}},"model":{"id":"claude-opus-5","display_name":"Opus"},"context_window":{"used_percentage":8},"prompt_cache":{"warm":true}}
`
	if err := os.MkdirAll(filepath.Dir(RateLimitsPath(state)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(RateLimitsPath(state), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err = ReadPlan(home, state)
	if err != nil || p.Source != "statusline" || p.Windows.FiveHour == nil || p.Windows.SevenDay == nil {
		t.Fatalf("plan: %+v %v", p, err)
	}
	if p.Windows.FiveHour.UsedPercentage != 23.5 || p.Windows.FiveHour.ResetsAt != "2025-09-19T02:46:40Z" || p.Windows.FiveHour.ObservedAt != "2025-09-19T01:00:00Z" {
		t.Fatalf("five_hour: %+v", p.Windows.FiveHour)
	}
	if *p.Model != "claude-opus-5" || string(p.ContextWindow) != `{"used_percentage":8}` || string(p.PromptCache) != `{"warm":true}` {
		t.Fatalf("model/context/cache: %v %s %s", *p.Model, p.ContextWindow, p.PromptCache)
	}
}
