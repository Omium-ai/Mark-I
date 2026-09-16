// Package adapters declares 04 §2.10's one interface over seven agents.
// Rules binding on every implementation (08 §5): field maps live in
// agent_maps bundle data, never code; a sniffed version with no map goes
// inert with Dropped{UNSUPPORTED_AGENT_VERSION} + a coverage bypass — never
// a guessed field; a slot opens only when its spike fixture lands in
// conformance/.
package adapters

import "context"

// Regime drives proxy eligibility: the subscription regime never touches the
// proxy binary (04 §3); only API-key traffic is guard-eligible.
type Regime int

const (
	RegimeSubscription Regime = iota
	RegimeAPIKey
)

type Detection struct {
	Installed bool
	Version   string // runtime-sniffed; selects the agent_maps field map
	Regime    Regime
}

// Workspace is one `mark1 enable`d root.
type Workspace struct {
	Root string
}

// Maps is the agent_maps PolicyBundle section, opaque here: the typed decode
// is internal/policy's row (04 §2.6), and adapters must keep working across
// a field-rename bundle push with no binary change (FR-AGENT-001).
type Maps []byte

// CaptureSurface names one thing an adapter captures from: hook
// registration, transcript globs, artifact dirs (04 §2.10).
type CaptureSurface struct {
	Kind string // "hooks" | "transcripts" | "artifacts"
	Path string // glob or directory, workspace-resolved
}

type Adapter interface {
	Name() string
	Detect() (Detection, error)
	// Provision registers capture via 08 §8 fenced config fragments ONLY.
	Provision(ws Workspace, m Maps) error
	Surfaces() []CaptureSurface
}

// Slot is one row of the adapter registry 08 §5 enumerates.
type Slot struct {
	Name string
	// Mechanism is 08 §8's A (owned file) or B (fenced fragment) — and is set
	// ONLY where code exists. 08 §8 says which mechanism an agent uses is
	// agent_maps bundle data; hard-coding a guess for a slot whose config
	// location is still `UNVERIFIED — spike gates this adapter slot` is exactly
	// the invented field map the package rules forbid, so those rows say so.
	Mechanism string
	// Implemented is whether provisioning this agent does anything at all.
	Implemented bool
	Phase       string // 08 §5's phase, so "not yet" carries a when
}

// Roster is the seven slots of 08 §5, in section order, and the honest state
// of each. `mark1 doctor` prints the whole list: a user of codex or cursor
// should learn Mark 1 does nothing for their agent from the tool, not from
// silence followed by a missing receipt.
var Roster = []Slot{
	{"claudecode", "B", true, "1"}, // strict-JSON settings, no include mechanism
	{"codex", "A/B", true, "2"},    // hooks.json: owned file when absent, fenced entries when present
	{"gemini", "B", true, "3"},     // ~/.gemini/settings.json: fenced entries; MARK1_AGENT rides the hook entry's env
	{"opencode", "A", true, "4"},   // $XDG_CONFIG_HOME/opencode/plugins/mark1.js: owned plugin; usage via its own capture JSONL
	{"copilot", "A", true, "5"},    // $COPILOT_HOME/hooks/mark1.json: owned file; events.jsonl is DIAGNOSTIC-class, Usage rides the BYOK wire path
	{"cursor", "A/B", true, "5"},   // ~/.cursor/hooks.json: owned when absent, fenced when present; hooks only, the wire proxy is a permanent NO-GO
	{"crush", "", false, "roadmap"},
}

// Tail is the transcript-capture lifecycle an adapter exposes when its Usage
// source is transcripts (claudecode in the subscription regime, 08 §5.1).
// Run blocks until ctx ends, then drains.
type Tail interface {
	Run(ctx context.Context) error
}
