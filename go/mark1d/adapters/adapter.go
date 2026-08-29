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

// Tail is the transcript-capture lifecycle an adapter exposes when its Usage
// source is transcripts (claudecode in the subscription regime, 08 §5.1).
// Run blocks until ctx ends, then drains.
type Tail interface {
	Run(ctx context.Context) error
}
