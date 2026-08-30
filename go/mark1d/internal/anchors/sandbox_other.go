//go:build !linux

package anchors

import "context"

// UnavailableSandbox is the non-Linux placeholder for this phase: every run
// is refused. 04 §11.5 assigns macOS sandbox-exec and Windows job objects;
// until those land, refusing beats running unsandboxed (CON-009 — network
// denial is a MUST for every anchor class, so there is no degraded mode
// where anchors run without it).
type UnavailableSandbox struct{}

func NewSandbox(scratchRoot string) *UnavailableSandbox { return &UnavailableSandbox{} }

func (*UnavailableSandbox) FSConfined() bool { return false }

func (*UnavailableSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	return RunResult{}, ErrSandboxUnavailable
}

// MaybeRunHelper is Linux-only re-exec plumbing; a no-op elsewhere so
// cmd/main.go can call it unconditionally.
func MaybeRunHelper() {}
