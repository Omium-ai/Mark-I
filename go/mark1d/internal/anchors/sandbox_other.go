//go:build !linux && !darwin && !windows

package anchors

import (
	"context"
	"fmt"
	"runtime"
)

// UnavailableSandbox is the placeholder for platforms without a sandbox yet:
// every run is refused. 04 §11.5 assigns Windows job objects + AppContainer;
// until that lands, refusing beats running unsandboxed (CON-009 — network
// denial is a MUST for every anchor class, so there is no degraded mode
// where anchors run without it).
type UnavailableSandbox struct{}

func NewSandbox(scratchRoot string) *UnavailableSandbox { return &UnavailableSandbox{} }

func (*UnavailableSandbox) FSConfined() bool { return false }

func (*UnavailableSandbox) Status() SandboxStatus {
	return SandboxStatus{Reason: fmt.Sprintf("no sandbox on %s yet (04 §11.5)", runtime.GOOS)}
}

func (*UnavailableSandbox) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	return RunResult{}, fmt.Errorf("%w: no sandbox on %s yet (04 §11.5)", ErrSandboxUnavailable, runtime.GOOS)
}

// MaybeRunHelper is linux/darwin re-exec plumbing; a no-op elsewhere so
// cmd/main.go can call it unconditionally.
func MaybeRunHelper() {}
