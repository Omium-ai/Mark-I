// The daemon→proxy-supervisor hand-off (FR-SPINE-026). superviseProxy is the
// only caller of supervise.ProxyChild in the estate, and internal/supervise's
// own tests supply the ProxyConfig they assert on — so every field the daemon
// fills is proven on the callee side and nowhere on the caller side.
package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TestProxyChildReceivesTheCoverageEmitter pins ProxyConfig.Coverage at the one
// place it is populated. ProxyConfig documents nil Coverage as a tolerated
// degradation, so a refactor that dropped the field would compile, supervise,
// and still revert the base-URL fragment on FAILED — the only lost behaviour is
// the bypass-window receipt, and an unreceipted bypass window reads downstream
// as full coverage. That is coverage we would bill for and did not have.
//
// It reads proxyChildConfig, the function superviseProxy actually calls, rather
// than rebuilding the struct: a test that constructs its own ProxyConfig would
// stay green through the deletion it exists to catch.
func TestProxyChildReceivesTheCoverageEmitter(t *testing.T) {
	// A live emitter, not a bare &coverage.Emitter{}: coverage.New returns nil
	// for a nil admit func, so a broken fixture here would look like the defect.
	cov := coverage.New(func(context.Context, *m1pv1.Event) error { return nil }, nil)
	if cov == nil {
		t.Fatal("fixture: coverage.New returned nil, so this test could not tell a wired emitter from an unwired one")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config{stateDir: t.TempDir()}

	got := proxyChildConfig(cfg, log, cov)

	if got.Coverage != cov {
		t.Errorf("ProxyConfig.Coverage = %p, want the daemon's emitter %p — the proxy's FAILED arm cannot receipt the bypass window it opens, and the gap reads downstream as full coverage",
			got.Coverage, cov)
	}
	// Positive control: the other two fields the daemon fills. If these are also
	// wrong the failure above is a hand-off that broke wholesale, not the
	// Coverage field specifically.
	if got.StateDir != cfg.stateDir {
		t.Errorf("ProxyConfig.StateDir = %q, want %q — the proxy's HOME is derived from this, so it would publish proxy.port where nothing looks", got.StateDir, cfg.stateDir)
	}
	if got.Log != log {
		t.Errorf("ProxyConfig.Log = %p, want the daemon's logger %p — the supervisor's diagnostics would go to a default stderr handler", got.Log, log)
	}
}
