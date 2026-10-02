package fabric

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

// TestGateReadsTheSessionProfile is FR-SPINE-037 for the gate: Answer's
// ProfileFor reaches the registry, reads Default for a session that declared
// nothing (and when no registry is wired at all), reads the declared profile
// otherwise, and logs each session once.
func TestGateReadsTheSessionProfile(t *testing.T) {
	var log bytes.Buffer
	g := NewGate(stubReader{}, verdict.NewBlocks(), t.TempDir())
	g.Log = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	solo := [16]byte{1}
	if p := g.ProfileFor(solo); p != hostprofile.Default {
		t.Fatalf("no registry: %+v, want Default", p)
	}
	reg := hostprofile.NewRegistry()
	g.Profiles = reg
	if p := g.ProfileFor(solo); p != hostprofile.Default {
		t.Fatalf("unknown session: %+v, want Default", p)
	}
	cem := hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	host := [16]byte{2}
	reg.Set(host, cem)
	if p := g.ProfileFor(host); p != cem {
		t.Fatalf("declared session: %+v, want %+v", p, cem)
	}
	_ = g.ProfileFor(host)
	if n := strings.Count(log.String(), "gate: host profile"); n != 2 {
		t.Fatalf("profile logged %d time(s), want once per session (2 sessions): %s", n, log.String())
	}
	if !strings.Contains(log.String(), "host_id=cem888") || !strings.Contains(log.String(), "arrest_mode=recommend") {
		t.Fatalf("declared profile not in the log: %s", log.String())
	}
}
