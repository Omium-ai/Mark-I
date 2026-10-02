package memory

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// TestMemoryReadsTheSessionProfile is FR-SPINE-037 for memory: record's
// ProfileFor reaches the registry, reads Default for a session that declared
// nothing (and when no registry is wired), reads the declared profile
// otherwise, and logs each session once. Injection itself is untouched in
// this revision; Part 5 selects the sink from OwnsMemory.
func TestMemoryReadsTheSessionProfile(t *testing.T) {
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c, err := New(Config{StateDir: t.TempDir(), Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	solo := [16]byte{1}
	if p := c.ProfileFor(solo); p != hostprofile.Default {
		t.Fatalf("no registry: %+v, want Default", p)
	}
	reg := hostprofile.NewRegistry()
	c.cfg.Profiles = reg
	if p := c.ProfileFor(solo); p != hostprofile.Default {
		t.Fatalf("unknown session: %+v, want Default", p)
	}
	cem := hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	host := [16]byte{2}
	reg.Set(host, cem)
	if p := c.ProfileFor(host); p != cem {
		t.Fatalf("declared session: %+v, want %+v", p, cem)
	}
	_ = c.ProfileFor(host)
	if n := strings.Count(log.String(), "memory: host profile"); n != 2 {
		t.Fatalf("profile logged %d time(s), want once per session: %s", n, log.String())
	}
	if !strings.Contains(log.String(), "owns_memory=true") || !strings.Contains(log.String(), "host_id=cem888") {
		t.Fatalf("declared profile not in the log: %s", log.String())
	}
}
