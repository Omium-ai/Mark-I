package provision

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// TestApplyReadsTheHostProfile is FR-SPINE-037 for provisioning: the walk
// resolves the session's profile — Default when none was declared — reports
// it on the Result and logs it at debug. It decides nothing on it yet (that
// is Part 3's refusal), so the walk itself is the same walk either way.
func TestApplyReadsTheHostProfile(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	res, err := Apply(Options{Home: home, StateDir: state, Only: []string{"claudecode"}, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	if res.Profile != hostprofile.Default {
		t.Fatalf("no manifest: Result.Profile = %+v, want hostprofile.Default", res.Profile)
	}
	if !strings.Contains(log.String(), "provision: host profile") || !strings.Contains(log.String(), "default=true") {
		t.Fatalf("Default not logged at debug: %s", log.String())
	}

	log.Reset()
	cem := hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	res2, err := Apply(Options{Home: home, StateDir: state, Only: []string{"claudecode"}, Profile: &cem, Log: logger})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Profile != cem {
		t.Fatalf("declared profile not reported: %+v", res2.Profile)
	}
	if !strings.Contains(log.String(), "host_id=cem888") {
		t.Fatalf("declared profile not logged: %s", log.String())
	}
	// No decision changes on the profile in this feature: the walk's
	// outcome is identical with and without it.
	if len(res.Provisioned) != len(res2.Provisioned) || len(res.Refused) != len(res2.Refused) {
		t.Fatalf("the profile changed the walk: %+v vs %+v", res, res2)
	}
}
