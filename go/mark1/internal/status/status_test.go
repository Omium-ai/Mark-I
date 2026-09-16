package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1/internal/cli"
)

func enrolledEnv(t *testing.T) (*cli.Env, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	env := &cli.Env{StateDir: t.TempDir(), JSON: true, Stdout: out, Stderr: os.Stderr}
	if err := env.SaveEnrollment(&cli.Enrollment{
		Version: 1, State: "active", DeviceID: "dev-1", TenantID: "ten-1",
		DeviceToken: "tok", TokenExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return env, out
}

func TestStatusNotEnrolled(t *testing.T) {
	env := &cli.Env{StateDir: t.TempDir(), Stdout: os.Stderr, Stderr: os.Stderr}
	err := Run(env, Options{})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled {
		t.Fatalf("got %v, want exit 3", err)
	}
}

// TestStatusAnswersDegraded: §7.3 — status exits 0 even with no daemon, no
// workspaces, no bundle; the surface is honest about each absence.
func TestStatusAnswersDegraded(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout not one JSON object: %v", err)
	}
	if !rep.OK || rep.Daemon.Running || rep.Bundle != nil || rep.Off.Active {
		t.Fatalf("report %+v", rep)
	}
	if rep.Enrollment.DeviceID != "dev-1" || !rep.Enrollment.TokenFresh {
		t.Fatalf("enrollment %+v", rep.Enrollment)
	}
}

func TestStatusReadsLiveSurfaces(t *testing.T) {
	env, out := enrolledEnv(t)

	// Enabled workspace in the allow-list.
	ws, _ := env.LoadWorkspaces()
	ws.Workspaces = append(ws.Workspaces, cli.WorkspaceEntry{Path: "/w/api", EnabledAt: time.Now()})
	if err := env.SaveWorkspaces(ws); err != nil {
		t.Fatal(err)
	}
	// Spool segments on disk (mark1d's seg-*.m1s naming, 07 §6).
	if err := os.MkdirAll(env.SpoolDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{"seg-0000000000000001.m1s": 64, "seg-0000000000000002.m1s": 32} {
		if err := os.WriteFile(filepath.Join(env.SpoolDir(), name), make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// OFF marker active.
	if err := cli.WriteFileAtomic(env.OffMarkerPath(), []byte(`{"scope":"all"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A live daemon socket.
	sockDir, _ := os.MkdirTemp("", "m1")
	defer func() { _ = os.RemoveAll(sockDir) }()
	sock := filepath.Join(sockDir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	if err := Run(env, Options{Socket: sock}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Daemon.Running {
		t.Fatal("daemon not reported running")
	}
	if len(rep.Workspaces) != 1 || rep.Workspaces[0].Path != "/w/api" {
		t.Fatalf("workspaces %+v", rep.Workspaces)
	}
	if rep.Spool.Segments != 2 || rep.Spool.Bytes != 96 {
		t.Fatalf("spool %+v", rep.Spool)
	}
	if !rep.Off.Active || rep.Off.Scope != "all" {
		t.Fatalf("off %+v", rep.Off)
	}
}

// TestStatusShowsKeyCustodyDegradation: NFR-PORTABILITY-004 — the ladder may
// fall to the 0600 file floor, it may not fall quietly. Asserted on the HUMAN
// render as well as the JSON, because "visible in `mark1 status`" means the
// output an operator actually reads, not a field only --json consumers see.
func TestStatusShowsKeyCustodyDegradation(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := os.WriteFile(env.DeviceKeyPath(), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	tier, degradation := cli.KeyCustody()
	if rep.KeyCustody.Tier != tier || !rep.KeyCustody.Present {
		t.Fatalf("key custody %+v, want tier %q present", rep.KeyCustody, tier)
	}
	if rep.KeyCustody.Reason != degradation || rep.KeyCustody.Degraded != (degradation != "") {
		t.Fatalf("degradation must be reported verbatim: %+v", rep.KeyCustody)
	}
	if !rep.KeyCustody.Degraded {
		t.Fatal("cli.KeyCustody reports no degradation — a rung above the floor has landed, so this test must be rewritten to assert the new rung, not deleted")
	}

	var human bytes.Buffer
	renderHuman(&human, &rep)
	if !strings.Contains(human.String(), "key custody") || !strings.Contains(human.String(), degradation) {
		t.Fatalf("human render hides the custody degradation:\n%s", human.String())
	}
}

// TestStatusKeyCustodyAbsentKey: enrolled with no key on disk is its own broken
// state — the daemon can capture but never attribute — so it must not render as
// a healthy floor.
func TestStatusKeyCustodyAbsentKey(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.KeyCustody.Present {
		t.Fatal("no device.key on disk, but custody reports one present")
	}
	var human bytes.Buffer
	renderHuman(&human, &rep)
	if !strings.Contains(human.String(), "no key stored yet") {
		t.Fatalf("absent device key is invisible:\n%s", human.String())
	}
}

func TestStatusBundleMeta(t *testing.T) {
	env, out := enrolledEnv(t)
	meta := map[string]any{
		"channel": "stable", "seq": 483,
		"applied_at": time.Now().Add(-20 * time.Minute).UTC().Format(time.RFC3339),
		"max_age_s":  600,
	}
	data, _ := json.Marshal(meta)
	if err := cli.WriteFileAtomic(env.BundleMetaPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if rep.Bundle == nil || rep.Bundle.Seq != 483 || !rep.Bundle.Stale {
		t.Fatalf("bundle %+v (age 20m > max_age 10m must be stale — M1E-3006 surface)", rep.Bundle)
	}
}

// TestStatusListsQuarantinedBatches is NFR-OPERABILITY-003: every 4xx-parked
// batch is listed with the reason the daemon recorded and the retention that
// applies, in the JSON and in the text an operator reads. The fixture is the
// daemon's own on-disk format — <id>.m1p.zst.sealed beside <id>.manifest.json
// with uplink's manifest fields (go/mark1d/internal/uplink/quarantine.go:28-36,
// written at :59 and :74).
func TestStatusListsQuarantinedBatches(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := os.MkdirAll(env.QuarantineDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	plant := func(id string, sealed int, manifest string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(env.QuarantineDir(), id+".m1p.zst.sealed"), make([]byte, sealed), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.QuarantineDir(), id+".manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const a, b, torn = "0192a1b2-0000-7000-8000-00000000000a", "0192a1b2-0000-7000-8000-00000000000b", "0192a1b2-0000-7000-8000-00000000000c"
	plant(a, 512, `{
  "batch_id": "`+a+`",
  "status": 400,
  "err_code": "M1E-2001",
  "event_ids": ["e1", "e2", "e3"],
  "event_count": 3,
  "quarantined_at": "2026-09-14T10:00:00.123456789Z"
}`)
	plant(b, 64, `{
  "batch_id": "`+b+`",
  "status": 409,
  "err_code": "M1E-2003",
  "event_ids": ["e4"],
  "event_count": 1,
  "quarantined_at": "2026-09-14T11:00:00Z",
  "note": "M1E-2003: batch_id landed with different bytes — local spool corruption suspected"
}`)
	plant(torn, 8, `{"batch_id": "`+torn+`", "status": 4`) // crash mid-write

	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if rep.Spool.Quarantined != 3 || len(rep.Spool.Quarantine) != 3 {
		t.Fatalf("quarantined=%d, listed=%d, want 3 batches (not 6 files): %+v", rep.Spool.Quarantined, len(rep.Spool.Quarantine), rep.Spool.Quarantine)
	}
	byID := map[string]Quarantined{}
	for _, q := range rep.Spool.Quarantine {
		byID[q.BatchID] = q
	}
	if q := byID[a]; q.Status != 400 || q.ErrCode != "M1E-2001" || q.Bytes != 512 || q.Events != 3 ||
		q.QuarantinedAt != "2026-09-14T10:00:00.123456789Z" || q.Reason != "HTTP 400 M1E-2001" {
		t.Fatalf("batch a: %+v", q)
	}
	if q := byID[b]; q.Status != 409 || q.Bytes != 64 || !strings.HasPrefix(q.Reason, "HTTP 409 M1E-2003 ") || !strings.Contains(q.Reason, "spool corruption") {
		t.Fatalf("batch b: %+v", q)
	}
	if q := byID[torn]; q.Bytes != 8 || !strings.HasPrefix(q.Reason, "manifest unreadable: ") {
		t.Fatalf("torn manifest must be listed, not hidden: %+v", q)
	}
	if rep.Spool.QuarantineRetention != quarantineRetention || !strings.HasPrefix(rep.Spool.QuarantineRetention, "none") {
		t.Fatalf("retention %q: no window exists anywhere, none may be claimed", rep.Spool.QuarantineRetention)
	}

	var human bytes.Buffer
	renderHuman(&human, &rep)
	for _, want := range []string{
		"quarantined: 3",
		a + " parked 2026-09-14T10:00:00.123456789Z, 512 bytes, 3 events — reason: HTTP 400 M1E-2001",
		b + " parked 2026-09-14T11:00:00Z, 64 bytes, 1 events — reason: HTTP 409 M1E-2003 M1E-2003: batch_id landed",
		torn + " parked , 8 bytes, 0 events — reason: manifest unreadable: ",
		"retention: none — kept until removed by an operator",
	} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("human render lacks %q:\n%s", want, human.String())
		}
	}
}

// TestStatusShowsStopGatePosture: FR-POLICY-006's opt-in is visible where an
// operator reads — opted_in with the artifact's ts/user, not_opted_in when the
// file is absent, and (exactly as mark1d's optedIn reads it) when it is
// garbage or says false.
func TestStatusShowsStopGatePosture(t *testing.T) {
	env, out := enrolledEnv(t)
	sock := filepath.Join(t.TempDir(), "no.sock")
	report := func() Report {
		t.Helper()
		out.Reset()
		if err := Run(env, Options{Socket: sock}); err != nil {
			t.Fatal(err)
		}
		var rep Report
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	if rep := report(); rep.StopGate.State != "not_opted_in" || rep.StopGate.TS != "" {
		t.Fatalf("absent artifact reported %+v", rep.StopGate)
	}
	if err := env.WriteStopGateOptIn("2026-09-15T00:00:00Z", "alice"); err != nil {
		t.Fatal(err)
	}
	rep := report()
	if rep.StopGate.State != "opted_in" || rep.StopGate.TS != "2026-09-15T00:00:00Z" || rep.StopGate.User != "alice" {
		t.Fatalf("opted-in artifact reported %+v", rep.StopGate)
	}
	env.JSON = false
	out.Reset()
	if err := Run(env, Options{Socket: sock}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stop gate     opted_in (by alice at 2026-09-15T00:00:00Z)") {
		t.Fatalf("human output must state the posture:\n%s", out.String())
	}
	env.JSON = true
	for _, body := range []string{`{"stop_gate":false}`, `not json`} {
		if err := os.WriteFile(env.StopGateOptInPath(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if rep := report(); rep.StopGate.State != "not_opted_in" {
			t.Fatalf("artifact %q reported %+v; the daemon would not arm on it", body, rep.StopGate)
		}
	}
}
