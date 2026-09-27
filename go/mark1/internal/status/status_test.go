package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	if err := os.WriteFile(filepath.Join(env.QuarantineDir(), "last-sweep.json"), []byte(`{"swept_at":"2026-09-16T11:00:00Z","deleted":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now = func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })

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
	if rep.Spool.QuarantineRetention != quarantineRetention || !strings.HasPrefix(rep.Spool.QuarantineRetention, "30 d, then deleted with a receipt") {
		t.Fatalf("retention %q: the founder-fixed 30 d window must be stated", rep.Spool.QuarantineRetention)
	}
	if rep.Spool.QuarantineOldestDays != 2 {
		t.Fatalf("oldest %d d, want 2 (batch a at 09-14T10:00 seen at 09-16T12:00; the torn manifest is undated and counts nothing)", rep.Spool.QuarantineOldestDays)
	}
	if s := rep.Spool.QuarantineLastSweep; s == nil || s.SweptAt != "2026-09-16T11:00:00Z" || s.Deleted != 1 {
		t.Fatalf("last sweep %+v, want the daemon's last-sweep.json", s)
	}

	var human bytes.Buffer
	renderHuman(&human, &rep)
	for _, want := range []string{
		"quarantined: 3",
		a + " parked 2026-09-14T10:00:00.123456789Z, 512 bytes, 3 events — reason: HTTP 400 M1E-2001",
		b + " parked 2026-09-14T11:00:00Z, 64 bytes, 1 events — reason: HTTP 409 M1E-2003 M1E-2003: batch_id landed",
		torn + " parked , 8 bytes, 0 events — reason: manifest unreadable: ",
		"quarantine    3 batches, oldest 2 d, retention 30 d, last sweep 2026-09-16T11:00:00Z deleted 1 (receipted)",
	} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("human render lacks %q:\n%s", want, human.String())
		}
	}
}

// TestStatusQuarantineSummaryBeforeAnySweep: no batches and no sweep record still state the window, claim no age and
// no sweep.
func TestStatusQuarantineSummaryBeforeAnySweep(t *testing.T) {
	env, out := enrolledEnv(t)
	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Spool.Quarantined != 0 || rep.Spool.QuarantineOldestDays != 0 || rep.Spool.QuarantineLastSweep != nil || rep.Spool.QuarantineRetention != quarantineRetention {
		t.Fatalf("spool %+v", rep.Spool)
	}
	var human bytes.Buffer
	renderHuman(&human, &rep)
	if !strings.Contains(human.String(), "quarantine    0 batches, retention 30 d, last sweep: none recorded\n") {
		t.Fatalf("human render:\n%s", human.String())
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

// Both reward models appear with their own state, so a down RM-B is named while RM-A keeps scoring.
func TestStatusShowsEachRewardModel(t *testing.T) {
	env, out := enrolledEnv(t)
	sock := filepath.Join(t.TempDir(), "no.sock")
	env.JSON = false
	if err := Run(env, Options{Socket: sock}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "reward model  not started") {
		t.Fatalf("no status file must read as not started:\n%s", out.String())
	}
	body := `{"state":"failed","model_id":"rm:mark1-rm-a@1,rm:mark1-rm-b@1","detail":"x","models":[` +
		`{"model_id":"rm:mark1-rm-a@1","state":"ready","detail":"scores after each task close"},` +
		`{"model_id":"rm:mark1-rm-b@1","state":"failed","detail":"runtime crash-looped"}],"rm_backlog":3}`
	if err := os.MkdirAll(filepath.Join(env.StateDir, "rm"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.StateDir, "rm", "status.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(env, Options{Socket: sock}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"reward model  rm:mark1-rm-a@1 ready — scores after each task close", "reward model  rm:mark1-rm-b@1 failed — runtime crash-looped", "reward model  3 finished tasks dropped unscored"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
}

func controlStub(t *testing.T, env *cli.Env, token string, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	if err := cli.WriteFileAtomic(ControlPath(env.StateDir), []byte(`{"port":`+strconv.Itoa(port)+`,"token":"`+token+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, "127.0.0.1:" + strconv.Itoa(port)
}

// TestStatusReadsTheControlAPI: with run/control.json present and the daemon
// answering, the daemon-state section is GET /v1/status — carried verbatim as
// `control`, with daemon.running taken from it — while the CLI-owned sections
// (enrollment, key custody, quarantine, bundle) stay file-derived.
func TestStatusReadsTheControlAPI(t *testing.T) {
	env, out := enrolledEnv(t)
	errOut := &bytes.Buffer{}
	env.Stderr = errOut
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const answer = `{"running":true,"paused":true,"version":"1.2.3","since":"2026-09-16T00:00:00Z","agents_live":[{"agent":"claudecode","session_id":"01","tokens":20}],"projects_enabled":2,"spool":{"bytes":64,"cap":1048576,"hard_stop":false}}`
	hits := 0
	var host string
	_, host = controlStub(t, env, token, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/v1/status" || r.Header.Get("Authorization") != "Bearer "+token || r.Host != host {
			t.Errorf("request %s %s auth=%q host=%q want host %q", r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Host, host)
		}
		if _, origin := r.Header["Origin"]; origin {
			t.Error("a local process sends no Origin")
		}
		_, _ = w.Write([]byte(answer + "\n"))
	})
	if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Report
		Control json.RawMessage `json:"control"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout %q: %v", out.String(), err)
	}
	if string(rep.Control) != answer || hits != 1 {
		t.Fatalf("control must be the daemon's bytes verbatim: %s (hits %d)", rep.Control, hits)
	}
	if !rep.Daemon.Running || rep.Daemon.Control != host || rep.Daemon.Socket != "" {
		t.Fatalf("daemon %+v must come from the API, not the socket probe", rep.Daemon)
	}
	if rep.Enrollment == nil || rep.Enrollment.DeviceID != "dev-1" || rep.KeyCustody.Tier == "" {
		t.Fatalf("CLI-owned sections must survive: %s", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("no notice on the live path: %q", errOut.String())
	}

	env.JSON = false
	out.Reset()
	if err := Run(env, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mark1d        running (control 127.0.0.1:", "version 1.2.3", "paused        YES", "projects      2 enabled", "spool         64 bytes of 1048576 cap", "claudecode session 01, 20 tokens", "enrollment    active device dev-1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("human output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "(socket ") {
		t.Fatalf("live path must not print the socket probe line:\n%s", out.String())
	}
}

// TestStatusFallsBackToFiles: control.json absent, stale (dead port), or
// refused — each falls back to the file read with one notice on stderr.
func TestStatusFallsBackToFiles(t *testing.T) {
	env, out := enrolledEnv(t)
	errOut := &bytes.Buffer{}
	env.Stderr = errOut
	run := func() Report {
		t.Helper()
		out.Reset()
		errOut.Reset()
		if err := Run(env, Options{Socket: filepath.Join(t.TempDir(), "no.sock")}); err != nil {
			t.Fatal(err)
		}
		var rep Report
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatalf("stdout not the file report: %v: %s", err, out.String())
		}
		if !strings.Contains(errOut.String(), "reading daemon state from files") || strings.Count(errOut.String(), "\n") != 1 {
			t.Fatalf("want one notice line, got %q", errOut.String())
		}
		return rep
	}
	if rep := run(); rep.Enrollment.DeviceID != "dev-1" || rep.Daemon.Running || rep.Daemon.Socket == "" || rep.Daemon.Control != "" {
		t.Fatalf("absent control.json: %+v", rep)
	}
	if !strings.Contains(errOut.String(), "no run/control.json") {
		t.Fatalf("notice names the cause: %q", errOut.String())
	}

	srv, _ := controlStub(t, env, "tok", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv.Close()
	run()
	if !strings.Contains(errOut.String(), "connection refused") && !strings.Contains(errOut.String(), "connect") {
		t.Fatalf("stale control.json: %q", errOut.String())
	}

	controlStub(t, env, "tok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"M1E-1002","message":"missing or wrong control bearer token"}}`))
	})
	run()
	if !strings.Contains(errOut.String(), "HTTP 401 M1E-1002") {
		t.Fatalf("refused bearer: %q", errOut.String())
	}

	if err := os.Chmod(ControlPath(env.StateDir), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		run()
		if !strings.Contains(errOut.String(), "must be 0600") {
			t.Fatalf("world-readable token file: %q", errOut.String())
		}
	}
}
