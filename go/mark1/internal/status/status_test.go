package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
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
	os.WriteFile(filepath.Join(env.SpoolDir(), "seg-0000000000000001.m1s"), make([]byte, 64), 0o600)
	os.WriteFile(filepath.Join(env.SpoolDir(), "seg-0000000000000002.m1s"), make([]byte, 32), 0o600)
	// OFF marker active.
	if err := cli.WriteFileAtomic(env.OffMarkerPath(), []byte(`{"scope":"all"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A live daemon socket.
	sockDir, _ := os.MkdirTemp("", "m1")
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
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
	json.Unmarshal(out.Bytes(), &rep)
	if rep.Bundle == nil || rep.Bundle.Seq != 483 || !rep.Bundle.Stale {
		t.Fatalf("bundle %+v (age 20m > max_age 10m must be stale — M1E-3006 surface)", rep.Bundle)
	}
}
