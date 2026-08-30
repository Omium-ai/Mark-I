package enable

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestEnableNotEnrolled(t *testing.T) {
	env := &cli.Env{StateDir: t.TempDir(), Stdout: os.Stderr, Stderr: os.Stderr}
	err := Run(env, Options{Path: t.TempDir()})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitNotEnrolled {
		t.Fatalf("got %v, want exit 3", err)
	}
}

func TestEnableMissingPathIsUsage(t *testing.T) {
	env, _ := enrolledEnv(t)
	err := Run(env, Options{Path: filepath.Join(t.TempDir(), "nope")})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitUsage {
		t.Fatalf("got %v, want exit 2 (§7.2 path missing)", err)
	}
}

func TestEnableWritesCanonicalAllowList(t *testing.T) {
	env, out := enrolledEnv(t)
	realRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Skip("no symlinks on this platform")
	}
	if err := Run(env, Options{Path: link}); err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	canon, _ := cli.CanonicalPath(realRoot)
	if res.Workspace != canon || !res.Changed {
		t.Fatalf("result %+v, want canonical %s", res, canon)
	}
	ws, err := env.LoadWorkspaces()
	if err != nil || len(ws.Workspaces) != 1 || ws.Workspaces[0].Path != canon {
		t.Fatalf("allow-list %+v %v", ws, err)
	}
	fi, _ := os.Stat(env.WorkspacesPath())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("allow-list mode %o, want 0600", fi.Mode().Perm())
	}
	// The enable window is journaled (§7.2's CoverageTransition record).
	if _, err := os.Stat(env.CoveragePath()); err != nil {
		t.Fatalf("coverage journal: %v", err)
	}
}

func TestEnableIdempotent(t *testing.T) {
	env, out := enrolledEnv(t)
	root := t.TempDir()
	if err := Run(env, Options{Path: root}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := Run(env, Options{Path: root}); err != nil {
		t.Fatal(err)
	}
	var res Result
	json.Unmarshal(out.Bytes(), &res)
	if res.Changed {
		t.Fatal("second enable reported a change; §7.2 requires a silent no-op")
	}
	ws, _ := env.LoadWorkspaces()
	if len(ws.Workspaces) != 1 {
		t.Fatalf("allow-list has %d entries after double enable", len(ws.Workspaces))
	}
}

func TestEnableMark1ignoreOptOut(t *testing.T) {
	env, _ := enrolledEnv(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mark1ignore"), []byte("# opted out\n*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Run(env, Options{Path: root})
	var ee *cli.ExitError
	if !errors.As(err, &ee) || ee.Code != cli.ExitRefused {
		t.Fatalf("got %v, want exit 4 (§7.2 opt-out)", err)
	}
	ws, _ := env.LoadWorkspaces()
	if len(ws.Workspaces) != 0 {
		t.Fatal("opted-out repo still landed in the allow-list")
	}
}
