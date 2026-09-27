package provision

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/codex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/copilot"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/cursor"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/gemini"
	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/opencode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/off"
)

// oldShim stands in for an earlier release: its fragment differs from this build's only in bytes Mark 1 owns.
const oldShim = "~/.omium/mark1/bin-old/mark1-hookshim"

type fixture struct {
	state   string
	targets map[string]string
}

// provisioned plants all six capture fragments as the release using shim wrote them, each beside a user file where the mechanism allows one.
func provisioned(t *testing.T, shim string) fixture {
	t.Helper()
	t.Setenv("MARK1_DISABLE", "")
	root := t.TempDir()
	f := fixture{state: filepath.Join(root, "state"), targets: map[string]string{
		"claudecode": filepath.Join(root, "claude", "settings.json"),
		"codex":      filepath.Join(root, "codex", "hooks.json"),
		"gemini":     filepath.Join(root, "gemini", "settings.json"),
		"opencode":   filepath.Join(root, "opencode", "plugins", "mark1.js"),
		"copilot":    filepath.Join(root, "copilot", "hooks", "mark1.json"),
		"cursor":     filepath.Join(root, "cursor", "hooks.json"),
	}}
	for _, d := range []string{"claude", "codex", "gemini", "opencode", "copilot", "cursor"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, f.targets["claudecode"], `{"model": "opus"}`)
	write(t, f.targets["gemini"], `{"theme": "Dracula"}`)
	apply := map[string]func(target, state, shim string) error{
		"claudecode": func(a, b, c string) error { _, err := claudecode.ApplyFragment(a, b, c); return err },
		"codex":      func(a, b, c string) error { _, err := codex.ApplyFragment(a, b, c); return err },
		"gemini":     func(a, b, c string) error { _, err := gemini.ApplyFragment(a, b, c); return err },
		"opencode":   func(a, b, c string) error { _, err := opencode.ApplyFragment(a, b, c); return err },
		"copilot":    func(a, b, c string) error { _, err := copilot.ApplyFragment(a, b, c); return err },
		"cursor":     func(a, b, c string) error { _, err := cursor.ApplyFragment(a, b, c); return err },
	}
	for name, fn := range apply {
		if err := fn(f.targets[name], f.state, shim); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return f
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func actions(out []Outcome) map[string]Outcome {
	m := map[string]Outcome{}
	for _, o := range out {
		m[o.Agent] = o
	}
	return m
}

func TestReconcileUpgradesStaleFragments(t *testing.T) {
	f := provisioned(t, oldShim)
	cc := f.targets["claudecode"]
	edited := strings.Replace(read(t, cc), `"model": "opus"`, `"model": "sonnet"`, 1)
	if !strings.Contains(edited, `"sonnet"`) {
		t.Fatal("fixture: user key not found in settings.json")
	}
	write(t, cc, edited)

	got := actions(Reconcile(f.state, "9.9.9"))
	if len(got) != len(Names) {
		t.Fatalf("every provisioned agent is reconciled: %v", got)
	}
	for name, target := range f.targets {
		if got[name].Action != "upgraded" {
			t.Errorf("%s: %+v, want upgraded", name, got[name])
		}
		body := read(t, target)
		if strings.Contains(body, "bin-old") || !strings.Contains(body, "mark1/bin/mark1-hookshim") {
			t.Errorf("%s still carries the old release's fragment:\n%s", name, body)
		}
		if s, err := ReadStamp(f.state, name); err != nil || s.Version != "9.9.9" {
			t.Errorf("%s: stamp %+v %v", name, s, err)
		}
	}
	if !strings.Contains(read(t, cc), `"model": "sonnet"`) || !strings.Contains(read(t, f.targets["gemini"]), `"theme": "Dracula"`) {
		t.Error("the user's own keys outside the fence must survive the upgrade")
	}
	if st, _ := claudecode.Inspect(f.state); st.State != claudecode.StateOK {
		t.Errorf("claudecode after upgrade: %+v", st)
	}

	before := map[string]string{}
	for name, target := range f.targets {
		before[name] = read(t, target)
	}
	for name, o := range actions(Reconcile(f.state, "9.9.9")) {
		if o.Action != "current" || read(t, f.targets[name]) != before[name] {
			t.Errorf("%s: a second start must be a no-op: %+v", name, o)
		}
	}
}

func TestReconcileLeavesCurrentUntouched(t *testing.T) {
	f := provisioned(t, "")
	type snap struct {
		body []byte
		mod  int64
	}
	before := map[string]snap{}
	for name, target := range f.targets {
		fi, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(target)
		before[name] = snap{b, fi.ModTime().UnixNano()}
	}
	for name, o := range actions(Reconcile(f.state, "1.0.0")) {
		fi, _ := os.Stat(f.targets[name])
		b, _ := os.ReadFile(f.targets[name])
		if o.Action != "current" || !bytes.Equal(b, before[name].body) || fi.ModTime().UnixNano() != before[name].mod {
			t.Errorf("%s: a current fragment is never opened for write: %+v", name, o)
		}
		if s, _ := ReadStamp(f.state, name); s.Version != "1.0.0" {
			t.Errorf("%s: a verified-current fragment is stamped with the running release: %+v", name, s)
		}
	}
}

func TestReconcileRefusesHandEditedFence(t *testing.T) {
	f := provisioned(t, oldShim)
	for _, target := range f.targets {
		write(t, target, strings.ReplaceAll(read(t, target), "bin-old", "bin-mine"))
	}
	got := actions(Reconcile(f.state, "9.9.9"))
	for name, target := range f.targets {
		if got[name].Action != "refused" || got[name].Code != claudecode.CodeDamaged {
			t.Errorf("%s: %+v, want refused %s", name, got[name], claudecode.CodeDamaged)
		}
		if !strings.Contains(read(t, target), "bin-mine") {
			t.Errorf("%s: a hand edit inside the fence was clobbered", name)
		}
		if _, err := ReadStamp(f.state, name); err == nil {
			t.Errorf("%s: a refused fragment must not be stamped", name)
		}
	}
}

func TestReconcileRespectsOffPausedRevertedAndRemoved(t *testing.T) {
	f := provisioned(t, oldShim)
	unchanged := func(name string) {
		t.Helper()
		if !strings.Contains(read(t, f.targets[name]), "bin-old") {
			t.Errorf("%s was rewritten", name)
		}
	}

	write(t, off.Marker(f.state), "{}")
	if out := Reconcile(f.state, "9.9.9"); out != nil {
		t.Fatalf("Mark 1 off: nothing is touched, got %v", out)
	}
	for name := range f.targets {
		unchanged(name)
	}
	if err := os.Remove(off.Marker(f.state)); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(off.AgentMarker(f.state, "opencode")), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, off.AgentMarker(f.state, "opencode"), "")
	if err := WriteStamp(f.state, "codex", "0.1.0", "blake3:00"); err != nil {
		t.Fatal(err)
	}
	if done, _ := Revert(f.state, "codex"); len(done) != 1 {
		t.Fatalf("codex revert: %v", done)
	}
	if err := os.Remove(f.targets["cursor"]); err != nil {
		t.Fatal(err)
	}

	got := actions(Reconcile(f.state, "9.9.9"))
	if o := got["opencode"]; o.Action != "paused" {
		t.Errorf("opencode paused: %+v", o)
	}
	unchanged("opencode")
	if o, ok := got["codex"]; ok {
		t.Errorf("a reverted agent is not reconciled: %+v", o)
	}
	if _, err := os.Stat(f.targets["codex"]); !os.IsNotExist(err) {
		t.Errorf("a reverted agent's file must not come back: %v", err)
	}
	if o := got["cursor"]; o.Action != "missing" {
		t.Errorf("cursor removed by the user: %+v", o)
	}
	if _, err := os.Stat(f.targets["cursor"]); !os.IsNotExist(err) {
		t.Errorf("a file the user deleted must not be recreated: %v", err)
	}
	for _, name := range []string{"claudecode", "gemini", "copilot"} {
		if got[name].Action != "upgraded" {
			t.Errorf("%s: %+v", name, got[name])
		}
	}
	if _, err := ReadStamp(f.state, "codex"); err == nil {
		t.Error("a reverted agent reports no provisioned release")
	}
}
