//go:build unix

package anchors

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeBin drops an executable shell script named `name` into dir that prints
// `version` for any invocation — enough for LookPath + the version sniff.
func fakeBin(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	script := "#!/bin/sh\necho '" + version + "'\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fixtureWorkspace builds a worktree configuring every detector, and a PATH
// dir holding every fake tool. Returns (worktree, binDir).
func fixtureWorkspace(t *testing.T) (string, string) {
	t.Helper()
	wt := t.TempDir()
	writeFixture(t, wt, "pyproject.toml", "[tool.ruff]\nline-length = 100\n")
	writeFixture(t, wt, "tsconfig.json", "{}")
	writeFixture(t, wt, "Cargo.toml", "[package]\nname = \"x\"\n")
	writeFixture(t, wt, "go.mod", "module x\n")
	writeFixture(t, wt, "eslint.config.js", "export default []\n")
	bin := t.TempDir()
	for tool, ver := range map[string]string{
		"ruff": "ruff 0.6.2", "tsc": "Version 5.5.4", "cargo": "cargo 1.80.0",
		"go": "go version go1.25.0 linux/amd64", "eslint": "v9.9.0",
	} {
		fakeBin(t, bin, tool, ver)
	}
	t.Setenv("PATH", bin)
	return wt, bin
}

func TestDeriveFullWorkspace(t *testing.T) {
	wt, bin := fixtureWorkspace(t)
	sb := testSandbox(t)
	got, err := Derive(sb, wt)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cargo-check@cat-1", "eslint@cat-1", "go-vet@cat-1", "ruff@cat-1", "tsc@cat-1"}
	if len(got) != len(want) {
		t.Fatalf("derived %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, e := range got {
		if e.ID != want[i] {
			t.Errorf("entry %d: ID %q, want %q (must be sorted)", i, e.ID, want[i])
		}
		if !filepath.IsAbs(e.Argv[0]) || filepath.Dir(e.Argv[0]) != bin {
			t.Errorf("%s: argv[0] %q not the resolved PATH binary", e.ID, e.Argv[0])
		}
		if len(e.BinaryHash) != 32 {
			t.Errorf("%s: binary hash len %d, want 32", e.ID, len(e.BinaryHash))
		}
		// The sniff runs INSIDE the sandbox and demands write confinement (the
		// binary is unconsented); a kernel without it yields an empty version
		// rather than a pre-consent unsandboxed exec.
		if e.ToolVersion == "" && sb.FSConfined() {
			t.Errorf("%s: version sniff empty", e.ID)
		}
		if e.SideEffect != SideEffectStatic {
			t.Errorf("%s: default catalog must be static-only (FR-VERIFY-003), got %q", e.ID, e.SideEffect)
		}
		// Tools that evaluate repo-supplied code (eslint config JS, build.rs,
		// cgo) must carry the write-confinement precondition; pure parsers
		// (ruff, tsc) must not — over-flagging would refuse them needlessly
		// on Landlock-less kernels.
		wantRepoCode := map[string]bool{
			"cargo-check@cat-1": true, "eslint@cat-1": true, "go-vet@cat-1": true,
			"ruff@cat-1": false, "tsc@cat-1": false,
		}
		if e.ExecsRepoCode != wantRepoCode[e.ID] {
			t.Errorf("%s: ExecsRepoCode = %v, want %v", e.ID, e.ExecsRepoCode, wantRepoCode[e.ID])
		}
	}
}

// TestDeriveNeverExecsOutsideTheSandbox is the property behind doc.go's
// "NOTHING RUNS WITHOUT CONSENT — and 'runs' includes derivation": the version
// sniff execs an UNCONSENTED binary that PATH may have resolved out of a
// freshly cloned repo's node_modules/.bin. The fake tool here touches a marker
// file when it runs; with a sandbox that refuses, that marker must not appear
// and the entry must still derive with an empty ToolVersion.
func TestDeriveNeverExecsOutsideTheSandbox(t *testing.T) {
	wt := t.TempDir()
	writeFixture(t, wt, "pyproject.toml", "[tool.ruff]\n")
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "i-ran")
	script := "#!/bin/sh\ntouch " + marker + "\necho 'ruff 0.6.2'\n"
	if err := os.WriteFile(filepath.Join(bin, "ruff"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	sb := &fakeSandbox{err: ErrSandboxUnavailable}
	got, err := Derive(sb, wt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ToolVersion != "" {
		t.Fatalf("a refused sniff must derive the entry with NO version: %+v", got)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the tool binary executed even though the sandbox refused — pre-consent exec")
	}
	// Whatever the sandbox is asked to run, it is asked with write confinement
	// required: the binary is unconsented, so a kernel that cannot confine it
	// gets no sniff rather than a weaker one (04 §11.5).
	if len(sb.specs) != 1 || !sb.specs[0].RequireFSConfined {
		t.Fatalf("sniff spec %+v did not demand FS confinement", sb.specs)
	}
	if sb.specs[0].Argv[0] != filepath.Join(bin, "ruff") || sb.specs[0].Limits.OutputCap <= 0 {
		t.Fatalf("sniff spec %+v: wrong binary or unbounded output", sb.specs[0])
	}
}

func TestDeriveNegatives(t *testing.T) {
	bin := t.TempDir()
	fakeBin(t, bin, "ruff", "ruff 0.6.2")
	t.Setenv("PATH", bin)

	t.Run("bare pyproject does not derive ruff", func(t *testing.T) {
		wt := t.TempDir()
		writeFixture(t, wt, "pyproject.toml", "[project]\nname = \"x\"\n")
		got, err := Derive(testSandbox(t), wt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("derived %+v from a pyproject that never configured ruff", got)
		}
	})
	t.Run("config present, binary absent", func(t *testing.T) {
		wt := t.TempDir()
		writeFixture(t, wt, "tsconfig.json", "{}")
		got, err := Derive(testSandbox(t), wt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("derived %+v with no tsc on PATH", got)
		}
	})
}

func TestExecHashDriftAxes(t *testing.T) {
	base := CatalogEntry{
		Tool: "ruff", Argv: []string{"/b/ruff", "check", "."},
		BinaryHash: bytes.Repeat([]byte{1}, 32), ToolVersion: "ruff 0.6.2",
	}
	h0 := ExecHash(base)
	for name, mut := range map[string]func(e *CatalogEntry){
		"argv":    func(e *CatalogEntry) { e.Argv = []string{"/b/ruff", "check", "--fix", "."} },
		"binary":  func(e *CatalogEntry) { e.BinaryHash = bytes.Repeat([]byte{2}, 32) },
		"version": func(e *CatalogEntry) { e.ToolVersion = "ruff 0.7.0" },
	} {
		e := base
		e.Argv = append([]string(nil), base.Argv...)
		mut(&e)
		if bytes.Equal(h0, ExecHash(e)) {
			t.Errorf("%s drift did not change the effective-execution hash", name)
		}
	}
	// Length-prefixing: field-boundary shifts must not collide.
	a := base
	a.Argv = []string{"/b/ruff", "checkx", ""}
	b := base
	b.Argv = []string{"/b/ruff", "check", "x"}
	if bytes.Equal(ExecHash(a), ExecHash(b)) {
		t.Error("argv boundary shift collided — parts are not length-prefixed")
	}
}

func TestConsentLifecycle(t *testing.T) {
	wt, bin := fixtureWorkspace(t)
	path := ConsentPath(t.TempDir())
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)

	derived, err := Derive(testSandbox(t), wt)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing consented: everything Pending, nothing runnable.
	rep := Reconcile(derived, nil)
	if len(rep.Enabled) != 0 || len(rep.Pending) != len(derived) {
		t.Fatalf("unconsented catalog must be all-Pending: %+v", rep)
	}

	if err := Approve(path, now, derived...); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("consent store must be 0600: %v %v", st.Mode(), err)
	}
	consented, err := LoadConsent(path)
	if err != nil {
		t.Fatal(err)
	}
	rep = Reconcile(derived, consented)
	if len(rep.Enabled) != len(derived) || len(rep.Pending)+len(rep.Drifted)+len(rep.Stale) != 0 {
		t.Fatalf("full consent must enable everything: %+v", rep)
	}
	for _, e := range rep.Enabled {
		if e.ConsentedAt.IsZero() {
			t.Errorf("%s: Enabled entry lost ConsentedAt", e.ID)
		}
	}

	// Drift: swap the ruff binary content — the argv-hash (exec hash) changes,
	// consent for that entry is INVALID until re-consented (04 §2.2).
	fakeBin(t, bin, "ruff", "ruff 0.9.9 TROJAN")
	derived2, err := Derive(testSandbox(t), wt)
	if err != nil {
		t.Fatal(err)
	}
	rep = Reconcile(derived2, consented)
	if len(rep.Drifted) != 1 || rep.Drifted[0].ID != "ruff@cat-1" {
		t.Fatalf("binary swap must drift exactly ruff: %+v", rep.Drifted)
	}
	if len(rep.Enabled) != len(derived)-1 {
		t.Fatalf("drifted entry must be disabled, siblings untouched: %d enabled", len(rep.Enabled))
	}
	for _, e := range rep.Enabled {
		if e.ID == "ruff@cat-1" {
			t.Fatal("drifted entry leaked into Enabled")
		}
	}

	// Re-consent re-enables.
	for _, e := range derived2 {
		if e.ID == "ruff@cat-1" {
			if err := Approve(path, now.Add(time.Hour), e); err != nil {
				t.Fatal(err)
			}
		}
	}
	consented2, err := LoadConsent(path)
	if err != nil {
		t.Fatal(err)
	}
	rep = Reconcile(derived2, consented2)
	if len(rep.Enabled) != len(derived2) || len(rep.Drifted) != 0 {
		t.Fatalf("re-consent must re-enable: %+v", rep)
	}

	// Revoke: back to Pending — shown, never run.
	if err := Revoke(path, "ruff@cat-1"); err != nil {
		t.Fatal(err)
	}
	consented3, _ := LoadConsent(path)
	rep = Reconcile(derived2, consented3)
	if len(rep.Pending) != 1 || rep.Pending[0].ID != "ruff@cat-1" {
		t.Fatalf("revoked entry must be Pending: %+v", rep.Pending)
	}

	// Stale: config gone, consent remains ⇒ doctor shows it, nothing runs it.
	if err := os.Remove(filepath.Join(wt, "tsconfig.json")); err != nil {
		t.Fatal(err)
	}
	derived3, _ := Derive(testSandbox(t), wt)
	rep = Reconcile(derived3, consented3)
	found := false
	for _, r := range rep.Stale {
		if r.ID == "tsc@cat-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("consented-but-underivable entry must be Stale: %+v", rep.Stale)
	}
}

func TestLoadConsentCorruptIsError(t *testing.T) {
	dir := t.TempDir()
	path := ConsentPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConsent(path); err == nil {
		t.Fatal("corrupt consent store must error, never read as consented or empty")
	}
	if err := os.WriteFile(path, []byte(`{"version":9,"entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConsent(path); err == nil {
		t.Fatal("unknown consent-store version must error")
	}
}

// testSandbox is the REAL sandbox, used wherever a test derives a catalog:
// derivation's version sniff execs an unconsented binary and must go through it
// (catalog.go Derive). It lives here rather than in main_test.go because every
// caller is unix-tagged, and main_test.go builds on every GOOS for TestMain.
func testSandbox(t *testing.T) Sandbox {
	t.Helper()
	return NewSandbox(t.TempDir())
}
