package anchors

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// canonTemp is t.TempDir() with symlinks resolved: the catalog resolves argv[0] through
// EvalSymlinks (FR-VERIFY-004), macOS's /var/folders is itself a symlink to /private/var, and
// windows' %TEMP% may be an 8.3 short name.
func canonTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// binName is the file LookPath resolves `name` to: bare on unix, an .exe on windows (PATHEXT).
func binName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// fakeBin drops an executable named `name` into dir that prints `version` for
// any invocation — a sh script on unix; on windows a byte copy of this test
// binary (an AppContainer cannot run a batch file; a hard link would share the
// running image, which Windows lets nobody rewrite or delete) beside a
// `<name>.exe.version` sidecar that TestMain prints — enough for LookPath +
// the version sniff.
func fakeBin(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, binName(name))
	if runtime.GOOS == "windows" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p+versionSidecar, []byte(version+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
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
	wt := canonTemp(t)
	writeFixture(t, wt, "pyproject.toml", "[tool.ruff]\nline-length = 100\n")
	writeFixture(t, wt, "tsconfig.json", "{}")
	writeFixture(t, wt, "Cargo.toml", "[package]\nname = \"x\"\n")
	writeFixture(t, wt, "go.mod", "module x\n")
	writeFixture(t, wt, "eslint.config.js", "export default []\n")
	bin := canonTemp(t)
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
			res, err := sb.Run(context.Background(), RunSpec{Argv: append([]string{e.BinaryPath}, detectors[e.Kind].versionArgs...), WorktreeRO: wt,
				Env: map[string]string{"PATH": filepath.Dir(e.BinaryPath), "LANG": "C"}, Limits: DefaultLimits(ClassFast), RequireFSConfined: true})
			t.Errorf("%s: version sniff empty (rerun: err=%v exit=%d signal=%q timed_out=%v dur=%s stdout=%q stderr=%q)", e.ID, err, res.ExitCode, res.Signal, res.TimedOut, res.Duration, res.Stdout, res.Stderr)
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
// file when it runs; with a sandbox that refuses, that marker must not appear,
// and an entry no run could admit either must not publish (it would only ever
// vote VERDICT_ERROR/sandbox_unavailable — candidates.json's sandbox field says why).
func TestDeriveNeverExecsOutsideTheSandbox(t *testing.T) {
	wt := canonTemp(t)
	writeFixture(t, wt, "pyproject.toml", "[tool.ruff]\n")
	bin := canonTemp(t)
	marker := filepath.Join(canonTemp(t), "i-ran")
	if runtime.GOOS == "windows" {
		fakeBin(t, bin, "ruff", "ruff 0.6.2") // the refusing sandbox below never runs it; the marker is the unix script's tell
	} else {
		script := "#!/bin/sh\ntouch " + marker + "\necho 'ruff 0.6.2'\n"
		if err := os.WriteFile(filepath.Join(bin, binName("ruff")), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)

	sb := &fakeSandbox{err: ErrSandboxUnavailable}
	got, err := Derive(sb, wt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("no sandbox floor: nothing can run, so nothing must derive, got %+v", got)
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
	if sb.specs[0].Argv[0] != filepath.Join(bin, binName("ruff")) || sb.specs[0].Limits.OutputCap <= 0 {
		t.Fatalf("sniff spec %+v: wrong binary or unbounded output", sb.specs[0])
	}
}

// TestDeriveWithoutWriteConfinement is the Landlock-less Linux shape: the floor stands, the sniff is refused (unconsented binary, RequireFSConfined), so pure parsers still derive with no version — they run under the remaining caps (doc.go) — while a repo-code executor, which the runner would refuse identically, is dropped.
func TestDeriveWithoutWriteConfinement(t *testing.T) {
	wt := canonTemp(t)
	writeFixture(t, wt, "pyproject.toml", "[tool.ruff]\n")
	writeFixture(t, wt, "eslint.config.js", "export default []\n")
	bin := canonTemp(t)
	fakeBin(t, bin, "ruff", "ruff 0.6.2")
	fakeBin(t, bin, "eslint", "v9.9.0")
	t.Setenv("PATH", bin)

	got, err := Derive(&fakeSandbox{err: ErrSandboxUnavailable, floorUp: true}, wt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ruff@cat-1" || got[0].ToolVersion != "" {
		t.Fatalf("want ruff alone with no version (eslint executes repo code and would refuse at run time), got %+v", got)
	}
}

func TestDeriveNegatives(t *testing.T) {
	bin := canonTemp(t)
	fakeBin(t, bin, "ruff", "ruff 0.6.2")
	t.Setenv("PATH", bin)

	t.Run("bare pyproject does not derive ruff", func(t *testing.T) {
		wt := canonTemp(t)
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
		wt := canonTemp(t)
		writeFixture(t, wt, "tsconfig.json", "{}")
		got, err := Derive(testSandbox(t), wt)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("derived %+v with no tsc on PATH", got)
		}
	})
	t.Run("every miss says what was looked for and why", func(t *testing.T) {
		wt := canonTemp(t)
		writeFixture(t, wt, "tsconfig.json", "{}")
		writeFixture(t, wt, "go.mod", "module x\n")
		d, err := Explain(testSandbox(t), wt)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Entries) != 0 || len(d.Looked) != len(detectors) {
			t.Fatalf("entries %d, looked %d of %d kinds", len(d.Entries), len(d.Looked), len(detectors))
		}
		why := map[string]string{}
		for _, m := range d.Looked {
			why[m.Tool] = m.Why
		}
		for tool, want := range map[string]string{
			"tsc":     "tsc is not on PATH",
			"go-test": "tests are off for this project",
			"ruff":    "no ruff.toml, .ruff.toml or [tool.ruff] in pyproject.toml",
		} {
			if why[tool] != want {
				t.Errorf("%s: %q, want %q", tool, why[tool], want)
			}
		}
		if _, ok := why["go-vet"]; !ok || why["go-vet"] == "no go.mod" {
			t.Errorf("go-vet with go.mod present: %q", why["go-vet"])
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
	path := ConsentPath(canonTemp(t))
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
	// Mode bits are a unix statement; windows has no 0600 to read back (the store sits under the 0700-equivalent state dir).
	if st, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
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
	dir := canonTemp(t)
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
// (catalog.go Derive).
func testSandbox(t *testing.T) Sandbox {
	t.Helper()
	return NewSandbox(canonTemp(t))
}

// optInTests writes the FR-VERIFY-003 per-repo opt-in into wt.
func optInTests(t *testing.T, wt string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(RepoOptInPath(wt)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(RepoOptInPath(wt), []byte(`{"tests": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDeriveTestRunnersNeedRepoOptIn: test anchors derive only under <workspace>/.mark1/anchors.json {"tests": true}.
func TestDeriveTestRunnersNeedRepoOptIn(t *testing.T) {
	wt, bin := fixtureWorkspace(t)
	writeFixture(t, wt, "pytest.ini", "[pytest]\n")
	writeFixture(t, wt, "package.json", `{"scripts":{"test":"jest"}}`)
	fakeBin(t, bin, "pytest", "pytest 8.3.2")
	fakeBin(t, bin, "npm", "10.8.1")
	sb := testSandbox(t)

	got, err := Derive(sb, wt)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if e.SideEffect == SideEffectTest {
			t.Fatalf("%s derived without the per-repo opt-in", e.ID)
		}
	}

	optInTests(t, wt)
	got, err = Derive(sb, wt)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"cargo-test@cat-1": true, "go-test@cat-1": true, "npm-test@cat-1": true, "pytest@cat-1": true}
	for _, e := range got {
		if e.SideEffect != SideEffectTest {
			continue
		}
		if !want[e.ID] {
			t.Errorf("unexpected test anchor %s", e.ID)
		}
		delete(want, e.ID)
		if e.Class != ClassSlow || !e.ExecsRepoCode {
			t.Errorf("%s: class %q repoCode %v — test anchors are Slow and execute repo code", e.ID, e.Class, e.ExecsRepoCode)
		}
	}
	if len(want) != 0 {
		t.Errorf("test runners not derived: %v", want)
	}
	if TestsOptedIn(canonTemp(t)) {
		t.Error("absent opt-in read as opted in")
	}
}

// TestExecHashSymlinkIndependent: a symlinked PATH derives the real file's BinaryPath and exec hash.
func TestExecHashSymlinkIndependent(t *testing.T) {
	wt := canonTemp(t)
	writeFixture(t, wt, "pyproject.toml", "[tool.ruff]\n")
	real := canonTemp(t)
	target := fakeBin(t, real, "ruff", "ruff 0.6.2")
	links := canonTemp(t)
	if err := os.Symlink(target, filepath.Join(links, binName("ruff"))); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink: %v (SeCreateSymbolicLinkPrivilege or developer mode needed on windows)", err)
		}
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(filepath.Join(links, binName("ruff"))+versionSidecar, []byte("ruff 0.6.2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sb := testSandbox(t)
	derive := func(path string) CatalogEntry {
		t.Helper()
		t.Setenv("PATH", path)
		got, err := Derive(sb, wt)
		if err != nil || len(got) != 1 {
			t.Fatalf("derived %v, %v", got, err)
		}
		return got[0]
	}
	direct, viaLink := derive(real), derive(links)
	if viaLink.BinaryPath != target || viaLink.Argv[0] != target {
		t.Fatalf("symlinked PATH kept the alias: %q / %q, want %q", viaLink.BinaryPath, viaLink.Argv[0], target)
	}
	if !bytes.Equal(ExecHash(direct), ExecHash(viaLink)) {
		t.Fatal("exec hash depends on the PATH alias, not the file that executes")
	}
}

// TestPublishCandidatesCarriesSandboxStatus: the additive sandbox field is what `mark1 doctor` and the app print when a workspace derives nothing.
func TestPublishCandidatesCarriesSandboxStatus(t *testing.T) {
	path := CandidatesPath(canonTemp(t))
	st := SandboxStatus{Available: false, Reason: "no sandbox on plan9 yet (04 §11.5)"}
	if err := PublishCandidates(path, nil, map[string][]CatalogEntry{"/w": {}}, nil, st); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c Candidates
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Sandbox != st || len(c.Workspaces) != 1 || len(c.Workspaces[0].Anchors) != 0 {
		t.Fatalf("published %s", raw)
	}
}

func TestNpmShimTarget(t *testing.T) {
	dir := canonTemp(t)
	script := filepath.Join(dir, "node_modules", "typescript", "bin", "tsc")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Dir(script), "tsc", "#!/usr/bin/env node\n")
	node := fakeBin(t, dir, "node", "v22.0.0")
	for name, body := range map[string]string{
		"new.cmd": "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\n\r\nIF EXIST \"%dp0%\\node.exe\" (\r\n  SET \"_prog=%dp0%\\node.exe\"\r\n) ELSE (\r\n  SET \"_prog=node\"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n)\r\n\r\nendLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\node_modules\\typescript\\bin\\tsc\" %*\r\n",
		"old.cmd": "@IF EXIST \"%~dp0\\node.exe\" (\r\n  \"%~dp0\\node.exe\"  \"%~dp0\\node_modules\\typescript\\bin\\tsc\" %*\r\n) ELSE (\r\n  @SETLOCAL\r\n  @SET PATHEXT=%PATHEXT:;.JS;=;%\r\n  node  \"%~dp0\\node_modules\\typescript\\bin\\tsc\" %*\r\n)\r\n",
	} {
		writeFixture(t, dir, name, body)
		gotNode, gotScript, ok := npmShimTarget(filepath.Join(dir, name))
		if !ok || gotScript != script || (runtime.GOOS == "windows" && gotNode != node) {
			t.Errorf("%s: node=%q script=%q ok=%v (want script %q)", name, gotNode, gotScript, ok, script)
		}
	}
	writeFixture(t, dir, "plain.cmd", "@echo hi\r\n")
	if _, _, ok := npmShimTarget(filepath.Join(dir, "plain.cmd")); ok {
		t.Error("a plain batch file is not an npm shim")
	}
}
