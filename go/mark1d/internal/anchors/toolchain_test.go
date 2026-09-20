package anchors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The compiler anchors run offline with their module caches where the user keeps them and their build cache in the daemon's dir; a linter gets nothing extra.
func TestToolchainEnvIsOfflineAndCacheScoped(t *testing.T) {
	t.Setenv("CARGO_HOME", "/c")
	t.Setenv("RUSTUP_HOME", "/r")
	t.Setenv("GOMODCACHE", "/m")
	cargo := toolchainEnv("cargo", "/cache/cargo-check", "/usr/bin/cargo")
	if cargo["CARGO_HOME"] != "/c" || cargo["RUSTUP_HOME"] != "/r" || cargo["CARGO_NET_OFFLINE"] != "true" || len(cargo) != 3 {
		t.Fatalf("cargo env %v", cargo)
	}
	gov := toolchainEnv("go", "/cache/go-vet", "/usr/local/go/bin/go")
	if gov["GOMODCACHE"] != "/m" || gov["GOPROXY"] != "off" || gov["GOTOOLCHAIN"] != "" || gov["GOCACHE"] != filepath.Join("/cache/go-vet", "go-build") {
		t.Fatalf("go env %v", gov)
	}
	if _, ok := toolchainEnv("go", "", "/usr/local/go/bin/go")["GOCACHE"]; ok {
		t.Fatal("no cache dir ⇒ GOCACHE stays the sandbox's cold default")
	}
	if toolchainEnv("ruff", "/cache/ruff", "/usr/bin/ruff") != nil {
		t.Fatal("a linter inherits nothing")
	}
}

// A node script from node_modules/.bin needs node on the sandbox PATH; with nvm/fnm/volta it lives nowhere near the tool. No node ⇒ nothing extra, the sniff then fails honestly.
func TestNodeToolsGetNodeOnPath(t *testing.T) {
	prev := lookNode
	t.Cleanup(func() { lookNode = prev })
	lookNode = func() (string, error) {
		return filepath.Join("/", "home", "u", ".nvm", "versions", "node", "v22", "bin", "node"), nil
	}
	tsc := filepath.Join("/", "repo", "node_modules", ".bin", "tsc")
	got := toolchainEnv("tsc", "", tsc)["PATH"]
	want := filepath.Dir(tsc) + string(os.PathListSeparator) + filepath.Join("/", "home", "u", ".nvm", "versions", "node", "v22", "bin")
	if got != want {
		t.Fatalf("PATH %q, want %q", got, want)
	}
	if toolchainEnv("eslint", "", filepath.Join("/", "home", "u", ".nvm", "versions", "node", "v22", "bin", "eslint"))["PATH"] != filepath.Join("/", "home", "u", ".nvm", "versions", "node", "v22", "bin") {
		t.Fatal("a tool beside node repeats no dir")
	}
	lookNode = func() (string, error) { return "", os.ErrNotExist }
	if toolchainEnv("tsc", "", tsc) != nil {
		t.Fatal("no node ⇒ nothing extra")
	}
}

// A go.work root is a Go root: `go vet ./...` there covers every module the workspace uses (go.mod under go/<service>/ in a monorepo).
func TestGoWorkRootDerivesTheGoAnchors(t *testing.T) {
	wt := t.TempDir()
	if goRoot(wt) {
		t.Fatal("an empty dir is no Go root")
	}
	if err := os.WriteFile(filepath.Join(wt, "go.work"), []byte("go 1.25\nuse ./svc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !goRoot(wt) {
		t.Fatal("go.work did not make a Go root")
	}
	if got := goPatterns(wt); len(got) != 1 || got[0] != "./svc/..." {
		t.Fatalf("go.work patterns %v, want [./svc/...]", got)
	}
	if err := os.WriteFile(filepath.Join(wt, "go.work"), []byte("go 1.25\n\nuse (\n\t./go/a // the daemon\n\t\"./go/b\"\n\t/abs/never\n)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := goPatterns(wt); len(got) != 2 || got[0] != "./go/a/..." || got[1] != "./go/b/..." {
		t.Fatalf("go.work block patterns %v", got)
	}
	if err := os.WriteFile(filepath.Join(wt, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := goPatterns(wt); len(got) != 1 || got[0] != "./..." {
		t.Fatalf("a module root walks ./..., got %v", got)
	}
}

// A solution-style tsconfig (references, files: []) type-checks nothing under plain `tsc --noEmit`; build mode is the check.
func TestSolutionTsconfigUsesBuildMode(t *testing.T) {
	wt := t.TempDir()
	if err := os.WriteFile(filepath.Join(wt, "tsconfig.json"), []byte("{\n  // solution\n  \"files\": [],\n  \"references\": [{ \"path\": \"./tsconfig.web.json\" }]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectors[KindTsc].argvFor("/r/node_modules/.bin/tsc", wt); len(got) != 5 || got[1] != "-b" || got[2] != "--noEmit" {
		t.Fatalf("solution tsconfig argv %v", got)
	}
	if err := os.WriteFile(filepath.Join(wt, "tsconfig.json"), []byte(`{"compilerOptions":{"strict":true},"include":["src"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectors[KindTsc].argvFor("/r/node_modules/.bin/tsc", wt); len(got) != 4 || got[1] != "--noEmit" {
		t.Fatalf("plain tsconfig argv %v", got)
	}
}

// A scratch dir a stopped daemon left behind is swept at boot; a fresh one (a run in flight now) is not.
func TestSweepScratchRemovesOnlyStaleRunDirs(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "anchor-scratch-1")
	fresh := filepath.Join(root, "anchor-scratch-2")
	keep := filepath.Join(root, "cache")
	for _, d := range []string{stale, fresh, keep} {
		if err := os.MkdirAll(filepath.Join(d, "x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if n := SweepScratch(root); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	for d, want := range map[string]bool{stale: false, fresh: true, keep: true} {
		if _, err := os.Stat(d); (err == nil) != want {
			t.Fatalf("%s present=%v, want %v", d, err == nil, want)
		}
	}
}
