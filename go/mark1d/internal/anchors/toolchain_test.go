package anchors

import (
	"os"
	"path/filepath"
	"testing"
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
	lookNode = func() (string, error) { return filepath.Join("/", "home", "u", ".nvm", "versions", "node", "v22", "bin", "node"), nil }
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
