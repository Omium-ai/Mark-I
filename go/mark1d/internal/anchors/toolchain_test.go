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
	cargo := toolchainEnv("cargo", "/cache/cargo-check")
	if cargo["CARGO_HOME"] != "/c" || cargo["RUSTUP_HOME"] != "/r" || cargo["CARGO_NET_OFFLINE"] != "true" || len(cargo) != 3 {
		t.Fatalf("cargo env %v", cargo)
	}
	gov := toolchainEnv("go", "/cache/go-vet")
	if gov["GOMODCACHE"] != "/m" || gov["GOPROXY"] != "off" || gov["GOTOOLCHAIN"] != "" || gov["GOCACHE"] != filepath.Join("/cache/go-vet", "go-build") {
		t.Fatalf("go env %v", gov)
	}
	if _, ok := toolchainEnv("go", "")["GOCACHE"]; ok {
		t.Fatal("no cache dir ⇒ GOCACHE stays the sandbox's cold default")
	}
	if toolchainEnv("ruff", "/cache/ruff") != nil {
		t.Fatal("a linter inherits nothing")
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
