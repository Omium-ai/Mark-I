package anchors

import (
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
	if gov["GOMODCACHE"] != "/m" || gov["GOPROXY"] != "off" || gov["GOTOOLCHAIN"] != "local" || gov["GOCACHE"] != filepath.Join("/cache/go-vet", "go-build") {
		t.Fatalf("go env %v", gov)
	}
	if _, ok := toolchainEnv("go", "")["GOCACHE"]; ok {
		t.Fatal("no cache dir ⇒ GOCACHE stays the sandbox's cold default")
	}
	if toolchainEnv("ruff", "/cache/ruff") != nil {
		t.Fatal("a linter inherits nothing")
	}
}
