package anchors

import (
	"os"
	"path/filepath"
)

// toolchainEnv spells out what a compiler needs to run OFFLINE with HOME pointed at sandbox scratch (founder ruling 2026-09-19: module caches readable, never network): rustup's proxy finds no toolchain and cargo no registry under a scratch HOME, and go would try the proxy for every module. Build caches go to cacheDir (the sandbox's one extra writable root); module caches stay where they are, read-only under the sandbox.
func toolchainEnv(binary, cacheDir string) map[string]string {
	home, _ := os.UserHomeDir()
	pick := func(k, dflt string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return dflt
	}
	switch binary {
	case "cargo":
		// target/ stays the worktree's: the warm cache rust-analyzer shares too; a cold one is minutes per run
		return map[string]string{
			"RUSTUP_HOME":       pick("RUSTUP_HOME", filepath.Join(home, ".rustup")),
			"CARGO_HOME":        pick("CARGO_HOME", filepath.Join(home, ".cargo")),
			"CARGO_NET_OFFLINE": "true",
		}
	case "go":
		gopath := pick("GOPATH", filepath.Join(home, "go"))
		env := map[string]string{
			"GOPATH":     gopath,
			"GOMODCACHE": pick("GOMODCACHE", filepath.Join(gopath, "pkg", "mod")),
			"GOPROXY":    "off",
			// GOTOOLCHAIN stays auto: the founder's /usr/local/go is 1.22 and his repos want 1.25, served from the module cache's toolchain — `local` would refuse every run; a toolchain not cached fails on the denied network, honestly
			"GOFLAGS":     "-mod=readonly",
			"CGO_ENABLED": "0", // the sandbox PATH holds the Go dir alone: no C compiler, so cgo packages vet as their pure-Go build rather than failing the run
		}
		if cacheDir != "" {
			env["GOCACHE"] = filepath.Join(cacheDir, "go-build")
		}
		return env
	}
	return nil
}
