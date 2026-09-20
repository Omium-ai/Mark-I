package anchors

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

// lookRuntime is adapters.LookPath — nvm/fnm/volta/bun dirs included; a test seam.
var lookRuntime = func(name string) (string, error) { return adapters.LookPath(name, "") }

// nodeEnv puts the JavaScript runtimes' own directories on the sandbox PATH for a tool that is a script from node_modules/.bin (`#!/usr/bin/env node`, or bun's shims, which exec `bun`: the founder's Vite site answered "bun is not installed"). The sandbox PATH is the tool's directory alone, and with nvm/fnm/volta/bun the runtime lives nowhere near it. Neither installed ⇒ nothing extra, and the sniff fails honestly.
func nodeEnv(binaryPath string) map[string]string {
	dirs := []string{filepath.Dir(binaryPath)}
	for _, rt := range []string{"node", "bun"} {
		p, err := lookRuntime(rt)
		if err != nil {
			continue
		}
		if d := filepath.Dir(p); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) == 1 {
		return nil
	}
	return map[string]string{"PATH": strings.Join(dirs, string(os.PathListSeparator))}
}

// toolchainEnv spells out what a compiler needs to run OFFLINE with HOME pointed at sandbox scratch (founder ruling 2026-09-19: module caches readable, never network): rustup's proxy finds no toolchain and cargo no registry under a scratch HOME, and go would try the proxy for every module. Build caches go to cacheDir (the sandbox's one extra writable root); module caches stay where they are, read-only under the sandbox.
func toolchainEnv(binary, cacheDir, binaryPath string) map[string]string {
	home, _ := os.UserHomeDir()
	pick := func(k, dflt string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return dflt
	}
	switch binary {
	case "tsc", "eslint", "npm":
		return nodeEnv(binaryPath)
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
