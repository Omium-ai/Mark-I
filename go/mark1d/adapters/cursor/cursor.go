// Package cursor is the Phase-5 observe/gate adapter (08 §5.6): version sniff
// over both vendor surfaces (`cursor-agent --version`, then `cursor --version`),
// the 08 §8 fence into ~/.cursor/hooks.json (8 handlers through the shim,
// the agent as its argv[1]), and nothing else — every request Cursor
// makes transits Cursor's backend in every regime, so the wire proxy and model
// rewrite are a permanent NO-GO and no durable local Usage surface exists
// (docs/spikes/cursor-observe-gate.md). Pinned to
// conformance/hooks/cursor/v2026.09.10-fd3934a.
package cursor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/procattr"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
)

type Adapter struct {
	Home      string // overrides $HOME (test seam)
	CursorDir string // overrides ~/.cursor (test seam); the vendor has no env override for it
	StateDir  string // mark1d state root; empty falls back to ~/.omium/mark1
	ShimPath  string // overrides 08 §8.1's command string
}

func (a *Adapter) Name() string { return "cursor" }

func (a *Adapter) home() (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return os.UserHomeDir()
}

// cursorDir is ~/.cursor: userConfigPath = join(homedir(), ".cursor", "hooks.json") at the pin.
func (a *Adapter) cursorDir() (string, error) {
	if a.CursorDir != "" {
		return a.CursorDir, nil
	}
	home, err := a.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cursor"), nil
}

// versionRe reads both surfaces: the CLI's "YYYY.MM.DD-<sha7>" build and the IDE's semver.
var versionRe = regexp.MustCompile(`\d{4}\.\d{2}\.\d{2}-[0-9a-f]{7}|\d+\.\d+\.\d+`)

const (
	versionSniffTimeout = 5 * time.Second
	versionSniffCap     = 64 << 10
)

type capWriter struct {
	w         io.Writer
	remaining int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.remaining > 0 {
		n := min(len(p), c.remaining)
		if _, err := c.w.Write(p[:n]); err != nil {
			return len(p), nil
		}
		c.remaining -= n
	}
	return len(p), nil
}

// CodeNotEligible is 08 §9's CON-001 boundary code, shared with claudecode's base-URL fragment.
const CodeNotEligible = "M1E-7105"

// ErrWireNoGo is the typed refusal for anything on the wire column: "even if
// you use your API key, your requests will still go through our backend"
// (cursor.com/data-use), so no credential state on this machine changes where
// the client sends bytes and there is nothing for a provenance guard to admit.
var ErrWireNoGo = errors.New(CodeNotEligible + ": not proxy-eligible in any regime; Cursor's client speaks only to Cursor's backend, so the wire proxy and model rewrite are a permanent NO-GO (docs/spikes/cursor-observe-gate.md Q3)")

// Detect sniffs installation and version, CLI first (`cursor-agent --version`
// → "2026.09.10-fd3934a"), else the IDE (`cursor --version` → "3.20.21\n<commit>\n<arch>").
// The regime is subscription unconditionally: Cursor's BYOK never makes the
// client the HTTP caller, so it is capture-only whatever key is configured.
func (a *Adapter) Detect() (adapters.Detection, error) {
	d := adapters.Detection{Regime: adapters.RegimeSubscription}
	for _, name := range []string{"cursor-agent", "cursor"} {
		bin, err := adapters.LookPath(name, a.Home)
		if err != nil {
			continue
		}
		d.Installed = true
		ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
		cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // G204: bin is LookPath over two fixed names — the operator's own PATH, no shell
		procattr.Hide(cmd)
		var buf bytes.Buffer
		cmd.Stdout = &capWriter{w: &buf, remaining: versionSniffCap}
		err = cmd.Run()
		cancel()
		if err != nil {
			return d, nil
		}
		d.Version = versionRe.FindString(buf.String())
		return d, nil
	}
	return d, nil
}

// SupportedVersions: one entry per fixture directory under conformance/hooks/cursor.
// The corpus is keyed by the CLI build; the IDE build it was read against is
// 3.20.21, which stays unsupported until an IDE-recorded corpus lands.
var SupportedVersions = map[string]struct{}{
	"2026.09.10-fd3934a": {},
}

// Supported: FR-AGENT-002's "never parse blind" — no fixture, no parse.
func Supported(version string) bool {
	_, ok := SupportedVersions[version]
	return ok
}

func (a *Adapter) Provision(adapters.Workspace, adapters.Maps) error {
	_, err := a.Apply()
	return err
}

func (a *Adapter) Apply() (ApplyResult, error) {
	target, state, err := a.paths()
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyFragment(target, state, a.ShimPath)
}

func (a *Adapter) Repair() (ApplyResult, error) {
	target, state, err := a.paths()
	if err != nil {
		return ApplyResult{}, err
	}
	return RepairFragment(target, state, a.ShimPath)
}

func (a *Adapter) paths() (target, state string, err error) {
	dir, err := a.cursorDir()
	if err != nil {
		return "", "", err
	}
	state = a.StateDir
	if state == "" {
		home, err := a.home()
		if err != nil {
			return "", "", err
		}
		state = filepath.Join(home, ".omium", "mark1")
	}
	return filepath.Join(dir, "hooks.json"), state, nil
}

// RecentProjects is always empty: Cursor keeps no local session tree (Surfaces is hooks only), so no head names a cwd.
func (a *Adapter) RecentProjects(int) []string { return []string{} }

// Surfaces: hooks only. state.vscdb's tokenCount is context occupancy, the
// CLI's stream-json is a process's stdout rather than a file, and the enterprise
// OTLP export is customer infrastructure — none is a durable local Usage surface.
func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.cursor/hooks.json"},
	}
}
