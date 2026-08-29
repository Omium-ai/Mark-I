// Package claudecode is the Phase-1 adapter (04 §2.10): transcript-dir
// resolution and tailer lifecycle over internal/tailers. Hook provisioning is
// the hookshim row's concern — the shim registers itself via 08 §8 fenced
// fragments; C8 acceptance is the transcript replay, which needs no hooks.
package claudecode

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

// ErrNotProvisioned: hook-fragment provisioning ships with mark1-hookshim
// (04 §5, 08 §8). Returning it beats a no-op nil that would claim hooks are
// registered when they are not.
var ErrNotProvisioned = errors.New("claudecode: hook provisioning lands with the hookshim row (08 §8)")

type Adapter struct {
	// Home overrides $HOME for transcript-dir resolution (test seam).
	Home string
}

func (a *Adapter) Name() string { return "claudecode" }

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Detect sniffs installation and version at runtime — the version selects the
// agent_maps field map and an unmapped version must go inert, never guess
// (08 §5 rule 2; the map check itself lives with internal/policy).
func (a *Adapter) Detect() (adapters.Detection, error) {
	bin, err := exec.LookPath("claude")
	if err != nil {
		return adapters.Detection{}, nil
	}
	d := adapters.Detection{Installed: true, Regime: adapters.RegimeSubscription}
	// ponytail: ANTHROPIC_API_KEY presence as the regime sniff — the guard's
	// authoritative Detect()==apikey input is the proxy row's provenance
	// check (04 §3.1); this only steers eligibility, and subscription is the
	// conservative default.
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		d.Regime = adapters.RegimeAPIKey
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return d, nil // installed but unsniffable: no version ⇒ no field map ⇒ inert
	}
	d.Version = versionRe.FindString(string(out))
	return d, nil
}

func (a *Adapter) Provision(ws adapters.Workspace, m adapters.Maps) error {
	return ErrNotProvisioned
}

func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.claude/settings.json"},
		{Kind: "transcripts", Path: "~/.claude/projects/<munged-cwd>/*.jsonl"},
	}
}

// TranscriptDir is 08 §5.1's fallback derivation: ~/.claude/projects/<munged-cwd>,
// where <munged-cwd> is the absolute cwd with '/' replaced by '-'. The
// primary source (hook payloads' transcript_path) arrives with the shim.
func (a *Adapter) TranscriptDir(cwd string) (string, error) {
	home := a.Home
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "projects", strings.ReplaceAll(abs, "/", "-")), nil
}

// TailConfig is the wiring the daemon supplies; everything vendor-shaped is
// derived here.
type TailConfig struct {
	StateDir     string
	UsageIdemKey []byte
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
}

// StartTail builds the tailer manager for one enabled workspace. The root
// pre-check is a cheap refusal; the oracle itself rides into the manager and
// is consulted on EVERY discovered stream's own cwd (04 §2.1), because the
// '/'→'-' munge is not injective — …/foo/bar and …/foo-bar derive the same
// vendor dir, so the derived path alone proves nothing about containment.
// Per-payload transcript_path checks ride the shim.
func (a *Adapter) StartTail(ws adapters.Workspace, set tailers.WorkspaceSet, cfg TailConfig) (*tailers.Manager, error) {
	root, err := filepath.Abs(ws.Root)
	if err != nil {
		return nil, err
	}
	if !set.Allowed(root) {
		return nil, errors.New("claudecode: workspace root is not an enabled root")
	}
	dir, err := a.TranscriptDir(root)
	if err != nil {
		return nil, err
	}
	return tailers.NewManager(tailers.Config{
		Dir:          dir,
		StateDir:     cfg.StateDir,
		Allowed:      set.Allowed,
		UsageIdemKey: cfg.UsageIdemKey,
		Emit:         cfg.Emit,
		Log:          cfg.Log,
	})
}
