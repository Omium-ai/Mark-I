// Package claudecode is the Phase-1 adapter (04 §2.10): transcript-dir
// resolution, tailer lifecycle over internal/tailers, and the 08 §8 fenced
// settings fragment (fragment.go) that registers §5.1's nine hook handlers —
// the Stop gate and the SessionStart injection among them.
package claudecode

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

type Adapter struct {
	// Home overrides $HOME for transcript-dir and settings resolution (test seam).
	Home string
	// StateDir is mark1d's state root (04 §2) — where Provision writes the
	// 08 §8.2 manifest. Empty falls back to ~/.omium/mark1, which is only safe
	// for the read-only surfaces; anything that provisions MUST set it to the
	// same root `mark1 off` globs, or the manifest lands somewhere off cannot
	// find and the fence outlives the uninstall. `mark1 enable` sets it; the
	// daemon leaves it empty because it only ever tails.
	StateDir string
	// ShimPath overrides 08 §8.1's command string for a non-default install.
	ShimPath string
}

// home resolves the `~` every path below hangs off.
func (a *Adapter) home() (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return os.UserHomeDir()
}

func (a *Adapter) Name() string { return "claudecode" }

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

const (
	versionSniffTimeout = 5 * time.Second
	versionSniffCap     = 64 << 10 // a version line is tens of bytes
)

// capWriter drops everything past remaining bytes — never errors, so a chatty
// tool is truncated rather than turned into a failed sniff.
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

// apiKeyCredential is the ONE reading of the customer-owned API key: Detect
// classifies the regime from it and the base-URL fragment fingerprints it into
// the guard registry. Two readings could disagree, and a disagreement here is a
// subscription agent pointed at the proxy (CON-001).
func apiKeyCredential() string { return os.Getenv("ANTHROPIC_API_KEY") }

// Detect sniffs installation and version at runtime — the version selects the
// agent_maps field map and an unmapped version must go inert, never guess
// (08 §5 rule 2; the map check itself lives with internal/policy).
func (a *Adapter) Detect() (adapters.Detection, error) {
	d := adapters.Detection{Regime: adapters.RegimeSubscription}
	// ponytail: ANTHROPIC_API_KEY presence as the regime sniff — the guard's
	// authoritative Detect()==apikey input is the proxy row's provenance
	// check (04 §3.1); this only steers eligibility, and subscription is the
	// conservative default.
	//
	// Read BEFORE the PATH lookup, not after: the regime is a property of the
	// credential, not of this process's PATH, and a `claude` the daemon cannot
	// see must not silently reclassify an API-key install as subscription.
	if apiKeyCredential() != "" {
		d.Regime = adapters.RegimeAPIKey
	}
	bin, err := exec.LookPath("claude")
	if err != nil {
		return d, nil
	}
	d.Installed = true
	// Bounded sniff: a wedged or chatty `claude --version` must not hang the
	// daemon's Detect() or buffer without limit. Same class as the anchors
	// version sniff (internal/anchors/catalog.go) — this one stays unsandboxed
	// because the binary IS the agent the user is already running, not
	// repo-supplied code.
	ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // G204: bin is LookPath("claude") — the operator's own PATH, no shell
	var buf bytes.Buffer
	cmd.Stdout = &capWriter{w: &buf, remaining: versionSniffCap}
	if err := cmd.Run(); err != nil {
		return d, nil // installed but unsniffable: no version ⇒ no field map ⇒ inert
	}
	d.Version = versionRe.FindString(buf.String())
	return d, nil
}

// SupportedVersions is every Claude Code release this adapter has been proven
// against — one entry per fixture directory under conformance/hooks/claudecode,
// which TestSupportedVersionsMatchTheFixtureTree keeps equal in both
// directions, so a fixture drop and a const edit cannot separate.
//
// Compiled rather than read from a bundle on purpose. agent_maps is the
// designed home for field maps (08 §5 rule 2) and extending this set from a
// bundle push is still owed, but the set cannot ONLY live there: a fresh
// install with no control plane reachable would then support no version at
// all, and capture is fail-open-for-availability, not fail-static.
var SupportedVersions = map[string]struct{}{
	"2.1.251": {},
	"2.1.273": {},
}

// Supported reports whether the transcript tailer may parse this agent's
// output. FR-AGENT-002's "never parse blind", and the blindness is literal:
// internal/tailers.txLine names every token field as a compiled struct tag, so
// a release that renames one does not fail — encoding/json leaves the field at
// its zero value and the tailer emits a well-formed billing-grade Usage that
// reads zero. Wrong numbers admitted as right ones poison the ledger, every
// TVO figure derived from it, and the corpus, and nothing downstream can tell.
// Refusing a version we have no fixture for is the only failure mode that is
// visible.
//
// An unsniffable version ("" from Detect, including a `claude` the daemon
// cannot see on its PATH) is NOT supported, for the same reason: not knowing
// the version and guessing the format are the same act.
func Supported(version string) bool {
	_, ok := SupportedVersions[version]
	return ok
}

// Provision applies the 08 §8 mechanism-B fragment (fragment.go) to the user's
// EXISTING ~/.claude/settings.json, registering §5.1's nine handlers through
// the shim. ErrNoTarget when the file does not exist and ErrDamaged when a
// human edited inside our pointers are both returned as-is: they are states
// `mark1 doctor` reports, not failures to retry.
//
// ws and m are unused by design. The hook config is user-scoped (Surfaces()),
// so registration is once per machine, not once per enabled workspace — the
// shim's own workspace scoping does the rest. And no vendor field name is ever
// baked into the fragment: the shim loads agent_maps itself, which is what lets
// a rename ship as a bundle push with no reprovision (FR-AGENT-001).
func (a *Adapter) Provision(adapters.Workspace, adapters.Maps) error {
	_, err := a.Apply()
	return err
}

// Apply is Provision carrying the §8.3 result back. The daemon calls
// Provision (the adapters.Adapter shape) and discards it; `mark1 enable` needs
// it, because §7.2's "unchanged state exits 0 silently" is a promise only a
// caller that can tell a no-op from a write is able to keep.
func (a *Adapter) Apply() (ApplyResult, error) {
	target, state, err := a.paths()
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyFragment(target, state, a.ShimPath)
}

// Repair is `mark1 doctor --fix` (08 §7.4): re-apply a MISSING fragment,
// rewrite a FRAGMENT-DAMAGED one. It is the same write Provision performs with
// exactly one bit different, so there is no second definition of the fence to
// drift — and like Provision it touches nothing outside the recorded pointers.
func (a *Adapter) Repair() (ApplyResult, error) {
	target, state, err := a.paths()
	if err != nil {
		return ApplyResult{}, err
	}
	return RepairFragment(target, state, a.ShimPath)
}

// paths resolves the mechanism-B fence target — the ONE user-owned file Claude
// Code reads hook config from — and the manifest root. See StateDir: an empty
// one resolves to ~/.omium/mark1 here, so a provisioning caller running under
// a non-default root must set it or the manifest and `mark1 off` diverge.
func (a *Adapter) paths() (target, state string, err error) {
	home, err := a.home()
	if err != nil {
		return "", "", err
	}
	state = a.StateDir
	if state == "" {
		state = filepath.Join(home, ".omium", "mark1")
	}
	return filepath.Join(home, ".claude", "settings.json"), state, nil
}

func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.claude/settings.json"},
		{Kind: "transcripts", Path: "~/.claude/projects/<munged-cwd>/*.jsonl"},
	}
}

// TranscriptDir is 08 §5.1's fallback derivation: ~/.claude/projects/<munged-cwd>.
// The primary source (hook payloads' transcript_path) arrives with the shim.
func (a *Adapter) TranscriptDir(cwd string) (string, error) {
	home, err := a.home()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".claude", "projects", mungeCwd(abs)), nil
}

// mungeCwd is Claude Code's projects-dir slug: every rune outside ASCII
// [A-Za-z0-9] becomes '-' — separators, but also '.', '_', ':', spaces and
// each non-ASCII character, one dash per rune. Not "'/' replaced by '-'":
// that reading tails nothing under any cwd holding a dot or underscore.
// Established from directory names real installs wrote, never guessed:
// anthropics/claude-code#93231 (windows, `X:\myrepo\.claude\worktrees\b`
// → `F--myrepo--claude-worktrees-b`, drive-letter case kept),
// #93743 (windows, `C:\Users\u\Downloads\근평 웹만들기` →
// `C--Users-u-Downloads--------`), #92734 (`…/<proj>_b` → `…-<proj>-b`),
// #40946 (`~/projects/외주/app` → `…projects----app`, one dash per rune).
func mungeCwd(abs string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, abs)
}

// TailConfig is the wiring the daemon supplies; everything vendor-shaped is
// derived here.
type TailConfig struct {
	StateDir     string
	UsageIdemKey []byte
	Observe      func(*m1pv1.Event) // tailers.Config.Observe: the segmenter's task_id stamp
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
}

// StartTail builds the tailer manager for one enabled workspace. The root
// pre-check is a cheap refusal; the oracle itself rides into the manager and
// is consulted on EVERY discovered stream's own cwd (04 §2.1), because the
// munge is not injective — …/foo/bar, …/foo-bar and …/foo_bar derive the
// same vendor dir, so the derived path alone proves nothing about containment.
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
		Observe:      cfg.Observe,
		Emit:         cfg.Emit,
		Log:          cfg.Log,
	})
}
