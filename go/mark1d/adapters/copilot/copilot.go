// Package copilot is the Phase-5 adapter (08 §5.5): `copilot --version`
// sniff, BYOK-vs-GitHub-billed regime from the CLI's own provider resolution,
// a mechanism-A owned hook file under $COPILOT_HOME/hooks (7 PascalCase
// handlers through the shim, MARK1_AGENT via the entry's env), and a
// DIAGNOSTIC-class reader behind adapters.Tail over session-state/*/events.jsonl
// that emits session boundaries and never Usage. Pinned to
// conformance/hooks/copilot/v1.0.85.
package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

type Adapter struct {
	Home        string // overrides $HOME (test seam)
	CopilotHome string // overrides $COPILOT_HOME; default ~/.copilot
	StateDir    string // mark1d state root; empty falls back to ~/.omium/mark1
	ShimPath    string // overrides 08 §8.1's command string
	// Env overrides os.Getenv for the regime sniff (test seam); nil reads the process environment.
	Env func(string) string
}

func (a *Adapter) Name() string { return "copilot" }

func (a *Adapter) getenv(k string) string {
	if a.Env != nil {
		return a.Env(k)
	}
	return os.Getenv(k)
}

func (a *Adapter) home() (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return os.UserHomeDir()
}

// copilotHome is $COPILOT_HOME or ~/.copilot (resolveCopilotHome in the pinned bundle).
func (a *Adapter) copilotHome() (string, error) {
	if a.CopilotHome != "" {
		return a.CopilotHome, nil
	}
	if v := a.getenv("COPILOT_HOME"); v != "" {
		return v, nil
	}
	home, err := a.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".copilot"), nil
}

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

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

// providersFile mirrors the bundle's e0t: $COPILOT_PROVIDERS_CONFIG or
// <copilotHome>/providers.json; its providers win over every COPILOT_PROVIDER_*
// variable when non-empty. ok=false when the file is absent or empty. Entries
// are kept as raw JSON: this reader classifies credential SHAPE and never
// holds a credential value in a named field.
func (a *Adapter) providersFile() (entries []map[string]json.RawMessage, ok bool) {
	path := a.getenv("COPILOT_PROVIDERS_CONFIG")
	if path == "" {
		dir, err := a.copilotHome()
		if err != nil {
			return nil, false
		}
		path = filepath.Join(dir, "providers.json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cfg struct {
		Providers []map[string]json.RawMessage `json:"providers"`
	}
	if json.Unmarshal(b, &cfg) != nil || len(cfg.Providers) == 0 {
		return nil, false
	}
	return cfg.Providers, true
}

// plainKey: the entry authenticates with `apiKey` alone — `bearerToken` and
// `apiKeyCommand` take precedence over it at the pin (bundle field names).
func plainKey(entry map[string]json.RawMessage) bool {
	set := func(k string) bool {
		v := string(entry[k])
		return v != "" && v != `""` && v != "null"
	}
	return set("apiKey") && !set("bearerToken") && !set("apiKeyCommand")
}

// regime: BYOK with a plain API key is the API-key regime; everything else —
// GitHub-billed (no COPILOT_PROVIDER_BASE_URL), GHES-hosted, a bearer token or
// a key command (both take precedence over the key at the pin), or a
// providers.json whose entries are not all plain keys — reads as subscription,
// the conservative default (CON-001). The key's SHAPE is the gateway's tripwire,
// not this function's: a gho_ token in COPILOT_PROVIDER_API_KEY is refused on
// the wire (rust:gateway_refuses_a_github_billed_token_even_when_enrolled).
func (a *Adapter) regime() adapters.Regime {
	if entries, ok := a.providersFile(); ok {
		for _, e := range entries {
			if !plainKey(e) {
				return adapters.RegimeSubscription
			}
		}
		return adapters.RegimeAPIKey
	}
	if a.getenv("COPILOT_PROVIDER_BASE_URL") == "" || a.getenv("COPILOT_PROVIDER_API_KEY") == "" {
		return adapters.RegimeSubscription
	}
	if a.getenv("COPILOT_PROVIDER_BEARER_TOKEN") != "" || a.getenv("COPILOT_PROVIDER_API_KEY_COMMAND") != "" {
		return adapters.RegimeSubscription
	}
	return adapters.RegimeAPIKey
}

// Detect sniffs installation, version (`copilot --version` → "GitHub Copilot CLI X.Y.Z.") and regime.
func (a *Adapter) Detect() (adapters.Detection, error) {
	d := adapters.Detection{Regime: a.regime()}
	bin, err := exec.LookPath("copilot")
	if err != nil {
		return d, nil
	}
	d.Installed = true
	ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--no-auto-update", "--version") //nolint:gosec // G204: bin is LookPath("copilot") — the operator's own PATH, no shell
	var buf bytes.Buffer
	cmd.Stdout = &capWriter{w: &buf, remaining: versionSniffCap}
	if err := cmd.Run(); err != nil {
		return d, nil
	}
	d.Version = versionRe.FindString(buf.String())
	return d, nil
}

// CodeNotEligible is 08 §9's CON-001 boundary code, shared with claudecode's base-URL fragment.
const CodeNotEligible = "M1E-7105"

// ErrNotEligible: no wire-path credential exists for this install. A
// GitHub-billed session (no BYOK base URL) can never produce one — GitHub's
// own token is the subscription, and the proxy binary never sees it.
var ErrNotEligible = errors.New(CodeNotEligible + ": not proxy-eligible; Copilot rides the wire path only under BYOK with a plain provider API key (08 §5.5)")

// WireCredential is the ONE reading of the customer-owned BYOK key for the
// proxy's registry (10 §3.3): the bytes are returned only in the API-key
// regime, and only from the environment path — a providers.json install is
// classified but its key is not lifted here (unconfirmed entry schema).
func (a *Adapter) WireCredential() (string, error) {
	if a.regime() != adapters.RegimeAPIKey {
		return "", ErrNotEligible
	}
	if _, fromFile := a.providersFile(); fromFile {
		return "", ErrNotEligible
	}
	return a.getenv("COPILOT_PROVIDER_API_KEY"), nil
}

// SupportedVersions: one entry per fixture directory under conformance/hooks/copilot.
var SupportedVersions = map[string]struct{}{
	"1.0.85": {},
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

// paths: the owned file is <copilotHome>/hooks/mark1.json — the user-level hook
// directory the CLI loads every *.json from (hooks-reference, "Hooks locations").
func (a *Adapter) paths() (target, state string, err error) {
	dir, err := a.copilotHome()
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
	return filepath.Join(dir, "hooks", "mark1.json"), state, nil
}

func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.copilot/hooks/mark1.json"},
		{Kind: "transcripts", Path: "~/.copilot/session-state/<session-uuid>/events.jsonl"},
	}
}

// SessionStateDir is the ONE per-user tree every workspace's sessions live
// under: containment is decided per stream from session.start's context.cwd.
func (a *Adapter) SessionStateDir() (string, error) {
	dir, err := a.copilotHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "session-state"), nil
}

type TailConfig struct {
	StateDir     string
	UsageIdemKey []byte
	Observe      func(*m1pv1.Event)
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
}

// StartTail is the events.jsonl reader for one enabled workspace: the shared
// session-state tree under the WorkspaceSet oracle, consulted on every
// stream's own cwd. It emits DIAGNOSTIC-class session boundaries only.
func (a *Adapter) StartTail(ws adapters.Workspace, set tailers.WorkspaceSet, cfg TailConfig) (*tailers.Manager, error) {
	root, err := filepath.Abs(ws.Root)
	if err != nil {
		return nil, err
	}
	if !set.Allowed(root) {
		return nil, errors.New("copilot: workspace root is not an enabled root")
	}
	dir, err := a.SessionStateDir()
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
		Format:       eventsFormat(cfg),
	})
}
