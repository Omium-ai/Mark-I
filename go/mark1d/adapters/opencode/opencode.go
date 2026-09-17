// Package opencode is the Phase-4 adapter (08 §5.4): `opencode --version`
// sniff, regime from the provider credential opencode itself resolves, a
// mechanism-A owned plugin (mark1.js) under the XDG config dir that execs the
// shim for lifecycle hooks and appends step-finish usage to a per-session
// JSONL, and a Usage reader behind adapters.Tail over that JSONL. Pinned to
// conformance/hooks/opencode/v1.18.31.
package opencode

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

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

type Adapter struct {
	Home      string // overrides $HOME (test seam)
	ConfigDir string // overrides $XDG_CONFIG_HOME/opencode (Global.Path.config)
	DataDir   string // overrides $XDG_DATA_HOME/opencode (Global.Path.data: auth.json)
	OCState   string // overrides $XDG_STATE_HOME/opencode (Global.Path.state: model.json)
	StateDir  string // mark1d state root; empty falls back to ~/.omium/mark1
	ShimPath  string // overrides 08 §8.1's command string
}

func (a *Adapter) Name() string { return "opencode" }

func (a *Adapter) home() (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return os.UserHomeDir()
}

// xdg resolves one of core/src/global.ts's xdg-basedir dirs: $XDG_*_HOME or the
// platform default under the home, then /opencode.
func (a *Adapter) xdg(override, env, fallback string) (string, error) {
	if override != "" {
		return override, nil
	}
	if v := os.Getenv(env); v != "" {
		return filepath.Join(v, "opencode"), nil
	}
	home, err := a.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, fallback, "opencode"), nil
}

func (a *Adapter) configDir() (string, error) {
	return a.xdg(a.ConfigDir, "XDG_CONFIG_HOME", ".config")
}

func (a *Adapter) dataDir() (string, error) {
	return a.xdg(a.DataDir, "XDG_DATA_HOME", filepath.Join(".local", "share"))
}

func (a *Adapter) ocStateDir() (string, error) {
	return a.xdg(a.OCState, "XDG_STATE_HOME", filepath.Join(".local", "state"))
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

// providerID mirrors provider.ts defaultModel at the pin: opencode.json's
// `model` ("provider/model"), else the newest `recent` entry of the state
// dir's model.json. "" when neither resolves.
func (a *Adapter) providerID() string {
	var cfg struct {
		Model string `json:"model"`
	}
	if dir, err := a.configDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "opencode.json")); err == nil {
			_ = json.Unmarshal(b, &cfg)
		}
	}
	if cfg.Model != "" {
		p, _, _ := bytes.Cut([]byte(cfg.Model), []byte("/"))
		return string(p)
	}
	var recent struct {
		Recent []struct {
			ProviderID string `json:"providerID"`
		} `json:"recent"`
	}
	if dir, err := a.ocStateDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "model.json")); err == nil {
			_ = json.Unmarshal(b, &recent)
		}
	}
	if len(recent.Recent) > 0 {
		return recent.Recent[0].ProviderID
	}
	return ""
}

// regime classifies the resolved provider's credential the way opencode
// itself stores it: auth.json (Auth.Info: "api" | "oauth" | "wellknown") first,
// else a provider.<id>.options.apiKey in opencode.json. Only a stored API key
// is the API-key regime; OAuth, org-managed (wellknown), env-supplied keys
// (a models.dev lookup this daemon does not make) and an unresolvable provider
// all read as subscription — the conservative default (CON-001).
func (a *Adapter) regime() adapters.Regime {
	id := a.providerID()
	if id == "" {
		return adapters.RegimeSubscription
	}
	if dir, err := a.dataDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "auth.json")); err == nil {
			var auth map[string]struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(b, &auth) == nil {
				if entry, ok := auth[id]; ok {
					if entry.Type == "api" {
						return adapters.RegimeAPIKey
					}
					return adapters.RegimeSubscription
				}
			}
		}
	}
	var cfg struct {
		Provider map[string]struct {
			Options struct {
				APIKey string `json:"apiKey"`
			} `json:"options"`
		} `json:"provider"`
	}
	if dir, err := a.configDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "opencode.json")); err == nil {
			_ = json.Unmarshal(b, &cfg)
		}
	}
	if cfg.Provider[id].Options.APIKey != "" {
		return adapters.RegimeAPIKey
	}
	return adapters.RegimeSubscription
}

// Detect sniffs installation, version (`opencode --version` → "X.Y.Z") and regime.
func (a *Adapter) Detect() (adapters.Detection, error) {
	d := adapters.Detection{Regime: a.regime()}
	bin, err := adapters.LookPath("opencode", a.Home)
	if err != nil {
		return d, nil
	}
	d.Installed = true
	ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // G204: bin is LookPath("opencode") — the operator's own PATH, no shell
	var buf bytes.Buffer
	cmd.Stdout = &capWriter{w: &buf, remaining: versionSniffCap}
	if err := cmd.Run(); err != nil {
		return d, nil
	}
	d.Version = versionRe.FindString(buf.String())
	return d, nil
}

// SupportedVersions: one entry per fixture directory under conformance/hooks/opencode.
var SupportedVersions = map[string]struct{}{
	"1.18.31": {},
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

// paths: the owned file is <config>/plugins/mark1.js — config/plugin.ts scans
// {plugin,plugins}/*.{ts,js} under every config directory, Global.Path.config first.
func (a *Adapter) paths() (target, state string, err error) {
	dir, err := a.configDir()
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
	return filepath.Join(dir, "plugins", "mark1.js"), state, nil
}

func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.config/opencode/plugins/mark1.js"},
		{Kind: "transcripts", Path: "~/.omium/mark1/capture/opencode/<sessionID>.jsonl"},
	}
}

// CaptureDir is where mark1.js appends usage lines: fixed relative to the
// home, not StateDir, because the plugin has no way to learn a daemon flag.
func (a *Adapter) CaptureDir() (string, error) {
	home, err := a.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".omium", "mark1", "capture", "opencode"), nil
}

// SessionUUID is the m1p session_id for an opencode session id (ses_<26
// chars>, schema/identifier.ts): UUIDv5 over NameSpaceURL and
// "opencode:<id>", the recipe mark1.js sessionUUID computes for hook bodies.
func SessionUUID(sessionID string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("opencode:"+sessionID))
}

type TailConfig struct {
	StateDir     string
	UsageIdemKey []byte
	Observe      func(*m1pv1.Event)
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
}

// StartTail is the usage reader for one enabled workspace: the capture dir is
// shared by every project, so containment rides each stream's own
// path.cwd under the WorkspaceSet oracle.
func (a *Adapter) StartTail(ws adapters.Workspace, set tailers.WorkspaceSet, cfg TailConfig) (*tailers.Manager, error) {
	root, err := filepath.Abs(ws.Root)
	if err != nil {
		return nil, err
	}
	if !set.Allowed(root) {
		return nil, errors.New("opencode: workspace root is not an enabled root")
	}
	dir, err := a.CaptureDir()
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
		Format:       captureFormat(),
		Agent:        a.Name(),
		Roots:        set.Roots,
	})
}

// RecentProjects is the path.cwd each capture's first assistant message.updated names, newest capture first (recent_projects on GET /v1/agents); limit <= 0 is unbounded.
func (a *Adapter) RecentProjects(limit int) []string {
	dir, err := a.CaptureDir()
	if err != nil {
		return []string{}
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "ses_*.jsonl"))
	return tailers.RecentCwds(paths, assistantCwd, limit)
}
