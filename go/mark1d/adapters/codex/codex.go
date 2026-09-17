// Package codex is the Phase-2 adapter (08 §5.2): `codex --version` sniff,
// ChatGPT-login vs API-key regime, the 08 §8 fence into ~/.codex/hooks.json
// (11 handlers through the shim), and TWO Usage readers behind adapters.Tail —
// (a) the rollout JSONL tail, (b) the `codex exec --json` stream — with
// DetectUsage saying which is live. Pinned to conformance/hooks/codex/v0.154.0.
package codex

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
	Home      string // overrides $HOME (test seam)
	CodexHome string // overrides $CODEX_HOME; default ~/.codex
	StateDir  string // mark1d state root; empty falls back to ~/.omium/mark1
	ShimPath  string // overrides 08 §8.1's command string
}

func (a *Adapter) Name() string { return "codex" }

func (a *Adapter) home() (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return os.UserHomeDir()
}

// codexHome is $CODEX_HOME or ~/.codex (codex-rs/config: find_codex_home).
func (a *Adapter) codexHome() (string, error) {
	if a.CodexHome != "" {
		return a.CodexHome, nil
	}
	if v := os.Getenv("CODEX_HOME"); v != "" {
		return v, nil
	}
	home, err := a.home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex"), nil
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

// regime mirrors codex-rs/login load_auth + AuthDotJson::resolved_mode at the
// pin: CODEX_API_KEY env wins; then auth.json's explicit auth_mode; then a
// stored OPENAI_API_KEY with no PAT/Bedrock credential; else ChatGPT login.
// Subscription is the conservative default (CON-001).
func (a *Adapter) regime() adapters.Regime {
	if os.Getenv("CODEX_API_KEY") != "" {
		return adapters.RegimeAPIKey
	}
	ch, err := a.codexHome()
	if err != nil {
		return adapters.RegimeSubscription
	}
	b, err := os.ReadFile(filepath.Join(ch, "auth.json"))
	if err != nil {
		return adapters.RegimeSubscription
	}
	var auth struct {
		AuthMode            string  `json:"auth_mode"`
		OpenAIAPIKey        *string `json:"OPENAI_API_KEY"`
		PersonalAccessToken *string `json:"personal_access_token"`
		BedrockAPIKey       any     `json:"bedrock_api_key"`
		BedrockAccessKeys   any     `json:"bedrock_access_keys"`
	}
	if json.Unmarshal(b, &auth) != nil {
		return adapters.RegimeSubscription
	}
	switch {
	case auth.AuthMode != "":
		if auth.AuthMode == "apikey" {
			return adapters.RegimeAPIKey
		}
	case auth.PersonalAccessToken == nil && auth.BedrockAPIKey == nil && auth.BedrockAccessKeys == nil &&
		auth.OpenAIAPIKey != nil && *auth.OpenAIAPIKey != "":
		return adapters.RegimeAPIKey
	}
	return adapters.RegimeSubscription
}

// Detect sniffs installation, version (`codex --version` → "codex-cli X.Y.Z") and regime.
func (a *Adapter) Detect() (adapters.Detection, error) {
	d := adapters.Detection{Regime: a.regime()}
	bin, err := adapters.LookPath("codex", a.Home)
	if err != nil {
		return d, nil
	}
	d.Installed = true
	ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // G204: bin is LookPath("codex") — the operator's own PATH, no shell
	var buf bytes.Buffer
	cmd.Stdout = &capWriter{w: &buf, remaining: versionSniffCap}
	if err := cmd.Run(); err != nil {
		return d, nil
	}
	d.Version = versionRe.FindString(buf.String())
	return d, nil
}

// UsageSource names which Usage reader is live for this install.
type UsageSource string

const (
	// UsageRollout: $CODEX_HOME/sessions holds token_usage_record lines — reader (a) tails them.
	UsageRollout UsageSource = "rollout"
	// UsageExecJSON: no persisted usage seen yet — only a wrapped `codex exec --json` (reader (b)) can supply it.
	UsageExecJSON UsageSource = "exec-json"
)

// DetectUsage reports the live Usage source: rollout when persistence is
// observed on disk (a token_usage_record in one of the newest rollouts),
// exec-json otherwise. Vendor source at the pin persists the record
// (rollout/src/policy.rs), so exec-json on a used install is a finding.
func (a *Adapter) DetectUsage() UsageSource {
	dir, err := a.SessionsDir()
	if err == nil && hasUsageRecord(dir) {
		return UsageRollout
	}
	return UsageExecJSON
}

// SupportedVersions: one entry per fixture directory under conformance/hooks/codex.
var SupportedVersions = map[string]struct{}{
	"0.154.0": {},
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
	ch, err := a.codexHome()
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
	return filepath.Join(ch, "hooks.json"), state, nil
}

func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.codex/hooks.json"},
		{Kind: "transcripts", Path: "~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl"},
	}
}

// SessionsDir is the ONE rollout tree every workspace shares: containment is
// decided per stream from session_meta.cwd, never from the directory.
func (a *Adapter) SessionsDir() (string, error) {
	ch, err := a.codexHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(ch, "sessions"), nil
}

type TailConfig struct {
	StateDir     string
	UsageIdemKey []byte
	Emit         func(context.Context, *m1pv1.Event) error
	Observe      func(*m1pv1.Event) // tailers.Config.Observe: the segmenter's task_id stamp
	Log          *slog.Logger
}

// StartTail is reader (a) for one enabled workspace: the shared sessions tree
// under the WorkspaceSet oracle, consulted on every stream's own cwd.
func (a *Adapter) StartTail(ws adapters.Workspace, set tailers.WorkspaceSet, cfg TailConfig) (*tailers.Manager, error) {
	root, err := filepath.Abs(ws.Root)
	if err != nil {
		return nil, err
	}
	if !set.Allowed(root) {
		return nil, errors.New("codex: workspace root is not an enabled root")
	}
	dir, err := a.SessionsDir()
	if err != nil {
		return nil, err
	}
	return tailers.NewManager(tailers.Config{
		Dir:          dir,
		StateDir:     cfg.StateDir,
		Allowed:      set.Allowed,
		UsageIdemKey: cfg.UsageIdemKey,
		Emit:         cfg.Emit,
		Observe:      cfg.Observe,
		Log:          cfg.Log,
		Format:       rolloutFormat(),
		Agent:        a.Name(),
		Roots:        set.Roots,
	})
}

// RecentProjects is the cwd each rollout's session_meta names, newest rollout first (recent_projects on GET /v1/agents); limit <= 0 is unbounded.
func (a *Adapter) RecentProjects(limit int) []string {
	dir, err := a.SessionsDir()
	if err != nil {
		return []string{}
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*", "*", "*", "rollout-*.jsonl"))
	return tailers.RecentCwds(paths, sessionMetaCwd, limit)
}

// TailExec is reader (b): wrap a `codex exec --json` stdout for workspace cwd.
func (a *Adapter) TailExec(r io.Reader, cwd string, set tailers.WorkspaceSet, cfg TailConfig) adapters.Tail {
	return &ExecStream{R: r, Cwd: cwd, Set: set, Cfg: cfg}
}
