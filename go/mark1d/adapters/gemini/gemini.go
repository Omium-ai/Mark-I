// Package gemini is the Phase-3 adapter (08 §5.3): `gemini --version` sniff,
// OAuth-vs-API-key regime from the CLI's own auth resolution, the 08 §8 fence
// into ~/.gemini/settings.json (7 handlers through the shim, MARK1_AGENT via
// the hook entry's env), and a Usage reader behind adapters.Tail over the
// CLI's chat recordings. Pinned to conformance/hooks/gemini/v0.59.0.
package gemini

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
	GeminiDir string // overrides ~/.gemini (test seam); the vendor's own override is $GEMINI_CLI_HOME
	StateDir  string // mark1d state root; empty falls back to ~/.omium/mark1
	ShimPath  string // overrides 08 §8.1's command string
}

func (a *Adapter) Name() string { return "gemini" }

func (a *Adapter) home() (string, error) {
	if a.Home != "" {
		return a.Home, nil
	}
	return os.UserHomeDir()
}

// geminiDir is <homedir()>/.gemini, homedir() being $GEMINI_CLI_HOME or the
// user's home (Storage.getGlobalGeminiDir, utils/paths.ts homedir at the pin).
func (a *Adapter) geminiDir() (string, error) {
	if a.GeminiDir != "" {
		return a.GeminiDir, nil
	}
	h := os.Getenv("GEMINI_CLI_HOME")
	if h == "" {
		var err error
		if h, err = a.home(); err != nil {
			return "", err
		}
	}
	return filepath.Join(h, ".gemini"), nil
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

// AuthType values are core/contentGenerator.ts's AuthType enum, verbatim.
const (
	authGeminiAPIKey = "gemini-api-key"
	authOAuth        = "oauth-personal"
	authVertex       = "vertex-ai"
	authGateway      = "gateway"
	authComputeADC   = "compute-default-credentials"
)

// authTypeFromEnv is core/contentGenerator.ts getAuthTypeFromEnv, in its order.
func authTypeFromEnv() string {
	switch {
	case os.Getenv("GOOGLE_GENAI_USE_GCA") == "true":
		return authOAuth
	case os.Getenv("GOOGLE_GENAI_USE_VERTEXAI") == "true":
		return authVertex
	case os.Getenv("GOOGLE_GEMINI_BASE_URL") != "":
		return authGateway
	case os.Getenv("GEMINI_API_KEY") != "":
		return authGeminiAPIKey
	case os.Getenv("CLOUD_SHELL") == "true" || os.Getenv("GEMINI_CLI_USE_COMPUTE_ADC") == "true":
		return authComputeADC
	}
	return ""
}

// regime mirrors cli/validateNonInterActiveAuth.ts at the pin: the settings'
// security.auth.selectedType wins, else the env resolution; an enforcedType
// that disagrees makes the CLI refuse to run at all. Only gemini-api-key is
// the API-key regime; oauth-personal, vertex-ai, gateway and ADC are all
// non-proxyable here, and subscription is the conservative default (CON-001).
func (a *Adapter) regime() adapters.Regime {
	var s struct {
		Security struct {
			Auth struct {
				SelectedType string `json:"selectedType"`
				EnforcedType string `json:"enforcedType"`
			} `json:"auth"`
		} `json:"security"`
	}
	if dir, err := a.geminiDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(dir, "settings.json")); err == nil {
			_ = json.Unmarshal(b, &s)
		}
	}
	t := s.Security.Auth.SelectedType
	if t == "" {
		t = authTypeFromEnv()
	}
	if e := s.Security.Auth.EnforcedType; e != "" && e != t {
		return adapters.RegimeSubscription
	}
	if t == authGeminiAPIKey {
		return adapters.RegimeAPIKey
	}
	return adapters.RegimeSubscription
}

// Detect sniffs installation, version (`gemini --version` → "X.Y.Z") and regime.
func (a *Adapter) Detect() (adapters.Detection, error) {
	d := adapters.Detection{Regime: a.regime()}
	bin, err := adapters.LookPath("gemini", a.Home)
	if err != nil {
		return d, nil
	}
	d.Installed = true
	ctx, cancel := context.WithTimeout(context.Background(), versionSniffTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version") //nolint:gosec // G204: bin is LookPath("gemini") — the operator's own PATH, no shell
	var buf bytes.Buffer
	cmd.Stdout = &capWriter{w: &buf, remaining: versionSniffCap}
	if err := cmd.Run(); err != nil {
		return d, nil
	}
	d.Version = versionRe.FindString(buf.String())
	return d, nil
}

// SupportedVersions: one entry per fixture directory under conformance/hooks/gemini.
var SupportedVersions = map[string]struct{}{
	"0.59.0": {},
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
	dir, err := a.geminiDir()
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
	return filepath.Join(dir, "settings.json"), state, nil
}

func (a *Adapter) Surfaces() []adapters.CaptureSurface {
	return []adapters.CaptureSurface{
		{Kind: "hooks", Path: "~/.gemini/settings.json"},
		{Kind: "transcripts", Path: "~/.gemini/tmp/<project-slug>/chats/session-*.jsonl"},
	}
}

// TmpDir is the ONE per-user tree every project's chats live under
// (Storage.getGlobalTempDir): containment is decided per slug from its
// .project_root marker and per stream from its projectHash, never from the
// directory name.
func (a *Adapter) TmpDir() (string, error) {
	dir, err := a.geminiDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tmp"), nil
}

type TailConfig struct {
	StateDir     string
	UsageIdemKey []byte
	Observe      func(*m1pv1.Event)
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
}

// StartTail is the chat-recording reader for one enabled workspace: the
// shared tmp tree under the WorkspaceSet oracle, consulted on every stream's
// own project root.
func (a *Adapter) StartTail(ws adapters.Workspace, set tailers.WorkspaceSet, cfg TailConfig) (*tailers.Manager, error) {
	root, err := filepath.Abs(ws.Root)
	if err != nil {
		return nil, err
	}
	if !set.Allowed(root) {
		return nil, errors.New("gemini: workspace root is not an enabled root")
	}
	dir, err := a.TmpDir()
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
		Format:       chatsFormat(root),
		Agent:        a.Name(),
		Roots:        set.Roots,
	})
}

// RecentProjects is the .project_root marker each main chat's projectHash resolves to, newest chat first (recent_projects on GET /v1/agents); limit <= 0 is unbounded.
func (a *Adapter) RecentProjects(limit int) []string {
	tmp, err := a.TmpDir()
	if err != nil {
		return []string{}
	}
	return recentProjects(tmp, limit)
}
