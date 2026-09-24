package supervise

// The sidecar child: `mark1-proxy --mode=sidecar`, per 04 :81. cortexd, the
// other child 04 §1.2 names, is built by go/mark1d/internal/cortex on the same
// Child shape; only the binary lookup rule (FindProxy / FindCortexd) is shared
// here, because "a packaged install puts the siblings in ONE directory" is a
// fact about the install, not about either child.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/procattr"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
)

const (
	proxyBinary = "mark1-proxy"
	// MARK1_PROXY is the dev seam, the same shape (and the same reason) as
	// MARK1_VERIFIER in go/mark1/internal/verifyreceipts: `just build-edge`
	// puts the Go binaries in dist/ and the Rust ones in target/release/, so on
	// a developer machine no lookup rule can find both halves on its own.
	proxyBinaryEnv = "MARK1_PROXY"

	cortexdBinary    = "cortexd"
	cortexdBinaryEnv = "MARK1_CORTEXD"

	// proxyStopGrace is how long SIGINT gets before the kill. The proxy's stop
	// path is `tokio::signal::ctrl_c` on the accept loop; it holds no fsync
	// drain and no ledger, so this is "let in-flight responses finish", not
	// "let it persist state".
	proxyStopGrace = 5 * time.Second
)

// ErrNoProxyBinary is a refusal with an address on it: without mark1-proxy no
// port is ever published, ApplyProxyPointer refuses on every run, and the whole
// enablement path looks broken rather than un-installed (RECONCILIATION D-CM).
var ErrNoProxyBinary = errors.New("supervise: " + proxyBinary + " not found")

// ErrNoCortexdBinary is the cortex plane's twin: without cortexd no root is
// ever pushed, every anchor vote ships an incomplete integrity envelope and
// MCP has nothing to serve — an un-installed machine, named as such.
var ErrNoCortexdBinary = errors.New("supervise: " + cortexdBinary + " not found")

// ErrNoVerifierBinary: Run the verifier refuses with M1E-9500 until the binary is beside mark1d, on PATH, or named by MARK1_VERIFIER.
var ErrNoVerifierBinary = errors.New("supervise: mark1-verifier not found")

// GatewayFlags is 04 §3.4's gateway arm passed through verbatim (main.rs config() validates; its stderr is ours); nil ⇒ `--mode sidecar`.
type GatewayFlags struct {
	Bind     string // host:port the mTLS listener binds
	TLSCert  string // PEM server certificate
	TLSKey   string // PEM server key
	ClientCA string // PEM CA every client certificate must chain to
	CredDir  string // gateway::FileSource: one credential per 0600 file, named by M1-Cred-Ref
}

func (g *GatewayFlags) args() []string {
	if g == nil {
		return []string{"--mode", "sidecar"}
	}
	return []string{"--mode", "gateway", "--bind", g.Bind, "--tls-cert", g.TLSCert, "--tls-key", g.TLSKey, "--client-ca", g.ClientCA, "--cred-dir", g.CredDir}
}

type ProxyConfig struct {
	// StateDir is mark1d's --state-dir. See proxyHome for why it is load-bearing.
	StateDir string
	Log      *slog.Logger
	// Binary overrides the lookup (test seam and packaging escape hatch).
	Binary string
	// Gateway selects `--mode gateway` with its flags; nil is the sidecar.
	Gateway *GatewayFlags
	// Coverage receipts the bypass window a FAILED proxy opens (04 §2.7,
	// 04 :81 "revert base-URL fragment + coverage.Transition"). Left nil,
	// proxyFailed still reverts and still logs — but it logs that the window
	// is UNRECEIPTED, because a nil coverage plane that quietly no-ops is the
	// defect, not a degradation.
	Coverage *coverage.Emitter
}

// ProxyChild builds the sidecar's Child. Every reason it cannot be supervised
// is an error returned here, before the supervisor exists — a child whose Start
// can only ever fail would spend six restarts and a breaker trip discovering
// what a stat call already knows.
func ProxyChild(cfg ProxyConfig) (Child, error) {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	bin := cfg.Binary
	if bin == "" {
		var err error
		if bin, err = FindProxy(); err != nil {
			return Child{}, err
		}
	} else if err := isFile(bin); err != nil {
		// Checked even though it was handed to us: an override that does not
		// exist is the same un-installed machine as an empty PATH, and it must
		// fail here rather than as six exec failures and a breaker trip.
		return Child{}, fmt.Errorf("%w: %s: %w", ErrNoProxyBinary, bin, err)
	}
	home, err := proxyHome(cfg.StateDir)
	if err != nil {
		return Child{}, err
	}
	env := childEnv(home)
	port := claudecode.ProxyPortPath(cfg.StateDir)

	return Child{
		Name: proxyBinary,
		Start: func(ctx context.Context) (*exec.Cmd, error) {
			// Before the spawn, not only after the exit: a mark1d that was
			// SIGKILLed left its last proxy.port on disk, and the seconds
			// between this daemon booting and the new proxy binding are exactly
			// when `mark1 enable` would read it.
			if err := removePort(port); err != nil {
				return nil, err
			}
			cmd := exec.CommandContext(ctx, bin, cfg.Gateway.args()...) //nolint:gosec // G204: bin is FindProxy() or an operator-set MARK1_PROXY; args are a fixed slice, no shell
			procattr.Hide(cmd)
			cmd.Env = env
			// The proxy's own diagnostics go where the daemon's do. Dropping
			// them would make a proxy that refuses to start at all (hardening
			// failure, bad upstream) a silent crash loop.
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			cmd.Cancel = func() error {
				// SIGINT because that is the only stop the proxy listens for
				// (tokio::signal::ctrl_c, rust/mark1-proxy/src/main.rs). Windows
				// cannot deliver os.Interrupt to another process, so there the
				// fallback below — and the WaitDelay after it — is the stop.
				if err := cmd.Process.Signal(os.Interrupt); err != nil {
					return cmd.Process.Kill()
				}
				return nil
			}
			cmd.WaitDelay = proxyStopGrace
			return cmd, nil
		},
		// Part of the stale-port control, and the half that covers the ordinary
		// case: the proxy died, so the file naming its port stops existing
		// before anything can read it as a live listener.
		OnExit: func(error) {
			if err := removePort(port); err != nil {
				log.Error("supervise: could not remove the dead proxy's port file", "path", port, "err", err)
			}
		},
		OnFailed: func() { proxyFailed(log, cfg.Coverage, cfg.StateDir, port) },
	}, nil
}

// proxyFailed is 04 :81's FAILED arm for the sidecar.
func proxyFailed(log *slog.Logger, cov *coverage.Emitter, stateDir, port string) {
	// (i) The developer is never blocked. Only the base-URL fragment is
	// reverted — tearing out the hooks fragment would end capture as well, and
	// a proxy failure costs wire capture, not all capture (04 §1.2).
	res, err := claudecode.RevertBaseURL(stateDir)
	switch {
	case err != nil:
		log.Error("supervise: proxy FAILED and the base-URL fragment could not be reverted — the agent still points at a dead proxy",
			"err", err, "operator_action", "run `mark1 off`")
	case len(res.Retained) > 0:
		// The revert could not verify our own block, so it wrote nothing
		// (D-CR). This must never read as success: the agent is still pointed
		// at a port no process holds.
		log.Error("supervise: proxy FAILED and the base-URL fragment was left standing",
			"retained", strings.Join(res.Retained, ", "), "target", res.Target,
			"operator_action", "remove these by hand")
	default:
		log.Warn("supervise: proxy FAILED; base-URL fragment reverted, agent traffic now goes direct to the vendor",
			"kind", res.Kind)
	}
	// FAILED is the state that lasts — there is no seventh restart to clean up
	// after it — so a proxy.port left here names a freed ephemeral port for as
	// long as this daemon runs.
	if err := removePort(port); err != nil {
		log.Error("supervise: could not remove the FAILED proxy's port file", "path", port, "err", err)
	}

	// (ii) 04 :655's duty — no capture-affecting state change without a
	// transition event. FAILED is terminal for this daemon's proxy, so the
	// window this opens has no in-process close: it is emitted as a bypass
	// START (window 0) and the next transition on this surface bounds it.
	//
	// Device-wide, not per-workspace: one proxy serves every enabled root, so
	// there is no single workspace this degraded. See coverage.DeviceWide for
	// what that costs the band query.
	err = cov.Transition(context.Background(), m1pv1.CoverageKind_COVERAGE_KIND_BYPASS,
		coverage.DeviceWide(), coverage.ReasonProxyFailed, 0)
	if err != nil {
		// Loud, and worded as a gap: an unreceipted bypass window is
		// indistinguishable downstream from full coverage.
		log.Error("COVERAGE BYPASS NOT RECEIPTED — this is a gap, not a warning",
			"reason_code", coverage.ReasonProxyFailed, "err", err)
		return
	}
	log.Warn("supervise: proxy bypass window receipted", "reason_code", coverage.ReasonProxyFailed)
}

func removePort(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FindProxy resolves the sidecar binary, in the order a machine can answer.
//
// The assumption this names, because the repo has no existing rule for finding
// a sibling binary: a packaged install puts mark1d and mark1-proxy in ONE
// directory. That is the same shape 08 §8.1 already uses for the shim
// (`~/.omium/mark1/bin/mark1-hookshim`, docs/design/08-api-contracts.md:969), and it is
// the only rung that holds for an installed user with no PATH entry. It does
// NOT hold in this repo's own build: `just build-edge` writes dist/mark1d and
// target/release/mark1-proxy, which is why MARK1_PROXY and PATH follow it.
func FindProxy() (string, error) { return findBinary(proxyBinary, proxyBinaryEnv, ErrNoProxyBinary) }

// FindCortexd resolves the per-workspace cortexd child by the same rule, with
// MARK1_CORTEXD as its dev seam.
func FindCortexd() (string, error) {
	return findBinary(cortexdBinary, cortexdBinaryEnv, ErrNoCortexdBinary)
}

// FindVerifier: the offline receipt verifier ships beside mark1d since edge/v0.1.4; MARK1_VERIFIER is its dev seam.
func FindVerifier() (string, error) {
	return findBinary("mark1-verifier", "MARK1_VERIFIER", ErrNoVerifierBinary)
}

func findBinary(name, envVar string, missing error) (string, error) {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if p := os.Getenv(envVar); p != "" {
		// An operator-set path that is wrong is an error, never a fallthrough:
		// silently searching elsewhere would run a different binary than the
		// one they named.
		if err := isFile(p); err != nil {
			return "", fmt.Errorf("%w: %s=%s: %w", missing, envVar, p, err)
		}
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), name)
		if isFile(sibling) == nil {
			return sibling, nil
		}
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: not beside this binary, not on PATH, and %s is unset", missing, envVar)
	}
	return p, nil
}

// IsFile is the lookup's file check, exported for the cortex plane's Binary
// override so an override that does not exist fails before the supervisor
// exists, exactly as ProxyChild's does.
func IsFile(p string) error { return isFile(p) }

func isFile(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return errors.New("is a directory")
	}
	return nil
}

// proxyHome derives the HOME the child must run under.
//
// mark1-proxy takes no state-dir flag: it computes its own base as
// `$HOME/.omium/mark1` (rust/mark1-proxy/src/main.rs, config()), and that base
// is where it publishes proxy.port and reads guard.key, registry and the OFF
// marker from. A daemon started with any other --state-dir would therefore
// supervise a proxy publishing its port where the provisioner never looks and
// admitting against a registry nobody writes — a split brain whose only symptom
// is that everything refuses. So the child's HOME is set to make the proxy's
// derived base BE the daemon's state dir. On the default --state-dir this is
// exactly the value the child would have inherited anyway.
func proxyHome(stateDir string) (string, error) {
	if stateDir == "" {
		return "", errors.New("supervise: no state dir")
	}
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return "", err
	}
	home := filepath.Dir(filepath.Dir(abs))
	if filepath.Join(home, ".omium", "mark1") != abs {
		return "", fmt.Errorf("supervise: %s derives its state root as $HOME/.omium/mark1 and has no flag to override it; --state-dir %s cannot be expressed that way, so the proxy is not supervised", proxyBinary, abs)
	}
	return home, nil
}

func childEnv(home string) []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+2)
	for _, kv := range parent {
		k, _, _ := strings.Cut(kv, "=")
		// EqualFold because Windows environment names are case-insensitive: a
		// surviving `Home=` would win over the `HOME=` appended below.
		if strings.EqualFold(k, "HOME") || strings.EqualFold(k, "USERPROFILE") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "HOME="+home, "USERPROFILE="+home)
}
