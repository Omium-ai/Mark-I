// Package cortex is the daemon half of 04 §6: one supervised `cortexd` per
// enabled workspace (04 :80, NFR-AVAILABILITY-004), the session identity it
// Hellos with, and the consumer that turns its L0 root pushes into
// AnchorIntegrity.worktree_merkle_root (04 §6.7, FR-CORTEX-001).
//
// THE SESSION IDENTITY, and why it is a file. D-AT: every fabric writer Hellos
// with a 16-byte non-zero session_id, and D-AV struck cortexd's exemption —
// its pushes stay refused until it has one. The proto is frozen, so the
// identity reaches cortexd out of band: the daemon publishes the live session
// of each enabled workspace at <state>/run/sessions/<workspace-id>.json
// (0600, `{"session_id_hex","started_at"}`, removed on SessionEnd), and
// cortexd reads that file before each push. Every writer the daemon admits is
// therefore sessioned, literally; with no live session cortexd HOLDS its push,
// which is not a drop (fabric_dropped counts nothing for it).
//
// WHICH session belongs to WHICH workspace is the part the wire does not say:
// SessionStart.workspace_id ships empty (the shim has no tenant key) and no
// hook body carries a cwd (paths are content). The one honest oracle on the
// machine is the vendor's own transcript layout — a session's transcript lives
// at ~/.claude/projects/<munged-root>/<session>.jsonl (08 §5.1), so a stat of
// that path inside an ENABLED root's project dir is the vendor stating the
// session's cwd. That is the same read surface the tailers already own
// (claudecode.Surfaces), a stat and never a read, retried on each of the
// session's events until it resolves (the file appears with the first prompt,
// not at SessionStart). A session in no enabled root resolves to nothing and
// no file is written for it: attribution by guess is the lie D-AT exists to
// end, so the daemon refuses to guess.
// ponytail: mungeCwd is not injective (…/foo/bar vs …/foo-bar); two ENABLED
// roots that collide are excluded from resolution at New, but a session in an
// un-enabled sibling that collides with an enabled root still resolves to it.
// The tailers close that hole by reading the stream's own cwd line; this
// package does not read transcript content. Same ceiling as anchorWorktree's
// "one scheduler over the first root"; both lift when Hello carries a cwd.
package cortex

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/procattr"

	"github.com/google/uuid"
	"lukechampine.com/blake3"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/memory"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/supervise"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
)

const (
	// DefaultBudget mirrors cortexd's DEFAULT_BUDGET_TOKENS (04 §6.4: 2k
	// default, 8k ceiling) and is passed only when the bundle states none —
	// the daemon never invents a budget cortexd would not have used itself.
	DefaultBudget uint32 = 2000
	// stopGrace is how long SIGINT (cortexd's only stop: tokio ctrl_c) gets
	// before the kill. Every durable artifact (CAS, shards, l0.merkle) is
	// crash-safe by design (main.rs), so this is politeness, not persistence.
	stopGrace = 5 * time.Second
)

// Config is the daemon's hand-off. Roots are the enabled workspace roots as
// Roots returns them (canonical); Budget is BudgetFrom(bundle.cortex).
type Config struct {
	StateDir string
	Roots    []string
	Budget   uint32
	// Ranker is the boot bundle's cortex learned_ranker (nil = none); later
	// bundles arrive through SetRanker (bundle.Client.ApplyRanker).
	Ranker *policy.LearnedRanker
	Log    *slog.Logger
	// Binary overrides the lookup (test seam and packaging escape hatch).
	Binary string
	// Home overrides $HOME for the transcript-dir oracle (test seam).
	Home string
}

// BudgetFrom is NFR-FOOTPRINT-003's bundle-configured clause on the daemon
// side: the bundle's map_budget_tokens.max is the binary-search ceiling
// cortexd fits the map into. An absent section (built-ins, FR-POLICY-005)
// yields cortexd's own default; cortexd clamps whatever it is handed to
// 08 §6's [256, 8000], so the clamp is not duplicated here.
func BudgetFrom(sec policy.CortexSection) uint32 {
	if sec.MapBudgetTokensMax == 0 || sec.MapBudgetTokensMax > uint64(^uint32(0)) {
		return DefaultBudget
	}
	return uint32(sec.MapBudgetTokensMax)
}

// Roots is the enabled workspace set at session start: <state>/workspaces.json
// plus the --workspace override, canonicalized the way tailWorkspaces does
// (Abs + EvalSymlinks + dedupe) so a root names one workspace everywhere.
// ponytail: read once per daemon session, like superviseProxy reads the
// credential regime — an enable mid-session starts its cortexd on the next
// `mark1 off`/`on` cycle or restart.
func Roots(stateDir, extra string) ([]string, error) {
	roots, err := tailers.LoadWorkspacesFile(filepath.Join(stateDir, "workspaces.json"))
	if err != nil {
		return nil, err
	}
	if extra != "" {
		roots = append(roots, extra)
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range roots {
		abs, aerr := filepath.Abs(r)
		if aerr != nil {
			continue
		}
		if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
			abs = resolved
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out, nil
}

// WorkspaceID is cortexd's own store key (main.rs default_store): the first
// 16 hex chars of BLAKE3(canonical root). 07's HMAC_tenant(root) needs a
// tenant key an unenrolled daemon does not hold; this is the same recipe
// cortexd already uses, so the daemon's files and cortexd's store agree.
func WorkspaceID(root string) string {
	sum := blake3.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])[:16]
}

// SessionFile is where the daemon publishes root's live session for its
// cortexd: <state>/run/sessions/<workspace-id>.json.
func SessionFile(stateDir, root string) string {
	return filepath.Join(stateDir, "run", "sessions", WorkspaceID(root)+".json")
}

// sessionFile is the on-disk shape. cortexd parses it with serde
// (rust/cortexd/src/session/mod.rs LiveSession); the two are one contract.
type sessionFile struct {
	SessionIDHex string `json:"session_id_hex"`
	StartedAt    string `json:"started_at"`
}

// RankerFile is where the daemon publishes the applied bundle's learned
// ranker for every cortexd (`--ranker-file`): <state>/run/ranker.json. One
// file, not per workspace — the weights are tenant policy, not tree state.
func RankerFile(stateDir string) string {
	return filepath.Join(stateDir, "run", "ranker.json")
}

// rankerFile is the on-disk shape; cortexd parses it with serde
// (rust/cortexd/src/session/mod.rs RankerFile) through RankerWeights::new only.
type rankerFile struct {
	Stage        policy.RankerStage `json:"stage"`
	Weight       float64            `json:"weight"`
	Bias         float64            `json:"bias"`
	Coefficients [4]float64         `json:"coefficients"`
}

// SetRanker publishes r for the supervised cortexds, or removes the file when
// the bundle in force carries none. Called from New (boot) and from the bundle
// client's Run goroutine on every posture change; cortexd polls the file.
func (p *Plane) SetRanker(r *policy.LearnedRanker) {
	path := RankerFile(p.cfg.StateDir)
	if r == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			p.log.Error("cortex: stale ranker file could not be removed; cortexd keeps the old weights", "path", path, "err", err)
		}
		return
	}
	b, err := json.Marshal(rankerFile{Stage: r.Stage, Weight: r.Weight, Bias: r.Bias, Coefficients: r.Coefficients})
	if err == nil {
		err = writeAtomic(path, b)
	}
	if err != nil {
		p.log.Error("cortex: ranker file not published; cortexd serves PPR order", "path", path, "err", err)
	}
}

// writeAtomic is tmp + rename at 0600: cortexd reads these files between two
// of our writes and must never see a torn one.
func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Plane owns the per-workspace children and the session registry both they
// and the root consumer key on.
type Plane struct {
	cfg Config
	log *slog.Logger
	// dirs is the session→workspace oracle: root → its vendor transcript dir.
	dirs map[string]string

	mu        sync.Mutex
	live      map[[16]byte]string     // session → root; "" while unresolved
	published map[string][16]byte     // root → the session its file names
	set       map[string]func([]byte) // root → the runner's SetL0Root
}

// New builds the plane and clears run/sessions: a file left by a SIGKILLed
// daemon names a session this daemon cannot vouch for until it speaks again.
func New(cfg Config) (*Plane, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("cortex: no state dir")
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	dir := filepath.Join(cfg.StateDir, "run", "sessions")
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := &Plane{
		cfg: cfg, log: log,
		dirs:      map[string]string{},
		live:      map[[16]byte]string{},
		published: map[string][16]byte{},
		set:       map[string]func([]byte){},
	}
	p.SetRanker(cfg.Ranker)
	a := &claudecode.Adapter{Home: cfg.Home}
	byDir := map[string][]string{}
	for _, root := range cfg.Roots {
		d, err := a.TranscriptDir(root)
		if err != nil {
			return nil, err
		}
		byDir[d] = append(byDir[d], root)
	}
	for d, roots := range byDir {
		if len(roots) > 1 {
			// Two enabled roots the vendor files under one dir: a transcript
			// there says nothing about which root, so neither resolves.
			log.Warn("cortex: enabled roots share one transcript dir; sessions in them cannot be attributed and their cortexd pushes are held", "dir", d, "roots", roots)
			continue
		}
		p.dirs[roots[0]] = d
	}
	return p, nil
}

// OnRoot registers root's L0 consumer — anchors.Runner.SetL0Root in the
// daemon. root is canonicalized like Roots so the key matches. A push from a
// workspace with no consumer is admitted to the spool and goes no further.
func (p *Plane) OnRoot(root string, set func([]byte)) {
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
		if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
			root = resolved
		}
	}
	p.mu.Lock()
	p.set[root] = set
	p.mu.Unlock()
}

// Observe is the daemon's one call site, on the fabric handler after the
// Event decodes (cmd/main.go): it tracks the live sessions, resolves each to
// a workspace, publishes the session file, and routes an admitted
// CortexInjection's root_hash to that workspace's consumer.
func (p *Plane) Observe(ev *m1pv1.Event) {
	if len(ev.GetSessionId()) != 16 {
		return
	}
	var sid [16]byte
	copy(sid[:], ev.GetSessionId())
	if sid == ([16]byte{}) {
		return // D-AL: the sentinel addresses nothing
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ev.GetSessionEnd() != nil {
		p.end(sid)
		return
	}
	if ci := ev.GetCortexInjection(); ci != nil {
		// cortexd's own event is never evidence that its session is live —
		// only the agent's are — so a push under an ended session resolves
		// nothing and stamps nothing. The root is a true fact about the tree;
		// the attribution is not, and the next settle re-pushes it.
		root := p.live[sid]
		if fn := p.set[root]; root != "" && fn != nil && len(ci.GetRootHash()) == 32 {
			fn(ci.GetRootHash())
		}
		return
	}
	root, known := p.live[sid]
	if known && root != "" {
		return
	}
	if root = p.resolve(sid); root != "" {
		p.publish(root, sid)
	}
	p.live[sid] = root
}

// resolve is the transcript-dir stat, roots in sorted order for determinism.
func (p *Plane) resolve(sid [16]byte) string {
	roots := make([]string, 0, len(p.dirs))
	for r := range p.dirs {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	name := uuid.UUID(sid).String() + ".jsonl"
	for _, r := range roots {
		if _, err := os.Stat(filepath.Join(p.dirs[r], name)); err == nil {
			return r
		}
	}
	return ""
}

func (p *Plane) publish(root string, sid [16]byte) {
	if p.published[root] == sid {
		return
	}
	path := SessionFile(p.cfg.StateDir, root)
	b, err := json.Marshal(sessionFile{SessionIDHex: hex.EncodeToString(sid[:]), StartedAt: time.Now().UTC().Format(time.RFC3339)})
	if err == nil {
		err = writeAtomic(path, b)
	}
	if err != nil {
		p.log.Error("cortex: session file not published; cortexd holds its pushes", "path", path, "err", err)
		return
	}
	p.published[root] = sid
}

func (p *Plane) end(sid [16]byte) {
	root := p.live[sid]
	delete(p.live, sid)
	if root == "" || p.published[root] != sid {
		return
	}
	// Another session still live in this workspace inherits the file.
	for other, r := range p.live {
		if r == root {
			p.publish(root, other)
			return
		}
	}
	delete(p.published, root)
	if err := os.Remove(SessionFile(p.cfg.StateDir, root)); err != nil && !os.IsNotExist(err) {
		p.log.Error("cortex: stale session file could not be removed", "root", root, "err", err)
	}
}

// Supervise runs one cortexd per enabled root until ctx is cancelled and
// every child is reaped (04 :80's restart policy is supervise's). A missing
// binary is logged once and supervises nothing: the anchor plane then runs
// with incomplete integrity envelopes, which is a legible state, not a crash.
func (p *Plane) Supervise(ctx context.Context) {
	if len(p.cfg.Roots) == 0 {
		return
	}
	bin := p.cfg.Binary
	if bin == "" {
		var err error
		if bin, err = supervise.FindCortexd(); err != nil {
			p.log.Error("mark1d: cortexd not supervised — no root pushes, every anchor vote carries an incomplete integrity envelope", "err", err)
			return
		}
	} else if err := supervise.IsFile(bin); err != nil {
		p.log.Error("mark1d: cortexd not supervised", "err", fmt.Errorf("%w: %s: %w", supervise.ErrNoCortexdBinary, bin, err))
		return
	}
	s := supervise.New(p.log)
	for _, root := range p.cfg.Roots {
		s.Add(p.child(bin, root))
	}
	s.Run(ctx)
}

func (p *Plane) child(bin, root string) supervise.Child {
	budget := p.cfg.Budget
	if budget == 0 {
		budget = DefaultBudget
	}
	store := filepath.Join(p.cfg.StateDir, "cortex", WorkspaceID(root))
	file := SessionFile(p.cfg.StateDir, root)
	log := p.log.With("root", root)
	return supervise.Child{
		Name: "cortexd:" + WorkspaceID(root),
		Start: func(ctx context.Context) (*exec.Cmd, error) {
			// --store is explicit so the child's store follows --state-dir
			// rather than the $HOME cortexd would otherwise derive it from
			// (the split brain proxyHome exists to prevent). Not pre-created:
			// cortexd creates it 0700 and refuses a looser existing one.
			cmd := exec.CommandContext(ctx, bin, //nolint:gosec // G204: bin is FindCortexd() or an operator-set MARK1_CORTEXD; args are a fixed slice, no shell
				"--root", root, "--store", store,
				"--budget", strconv.FormatUint(uint64(budget), 10),
				"--session-file", file,
				"--memory-file", memory.CustodyPath(p.cfg.StateDir),
				"--ranker-file", RankerFile(p.cfg.StateDir))
			procattr.Hide(cmd)
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			cmd.Cancel = func() error {
				// SIGINT is the only stop cortexd listens for (tokio ctrl_c,
				// main.rs); Windows cannot deliver it, so there the kill is
				// the stop.
				if err := cmd.Process.Signal(os.Interrupt); err != nil {
					return cmd.Process.Kill()
				}
				return nil
			}
			cmd.WaitDelay = stopGrace
			return cmd, nil
		},
		// 04 §6.7: cortexd down ⇒ no fresh root ⇒ the envelope is incomplete.
		// Cleared at the instant the supervisor knows, so a vote cast between
		// the crash and the restart's first settle never carries a root the
		// tree may have moved past.
		OnExit: func(error) { p.clearRoot(root) },
		// FAILED is DIAGNOSTIC-ONLY for cortexd (04 :80 vs :81): it flips MCP
		// to refusals and marks anchor integrity incomplete — capture is
		// unaffected, no fragment is reverted, and no coverage bypass window
		// is receipted, because cortexd is not a capture surface and a
		// CoverageTransition here would claim a loss of capture that did not
		// happen.
		OnFailed: func() {
			log.Error("mark1d: cortexd FAILED — crash-loop breaker tripped; MCP tools refuse (M1E-6404) and anchor votes carry an incomplete integrity envelope for this workspace until restart; capture unaffected, nothing receipted",
				"operator_action", "restart mark1d after fixing the cause; `mark1 doctor` names it")
		},
	}
}

func (p *Plane) clearRoot(root string) {
	p.mu.Lock()
	fn := p.set[root]
	p.mu.Unlock()
	if fn != nil {
		fn(nil)
	}
}
