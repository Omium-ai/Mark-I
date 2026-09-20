package tailers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
)

// Config wires one workspace's transcript directory to the admission door.
type Config struct {
	// Dir is the vendor transcript directory for one enabled workspace:
	// ~/.claude/projects/<munged-cwd>/ (08 §5.1). Deriving it from the enabled
	// root does NOT prove containment — the '/'→'-' munge is lossy
	// (…/foo/bar and …/foo-bar share one dir) — which is why Allowed exists.
	Dir      string
	StateDir string // cursor store, 0700
	// Allowed is the WorkspaceSet oracle (04 §0.3 invariant 3), consulted on
	// every file DISCOVERY against the transcript's own cwd: a stream whose
	// cwd resolves outside an enabled root is never tailed, full stop
	// (04 §2.1). Required — there is no gate-less mode.
	Allowed func(absCwd string) bool
	// UsageIdemKey is the tenant usage-idem key (DeriveUsageIdemKey). The
	// tenant HMAC root arrives with enrollment (04 §2.9) — a config seam
	// here, custody there.
	UsageIdemKey []byte
	// Observe runs on every Usage BEFORE Emit — the segmenter's task_id stamp (ADR-0002), so Emit's decorators see it. nil is legal.
	Observe      func(*m1pv1.Event)
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
	PollInterval time.Duration    // discovery/quiesce tick; default 500 ms
	Now          func() time.Time // injectable clock for the quiesce debounce
	// Format is the vendor stream layout; the zero value is claudecode's.
	Format Format
	// Agent names the vendor in Sessions(); Roots (the oracle's enabled roots) lets each session carry the root that admitted it. Both optional.
	Agent string
	Roots func() []string
	// BackfillWindow bounds how much history a never-tailed transcript imports (founder ruling 2026-09-19: BackfillWindow). 0 imports everything, today's behaviour, which corpus replays rely on.
	BackfillWindow time.Duration
}

// SessionInfo is one admitted session as the control API needs it: the vendor, the enabled root its cwd fell under, and when this manager first opened one of its streams.
type SessionInfo struct {
	Agent   string
	Root    string
	Cwd     string
	Started time.Time
}

// Format is one vendor's stream format: how streams are found under Dir, where
// a line carries its cwd, and how a usage line parses. Each nil field is
// claudecode's (08 §5.1) — an adapter overrides only what differs.
type Format struct {
	// Discover calls open for every candidate stream under dir.
	Discover func(dir string, open func(path string, role Role, session uuid.UUID))
	// Cwd returns the cwd a line attributes itself to, "" when it carries none.
	Cwd func(line []byte) string
	// NewParser returns a per-stream line parser (a stream may keep state).
	NewParser func() func(line []byte) (Line, bool)
}

// Manager discovers and follows every stream under one transcript dir:
// <session>.jsonl parents and <session>/subagents/*.jsonl subagent streams,
// each tailed under the PARENT session_id (04 §2.1).
type Manager struct {
	cfg    Config
	ts     map[string]*Tailer // by path
	cwds   map[string]string  // open stream -> the cwd its admission was granted on
	denied map[string]bool    // cwd resolved outside the read surface — final per path

	mu       sync.Mutex // sessions only: written on the Run goroutine, read by Resolve on the control API's
	sessions map[uuid.UUID]SessionInfo
}

// fleet is every Manager inside Run, the table Resolve reads.
// ponytail: process-wide so main.go wires the control hub in one line; thread a fleet value through StartTail if two daemons ever share a process.
var fleet = struct {
	sync.Mutex
	m map[*Manager]struct{}
}{m: map[*Manager]struct{}{}}

// Resolve answers session -> (agent, root) across every running Manager: the control hub's first stop for agents_live, ahead of the Claude Code transcript-head fallback, because a derived (UUIDv5) session id is known only to its vendor's tailer.
func Resolve(id uuid.UUID) (agent, root string, ok bool) {
	fleet.Lock()
	defer fleet.Unlock()
	for m := range fleet.m {
		m.mu.Lock()
		s, hit := m.sessions[id]
		m.mu.Unlock()
		if hit {
			return s.Agent, s.Root, true
		}
	}
	return "", "", false
}

// Sessions is the read-only session table: every session with an admitted stream since the last CloseFlush, keyed by the PARENT session id.
func (m *Manager) Sessions() map[uuid.UUID]SessionInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.sessions)
}

// enclosingRoot is the innermost enabled root containing cwd, canonicalized the way rootSet.Allowed canonicalizes, "" when none (an oracle-admitted cwd always has one).
func enclosingRoot(roots []string, cwd string) string {
	if abs, err := filepath.Abs(cwd); err == nil {
		cwd = abs
	}
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = resolved
	}
	best := ""
	for _, r := range roots {
		if (cwd == r || strings.HasPrefix(cwd, r+string(filepath.Separator))) && len(r) > len(best) {
			best = r
		}
	}
	return best
}

// RecentCwds is the adapters' recent_projects reader: the cwd each stream head names, newest file first, de-duplicated, only directories still on disk; limit <= 0 is unbounded.
func RecentCwds(paths []string, cwdOf func([]byte) string, limit int) []string {
	type file struct {
		path string
		mod  time.Time
	}
	files := make([]file, 0, len(paths))
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil {
			files = append(files, file{p, fi.ModTime()})
		}
	}
	slices.SortFunc(files, func(a, b file) int { return b.mod.Compare(a.mod) })
	out := []string{}
	for _, f := range files {
		if limit > 0 && len(out) >= limit {
			break
		}
		cwd, ok := peekCwd(f.path, cwdOf)
		if !ok || slices.Contains(out, cwd) {
			continue
		}
		if fi, err := os.Stat(cwd); err != nil || !fi.IsDir() {
			continue
		}
		out = append(out, cwd)
	}
	return out
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.Allowed == nil {
		// Structural, like capture's Redact: a nil oracle would silently tail
		// whatever the lossy munge collides into the vendor dir (invariant 3).
		return nil, errors.New("tailers: Allowed is required; discovery has no gate-less mode (04 §2.1)")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	return &Manager{cfg: cfg, ts: map[string]*Tailer{}, cwds: map[string]string{}, denied: map[string]bool{}, sessions: map[uuid.UUID]SessionInfo{}}, nil
}

// Run follows the directory until ctx ends, then drains: every pending Usage
// flushes (the shutdown emission trigger, 04 §2.1) and cursors persist.
// fsnotify shortens discovery latency; the tick is the correctness path —
// watcher loss only degrades to polling, exactly 04 §2.1's overflow posture.
// ponytail: one goroutine sweeps all streams instead of 04 §2.1's
// per-stream goroutines — same observable behavior; split if one giant
// transcript's backlog ever delays siblings measurably.
func (m *Manager) Run(ctx context.Context) error {
	fleet.Lock()
	fleet.m[m] = struct{}{}
	fleet.Unlock()
	defer func() {
		fleet.Lock()
		delete(fleet.m, m)
		fleet.Unlock()
	}()
	w, werr := fsnotify.NewWatcher()
	var events chan fsnotify.Event
	if werr == nil {
		defer func() { _ = w.Close() }()
		_ = w.Add(m.cfg.Dir) // may not exist yet; the tick retries below
		events = make(chan fsnotify.Event)
		go func() {
			defer close(events)
			for {
				select {
				case ev, ok := <-w.Events:
					if !ok {
						return
					}
					select {
					case events <- ev:
					case <-ctx.Done():
						return
					}
				case _, ok := <-w.Errors:
					if !ok {
						return
					}
					// Watcher trouble (overflow included) is latency, not
					// loss: the tick below still sweeps everything.
				}
			}
		}()
	} else {
		m.cfg.Log.Warn("tailers: fsnotify unavailable, polling only", "err", werr)
	}
	tick := time.NewTicker(m.cfg.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return m.CloseFlush(context.WithoutCancel(ctx))
		case <-events:
			m.Sweep(ctx)
		case <-tick.C:
			if w != nil {
				_ = w.Add(m.cfg.Dir) // idempotent; picks the dir up once it exists
			}
			m.Sweep(ctx)
		}
	}
}

// Sweep is one discovery+poll pass over every stream. Failure posture is
// fail-open per stream: one stream's I/O error logs and never stops siblings
// (04 §2.1).
func (m *Manager) Sweep(ctx context.Context) {
	m.discover()
	m.revoke()
	now := m.cfg.Now()
	for path, t := range m.ts {
		if err := t.poll(now, m.emitAll(ctx)); err != nil {
			m.cfg.Log.Error("tailers: stream poll failed", "path", path, "err", err)
		}
		if t.gone {
			t.close()
			delete(m.ts, path)
		}
	}
}

// revoke re-asks the oracle about every OPEN stream. 04 §2.1 says the
// WorkspaceSet is "consulted on every file DISCOVERY, not just once" — and
// admission is not a one-time grant: a `.mark1ignore` written mid-session, or
// a `mark1 disable`, must stop the stream before its next line. Pending Usage
// is DROPPED rather than flushed: the customer's last word wins, so a
// half-buffered event from a now-excluded tree must not escape on the way out.
// ponytail: one oracle call per open stream per tick (a stat plus a symlink
// resolve); memoize per (cwd, tick) if stream counts ever reach the hundreds.
func (m *Manager) revoke() {
	for path, t := range m.ts {
		if m.cfg.Allowed(m.cwds[path]) {
			continue
		}
		m.denied[path] = true
		t.close()
		delete(m.ts, path)
		delete(m.cwds, path)
		m.mu.Lock()
		delete(m.sessions, t.str.session)
		m.mu.Unlock()
		m.cfg.Log.Warn("tailers: stream left the consented read surface mid-session; closed, pending dropped (04 §2.1)",
			"path", path)
	}
}

// CloseFlush drains every stream (read to EOF, flush pending, persist
// cursors) and closes handles. Used at shutdown and by the Stop-hook path
// once the shim lands.
func (m *Manager) CloseFlush(ctx context.Context) error {
	m.discover()
	m.revoke()
	now := m.cfg.Now()
	var firstErr error
	for _, t := range m.ts {
		if err := t.readLines(now, m.emitAll(ctx)); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := t.flushAndSave(m.emitAll(ctx)); err != nil && firstErr == nil {
			firstErr = err
		}
		t.close()
	}
	m.ts = map[string]*Tailer{}
	m.cwds = map[string]string{}
	m.mu.Lock()
	m.sessions = map[uuid.UUID]SessionInfo{}
	m.mu.Unlock()
	return firstErr
}

func (m *Manager) emitAll(ctx context.Context) func([]*m1pv1.Event) error {
	return func(evs []*m1pv1.Event) error {
		for _, ev := range evs {
			if m.cfg.Observe != nil {
				m.cfg.Observe(ev)
			}
			if err := m.cfg.Emit(ctx, ev); err != nil {
				return err
			}
		}
		return nil
	}
}

// discover walks the two vendor layouts (08 §5.1): parent sessions at
// <dir>/<session-uuid>.jsonl and subagent streams at
// <dir>/<session-uuid>/subagents/agent-<id>.jsonl.
func (m *Manager) discover() {
	if m.cfg.Format.Discover != nil {
		m.cfg.Format.Discover(m.cfg.Dir, m.open)
		return
	}
	// A session started in a SUBFOLDER of the enabled root writes to its own munged dir (<root munge>-<rest>), a sibling of Dir: those are this workspace's too — the founder's sessions in a package dir read "0 tokens" — and Allowed re-checks every stream's own cwd against the root, so the lossy munge admits nothing on its own.
	m.discoverDir(m.cfg.Dir)
	parent, base := filepath.Dir(m.cfg.Dir), filepath.Base(m.cfg.Dir)
	siblings, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, e := range siblings {
		if e.IsDir() && strings.HasPrefix(e.Name(), base+"-") {
			m.discoverDir(filepath.Join(parent, e.Name()))
		}
	}
}

func (m *Manager) discoverDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // dir not there yet — the tick retries
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() {
			session, ok := sessionFromName(name)
			if !ok {
				continue
			}
			m.open(filepath.Join(dir, name), RoleParent, session)
			continue
		}
		session, err := uuid.Parse(name)
		if err != nil {
			continue
		}
		subDir := filepath.Join(dir, name, "subagents")
		subs, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, s := range subs {
			if s.IsDir() || !strings.HasSuffix(s.Name(), ".jsonl") {
				continue
			}
			m.open(filepath.Join(subDir, s.Name()), RoleSubagent, session)
		}
	}
}

func (m *Manager) open(path string, role Role, session uuid.UUID) {
	if _, ok := m.ts[path]; ok || m.denied[path] {
		return
	}
	// Containment gate on the stream's OWN cwd (invariant 3): the fallback
	// discovery path has no hook payload carrying cwd, so attribution reads
	// the stream head — and nothing else — before any tailing begins. No cwd
	// yet (empty/torn head) means unattributable: not tailed, re-peeked next
	// sweep. Denial is final per path: a transcript's cwd provenance is fixed
	// at its head, so there is nothing to re-ask.
	cwd, ok := peekCwd(path, m.cfg.Format.Cwd)
	if !ok {
		return
	}
	if !m.cfg.Allowed(cwd) {
		m.denied[path] = true
		m.cfg.Log.Warn("tailers: stream cwd outside the consented read surface (enabled roots + .mark1ignore), never tailed (04 §2.1)",
			"path", path, "cwd", cwd)
		return
	}
	str := stream{role: role, session: session, idemKey: m.cfg.UsageIdemKey}
	if m.cfg.Format.NewParser != nil {
		str.parse = m.cfg.Format.NewParser()
	}
	t, err := newTailer(path, m.cfg.StateDir, str, m.cfg.Now(), m.cfg.BackfillWindow)
	if err != nil {
		m.cfg.Log.Error("tailers: open failed", "path", path, "err", err)
		return
	}
	m.ts[path] = t
	m.cwds[path] = cwd
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.sessions[session]; dup && role != RoleParent {
		return // a subagent stream rides its parent's row, whichever was discovered first
	}
	root := ""
	if m.cfg.Roots != nil {
		root = enclosingRoot(m.cfg.Roots(), cwd)
	}
	m.sessions[session] = SessionInfo{Agent: m.cfg.Agent, Root: root, Cwd: cwd, Started: m.cfg.Now()}
}

// peekCwd bounds for the containment gate: v2.1.251 stamps cwd on every line
// (the conformance fixtures pin it), so the head is authoritative; the line
// budget only tolerates leading noise lines that lost theirs.
const (
	peekMaxLines    = 64
	peekMaxLineSize = 1 << 20
)

// peekCwd reads the head of a candidate stream for its first non-empty cwd —
// the containment evidence 04 §2.1 keys discovery on. Returns ok=false when
// none is readable yet (empty file, torn head): unattributable, so not tailed.
func peekCwd(path string, cwdOf func([]byte) string) (string, bool) {
	if cwdOf == nil {
		cwdOf = topLevelCwd
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }() // read-only peek; nothing to lose on close
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), peekMaxLineSize)
	for n := 0; sc.Scan() && n < peekMaxLines; n++ {
		if cwd := cwdOf(sc.Bytes()); cwd != "" {
			return cwd, true
		}
	}
	return "", false
}

func topLevelCwd(line []byte) string {
	var l struct {
		Cwd string `json:"cwd"`
	}
	if json.Unmarshal(line, &l) != nil {
		return ""
	}
	return l.Cwd
}

func sessionFromName(name string) (uuid.UUID, bool) {
	base, ok := strings.CutSuffix(name, ".jsonl")
	if !ok {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(base)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}
