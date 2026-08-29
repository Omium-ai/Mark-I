package tailers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	Emit         func(context.Context, *m1pv1.Event) error
	Log          *slog.Logger
	PollInterval time.Duration    // discovery/quiesce tick; default 500 ms
	Now          func() time.Time // injectable clock for the quiesce debounce
}

// Manager discovers and follows every stream under one transcript dir:
// <session>.jsonl parents and <session>/subagents/*.jsonl subagent streams,
// each tailed under the PARENT session_id (04 §2.1).
type Manager struct {
	cfg    Config
	ts     map[string]*Tailer // by path
	denied map[string]bool    // cwd resolved outside the enabled roots — final per path
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
	return &Manager{cfg: cfg, ts: map[string]*Tailer{}, denied: map[string]bool{}}, nil
}

// Run follows the directory until ctx ends, then drains: every pending Usage
// flushes (the shutdown emission trigger, 04 §2.1) and cursors persist.
// fsnotify shortens discovery latency; the tick is the correctness path —
// watcher loss only degrades to polling, exactly 04 §2.1's overflow posture.
// ponytail: one goroutine sweeps all streams instead of 04 §2.1's
// per-stream goroutines — same observable behavior; split if one giant
// transcript's backlog ever delays siblings measurably.
func (m *Manager) Run(ctx context.Context) error {
	w, werr := fsnotify.NewWatcher()
	var events chan fsnotify.Event
	if werr == nil {
		defer w.Close()
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

// CloseFlush drains every stream (read to EOF, flush pending, persist
// cursors) and closes handles. Used at shutdown and by the Stop-hook path
// once the shim lands.
func (m *Manager) CloseFlush(ctx context.Context) error {
	m.discover()
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
	return firstErr
}

func (m *Manager) emitAll(ctx context.Context) func([]*m1pv1.Event) error {
	return func(evs []*m1pv1.Event) error {
		for _, ev := range evs {
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
	entries, err := os.ReadDir(m.cfg.Dir)
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
			m.open(filepath.Join(m.cfg.Dir, name), RoleParent, session)
			continue
		}
		session, err := uuid.Parse(name)
		if err != nil {
			continue
		}
		subDir := filepath.Join(m.cfg.Dir, name, "subagents")
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
	cwd, ok := peekCwd(path)
	if !ok {
		return
	}
	if !m.cfg.Allowed(cwd) {
		m.denied[path] = true
		m.cfg.Log.Warn("tailers: stream cwd outside enabled roots, never tailed (04 §2.1)",
			"path", path, "cwd", cwd)
		return
	}
	t, err := newTailer(path, m.cfg.StateDir, stream{
		role:    role,
		session: session,
		idemKey: m.cfg.UsageIdemKey,
	})
	if err != nil {
		m.cfg.Log.Error("tailers: open failed", "path", path, "err", err)
		return
	}
	m.ts[path] = t
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
func peekCwd(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }() // read-only peek; nothing to lose on close
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), peekMaxLineSize)
	for n := 0; sc.Scan() && n < peekMaxLines; n++ {
		var l struct {
			Cwd string `json:"cwd"`
		}
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Cwd != "" {
			return l.Cwd, true
		}
	}
	return "", false
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
