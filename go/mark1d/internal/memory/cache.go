package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

const (
	pathArtifacts = "/api/v1/memory/artifacts"
	pathMatch     = "/api/v1/memory/match"
	bodyLimit     = 8 << 20
	defaultPoll   = 15 * time.Minute
	defaultMaxAge = 7 * 24 * time.Hour
	// defaultPackTokens is D-AF's residual after the 2k map: ~2,000 characters for pack plus envelope.
	defaultPackTokens = 500
	// MInject is 06 §9.5 D30: at most three artifacts attributed per task.
	MInject = 3
	// matchBudget bounds the server fuzz tier (06 §9.5 D29) when the shim states no deadline.
	matchBudget = 1500 * time.Millisecond
	matchMargin = 50 * time.Millisecond
	cacheFile   = "artifacts.json"
)

// Artifact is one row of the retrieval route's JSON (python/intel/app/memory/routes.py).
type Artifact struct {
	ID        string  `json:"artifact_id"`
	Kind      string  `json:"kind"`
	Trigger   string  `json:"trigger"`
	Guidance  string  `json:"guidance"`
	LCB       float64 `json:"utility_lcb"`
	SigDigest string  `json:"error_sig_digest,omitempty"`
}

// injectable is the allowlist twin of retrieve.INJECTABLE_KINDS: routing hints (DB 'preference') and any unknown kind never render.
var injectable = map[string]bool{"pitfall": true, "fix_pattern": true, "invariant": true}

type Config struct {
	StateDir    string
	BaseURL     string // "" = never fetch: last-known-good forever
	Token       string
	EdgeVersion string
	Log         *slog.Logger
	// PackTokensMax is the bundle memory section's budget; 0 = defaultPackTokens.
	PackTokensMax uint64
	Admit         func(context.Context, *m1pv1.Event) error
	TaskFor       func(session, want [16]byte) ([16]byte, bool)
	Verdict       func(task [16]byte) (*m1pv1.VerdictEvent, bool)

	HTTPClient *http.Client
	Now        func() time.Time
	Poll       time.Duration
	MaxAge     time.Duration

	// Profiles is the ADR-0013 per-session host-profile registry; nil, or an
	// unknown session, reads as hostprofile.Default. record reads it and
	// logs it once per session; it decides nothing on it in this revision
	// (Part 5 selects the memory sink from OwnsMemory).
	Profiles *hostprofile.Registry
}

// ProfileFor is the session's host profile as memory sees it, logged at
// debug the first time a session is asked for.
func (c *Cache) ProfileFor(session [16]byte) hostprofile.Profile {
	p := hostprofile.Default
	if c.cfg.Profiles != nil {
		p = c.cfg.Profiles.Get(session)
	}
	if _, seen := c.profileSeen.LoadOrStore(session, struct{}{}); !seen && c.cfg.Log != nil {
		c.cfg.Log.Debug("memory: host profile", "session", hex.EncodeToString(session[:]), "host_id", p.HostID, "owns_memory", p.OwnsMemory, "default", p.IsDefault())
	}
	return p
}

type custody struct {
	SyncedAt  time.Time  `json:"synced_at"`
	Artifacts []Artifact `json:"artifacts"`
}

type taskState struct {
	session [16]byte
	ids     [][]byte
	seen    map[string]bool
	packed  bool
}

type Cache struct {
	profileSeen sync.Map // session → struct{}: the ADR-0013 profile line is logged once
	cfg         Config
	dir         string
	http        *http.Client
	now         func() time.Time

	mu    sync.Mutex
	lkg   custody
	tasks map[[16]byte]*taskState
}

// CustodyPath is the synced artifact file cortexd's memory_recall reads (--memory-file).
func CustodyPath(stateDir string) string { return filepath.Join(stateDir, "memory", cacheFile) }

func New(cfg Config) (*Cache, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("memory: StateDir required")
	}
	c := &Cache{cfg: cfg, dir: filepath.Dir(CustodyPath(cfg.StateDir)), http: cfg.HTTPClient, now: cfg.Now, tasks: map[[16]byte]*taskState{}}
	if c.cfg.Log == nil {
		c.cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	if c.http == nil {
		c.http = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.cfg.Poll <= 0 {
		c.cfg.Poll = defaultPoll
	}
	if c.cfg.MaxAge <= 0 {
		c.cfg.MaxAge = defaultMaxAge
	}
	if c.cfg.PackTokensMax == 0 {
		c.cfg.PackTokensMax = defaultPackTokens
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(filepath.Join(c.dir, cacheFile)); err == nil {
		var cu custody
		if json.Unmarshal(raw, &cu) == nil {
			c.lkg = custody{SyncedAt: cu.SyncedAt, Artifacts: keep(cu.Artifacts)}
		}
	}
	return c, nil
}

func keep(in []Artifact) []Artifact {
	out := make([]Artifact, 0, len(in))
	for _, a := range in {
		if injectable[a.Kind] && a.ID != "" {
			out = append(out, a)
		}
	}
	return out
}

// Run syncs on a fixed cadence until ctx is done; every failure keeps the last-known-good.
func (c *Cache) Run(ctx context.Context) {
	for {
		if err := c.Sync(ctx); err != nil {
			c.cfg.Log.Warn("mark1d: memory sync failed; serving last-known-good", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(c.cfg.Poll):
		}
	}
}

func (c *Cache) request(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, r)
	if err != nil {
		return nil, err
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	req.Header.Set("X-Mark1-Edge-Version", c.cfg.EdgeVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *Cache) get(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := c.request(ctx, method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// Sync is one fetch of the admitted set; nothing below last-known-good is ever installed.
func (c *Cache) Sync(ctx context.Context) error {
	if c.cfg.BaseURL == "" {
		return nil
	}
	var res struct {
		Artifacts []Artifact `json:"artifacts"`
	}
	if err := c.get(ctx, http.MethodGet, pathArtifacts, nil, &res); err != nil {
		return err
	}
	cu := custody{SyncedAt: c.now().UTC(), Artifacts: keep(res.Artifacts)}
	raw, err := json.Marshal(cu)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.lkg = cu
	c.mu.Unlock()
	tmp := filepath.Join(c.dir, cacheFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.dir, cacheFile))
}

// Purge is 04 §2.9's revocation step 2: the synced cache is dropped, on disk and in memory.
func (c *Cache) Purge() {
	c.mu.Lock()
	c.lkg = custody{}
	c.mu.Unlock()
	_ = os.Remove(filepath.Join(c.dir, cacheFile))
}

// artifacts is the servable set: empty once the last sync is older than MaxAge (fail-static has a clock, like the bundle).
func (c *Cache) artifacts() []Artifact {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lkg.SyncedAt.IsZero() || c.now().Sub(c.lkg.SyncedAt) > c.cfg.MaxAge {
		return nil
	}
	return c.lkg.Artifacts
}

func (c *Cache) state(session, task [16]byte) *taskState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.tasks[task]
	if st == nil {
		st = &taskState{session: session, seen: map[string]bool{}}
		c.tasks[task] = st
	}
	return st
}

func (c *Cache) Context(ctx context.Context, q fabric.ContextQuery, session [16]byte) string {
	if c.cfg.TaskFor == nil || c.cfg.Admit == nil {
		return ""
	}
	task, ok := c.cfg.TaskFor(session, [16]byte{})
	if !ok || task == ([16]byte{}) {
		return ""
	}
	switch q.Channel {
	case uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT):
		return c.pack(ctx, session, task)
	case uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL):
		if q.IsInterrupt {
			return ""
		}
		return c.pitfall(ctx, session, task, q)
	}
	return ""
}

// OnClose emits one ArtifactOutcome per artifact injected into the task (06 §9.5: attribution only for sets ≤ MInject).
func (c *Cache) OnClose(task [16]byte) {
	c.mu.Lock()
	st := c.tasks[task]
	delete(c.tasks, task)
	c.mu.Unlock()
	if st == nil || len(st.ids) == 0 || len(st.ids) > MInject || c.cfg.Admit == nil {
		return
	}
	verdict := m1pv1.Verdict_VERDICT_UNSPECIFIED
	if c.cfg.Verdict != nil {
		if ve, ok := c.cfg.Verdict(task); ok {
			verdict = ve.GetVerdict()
		}
	}
	for _, id := range st.ids {
		ev := c.event(st.session, task)
		// ponytail: artifact_followed stays false; no edge signal distinguishes followed from ignored advice yet.
		ev.Body = &m1pv1.Event_ArtifactOutcome{ArtifactOutcome: &m1pv1.ArtifactOutcome{ArtifactId: id, TaskVerdict: verdict}}
		if err := c.cfg.Admit(context.Background(), ev); err != nil {
			c.cfg.Log.Warn("mark1d: ArtifactOutcome not admitted", "err", err)
		}
	}
}
