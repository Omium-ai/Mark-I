package anchors

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// TaskBase is where a task's diff starts: its repository and that repository's HEAD when the task opened ("" = no commit yet).
type TaskBase struct {
	Top  string    `json:"top"`
	Head string    `json:"head,omitempty"`
	At   time.Time `json:"at"`
}

type baseEntry struct {
	done chan struct{} // closed once the open-time HEAD read settled
	b    TaskBase
	ok   bool // the read answered; false leaves the task on HEAD
}

const (
	baseKeep = 7 * 24 * time.Hour // every consumer reads the diff at close; a week covers a task left open over a weekend
	baseMax  = 4096
)

// TaskBasesPath persists the bases so a daemon restart mid-task keeps them.
func TaskBasesPath(stateDir string) string {
	return filepath.Join(stateDir, "anchors", "task_bases.json")
}

// Observe records the base of every TaskOpen, in the repository RepoFor names for its session; nil RepoFor records nothing.
func (r *Runner) Observe(ev *m1pv1.Event) {
	if ev.GetTaskOpen() == nil || len(ev.GetTaskId()) != 16 || len(ev.GetSessionId()) != 16 || r.RepoFor == nil {
		return
	}
	var task, session [16]byte
	copy(task[:], ev.GetTaskId())
	copy(session[:], ev.GetSessionId())
	r.OpenTask(task, r.RepoFor(session))
}

// OpenTask reads repo's HEAD for task off the caller's path; a reopened task keeps its first base.
// ponytail: the read lands tens of ms after TaskOpen; an agent committing inside that window moves the base with it.
func (r *Runner) OpenTask(task [16]byte, repo string) {
	top := GitTop(repo)
	if repo == "" || !isRepo(top) {
		return
	}
	r.mu.Lock()
	r.loadBases()
	if _, seen := r.bases[task]; seen {
		r.mu.Unlock()
		return
	}
	e := &baseEntry{done: make(chan struct{})}
	r.bases[task] = e
	r.mu.Unlock()
	go func() {
		defer close(e.done)
		b := TaskBase{Top: top, At: time.Now().UTC()}
		g := r.gitRun(context.Background(), repo, nil, "rev-parse", "--verify", "-q", "HEAD^{commit}")
		switch {
		case g.abstain == "":
			b.Head = strings.TrimSpace(string(g.out))
		case g.code != 1: // 1 is "no commit yet"; anything else leaves the task on HEAD
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		e.b, e.ok = b, true
		r.saveBases()
	}()
}

// baseFor waits out a pending open-time read and returns the task's base; false for no task, no record or a failed read.
func (r *Runner) baseFor(ctx context.Context, task [16]byte) (TaskBase, bool) {
	if task == ([16]byte{}) {
		return TaskBase{}, false
	}
	r.mu.Lock()
	r.loadBases()
	e := r.bases[task]
	r.mu.Unlock()
	if e == nil {
		return TaskBase{}, false
	}
	select {
	case <-e.done:
	case <-ctx.Done():
		return TaskBase{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return e.b, e.ok
}

// loadBases reads the persisted bases once; r.mu held.
func (r *Runner) loadBases() {
	if r.bases != nil {
		return
	}
	r.bases = map[[16]byte]*baseEntry{}
	if r.StateDir == "" {
		return
	}
	b, err := os.ReadFile(TaskBasesPath(r.StateDir))
	var disk map[string]TaskBase
	if err != nil || json.Unmarshal(b, &disk) != nil {
		return
	}
	for k, v := range disk {
		var task [16]byte
		if raw, err := hex.DecodeString(k); err == nil && len(raw) == 16 && time.Since(v.At) < baseKeep {
			copy(task[:], raw)
			done := make(chan struct{})
			close(done)
			r.bases[task] = &baseEntry{done: done, b: v, ok: true}
		}
	}
}

// saveBases drops bases past baseKeep, keeps the newest baseMax and rewrites the file; r.mu held.
func (r *Runner) saveBases() {
	type kv struct {
		k [16]byte
		b TaskBase
	}
	var live []kv
	for k, e := range r.bases {
		if e.ok && time.Since(e.b.At) >= baseKeep {
			delete(r.bases, k)
		} else if e.ok {
			live = append(live, kv{k, e.b})
		}
	}
	slices.SortFunc(live, func(a, b kv) int { return b.b.At.Compare(a.b.At) })
	for _, x := range live[min(len(live), baseMax):] {
		delete(r.bases, x.k)
	}
	if r.StateDir == "" {
		return
	}
	disk := map[string]TaskBase{}
	for _, x := range live[:min(len(live), baseMax)] {
		disk[hex.EncodeToString(x.k[:])] = x.b
	}
	if b, err := json.Marshal(disk); err == nil {
		_ = writePrivate(TaskBasesPath(r.StateDir), b)
	}
}

// TaskDiffFor is TaskDiff from the base recorded at the task's open: what the task committed, staged and left in the tree, plus its untracked files; nil with a typed reason in diff_status.json otherwise.
func (r *Runner) TaskDiffFor(ctx context.Context, task [16]byte, worktree string) []byte {
	t := r.readTree(ctx, worktree, 3, task)
	if t.abstain != "" {
		return nil
	}
	return t.raw
}
