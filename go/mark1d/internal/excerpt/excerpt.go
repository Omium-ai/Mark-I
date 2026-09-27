// Package excerpt is the E1 evidence path's edge half (16 §Independence, L6/L7 cloud views): under the device's e1 consent, each closed task yields one redacted, receipted part (task intent NUL diff hunks) uploaded through the 08 §2.1 attach path, then an EvidenceExcerpt event naming it.
package excerpt

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/judge"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
)

const (
	// MaxPart is the whole sanitized part controld accepts; MaxIntent bounds the task text inside it.
	MaxPart   = 64 << 10
	MaxIntent = 1 << 10
	// rawBudget leaves room for redaction tokens, which can be longer than the span they replace.
	rawBudget  = MaxPart - MaxIntent - 4<<10
	retryEvery = 5 * time.Minute
	queueDepth = 256
	maxSeen    = 4096
)

type Config struct {
	StateDir  string
	Store     *evidence.Store
	Scanner   *redact.Scanner
	AttachURL string
	Token     func(context.Context) (string, error) // the device token at send time, so a refreshed one is used without a restart
	Version   string
	// Intent is the task's redacted opening prompt (intent.Provider); "" uploads the hunks alone.
	Intent func(task [16]byte) string
	// Diff is the task's worktree diff after the path axis (contrib.FilterDiff); nil or empty ⇒ no excerpt.
	Diff func(ctx context.Context, session, task [16]byte) []byte
	// Emit admits the EvidenceExcerpt naming the landed part (anchors.Runner.EmitExcerpt).
	Emit func(ctx context.Context, session, task [16]byte, x *m1pv1.EvidenceExcerpt) error
	HTTP *http.Client
	Now  func() time.Time
	Log  *slog.Logger
}

type Uploader struct {
	cfg    Config
	closes chan closed
	mu     sync.Mutex
	id     *evidence.Identity
	seen   map[[16]byte]bool
	order  [][16]byte // seen in first-close order, persisted to settledPath so a restart never re-prepares (controld answers 409)
}

type closed struct{ session, task [16]byte }

// pending is the sidecar beside a prepared part: what the retry needs to upload it and name it afterwards.
type pending struct {
	Session string `json:"session"`
	Task    string `json:"task"`
	Receipt string `json:"receipt"`
}

func New(cfg Config) (*Uploader, error) {
	if cfg.StateDir == "" || cfg.Store == nil || cfg.Scanner == nil || cfg.AttachURL == "" || cfg.Token == nil || cfg.Diff == nil || cfg.Emit == nil {
		return nil, errors.New("excerpt: StateDir, Store, Scanner, AttachURL, Token, Diff and Emit required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	u := &Uploader{cfg: cfg, closes: make(chan closed, queueDepth), seen: map[[16]byte]bool{}}
	u.loadSettled()
	return u, nil
}

// settledPath sits beside, not inside, the e1 dir: withdrawal purges parts, never the record that a task already had one.
func settledPath(stateDir string) string { return filepath.Join(evidence.Dir(stateDir), "e1-settled") }

func (u *Uploader) loadSettled() {
	b, err := os.ReadFile(settledPath(u.cfg.StateDir))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if id, err := uuid.Parse(line); err == nil && !u.seen[id] {
			u.seen[id] = true
			u.order = append(u.order, id)
		}
	}
	if len(u.order) > maxSeen {
		u.prune()
	}
}

// settle records task as having had its one excerpt attempt: appended (0600), and rewritten to the newest half once past maxSeen. Callers hold mu.
func (u *Uploader) settle(task [16]byte) {
	u.seen[task] = true
	u.order = append(u.order, task)
	if len(u.order) > maxSeen {
		u.prune()
		return
	}
	f, err := os.OpenFile(settledPath(u.cfg.StateDir), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.WriteString(uuid.UUID(task).String() + "\n")
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		u.cfg.Log.Warn("excerpt: settled set not persisted; a restart may re-prepare this task", "task", uuid.UUID(task), "err", err)
	}
}

func (u *Uploader) prune() {
	for _, t := range u.order[:len(u.order)-maxSeen/2] {
		delete(u.seen, t)
	}
	u.order = append([][16]byte(nil), u.order[len(u.order)-maxSeen/2:]...)
	var b strings.Builder
	for _, t := range u.order {
		b.WriteString(uuid.UUID(t).String() + "\n")
	}
	path := settledPath(u.cfg.StateDir)
	if err := os.WriteFile(path+".tmp", []byte(b.String()), 0o600); err == nil {
		err = os.Rename(path+".tmp", path)
		if err != nil {
			u.cfg.Log.Warn("excerpt: settled set not pruned", "err", err)
		}
	}
}

// SetIdentity arms receipting; without the enrolled key no excerpt is ever prepared.
func (u *Uploader) SetIdentity(id evidence.Identity) {
	u.mu.Lock()
	u.id = &id
	u.mu.Unlock()
}

// Purge is withdrawal's edge half: every prepared, not-yet-uploaded part goes.
func Purge(stateDir string) error { return os.RemoveAll(evidence.E1Dir(stateDir)) }

func consented(stateDir string) bool { return consents.Read(stateDir).E1 }

// OnTaskClose is the segmenter hook (it runs under the segmenter lock), so it only queues.
func (u *Uploader) OnTaskClose(session, task [16]byte, res m1pv1.Resolution) {
	if res == m1pv1.Resolution_RESOLUTION_MERGED_FORWARD || !consented(u.cfg.StateDir) {
		return
	}
	select {
	case u.closes <- closed{session, task}:
	default:
		u.cfg.Log.Warn("excerpt: queue full; a closed task gets no E1 excerpt")
	}
}

// Run prepares closed tasks one at a time and retries pending uploads every few minutes.
func (u *Uploader) Run(ctx context.Context) {
	t := time.NewTicker(retryEvery)
	defer t.Stop()
	u.Retry(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-u.closes:
			u.Process(ctx, c.session, c.task)
		case <-t.C:
			u.Retry(ctx)
		}
	}
}

// Process prepares one task's excerpt (path axis upstream, admit axis + receipt in PrepareE1, only post-redaction bytes on disk) and uploads it.
// ponytail: one excerpt per task (the first close); an R3 reopen keeps it, like the diff judge's vote.
func (u *Uploader) Process(ctx context.Context, session, task [16]byte) {
	u.mu.Lock()
	id, dup := u.id, u.seen[task]
	ok := id != nil && !dup && consented(u.cfg.StateDir)
	if ok {
		u.settle(task)
	}
	u.mu.Unlock()
	if !ok {
		return
	}
	diff := u.cfg.Diff(ctx, session, task)
	if len(bytes.TrimSpace(diff)) == 0 {
		return
	}
	diff, _ = judge.BoundDiff(bytes.ReplaceAll(diff, []byte{0}, nil), rawBudget)
	if len(diff) == 0 {
		return
	}
	var intent string
	if u.cfg.Intent != nil {
		intent = strings.ReplaceAll(u.cfg.Intent(task), "\x00", "")
		if len(intent) > MaxIntent {
			intent = strings.ToValidUTF8(intent[:MaxIntent], "")
		}
	}
	x, err := u.cfg.Store.PrepareE1(u.cfg.Scanner, *id, task, append(append([]byte(intent), 0), diff...), u.cfg.Now())
	if err != nil {
		u.cfg.Log.Warn("excerpt: E1 part not prepared", "task", uuid.UUID(task), "err", err)
		return
	}
	part := filepath.Join(evidence.E1Dir(u.cfg.StateDir), x.GetAttachmentName())
	if fi, err := os.Stat(part); err != nil || fi.Size() > MaxPart {
		_ = os.Remove(part)
		return
	}
	p := pending{Session: uuid.UUID(session).String(), Task: uuid.UUID(task).String(), Receipt: hex.EncodeToString(x.GetRedactionReceiptId())}
	b, _ := json.Marshal(p)
	if err := os.WriteFile(part+".json", b, 0o600); err != nil {
		_ = os.Remove(part)
		return
	}
	u.send(ctx, part, p)
}

// Retry uploads every pending part; consent off purges them, a consent the cloud has not acknowledged yet waits.
func (u *Uploader) Retry(ctx context.Context) {
	if !consented(u.cfg.StateDir) {
		if err := Purge(u.cfg.StateDir); err != nil {
			u.cfg.Log.Warn("excerpt: withdrawal purge failed", "err", err)
		}
		return
	}
	files, _ := filepath.Glob(filepath.Join(evidence.E1Dir(u.cfg.StateDir), "*.e1.json"))
	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		var p pending
		b, err := os.ReadFile(f) //nolint:gosec // G304: our own 0600 sidecar
		if err != nil || json.Unmarshal(b, &p) != nil {
			drop(strings.TrimSuffix(f, ".json"))
			continue
		}
		u.send(ctx, strings.TrimSuffix(f, ".json"), p)
	}
}

func drop(part string) { _ = os.Remove(part); _ = os.Remove(part + ".json") }

// send posts one part; a 5xx, 401 or network failure keeps it for Retry, any other answer settles it.
func (u *Uploader) send(ctx context.Context, part string, p pending) {
	if !consented(u.cfg.StateDir) || !consents.Acknowledged(u.cfg.StateDir).E1 {
		return
	}
	session, serr := uuid.Parse(p.Session)
	task, terr := uuid.Parse(p.Task)
	ref, rerr := hex.DecodeString(p.Receipt)
	data, derr := os.ReadFile(part) //nolint:gosec // G304: our own 0600 part
	rf, ferr := os.ReadFile(filepath.Join(receipt.RedactionDir(u.cfg.StateDir), p.Receipt+".json"))
	if err := errors.Join(serr, terr, rerr, derr, ferr); err != nil || len(ref) != 32 {
		u.cfg.Log.Warn("excerpt: pending part unreadable; dropped", "part", filepath.Base(part), "err", err)
		drop(part)
		return
	}
	name := filepath.Base(part)
	status, err := u.post(ctx, name, rf, data)
	switch {
	case err != nil || status >= 500 || status == http.StatusUnauthorized || status == http.StatusTooManyRequests:
		u.cfg.Log.Info("excerpt: attach upload deferred", "task", task, "status", status, "err", err)
		return
	case status == http.StatusOK:
		x := &m1pv1.EvidenceExcerpt{Tier: m1pv1.EvidenceTier_EVIDENCE_TIER_E1, EvidenceEventId: task[:], AttachmentName: name, RedactionReceiptId: ref}
		if err := u.cfg.Emit(ctx, session, task, x); err != nil {
			u.cfg.Log.Warn("excerpt: landed but the EvidenceExcerpt was not admitted", "task", task, "err", err)
		}
	default:
		u.cfg.Log.Warn("excerpt: attach upload refused; part dropped", "task", task, "status", status)
	}
	drop(part)
}

func (u *Uploader) post(ctx context.Context, name string, receiptFile, data []byte) (int, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormField("receipt")
	if err == nil {
		_, err = fw.Write(receiptFile)
	}
	if err == nil {
		fw, err = mw.CreateFormFile(name, name)
	}
	if err == nil {
		_, err = fw.Write(data)
	}
	if err = errors.Join(err, mw.Close()); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.AttachURL, &body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	tok, err := u.cfg.Token(ctx)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Mark1-Edge-Version", u.cfg.Version)
	resp, err := u.cfg.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("excerpt: attach: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
