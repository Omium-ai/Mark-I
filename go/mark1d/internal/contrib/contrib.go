// Package contrib is 16 L8's edge half: a consented task becomes one OutcomeContribution N days after it closed, labelled by time and execution only.
package contrib

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/tailers"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

const (
	DefaultDelay = 30 * 24 * time.Hour
	maxDiff      = 256 << 10
	maxOpen      = 4096
	queueDepth   = 1024
	labelEvery   = time.Hour
)

// Dir holds one pending record per closed task: post-redaction text and hashes of the added lines, never raw content.
func Dir(stateDir string) string { return filepath.Join(stateDir, "contrib") }

func decidedPath(stateDir string) string {
	return filepath.Join(stateDir, "gates", "contribute_outcomes.decided")
}

func defaultPath(stateDir string) string {
	return filepath.Join(stateDir, "gates", "contribute_outcomes.default")
}

// StaffDefaultReason is the only contribute_outcomes_default_reason an enrollment body may carry for its default to apply: controld sets it for Omium's own tenants (DOGFOOD_TENANTS).
const StaffDefaultReason = "omium_staff"

type stamp struct {
	Tenant string    `json:"tenant"`
	At     time.Time `json:"at"`
}

// Decided: the person set contribute_outcomes themselves, so a later enrollment default never overrides it. A default applied by enrollment is not a decision (MarkDefault).
func Decided(stateDir string) bool {
	_, err := os.Stat(decidedPath(stateDir))
	return err == nil
}

// MarkDecided records the person's own choice under the tenant it was made in ("" before any enrollment).
func MarkDecided(stateDir, tenant string) error {
	_ = os.Remove(defaultPath(stateDir))
	return writeStamp(decidedPath(stateDir), tenant)
}

// MarkDefault records that contribute_outcomes is on because tenant's enrollment defaulted it, not because the person chose.
func MarkDefault(stateDir, tenant string) error { return writeStamp(defaultPath(stateDir), tenant) }

func writeStamp(p, tenant string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(stamp{Tenant: tenant, At: time.Now().UTC()})
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

// stampedTenant is the tenant contribute_outcomes was last set under, "" when it was set before any enrollment (or by a build that did not stamp); ok is false when it was never set.
func stampedTenant(stateDir string) (string, bool) {
	for _, p := range []string{decidedPath(stateDir), defaultPath(stateDir)} {
		b, err := os.ReadFile(p) //nolint:gosec // G304: our own 0600 gate marker
		if err != nil {
			continue
		}
		var st stamp
		_ = json.Unmarshal(b, &st)
		return st.Tenant, true
	}
	return "", false
}

// Undecided: contribute_outcomes carries no stamp, neither the person's choice nor a default, as after a tenant switch reset it; the relay then sends it absent so controld keeps the device's previous value (08 §3.7a).
func Undecided(stateDir string) bool {
	_, set := stampedTenant(stateDir)
	return !set
}

// ReconcileTenant keeps contribute_outcomes from following the device into another tenant: set under another tenant ⇒ off, undecided and every pending contribution purged (true is returned); set before any enrollment ⇒ adopted by this one. tenant "" (not enrolled) changes nothing.
func ReconcileTenant(stateDir, tenant string) (bool, error) {
	if tenant == "" {
		return false, nil
	}
	c := consents.Read(stateDir)
	was, set := stampedTenant(stateDir)
	switch {
	case !set && !c.ContributeOutcomes:
		return false, nil
	case !set, was == "":
		p := defaultPath(stateDir)
		if Decided(stateDir) || !set {
			p = decidedPath(stateDir)
		}
		return false, writeStamp(p, tenant)
	case was == tenant:
		return false, nil
	}
	if c.ContributeOutcomes {
		c.ContributeOutcomes = false
		if err := consents.Write(stateDir, c); err != nil {
			return false, err
		}
	}
	for _, p := range []string{decidedPath(stateDir), defaultPath(stateDir)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return true, Purge(stateDir)
}

// Purge is withdrawal's edge half: every pending contribution goes, so nothing uploads later.
func Purge(stateDir string) error { return os.RemoveAll(Dir(stateDir)) }

type Config struct {
	StateDir string
	Scanner  *redact.Scanner
	Admit    func(context.Context, *m1pv1.Event) error
	// Session names the agent and enabled root a session works in (tailers.Resolve); no root, no contribution.
	Session func(session [16]byte) (agent, root string, ok bool)
	// Intent is the task's opening prompt, already redacted and capped (intent.Provider.Intent, the RM's own input); none skips the task.
	Intent func(session, task [16]byte) (string, bool)
	// Diff is the task diff the RM itself reads (anchors.Runner.TaskDiffFor, from the task's open-time base), so training rows match inference input.
	Diff func(ctx context.Context, task [16]byte, repo string) []byte
	// Repo names the repository a session works in (an enabled folder can hold several); nil or "" ⇒ the enabled root.
	Repo func(session [16]byte) string
	// Git runs read-only git in the anchor sandbox (anchors.Runner.Git).
	Git func(ctx context.Context, worktree string, args ...string) ([]byte, bool)
	// Tests runs the project's consented test anchors once (anchors.Scheduler.TestsPass).
	Tests func(ctx context.Context, project string) (pass, known bool)
	Delay time.Duration
	Now   func() time.Time
	Log   *slog.Logger
}

type Recorder struct {
	cfg    Config
	events chan seen
	mu     sync.Mutex
	id     *evidence.Identity
	open   map[[16]byte]*opened
}

type seen struct {
	session, task, parent [16]byte
	at                    time.Time
	model                 string
	open, close, merged   bool
}

type opened struct {
	session [16]byte
	at      time.Time
	models  map[string]bool
}

type record struct {
	Tenant    string              `json:"tenant"`
	Task      string              `json:"task"`
	Session   string              `json:"session"`
	Root      string              `json:"root"`
	Top       string              `json:"top"`
	OpenedAt  time.Time           `json:"opened_at"`
	ClosedAt  time.Time           `json:"closed_at"`
	Generator string              `json:"generator"`
	Intent    string              `json:"intent"`
	Diff      string              `json:"diff"`
	Receipt   string              `json:"receipt"`
	Added     map[string][]string `json:"added"`
}

func New(cfg Config) (*Recorder, error) {
	if cfg.StateDir == "" || cfg.Scanner == nil || cfg.Admit == nil || cfg.Session == nil || cfg.Intent == nil || cfg.Diff == nil || cfg.Git == nil {
		return nil, errors.New("contrib: StateDir, Scanner, Admit, Session, Intent, Diff and Git required")
	}
	if cfg.Delay <= 0 {
		cfg.Delay = DefaultDelay
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Recorder{cfg: cfg, events: make(chan seen, queueDepth), open: map[[16]byte]*opened{}}, nil
}

// SetIdentity arms receipting; without an enrolled key a task is never recorded (the receipt is not optional).
func (r *Recorder) SetIdentity(id evidence.Identity) {
	r.mu.Lock()
	r.id = &id
	r.mu.Unlock()
}

func (r *Recorder) consented() bool { return consents.Read(r.cfg.StateDir).ContributeOutcomes }

// Observe is the admitter tap; it never blocks capture.
func (r *Recorder) Observe(ev *m1pv1.Event) {
	var s seen
	if copy(s.session[:], ev.GetSessionId()) != 16 {
		return
	}
	copy(s.task[:], ev.GetTaskId())
	switch {
	case ev.GetUsage() != nil:
		s.model = ev.GetUsage().GetModel()
	case ev.GetTaskOpen() != nil:
		s.open = true
		copy(s.parent[:], ev.GetTaskOpen().GetParentTaskId())
	case ev.GetTaskClose() != nil:
		s.close = true
		s.merged = ev.GetTaskClose().GetResolution() == m1pv1.Resolution_RESOLUTION_MERGED_FORWARD
	default:
		return
	}
	s.at = r.cfg.Now()
	if ts := ev.GetOccurredAt(); ts != nil {
		s.at = ts.AsTime()
	}
	select {
	case r.events <- s:
	default:
		r.cfg.Log.Warn("contrib: queue full; a task event was not observed")
	}
}

// Run records closing tasks and, once an hour, labels and uploads the ones past their delay.
func (r *Recorder) Run(ctx context.Context) {
	labelled := make(chan struct{})
	defer func() { <-labelled }()
	go func() {
		defer close(labelled)
		t := time.NewTicker(labelEvery)
		defer t.Stop()
		for {
			r.LabelDue(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-r.events:
			r.handle(ctx, s)
		}
	}
}

func (r *Recorder) handle(ctx context.Context, s seen) {
	switch {
	case s.model != "":
		for _, o := range r.open {
			if o.session == s.session {
				o.models[s.model] = true
			}
		}
	case s.open:
		if !r.consented() {
			return
		}
		if len(r.open) >= maxOpen {
			clear(r.open)
		}
		if p, ok := r.open[s.parent]; ok && s.parent != ([16]byte{}) {
			delete(r.open, s.parent)
			r.open[s.task] = p
			return
		}
		r.open[s.task] = &opened{session: s.session, at: s.at, models: map[string]bool{}}
	case s.close && !s.merged:
		o, ok := r.open[s.task]
		delete(r.open, s.task)
		if ok {
			r.record(ctx, s.task, o, s.at)
		}
	}
}

// record turns a closed task into a pending file: path axis, then the admit axis and a signed redaction receipt, before anything touches disk.
func (r *Recorder) record(ctx context.Context, task [16]byte, o *opened, closedAt time.Time) {
	r.mu.Lock()
	id := r.id
	r.mu.Unlock()
	if id == nil || !r.consented() {
		return
	}
	agent, root, ok := r.cfg.Session(o.session)
	if !ok || root == "" {
		return
	}
	intent, ok := r.cfg.Intent(o.session, task)
	if !ok || intent == "" {
		return
	}
	repo := root
	if r.cfg.Repo != nil {
		if x := r.cfg.Repo(o.session); x != "" {
			repo = x
		}
	}
	top := topOf(repo)
	diff := filterDiff(r.cfg.Diff(ctx, task, repo), top, root)
	if len(diff) == 0 || len(diff) > maxDiff {
		return
	}
	added := addedLines(diff)
	pre := sha256.Sum256(joinNUL([]byte(intent), diff))
	iout, iok, ispans := r.cfg.Scanner.AdmitSpans([]byte(intent))
	dout, dok, dspans := r.cfg.Scanner.AdmitSpans(diff)
	if iok == redact.Quarantine || dok == redact.Quarantine {
		r.cfg.Log.Warn("contrib: task quarantined by the admit axis; not recorded")
		return
	}
	now := r.cfg.Now().UTC()
	signed, err := receipt.SignRedaction(id.Key, receipt.Redaction{
		TenantID: id.TenantID, DeviceID: id.DeviceID, SubjectID: uuid.UUID(task),
		IssuedAt: now.Truncate(time.Second).Format(time.RFC3339),
		PreHash:  pre, PostHash: sha256.Sum256(joinNUL(iout, dout)), Spans: append(ispans, dspans...),
	})
	if err == nil {
		_, err = receipt.WriteRedaction(r.cfg.StateDir, id.Key.KeyID(), signed)
	}
	if err != nil {
		r.cfg.Log.Warn("contrib: redaction receipt not written; task not recorded", "err", err)
		return
	}
	models := slices.Sorted(maps.Keys(o.models))
	if agent == "" {
		agent = "unknown"
	}
	rec := record{
		Tenant: id.TenantID, Task: uuid.UUID(task).String(), Session: uuid.UUID(o.session).String(), Root: root, Top: top,
		OpenedAt: o.at, ClosedAt: closedAt, Generator: agent + "/" + strings.Join(models, ","),
		Intent: string(iout), Diff: string(dout), Receipt: hex.EncodeToString(signed.ReceiptHash[:]), Added: added,
	}
	if err := writeRecord(r.cfg.StateDir, rec); err != nil {
		r.cfg.Log.Warn("contrib: pending record not written", "err", err)
	}
}

func joinNUL(a, b []byte) []byte { return append(append(append([]byte(nil), a...), 0), b...) }

func topOf(root string) string {
	for d := root; ; {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return root
		}
		d = parent
	}
}

// secretNames never leave in a diff, whatever the scanner says about their content.
var secretNames = []string{".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks", "id_rsa*", "id_ed25519*", "id_ecdsa*", ".npmrc", ".pypirc", ".netrc", "credentials*", "*.tfvars", "*.tfstate"}

func secretFile(p string) bool {
	base := path.Base(p)
	for _, g := range secretNames {
		if ok, _ := path.Match(g, base); ok {
			return true
		}
	}
	return false
}

// FilterDiff is the path axis for another uploader (the E1 excerpt, internal/excerpt): repo is the session's repository, whose git top the diff's paths are relative to, and root the enabled root.
func FilterDiff(diff []byte, repo, root string) []byte { return filterDiff(diff, topOf(repo), root) }

// filterDiff is the path axis: a file section leaves only when every path it names (both sides of a rename or copy) sits inside the enabled root, .mark1ignore does not exclude it and it is not a secret file; a section whose paths cannot be read unambiguously is dropped.
func filterDiff(diff []byte, top, root string) []byte {
	ws, err := tailers.NewWorkspaceSet(root)
	if err != nil {
		return nil
	}
	var out []byte
	for _, sec := range sections(diff) {
		paths, ok := sectionPaths(sec)
		for _, p := range paths {
			ok = ok && p != "" && !secretFile(p) && ws.Allowed(filepath.Join(top, filepath.FromSlash(p)))
		}
		if ok {
			out = append(out, sec...)
		}
	}
	return out
}

// sections splits a unified diff at each `diff --git ` line; bytes before the first are dropped.
func sections(diff []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.SplitAfter(diff, []byte("\n")) {
		switch {
		case bytes.HasPrefix(l, []byte("diff --git ")):
			out = append(out, l)
		case len(out) > 0:
			out[len(out)-1] = append(out[len(out)-1], l...)
		}
	}
	return out
}

// sectionPaths is every repository path one file section names: the `diff --git` header when its halves are the same path, and each `---`/`+++`/rename/copy line of the extended header (never a hunk line, which the change's own content controls). false when any of them does not parse.
func sectionPaths(sec []byte) ([]string, bool) {
	lines := strings.Split(strings.TrimSuffix(string(sec), "\n"), "\n")
	var out []string
	if p, ok := headerPath(strings.TrimPrefix(lines[0], "diff --git ")); ok {
		out = append(out, p)
	}
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, "@@") || strings.HasPrefix(l, "diff --git ") {
			break
		}
		var raw, pfx string
		switch {
		case strings.HasPrefix(l, "--- "):
			raw, pfx = l[4:], "a/"
		case strings.HasPrefix(l, "+++ "):
			raw, pfx = l[4:], "b/"
		default:
			for _, k := range []string{"rename from ", "rename to ", "copy from ", "copy to "} {
				if r, ok := strings.CutPrefix(l, k); ok {
					raw = r
				}
			}
			if raw == "" {
				continue
			}
		}
		if raw == "/dev/null" {
			continue
		}
		p, ok := gitPath(strings.TrimSuffix(raw, "\t"), pfx)
		if !ok {
			return nil, false
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

// headerPath reads `a/P b/P` (each half C-quoted when core.quotePath quotes it); two different paths (a rename) or an ambiguous split read as nothing, and the extended header lines name the paths instead.
func headerPath(rest string) (string, bool) {
	if strings.HasPrefix(rest, "\"") {
		end := quotedEnd(rest)
		if end < 0 || !strings.HasPrefix(rest[end:], " ") {
			return "", false
		}
		a, aok := gitPath(rest[:end], "a/")
		b, bok := gitPath(rest[end+1:], "b/")
		return a, aok && bok && a == b
	}
	n := len(rest) - len("a/ b/")
	if n <= 0 || n%2 != 0 {
		return "", false
	}
	p := rest[2 : 2+n/2]
	return p, rest == "a/"+p+" b/"+p
}

// quotedEnd is the index just past the closing quote of the C-quoted token s starts with, -1 when it is unterminated.
func quotedEnd(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

// gitPath decodes one path token git printed (C-quoted when it holds control, quote, backslash or non-ASCII bytes) and strips its side prefix.
func gitPath(tok, prefix string) (string, bool) {
	if strings.HasPrefix(tok, "\"") {
		if quotedEnd(tok) != len(tok) {
			return "", false
		}
		u, err := strconv.Unquote(tok)
		if err != nil {
			return "", false
		}
		tok = u
	}
	p, ok := strings.CutPrefix(tok, prefix)
	return p, ok && p != ""
}

// addedLines hashes each substantive added line by file (the post-image path of its section): survival matching needs no raw line on disk.
func addedLines(diff []byte) map[string][]string {
	out := map[string][]string{}
	for _, sec := range sections(diff) {
		file, hunk := "", false
		for _, l := range strings.Split(string(sec), "\n") {
			switch {
			case strings.HasPrefix(l, "@@"):
				hunk = true
			case !hunk && strings.HasPrefix(l, "+++ "):
				file, _ = gitPath(strings.TrimSuffix(l[4:], "\t"), "b/")
			case hunk && strings.HasPrefix(l, "+") && file != "":
				if h, ok := lineHash(l[1:]); ok {
					out[file] = append(out[file], h)
				}
			}
		}
	}
	return out
}

// lineHash skips lines too short to identify anything (a lone brace survives every refactor).
func lineHash(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 4 {
		return "", false
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8]), true
}

func writeRecord(stateDir string, rec record) error {
	if err := os.MkdirAll(Dir(stateDir), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	p := filepath.Join(Dir(stateDir), rec.Task+".json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LabelDue uploads every pending task past its delay; consent off purges, a consent the cloud has not acknowledged yet waits (its refusal would quarantine the upload), and a record made under another tenant than the enrolled one is dropped, never uploaded into this one.
func (r *Recorder) LabelDue(ctx context.Context) {
	c := consents.Read(r.cfg.StateDir)
	if !c.ContributeOutcomes {
		if err := Purge(r.cfg.StateDir); err != nil {
			r.cfg.Log.Warn("contrib: withdrawal purge failed", "err", err)
		}
		return
	}
	r.mu.Lock()
	id := r.id
	r.mu.Unlock()
	if id == nil || id.TenantID == "" || !consents.Acknowledged(r.cfg.StateDir).ContributeOutcomes {
		return
	}
	files, _ := filepath.Glob(filepath.Join(Dir(r.cfg.StateDir), "*.json"))
	for _, f := range files {
		if ctx.Err() != nil {
			return
		}
		b, err := os.ReadFile(f) //nolint:gosec // G304: our own 0600 pending record
		var rec record
		if err != nil || json.Unmarshal(b, &rec) != nil {
			_ = os.Remove(f)
			continue
		}
		if rec.Tenant != id.TenantID {
			r.cfg.Log.Warn("contrib: pending contribution recorded under another tenant; dropped, not uploaded", "task", rec.Task, "recorded_tenant", rec.Tenant, "tenant", id.TenantID)
			_ = os.Remove(f)
			continue
		}
		now := r.cfg.Now()
		if now.Sub(rec.ClosedAt) < r.cfg.Delay {
			continue
		}
		if _, err := os.Stat(rec.Top); err != nil {
			_ = os.Remove(f)
			continue
		}
		ev, err := r.contribution(ctx, rec, now)
		if err != nil {
			_ = os.Remove(f)
			continue
		}
		if err := r.cfg.Admit(ctx, ev); err != nil && !errors.Is(err, capture.ErrQuarantined) {
			r.cfg.Log.Warn("contrib: contribution not admitted; retried next hour", "err", err)
			continue
		}
		_ = os.Remove(f)
	}
}

func (r *Recorder) contribution(ctx context.Context, rec record, now time.Time) (*m1pv1.Event, error) {
	task, err := uuid.Parse(rec.Task)
	if err != nil {
		return nil, err
	}
	session, err := uuid.Parse(rec.Session)
	if err != nil {
		return nil, err
	}
	ref, err := hex.DecodeString(rec.Receipt)
	if err != nil || len(ref) != 32 {
		return nil, errors.New("contrib: bad receipt ref")
	}
	labels := Labels(ctx, r.cfg.Git, r.cfg.Tests, rec.Top, rec.Root, rec.OpenedAt, rec.Added)
	return &m1pv1.Event{
		SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.New(now),
		Body: &m1pv1.Event_OutcomeContribution{OutcomeContribution: &m1pv1.OutcomeContribution{
			TaskId: task[:], IntentTextRedacted: rec.Intent, DiffRedacted: rec.Diff, Labels: labels,
			RedactionReceiptRef: ref, Generator: rec.Generator,
			LabelAgeDays: uint32(now.Sub(rec.ClosedAt) / (24 * time.Hour)), //nolint:gosec // G115: past Delay, positive and small
		}},
	}, nil
}
