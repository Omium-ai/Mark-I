//go:build unix

package contrib

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/consents"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/evidence"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/receipt"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

const planted = "AKIAIOSFODNN7EXAMPLE"

func plainGit(ctx context.Context, worktree string, args ...string) ([]byte, bool) {
	out, err := exec.CommandContext(ctx, "git", append([]string{"-C", worktree}, args...)...).Output()
	return out, err == nil
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return string(out)
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// repo is a fixture git repository with one base commit.
func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	write(t, dir, "calc.go", "package calc\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "base")
	return dir
}

const taskLines = "func Add(a, b int) int { return a + b }\nfunc Sub(a, b int) int { return a - b }\nfunc Mul(a, b int) int { return a * b }\nfunc Div(a, b int) int { return a / b }\n"

// agentTask applies the task's change and returns the added-line hashes the recorder would have kept.
func agentTask(t *testing.T, dir string) map[string][]string {
	t.Helper()
	write(t, dir, "calc.go", "package calc\n"+taskLines)
	diff, _ := plainGit(context.Background(), dir, "diff", "HEAD")
	return addedLines(diff)
}

func TestLabelsOnAFixtureRepo(t *testing.T) {
	ctx := context.Background()
	t.Run("half the lines survive", func(t *testing.T) {
		dir := repo(t)
		opened := time.Now().Add(-time.Minute)
		added := agentTask(t, dir)
		run(t, dir, "commit", "-qam", "agent: arithmetic")
		write(t, dir, "calc.go", "package calc\nfunc Add(a, b int) int { return a + b }\nfunc Sub(a, b int) int { return a - b }\n")
		run(t, dir, "commit", "-qam", "human: drop mul and div")
		if got := Survival(ctx, plainGit, dir, opened, added); got != 0.5 {
			t.Fatalf("survival = %v, want 0.5", got)
		}
		if got := Reverted(ctx, plainGit, dir, opened, added); got != m1pv1.OutcomeLabel_OUTCOME_LABEL_NO {
			t.Fatalf("reverted = %v, want NO (rewritten, not reverted)", got)
		}
	})
	t.Run("a revert commit names the task's commit", func(t *testing.T) {
		dir := repo(t)
		opened := time.Now().Add(-time.Minute)
		added := agentTask(t, dir)
		run(t, dir, "commit", "-qam", "agent: arithmetic")
		run(t, dir, "revert", "--no-edit", "HEAD")
		if got := Reverted(ctx, plainGit, dir, opened, added); got != m1pv1.OutcomeLabel_OUTCOME_LABEL_YES {
			t.Fatalf("reverted = %v, want YES", got)
		}
		if got := Survival(ctx, plainGit, dir, opened, added); got != 0 {
			t.Fatalf("survival after revert = %v, want 0", got)
		}
	})
	t.Run("never committed is unknown, not a failure", func(t *testing.T) {
		dir := repo(t)
		opened := time.Now().Add(time.Hour)
		added := agentTask(t, dir)
		if got := Survival(ctx, plainGit, dir, opened, added); got != -1 {
			t.Fatalf("survival = %v, want -1 (HEAD has not moved since the task)", got)
		}
		if got := Reverted(ctx, plainGit, dir, opened, added); got != m1pv1.OutcomeLabel_OUTCOME_LABEL_UNSPECIFIED {
			t.Fatalf("reverted = %v, want unknown", got)
		}
	})
	t.Run("tests run only on a clean HEAD", func(t *testing.T) {
		dir := repo(t)
		ran := 0
		tests := func(context.Context, string) (bool, bool) { ran++; return true, true }
		if l := Labels(ctx, plainGit, tests, dir, dir, time.Now(), nil); l.GetTestsPass() != m1pv1.OutcomeLabel_OUTCOME_LABEL_YES || ran != 1 {
			t.Fatalf("clean HEAD: tests_pass = %v, ran %d", l.GetTestsPass(), ran)
		}
		write(t, dir, "calc.go", "package calc\n// dirty\n")
		if l := Labels(ctx, plainGit, tests, dir, dir, time.Now(), nil); l.GetTestsPass() != m1pv1.OutcomeLabel_OUTCOME_LABEL_UNSPECIFIED || ran != 1 {
			t.Fatalf("dirty tree: tests_pass = %v, ran %d (HEAD is not what is on disk)", l.GetTestsPass(), ran)
		}
	})
}

type harness struct {
	state, dir string
	now        time.Time
	admitted   []*m1pv1.Event
	rec        *Recorder
}

func newHarness(t *testing.T, consent bool) *harness {
	t.Helper()
	h := &harness{state: t.TempDir(), dir: repo(t), now: time.Now()}
	if err := consents.Write(h.state, consents.Consents{ContributeOutcomes: consent}); err != nil {
		t.Fatal(err)
	}
	sc, err := redact.NewScanner([]byte("tenant-hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewDeviceKey(identity.FileCustody{Path: filepath.Join(h.state, "device.key")})
	if err != nil {
		t.Fatal(err)
	}
	h.rec, err = New(Config{
		StateDir: h.state, Scanner: sc,
		Admit:   func(_ context.Context, ev *m1pv1.Event) error { h.admitted = append(h.admitted, ev); return nil },
		Session: func([16]byte) (string, string, bool) { return "claudecode", h.dir, true },
		Intent:  func([16]byte, [16]byte) (string, bool) { return "add arithmetic, key " + planted, true },
		Diff: func(ctx context.Context, _ [16]byte, wt string) []byte {
			out, _ := plainGit(ctx, wt, "diff", "HEAD")
			return out
		},
		Git: plainGit,
		Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.rec.SetIdentity(evidence.Identity{Key: key, TenantID: uuid.NewString(), DeviceID: uuid.NewString()})
	return h
}

// task drives one task through the tap: open, a Usage naming the model, close.
func (h *harness) task(t *testing.T) [16]byte {
	t.Helper()
	session, task := uuid.New(), uuid.New()
	ev := func(body *m1pv1.Event) *m1pv1.Event {
		body.SessionId, body.TaskId, body.OccurredAt = session[:], task[:], timestamppb.New(h.now)
		return body
	}
	for _, e := range []*m1pv1.Event{
		ev(&m1pv1.Event{Body: &m1pv1.Event_TaskOpen{TaskOpen: &m1pv1.TaskOpen{}}}),
		ev(&m1pv1.Event{Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{Model: "claude-test-1"}}}),
		ev(&m1pv1.Event{Body: &m1pv1.Event_TaskClose{TaskClose: &m1pv1.TaskClose{Resolution: m1pv1.Resolution_RESOLUTION_VERDICT}}}),
	} {
		h.rec.Observe(e)
		h.rec.handle(context.Background(), <-h.rec.events)
	}
	return task
}

func TestConsentIsOffByDefault(t *testing.T) {
	if consents.Read(t.TempDir()).ContributeOutcomes {
		t.Fatal("contribute_outcomes read true with no consent record")
	}
	h := newHarness(t, false)
	write(t, h.dir, "calc.go", "package calc\n"+taskLines)
	h.task(t)
	if files, _ := filepath.Glob(filepath.Join(Dir(h.state), "*")); len(files) != 0 {
		t.Fatalf("recorded without consent: %v", files)
	}
}

func TestRedactionRunsBeforeAnythingPersists(t *testing.T) {
	h := newHarness(t, true)
	write(t, h.dir, "calc.go", "package calc\n"+taskLines+"const key = \""+planted+"\"\n")
	write(t, h.dir, ".env", "TOKEN=hunter2hunter2\n")
	write(t, h.dir, ".mark1ignore", "private/\n")
	if err := os.MkdirAll(filepath.Join(h.dir, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, h.dir, "private/notes.go", "package private\n")
	run(t, h.dir, "add", ".env", "private/notes.go", ".mark1ignore")
	run(t, h.dir, "commit", "-qm", "tracked")
	write(t, h.dir, ".env", "TOKEN=hunter2hunter2\nMORE=secretsecret\n")
	write(t, h.dir, "private/notes.go", "package private\n// the roadmap\n")
	task := h.task(t)

	b, err := os.ReadFile(filepath.Join(Dir(h.state), uuid.UUID(task).String()+".json"))
	if err != nil {
		t.Fatalf("pending record: %v", err)
	}
	pending := string(b)
	for _, leak := range []string{planted, "hunter2", "the roadmap", "private/notes.go", ".env"} {
		if strings.Contains(pending, leak) {
			t.Fatalf("%q persisted in the pending record: %s", leak, pending)
		}
	}
	if !strings.Contains(pending, "⟨redacted:") || !strings.Contains(pending, "func Add") {
		t.Fatalf("expected the redacted diff of calc.go: %s", pending)
	}

	h.now = h.now.Add(DefaultDelay + time.Hour)
	if err := os.WriteFile(consents.Path(h.state)+".relayed", mustRead(t, consents.Path(h.state)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.rec.LabelDue(context.Background())
	if len(h.admitted) != 1 {
		t.Fatalf("admitted %d contributions, want 1", len(h.admitted))
	}
	c := h.admitted[0].GetOutcomeContribution()
	if strings.Contains(c.GetIntentTextRedacted(), planted) || strings.Contains(c.GetDiffRedacted(), planted) {
		t.Fatal("a planted secret reached the event")
	}
	if c.GetGenerator() != "claudecode/claude-test-1" || c.GetLabelAgeDays() != 30 {
		t.Fatalf("generator %q age %d", c.GetGenerator(), c.GetLabelAgeDays())
	}
	if _, err := os.Stat(filepath.Join(receipt.RedactionDir(h.state), hex.EncodeToString(c.GetRedactionReceiptRef())+".json")); err != nil {
		t.Fatalf("the receipt the event names is not on disk: %v", err)
	}
	if files, _ := filepath.Glob(filepath.Join(Dir(h.state), "*.json")); len(files) != 0 {
		t.Fatalf("pending record kept after upload: %v", files)
	}
}

func TestUploadWaitsForTheDelayAndTheRelay(t *testing.T) {
	h := newHarness(t, true)
	write(t, h.dir, "calc.go", "package calc\n"+taskLines)
	h.task(t)
	h.now = h.now.Add(DefaultDelay + time.Hour)
	h.rec.LabelDue(context.Background())
	if len(h.admitted) != 0 {
		t.Fatal("uploaded before controld saw the consent: its refusal would quarantine the contribution")
	}
	if err := os.WriteFile(consents.Path(h.state)+".relayed", mustRead(t, consents.Path(h.state)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(-2 * time.Hour)
	h.rec.LabelDue(context.Background())
	if len(h.admitted) != 0 {
		t.Fatal("uploaded before the label delay")
	}
}

func TestWithdrawalPurgesPendingContributions(t *testing.T) {
	h := newHarness(t, true)
	write(t, h.dir, "calc.go", "package calc\n"+taskLines)
	h.task(t)
	if files, _ := filepath.Glob(filepath.Join(Dir(h.state), "*.json")); len(files) != 1 {
		t.Fatalf("pending = %v", files)
	}
	if err := consents.Write(h.state, consents.Consents{}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(DefaultDelay + time.Hour)
	h.rec.LabelDue(context.Background())
	if _, err := os.Stat(Dir(h.state)); !os.IsNotExist(err) || len(h.admitted) != 0 {
		t.Fatalf("withdrawal left pending contributions (%v) or uploaded %d", err, len(h.admitted))
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAFolderOfRepositoriesDiffsTheSessionsRepository (FR-VERIFY-021): with an enabled folder holding several repositories, the contribution reads the session's repository, is path-filtered against that repository's top, and labels there later.
func TestAFolderOfRepositoriesDiffsTheSessionsRepository(t *testing.T) {
	h := newHarness(t, true)
	folder := t.TempDir()
	inner := filepath.Join(folder, "svc")
	if err := os.Rename(h.dir, inner); err != nil {
		t.Fatal(err)
	}
	var gotTask [16]byte
	h.rec.cfg.Session = func([16]byte) (string, string, bool) { return "claudecode", folder, true }
	h.rec.cfg.Repo = func([16]byte) string { return inner }
	h.rec.cfg.Diff = func(ctx context.Context, task [16]byte, wt string) []byte {
		gotTask = task
		out, _ := plainGit(ctx, wt, "diff", "HEAD")
		return out
	}
	write(t, inner, "calc.go", "package calc\n"+taskLines)
	task := h.task(t)
	b, err := os.ReadFile(filepath.Join(Dir(h.state), uuid.UUID(task).String()+".json"))
	if err != nil {
		t.Fatalf("no pending record for a task in a folder of repositories: %v", err)
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Top != inner || rec.Root != folder || !strings.Contains(rec.Diff, "func Add") || gotTask != task {
		t.Fatalf("record top %q root %q task %x diff %q", rec.Top, rec.Root, gotTask, rec.Diff)
	}
	if got := FilterDiff([]byte("diff --git a/calc.go b/calc.go\n+x\n"), inner, folder); len(got) == 0 {
		t.Fatal("FilterDiff dropped a section inside the session's repository")
	}
}

// TestPendingContributionNeverUploadsIntoAnotherTenant (M3): a record carries the tenant it was made under; once the device is enrolled elsewhere it is dropped at upload time, never admitted under the new identity.
func TestPendingContributionNeverUploadsIntoAnotherTenant(t *testing.T) {
	h := newHarness(t, true)
	write(t, h.dir, "calc.go", "package calc\n"+taskLines)
	task := h.task(t)
	var rec record
	if err := json.Unmarshal(mustRead(t, filepath.Join(Dir(h.state), uuid.UUID(task).String()+".json")), &rec); err != nil || rec.Tenant != h.rec.id.TenantID {
		t.Fatalf("record tenant %q, want %q (%v)", rec.Tenant, h.rec.id.TenantID, err)
	}
	h.rec.SetIdentity(evidence.Identity{Key: h.rec.id.Key, TenantID: uuid.NewString(), DeviceID: uuid.NewString()})
	if err := os.WriteFile(consents.Path(h.state)+".relayed", mustRead(t, consents.Path(h.state)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(DefaultDelay + time.Hour)
	h.rec.LabelDue(context.Background())
	if len(h.admitted) != 0 {
		t.Fatal("a contribution recorded under the old tenant uploaded into the new one")
	}
	if files, _ := filepath.Glob(filepath.Join(Dir(h.state), "*.json")); len(files) != 0 {
		t.Fatalf("the other tenant's record was kept: %v", files)
	}
}

// TestFilterDiffOnGitsOwnOutputForHostileNames: the names the path axis must read exactly, as git itself prints them under core.quotePath.
func TestFilterDiffOnGitsOwnOutputForHostileNames(t *testing.T) {
	dir := repo(t)
	for _, p := range []string{"secrets b/app", "é"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, dir, "secrets b/app/x", "one\n")
	write(t, dir, "é/café.go", "one\n")
	write(t, dir, ".mark1ignore", "secrets b/\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "names")
	write(t, dir, "secrets b/app/x", "one\nLEAKED-IGNORED\n")
	write(t, dir, "é/café.go", "one\nKEPT-UNICODE\n")
	diff, ok := plainGit(context.Background(), dir, "-c", "core.quotePath=true", "diff", "HEAD")
	if !ok {
		t.Fatal("git diff failed")
	}
	got := string(FilterDiff(diff, dir, dir))
	if strings.Contains(got, "LEAKED-IGNORED") || !strings.Contains(got, "KEPT-UNICODE") {
		t.Fatalf("filtered:\n%s\nfrom:\n%s", got, diff)
	}
}
