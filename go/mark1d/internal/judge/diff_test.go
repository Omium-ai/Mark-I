package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
)

const (
	intentText  = "Make parse() reject empty input."
	anchorProbe = "ANCHOR-OUTPUT-SENTINEL ruff:E501 errors=3"
	diffText    = "diff --git a/p.py b/p.py\n--- a/p.py\n+++ b/p.py\n@@ -1,0 +2,2 @@\n+    if not s:\n+        raise ValueError\n"
)

func diffHarness(t *testing.T, diff string) (*harness, *atomic.Int32) {
	t.Helper()
	h := newHarness(t)
	sc, err := redact.NewScanner([]byte("tenant-hmac-key"))
	if err != nil {
		t.Fatal(err)
	}
	var evidenceReads atomic.Int32
	h.cfg.Evidence = func(verdict.TaskID) string { evidenceReads.Add(1); return anchorProbe }
	h.cfg.Diff = func(_ context.Context, s, got [16]byte) []byte {
		if s != session || got != task {
			return nil
		}
		return []byte(diff)
	}
	h.cfg.Agent = func(s [16]byte) string {
		if s == session {
			return DiffJudgeAgent
		}
		return ""
	}
	h.cfg.Intent = func([16]byte) string { return intentText }
	h.cfg.Scanner = sc
	return h, &evidenceReads
}

// The independence contract (16 §Independence): the diff judge's prompt is the rubric, the task text and the diff; no anchor output reaches it.
func TestDiffJudgePromptCarriesOnlyTaskAndDiff(t *testing.T) {
	h, evidenceReads := diffHarness(t, diffText)
	r := h.runner()
	r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
	jv := h.vote(r)

	if evidenceReads.Load() != 0 {
		t.Fatal("the diff judge read the anchors' typed evidence")
	}
	if h.stub.count() != 1 {
		t.Fatalf("%d model calls, want 1", h.stub.count())
	}
	c := h.stub.calls[0]
	raw, _ := json.Marshal(c.body)
	if bytes.Contains(raw, []byte("ANCHOR-OUTPUT-SENTINEL")) {
		t.Fatalf("anchor output reached the prompt: %s", raw)
	}
	want := map[string]any{
		"model": diffModel, "max_tokens": float64(diffMaxTokens),
		"system":   []any{map[string]any{"type": "text", "text": diffRubric, "cache_control": map[string]any{"type": "ephemeral"}}},
		"messages": []any{map[string]any{"role": "user", "content": "<task>\n" + intentText + "\n</task>\n<diff>\n" + diffText + "</diff>"}},
	}
	exp, _ := json.Marshal(want)
	if string(raw) != string(exp) {
		t.Fatalf("request body\n got %s\nwant %s", raw, exp)
	}
	if c.header.Get("x-api-key") != apiKey || c.header.Get("Authorization") != "" {
		t.Fatalf("headers = %v", c.header)
	}
	if jv.GetJudgeId() != DiffJudgeID || jv.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED ||
		jv.GetTierUsed() != m1pv1.EvidenceTier_EVIDENCE_TIER_E1_LOCAL || jv.GetTrigger() != m1pv1.JudgeTrigger_JUDGE_TRIGGER_ALWAYS ||
		jv.GetLocus() != m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE || !bytes.Equal(jv.GetRubricHash(), r.rubricHash(diffRubric)) {
		t.Fatalf("vote = %v", jv)
	}
}

// The rubric rows used for estimation never reference another view's output (rm-design D-RM5).
func TestDiffRubricNamesNoVerifierOutput(t *testing.T) {
	low := strings.ToLower(diffRubric)
	for _, banned := range []string{"anchor", "diagnostic", "lint", "compil", "evidence", "output", "result", "typecheck", "ruff", "eslint", "pytest", "judge's", "reward model", "rm score", "verdict"} {
		if strings.Contains(low, banned) {
			t.Errorf("rubric mentions %q", banned)
		}
	}
}

// The registry row (m1_095) names this rubric's hash; a rubric edit without a new version fails here.
func TestDiffRubricHashMatchesTheRegistryMigration(t *testing.T) {
	sql, err := os.ReadFile("../../../../migrations/m1_095_diff_judge_verifier.sql")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(diffRubric))
	if !bytes.Contains(sql, []byte(`"rubric_sha256":"`+hex.EncodeToString(sum[:])+`"`)) || !bytes.Contains(sql, []byte(`"judge_id":"`+DiffJudgeID+`"`)) {
		t.Fatal("m1_095 does not register this rubric under " + DiffJudgeID)
	}
}

// A dispatched request can never run the diff judge: its trigger would be the cloud's ambiguity, not ALWAYS.
func TestDispatchedRequestForTheDiffJudgeIsIgnored(t *testing.T) {
	h, _ := diffHarness(t, diffText)
	r := h.runner()
	r.Handle(request(func(q *m1pv1.JudgeRequest) { q.JudgeId = DiffJudgeID }))
	h.noVote()
	if h.stub.count() != 0 {
		t.Fatal("a dispatched request ran the diff judge")
	}
}

func TestE0VoteIsTierE0TriggerAmbiguous(t *testing.T) {
	h := newHarness(t)
	r := h.runner()
	r.Handle(request(nil))
	if jv := h.vote(r); jv.GetTierUsed() != m1pv1.EvidenceTier_EVIDENCE_TIER_E0 || jv.GetTrigger() != m1pv1.JudgeTrigger_JUDGE_TRIGGER_AMBIGUOUS {
		t.Fatalf("E0 vote tier/trigger = %v/%v", jv.GetTierUsed(), jv.GetTrigger())
	}
}

// A subscription user has no edge judge: no key, or an OAuth-shaped credential, casts no vote and makes no call.
func TestDiffJudgeWithoutAnAPIKeyCastsNoVote(t *testing.T) {
	for _, cred := range []string{"", "sk-ant-oat01-" + strings.Repeat("a", 40)} {
		h, _ := diffHarness(t, diffText)
		h.cred = cred
		r := h.runner()
		r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
		h.noVote()
		settle(t, r)
		if h.stub.count() != 0 {
			t.Fatalf("cred %q: %d model calls", cred, h.stub.count())
		}
	}
}

func TestDiffJudgeRunsOnlyWhereItCan(t *testing.T) {
	for name, tc := range map[string]struct {
		diff string
		res  m1pv1.Resolution
		mut  func(*harness)
	}{
		"clean tree":     {"", m1pv1.Resolution_RESOLUTION_VERDICT, nil},
		"merged forward": {diffText, m1pv1.Resolution_RESOLUTION_MERGED_FORWARD, nil},
		"no scanner":     {diffText, m1pv1.Resolution_RESOLUTION_VERDICT, func(h *harness) { h.cfg.Scanner = nil }},
		"no diff seam":   {diffText, m1pv1.Resolution_RESOLUTION_VERDICT, func(h *harness) { h.cfg.Diff = nil }},
		"no agent seam":  {diffText, m1pv1.Resolution_RESOLUTION_VERDICT, func(h *harness) { h.cfg.Agent = nil }},
		"cap off":        {diffText, m1pv1.Resolution_RESOLUTION_VERDICT, func(h *harness) { h.cfg.DiffDailyTasks = -1 }},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := diffHarness(t, tc.diff)
			if tc.mut != nil {
				tc.mut(h)
			}
			r := h.runner()
			r.OnTaskClose(session, task, tc.res)
			h.noVote()
			settle(t, r)
			if h.stub.count() != 0 {
				t.Fatalf("%d model calls", h.stub.count())
			}
		})
	}
}

func TestDiffJudgeVotesOncePerTask(t *testing.T) {
	h, _ := diffHarness(t, diffText)
	r := h.runner()
	r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
	h.vote(r)
	r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_UNRESOLVED_SESSION_END)
	h.noVote()
	settle(t, r)
	if r2 := h.runner(); !r2.seen["diff:"+hex.EncodeToString(task[:])] {
		t.Fatal("the diff vote's id did not survive a restart")
	}
	if h.stub.count() != 1 {
		t.Fatalf("%d model calls, want 1", h.stub.count())
	}
}

// Secrets in the diff and the task text are redacted before the model call (the admit axis's scanner).
func TestDiffJudgeRedactsBeforeTheCall(t *testing.T) {
	aws, gh := "AKIAIOSFODNN7EXAMPLE", "ghp_"+strings.Repeat("a1B2", 9)
	h, _ := diffHarness(t, "diff --git a/c.py b/c.py\n@@ -0,0 +1,2 @@\n+AWS = \""+aws+"\"\n+GH = \""+gh+"\"\n")
	h.cfg.Intent = func([16]byte) string { return "rotate " + aws }
	r := h.runner()
	r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
	h.vote(r)
	raw, _ := json.Marshal(h.stub.calls[0].body)
	for _, secret := range []string{aws, gh} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("secret %q reached the model call", secret)
		}
	}
	if n := strings.Count(string(raw), "⟨redacted:"); n != 3 {
		t.Fatalf("%d redaction tokens in the call, want 3: %s", n, raw)
	}
}

func TestBoundDiffCutsByWholeHunks(t *testing.T) {
	hunk := func(tag string, n int) string { return "@@ -1 +1 @@\n+" + strings.Repeat(tag, n) + "\n" }
	fileA := "diff --git a/a b/a\n--- a/a\n+++ b/a\n"
	fileB := "diff --git a/b b/b\n--- a/b\n+++ b/b\n"
	d := fileA + hunk("x", 10) + hunk("y", 500) + hunk("z", 10) + fileB + hunk("w", 10)
	out, omitted := boundDiff([]byte(d), 150)
	if want := fileA + hunk("x", 10) + hunk("z", 10) + fileB + hunk("w", 10); string(out) != want || omitted != 1 {
		t.Fatalf("got %q omitted=%d", out, omitted)
	}
	out, omitted = boundDiff([]byte(d), 60)
	if len(out) > 60 || omitted != 3 || !strings.HasPrefix(string(out), fileA) {
		t.Fatalf("got %q (%d bytes) omitted=%d; a file whose header did not fit must lose its hunks", out, len(out), omitted)
	}
	if out, omitted := boundDiff([]byte(d), len(d)); string(out) != d || omitted != 0 {
		t.Fatal("a diff inside the budget changed")
	}

	big := strings.Repeat(hunk("q", 1000), 100)
	p := diffPrompt(strings.Repeat("t", 2*intentMax), []byte(fileA+big))
	if len(p) > diffInputBytes+200 {
		t.Fatalf("prompt is %d bytes, budget %d", len(p), diffInputBytes)
	}
	if !strings.Contains(p, "hunks omitted") || !strings.Contains(p, "[task text truncated]") {
		t.Fatal("truncation is not stated in the prompt")
	}
}

// TestDiffJudgeReadsOnlyClaudeCodeSessions (H6): the customer's key is their Anthropic key, so another agent's code never goes there, and a session no source names is not assumed to be Claude Code.
func TestDiffJudgeReadsOnlyClaudeCodeSessions(t *testing.T) {
	for _, agent := range []string{"codex", "gemini", "copilot", "opencode", "cursor", "crush", ""} {
		h, _ := diffHarness(t, diffText)
		var diffReads atomic.Int32
		inner := h.cfg.Diff
		h.cfg.Diff = func(ctx context.Context, s, tk [16]byte) []byte { diffReads.Add(1); return inner(ctx, s, tk) }
		h.cfg.Agent = func([16]byte) string { return agent }
		r := h.runner()
		r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
		h.noVote()
		settle(t, r)
		if h.stub.count() != 0 || diffReads.Load() != 0 {
			t.Fatalf("agent %q: %d model calls, %d diff reads", agent, h.stub.count(), diffReads.Load())
		}
	}
}

// TestDiffJudgeDailyCapSkipsAndCounts (H6): past the per-day task cap a closed task makes no call and is counted; the count survives a restart, and a new UTC day starts from zero.
func TestDiffJudgeDailyCapSkipsAndCounts(t *testing.T) {
	h, _ := diffHarness(t, diffText)
	h.cfg.DiffDailyTasks = 2
	r := h.runner()
	tasks := [][16]byte{{1}, {2}, {3}}
	h.cfg.Diff = func(context.Context, [16]byte, [16]byte) []byte { return []byte(diffText) }
	r.cfg.Diff = h.cfg.Diff
	for i, tk := range tasks {
		r.OnTaskClose(session, tk, m1pv1.Resolution_RESOLUTION_VERDICT)
		if i < 2 {
			anyVote(t, h, r)
		}
	}
	h.noVote()
	settle(t, r)
	if h.stub.count() != 2 {
		t.Fatalf("%d model calls under a cap of 2 tasks", h.stub.count())
	}
	var b diffBudget
	raw, err := os.ReadFile(r.budgetPath())
	if err != nil || json.Unmarshal(raw, &b) != nil || b.Tasks != 2 || b.Skipped != 1 || b.Tokens <= 2*diffMaxTokens {
		t.Fatalf("budget %s (%v)", raw, err)
	}
	r2 := h.runner()
	r2.cfg.Diff = h.cfg.Diff
	r2.OnTaskClose(session, [16]byte{4}, m1pv1.Resolution_RESOLUTION_VERDICT)
	h.noVote()
	settle(t, r2)
	if h.stub.count() != 2 {
		t.Fatal("a restart reset the day's cap")
	}
	b.Day = "2000-01-01"
	raw, _ = json.Marshal(b)
	if err := os.WriteFile(r.budgetPath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r3 := h.runner()
	r3.cfg.Diff = h.cfg.Diff
	r3.OnTaskClose(session, [16]byte{5}, m1pv1.Resolution_RESOLUTION_VERDICT)
	anyVote(t, h, r3)
	if h.stub.count() != 3 {
		t.Fatalf("a new day: %d model calls, want 3", h.stub.count())
	}
}

// TestDiffJudgeTokenCapBinds: one task whose estimate exceeds the day's token cap is skipped even with task budget left.
func TestDiffJudgeTokenCapBinds(t *testing.T) {
	h, _ := diffHarness(t, diffText)
	h.cfg.DiffDailyTokens = diffMaxTokens
	r := h.runner()
	r.OnTaskClose(session, task, m1pv1.Resolution_RESOLUTION_VERDICT)
	h.noVote()
	settle(t, r)
	if h.stub.count() != 0 {
		t.Fatal("a task past the token cap made a call")
	}
}

func anyVote(t *testing.T, h *harness, r *Runner) {
	t.Helper()
	select {
	case <-h.admitted:
		settle(t, r)
	case <-time.After(10 * time.Second):
		t.Fatal("no vote admitted within 10s")
	}
}
