package contrib

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// blameSkew tolerates a commit stamped a little before the task opened (clock drift between agent and git).
const blameSkew = time.Minute

// maxLogCommits bounds the revert scan; a month of history in a busy repo fits.
const maxLogCommits = 500

type gitFunc func(ctx context.Context, worktree string, args ...string) ([]byte, bool)

// Labels computes the delayed, execution- and time-grounded labels with no LLM and nothing Mark 1 itself decided (16 "Independence rules").
func Labels(ctx context.Context, git gitFunc, tests func(context.Context, string) (bool, bool), top, root string, openedAt time.Time, added map[string][]string) *m1pv1.OutcomeLabels {
	l := &m1pv1.OutcomeLabels{Survival_30D: Survival(ctx, git, top, openedAt, added), Reverted: Reverted(ctx, git, top, openedAt, added)}
	if tests == nil {
		return l
	}
	if st, ok := git(ctx, top, "status", "--porcelain", "--untracked-files=no"); !ok || len(bytes.TrimSpace(st)) > 0 {
		return l
	}
	if pass, known := tests(ctx, root); known {
		l.TestsPass = yesNo(pass)
	}
	return l
}

func yesNo(b bool) m1pv1.OutcomeLabel {
	if b {
		return m1pv1.OutcomeLabel_OUTCOME_LABEL_YES
	}
	return m1pv1.OutcomeLabel_OUTCOME_LABEL_NO
}

// Survival is the fraction of the task's added lines that git blame on HEAD attributes to a commit made since the task opened; -1 when HEAD has not moved since (nothing committed, so nothing to judge).
func Survival(ctx context.Context, git gitFunc, top string, openedAt time.Time, added map[string][]string) float64 {
	total := 0
	for _, hs := range added {
		total += len(hs)
	}
	if total == 0 {
		return -1
	}
	out, ok := git(ctx, top, "log", "-1", "--format=%ct", "HEAD", "--")
	head, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	since := openedAt.Add(-blameSkew).Unix()
	if !ok || err != nil || head < since {
		return -1
	}
	alive := 0
	for file, hs := range added {
		blame, ok := git(ctx, top, "blame", "--no-textconv", "--line-porcelain", "HEAD", "--", file)
		if !ok {
			continue
		}
		live := map[string]int{}
		var ct int64
		for _, line := range strings.Split(string(blame), "\n") {
			switch {
			case strings.HasPrefix(line, "committer-time "):
				ct, _ = strconv.ParseInt(strings.TrimPrefix(line, "committer-time "), 10, 64)
			case strings.HasPrefix(line, "\t") && ct >= since:
				if h, ok := lineHash(line[1:]); ok {
					live[h]++
				}
			}
		}
		for _, h := range hs {
			if live[h] > 0 {
				live[h]--
				alive++
			}
		}
	}
	return float64(alive) / float64(total)
}

type commit struct {
	sha, msg string
	added    map[string]bool
}

// Reverted: YES when a later commit's message names (revert + sha prefix) a commit that carried the task's lines, NO when such commits exist and none is reverted, unknown when the task's lines were never committed.
func Reverted(ctx context.Context, git gitFunc, top string, openedAt time.Time, added map[string][]string) m1pv1.OutcomeLabel {
	task := map[string]bool{}
	for _, hs := range added {
		for _, h := range hs {
			task[h] = true
		}
	}
	if len(task) == 0 {
		return m1pv1.OutcomeLabel_OUTCOME_LABEL_UNSPECIFIED
	}
	out, ok := git(ctx, top, "log", "--since=@"+strconv.FormatInt(openedAt.Add(-blameSkew).Unix(), 10), "-n", strconv.Itoa(maxLogCommits),
		"--no-color", "--no-ext-diff", "--no-textconv", "--unified=0", "-p", "--format=%x1e%H%x1f%B%x1f", "HEAD", "--")
	if !ok {
		return m1pv1.OutcomeLabel_OUTCOME_LABEL_UNSPECIFIED
	}
	var commits []commit
	for _, chunk := range strings.Split(string(out), "\x1e")[1:] {
		parts := strings.SplitN(chunk, "\x1f", 3)
		if len(parts) != 3 {
			continue
		}
		c := commit{sha: parts[0], msg: strings.ToLower(parts[1]), added: map[string]bool{}}
		for _, l := range strings.Split(parts[2], "\n") {
			if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
				if h, ok := lineHash(l[1:]); ok {
					c.added[h] = true
				}
			}
		}
		commits = append(commits, c)
	}
	need := min(3, len(task))
	var carriers []string
	for _, c := range commits {
		n := 0
		for h := range c.added {
			if task[h] {
				n++
			}
		}
		if n >= need && len(c.sha) >= 12 {
			carriers = append(carriers, c.sha)
		}
	}
	if len(carriers) == 0 {
		return m1pv1.OutcomeLabel_OUTCOME_LABEL_UNSPECIFIED
	}
	for _, c := range commits {
		if !strings.Contains(c.msg, "revert") {
			continue
		}
		for _, sha := range carriers {
			if sha != c.sha && strings.Contains(c.msg, sha[:7]) {
				return m1pv1.OutcomeLabel_OUTCOME_LABEL_YES
			}
		}
	}
	return m1pv1.OutcomeLabel_OUTCOME_LABEL_NO
}
