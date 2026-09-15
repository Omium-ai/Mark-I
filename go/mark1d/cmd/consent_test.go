//go:build unix

// Unix-tagged with the rest of this package: run() binds the fabric, and
// fabric.Listen refuses on Windows until 07 §5's named pipe lands (main_test.go).
package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
)

// syncBuf is a goroutine-safe log sink: the daemon logs from several
// goroutines and bytes.Buffer is not safe for that.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ruffWorkspace is the smallest repo that derives one anchor: a pyproject
// configuring ruff, and a fake `ruff` as the only binary on PATH (the same
// fixture shape anchors/catalog_test.go uses).
func ruffWorkspace(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[tool.ruff]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ruff"), []byte("#!/bin/sh\necho 'ruff 0.6.2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	canon, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return canon
}

// consentDaemon boots a daemon with no tenant salt — the consent surface must
// work on an install where enrollment has not delivered one — and returns the
// state dir, the captured log, and the stopper.
func consentDaemon(t *testing.T) (string, *syncBuf, func()) {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	stop := runDaemonLog(t, config{
		stateDir: stateDir,
		spoolDir: filepath.Join(dir, "spool"),
		socket:   filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock"),
		offPoll:  10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(logs, nil)))
	return stateDir, logs, stop
}

func readCandidates(t *testing.T, stateDir string) (anchors.Candidates, bool) {
	t.Helper()
	b, err := os.ReadFile(anchors.CandidatesPath(stateDir))
	if err != nil {
		return anchors.Candidates{}, false
	}
	var c anchors.Candidates
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("candidates.json unparseable: %v\n%s", err, b)
	}
	return c, true
}

func enableRoots(t *testing.T, stateDir string, roots ...string) {
	t.Helper()
	var entries []string
	for _, r := range roots {
		entries = append(entries, `{"path":"`+r+`","enabled_at":"2026-08-29T00:00:00Z"}`)
	}
	ws := `{"version":1,"workspaces":[` + strings.Join(entries, ",") + `]}`
	if err := os.WriteFile(filepath.Join(stateDir, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}
}

// candidateFor waits until candidates.json lists root with the ruff anchor.
func candidateFor(t *testing.T, stateDir, root string) anchors.Candidate {
	t.Helper()
	var got anchors.Candidate
	waitFor(t, "candidates.json listing "+root, func() bool {
		c, ok := readCandidates(t, stateDir)
		if !ok {
			return false
		}
		for _, ws := range c.Workspaces {
			if ws.Path == root && len(ws.Anchors) == 1 {
				got = ws.Anchors[0]
				return true
			}
		}
		return false
	})
	return got
}

func appendApproval(t *testing.T, stateDir string, a anchors.Approval) {
	t.Helper()
	line, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(anchors.ApprovalsPath(stateDir), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCandidatesArePublishedForEnabledWorkspaces: the daemon publishes
// <state>/anchors/candidates.json (0600) at boot — an empty workspace list,
// which is a state distinct from "not published" — and, once `mark1 enable`
// lands a root in workspaces.json, every anchor that root derives with its
// exact exec_hash and consented=false. A root that derives nothing is listed
// with an empty anchor list, not omitted.
func TestCandidatesArePublishedForEnabledWorkspaces(t *testing.T) {
	root := ruffWorkspace(t)
	stateDir, _, stop := consentDaemon(t)
	defer stop()

	waitFor(t, "boot publish of candidates.json", func() bool {
		c, ok := readCandidates(t, stateDir)
		return ok && c.Version == 1 && c.Workspaces != nil && len(c.Workspaces) == 0
	})
	fi, err := os.Stat(anchors.CandidatesPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("candidates.json mode %o, want 0600", fi.Mode().Perm())
	}

	empty := filepath.Join(t.TempDir(), "nothing-here")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	empty, _ = filepath.EvalSymlinks(empty)
	enableRoots(t, stateDir, root, empty)

	cand := candidateFor(t, stateDir, root)
	if cand.ID != "ruff@cat-1" || cand.Tool != "ruff" || cand.Class != anchors.ClassFast || cand.SideEffect != anchors.SideEffectStatic {
		t.Fatalf("candidate %+v, want ruff@cat-1 fast static", cand)
	}
	if len(cand.ExecHash) != 64 || len(cand.BinaryHash) != 64 {
		t.Fatalf("candidate %+v: exec_hash/binary_hash must be hex BLAKE3", cand)
	}
	if cand.Consented || !cand.ConsentedAt.IsZero() {
		t.Fatalf("candidate %+v published as consented with an empty store", cand)
	}
	if len(cand.Argv) == 0 || filepath.Base(cand.Argv[0]) != "ruff" {
		t.Fatalf("candidate argv %v, want the resolved ruff binary first", cand.Argv)
	}
	c, _ := readCandidates(t, stateDir)
	var sawEmpty bool
	for _, ws := range c.Workspaces {
		if ws.Path == empty {
			sawEmpty = true
			if ws.Anchors == nil || len(ws.Anchors) != 0 {
				t.Fatalf("workspace with nothing derivable published %+v, want an empty list", ws.Anchors)
			}
		}
	}
	if !sawEmpty {
		t.Fatalf("workspace with nothing derivable omitted from %+v", c.Workspaces)
	}
}

// TestApprovalLineConsentsTheMatchingCandidate: an approvals.jsonl line whose
// (id, exec_hash) names a current candidate lands in the consent store; a line
// with the right id and the wrong hash is refused with a log line and never
// approved — consent binds to the exact effective-execution hash.
func TestApprovalLineConsentsTheMatchingCandidate(t *testing.T) {
	root := ruffWorkspace(t)
	stateDir, logs, stop := consentDaemon(t)
	defer stop()
	enableRoots(t, stateDir, root)
	cand := candidateFor(t, stateDir, root)

	appendApproval(t, stateDir, anchors.Approval{TS: "2026-09-15T00:00:00Z", User: "anurag", Workspace: root, ID: cand.ID, ExecHash: "deadbeef"})
	waitFor(t, "the wrong-hash refusal to be logged", func() bool {
		return strings.Contains(logs.String(), "approval names no current candidate")
	})
	recs, err := anchors.LoadConsent(anchors.ConsentPath(stateDir))
	if err != nil || len(recs) != 0 {
		t.Fatalf("store after a wrong-hash line: %+v %v — want empty", recs, err)
	}

	appendApproval(t, stateDir, anchors.Approval{TS: "2026-09-15T00:00:01Z", User: "anurag", Workspace: root, ID: cand.ID, ExecHash: cand.ExecHash})
	waitFor(t, "the matching line to be approved", func() bool {
		recs, _ := anchors.LoadConsent(anchors.ConsentPath(stateDir))
		return len(recs) == 1 && recs[0].ID == cand.ID && recs[0].ExecHash == cand.ExecHash
	})
	waitFor(t, "candidates.json to show the consent", func() bool {
		c, ok := readCandidates(t, stateDir)
		return ok && len(c.Workspaces) == 1 && len(c.Workspaces[0].Anchors) == 1 &&
			c.Workspaces[0].Anchors[0].Consented && !c.Workspaces[0].Anchors[0].ConsentedAt.IsZero()
	})
	if !strings.Contains(logs.String(), "anchor plane armed") {
		t.Fatalf("consent landed but the scheduler was not armed live:\n%s", logs.String())
	}
}

// TestApprovalsReplayIsIdempotent: the same line re-read — by a restarted
// daemon from offset 0, or appended twice — changes nothing in the store,
// not even consented_at.
func TestApprovalsReplayIsIdempotent(t *testing.T) {
	root := ruffWorkspace(t)
	stateDir, _, stop := consentDaemon(t)
	enableRoots(t, stateDir, root)
	cand := candidateFor(t, stateDir, root)
	line := anchors.Approval{TS: "2026-09-15T00:00:00Z", Workspace: root, ID: cand.ID, ExecHash: cand.ExecHash}
	appendApproval(t, stateDir, line)
	waitFor(t, "the line to be approved", func() bool {
		recs, _ := anchors.LoadConsent(anchors.ConsentPath(stateDir))
		return len(recs) == 1
	})
	before, err := os.ReadFile(anchors.ConsentPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	stop()

	// Restart: the whole approvals file is re-read from the top.
	logs2 := &syncBuf{}
	stop2 := runDaemonLog(t, config{
		stateDir: stateDir,
		spoolDir: filepath.Join(filepath.Dir(stateDir), "spool"),
		socket:   filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock"),
		offPoll:  10 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(logs2, nil)))
	defer stop2()
	waitFor(t, "the restarted daemon to arm from the store", func() bool {
		return strings.Contains(logs2.String(), "anchor plane armed")
	})
	// Duplicate line, then a wrong-hash line as the "processed up to here" marker.
	appendApproval(t, stateDir, line)
	appendApproval(t, stateDir, anchors.Approval{TS: "x", Workspace: root, ID: cand.ID, ExecHash: "0000"})
	waitFor(t, "the marker line to be refused", func() bool {
		return strings.Contains(logs2.String(), "approval names no current candidate")
	})
	after, err := os.ReadFile(anchors.ConsentPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("store changed on replay:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if strings.Contains(logs2.String(), "consent recorded") {
		t.Fatalf("replay re-applied an approval:\n%s", logs2.String())
	}
}
