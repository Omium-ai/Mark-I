//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const codexFixtureRollout = "../../../conformance/hooks/codex/v0.154.0/transcripts/sessions/2026/09/16/rollout-2026-09-16T08-25-00-019965a0-0000-7000-8000-00000000aa01.jsonl"

func TestCodexRolloutsAreTailedForAnEnabledRoot(t *testing.T) {
	dir := t.TempDir()
	stateDir, spoolDir := filepath.Join(dir, "state"), filepath.Join(dir, "spool")
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	root := filepath.Join(dir, "ws")
	codexHome := filepath.Join(dir, "codex")
	for _, d := range []string{stateDir, root, filepath.Join(codexHome, "sessions", "2026", "09", "16")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fakeClaudeOnPath(t, pinnedAgentVersion(t))
	if err := os.WriteFile(filepath.Join(os.Getenv("PATH"), "codex"), []byte("#!/bin/sh\necho 'codex-cli 0.154.0'\n"), 0o755); err != nil { //nolint:gosec // G306: executable on purpose
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", codexHome)
	t.Setenv("CODEX_API_KEY", "")
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(codexFixtureRollout)
	if err != nil {
		t.Fatal(err)
	}
	rollout := strings.ReplaceAll(string(raw), "/home/devuser/workspace/acme-app", canonRoot)
	if err := os.WriteFile(filepath.Join(codexHome, "sessions", "2026", "09", "16", filepath.Base(codexFixtureRollout)), []byte(rollout), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := `{"version":1,"workspaces":[{"path":"` + canonRoot + `","enabled_at":"2026-09-16T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(stateDir, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}
	stop := runDaemon(t, config{stateDir: stateDir, spoolDir: spoolDir, socket: socket, saltHex: "aa", offPoll: 10 * time.Millisecond})
	waitFor(t, "fabric socket", func() bool { _, err := os.Stat(socket); return err == nil })
	thread := uuid.MustParse("019965a0-0000-7000-8000-00000000aa01")
	f := dialFabric(t, socket, [16]byte(thread))
	f.event([16]byte(thread), &m1pv1.Event{Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "codex"}}})
	f.event([16]byte(thread), &m1pv1.Event{Body: &m1pv1.Event_Turn{Turn: &m1pv1.Turn{Initiator: m1pv1.Initiator_INITIATOR_HUMAN}}})
	deadline := time.Now().Add(15 * time.Second)
	for {
		if ents, err := os.ReadDir(filepath.Join(stateDir, "cursors")); err == nil && len(ents) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no tailer cursor appeared for the enabled root")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(3 * time.Second)
	stop()

	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	usages, stamped := 0, 0
	for _, r := range recs {
		e := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, e); err != nil {
			t.Fatal(err)
		}
		if e.GetUsage() != nil {
			usages++
			if len(e.GetTaskId()) == 16 {
				stamped++
			}
		}
	}
	if usages != 4 {
		t.Fatalf("spool holds %d Usage records from the codex rollout, want the fixture's 4 (%d records total)", usages, len(recs))
	}
	if stamped != usages {
		t.Fatalf("%d of %d codex Usage records carry a task_id; the segmenter stamp must ride the codex tail too", stamped, usages)
	}
}
