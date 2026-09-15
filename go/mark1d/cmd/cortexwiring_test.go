// The daemon→cortex-plane hand-off (FR-CORTEX-001/005, NFR-AVAILABILITY-004).
// internal/cortex proves the plane in isolation; this pins the ONE line in
// main.go that feeds it -- cx.Observe on every decoded fabric event. Deleting
// that line left the whole cmd suite and the chaos cortexd leg green (lead
// mutation, 2026-09-15), the same shape as the M20 and srv.Sync ceilings, so
// this test exists to be the thing that goes red.
//
// unix: runDaemon and the fabric harness live in main_test.go, which is
// //go:build unix -- the same tag, for the same reason (D-F, named pipes).

//go:build unix

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/cortex"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
)

// TestDaemonPublishesTheCortexSessionFile: an assembled daemon, a workspace
// enabled at boot, a session the vendor has filed under that workspace, one
// event over the real socket -- and <state>/run/sessions/<wsid>.json names
// the session. cortexd reads exactly that file to Hello (D-AT/D-AV).
func TestDaemonPublishesTheCortexSessionFile(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	home := filepath.Join(dir, "home")
	root := filepath.Join(dir, "ws")
	for _, d := range []string{stateDir, home, root} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	// Enabled at boot: cortex.Roots reads workspaces.json when the plane is built.
	ws := `{"version":1,"workspaces":[{"path":"` + canonRoot + `","enabled_at":"2026-09-15T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(stateDir, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}
	// The vendor files the session under the workspace's projects dir; the
	// plane attributes a session to a root by that file, never by guessing.
	sid := uuid.New()
	vendorDir, err := (&claudecode.Adapter{StateDir: stateDir}).TranscriptDir(canonRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(vendorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, sid.String()+".jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	stop := runDaemon(t, config{
		stateDir: stateDir,
		spoolDir: filepath.Join(dir, "spool"),
		socket:   socket,
		saltHex:  "aa",
		offPoll:  10 * time.Millisecond,
	})
	defer stop()
	waitFor(t, "fabric socket bound", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	f := dialFabric(t, socket, [16]byte(sid))
	f.event([16]byte(sid), &m1pv1.Event{Body: &m1pv1.Event_SessionStart{SessionStart: &m1pv1.SessionStart{Agent: "claudecode"}}})
	f.event([16]byte(sid), &m1pv1.Event{Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{}}})

	file := cortex.SessionFile(stateDir, canonRoot)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(file); err == nil {
			var sf struct {
				SessionIDHex string `json:"session_id_hex"`
			}
			if err := json.Unmarshal(b, &sf); err != nil {
				t.Fatalf("session file is not the contract shape: %v\n%s", err, b)
			}
			if sf.SessionIDHex != hex.EncodeToString(sid[:]) {
				t.Fatalf("session file names %q, want %x", sf.SessionIDHex, sid[:])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon never published %s -- main.go is not feeding decoded events to the cortex plane", file)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
