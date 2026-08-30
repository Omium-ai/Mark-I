package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// waitFor polls cond up to 5 s — generous against CI jitter; the off-poll in
// the test config is 10 ms, so a correct daemon settles orders of magnitude
// earlier.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestOffMarkerGatesDaemon is 08 §7.6 / invariant 2 end to end at the daemon
// level: with the OFF marker present the (supervisor-restarted) daemon parks —
// no spool bytes, no fabric bind — and the gate re-arms across off/on cycles.
func TestOffMarkerGatesDaemon(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	// A fresh subdir so fabric.Listen creates it 0700 itself — t.TempDir()
	// arrives 0755, which Listen (correctly) refuses per 07 §5.
	socket := filepath.Join(dir, "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stateDir, "OFF")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- run(slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir: stateDir,
			spoolDir: spoolDir,
			socket:   socket,
			offPoll:  10 * time.Millisecond,
		})
	}()

	// Parked: the marker was present BEFORE boot, so nothing may touch disk
	// or bind the fabric (the finding this test pins: a daemon restart while
	// off must not resume capture).
	time.Sleep(150 * time.Millisecond)
	if _, err := os.Stat(spoolDir); !os.IsNotExist(err) {
		t.Fatal("spool dir created while off — pre-boot off-check missing")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatal("fabric socket bound while off")
	}

	// `mark1 on`: marker cleared ⇒ capture session comes up.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "fabric socket after marker cleared", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// `mark1 off` mid-run: session drains and the daemon parks again.
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "fabric socket removed after off", func() bool {
		_, err := os.Stat(socket)
		return os.IsNotExist(err)
	})

	// Re-arm: the loop must serve a second on-window (KeepAlive semantics).
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "fabric socket after second enable", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// SIGTERM lands in run's NotifyContext (installed by run itself); the
	// test binary keeps running because the handler owns the signal.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want clean exit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit on SIGTERM")
	}
}

// TestSpillRingDrainAcrossRestart is C8's "daemon-down replay via spill ring
// works" at the daemon level: boot once (mints the spill keypair and
// materializes spill.pub), park via the OFF marker, spill a sealed event into
// the ring while parked — exactly what the shim does against a dead daemon —
// then clear the marker and assert the startup drain lands the event in the
// spool exactly once and truncates the ring. The shim's own bytes are pinned
// by internal/spill's committed Rust-generated fixture; this test covers the
// wiring (key mint, startup drain, off/on cycle).
func TestSpillRingDrainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(dir, "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- run(slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir: stateDir,
			spoolDir: spoolDir,
			socket:   socket,
			offPoll:  10 * time.Millisecond,
		})
	}()

	pubPath := filepath.Join(stateDir, "spill", "spill.pub")
	waitFor(t, "spill.pub materialized on first boot", func() bool {
		b, err := os.ReadFile(pubPath)
		return err == nil && len(b) == 32
	})

	// `mark1 off`: the session drains and parks — the daemon-down window.
	marker := filepath.Join(stateDir, "OFF")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "fabric socket removed after off", func() bool {
		_, err := os.Stat(socket)
		return os.IsNotExist(err)
	})

	// The shim's move, byte for byte: seal one event to the device spill
	// pubkey and append it to the ring (format pinned against the real shim
	// by internal/spill's committed fixture).
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	session := uuid.MustParse("3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55")
	ev := &m1pv1.Event{
		EventId:   id[:],
		SessionId: session[:],
		Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{
			ToolName:  "Bash",
			ToolUseId: "toolu_01SynthDaemonDownTTTT",
		}},
	}
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte("M1PL"), 0x01)
	frame = binary.LittleEndian.AppendUint32(frame, uint32(len(payload))) // #nosec G115 -- test sizes
	frame = append(frame, payload...)
	rec, err := spill.Seal(pub, frame, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ring := filepath.Join(stateDir, "spill", "hookshim.ring")
	if err := os.WriteFile(ring, rec, 0o600); err != nil {
		t.Fatal(err)
	}

	// `mark1 on`: the next session's startup drain must replay the ring.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "ring truncated by the startup drain", func() bool {
		_, err := os.Stat(ring)
		return os.IsNotExist(err)
	})

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want clean exit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit on SIGTERM")
	}

	// The spool, reopened cold, holds the spilled event exactly once.
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("spool holds %d records, want the spilled event exactly once", len(recs))
	}
	if !bytes.Equal(recs[0].ID[:16], ev.GetEventId()) {
		t.Fatal("spooled record is not the spilled event")
	}
}

// TestEnableWorkspaceWhileRunning pins the workspaces.json wiring: `mark1
// enable` writes <state>/workspaces.json while the daemon runs, and the
// daemon's fsnotify/tick reconcile starts a tailer for the new root WITHOUT a
// restart — the file, not the --workspace flag, is the live allow-list.
func TestEnableWorkspaceWhileRunning(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(dir, "sock", "m1p.sock")
	home := filepath.Join(dir, "home")
	root := filepath.Join(dir, "ws")
	for _, d := range []string{stateDir, home, root} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The zero-value adapter resolves ~/.claude via $HOME (08 §5.1).
	t.Setenv("HOME", home)

	done := make(chan error, 1)
	go func() {
		done <- run(slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir: stateDir,
			spoolDir: spoolDir,
			socket:   socket,
			saltHex:  "aa", // arms the tail subsystem (idem-key derivation)
			offPoll:  10 * time.Millisecond,
		})
	}()
	waitFor(t, "fabric socket (daemon up, no workspaces yet)", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// A transcript already sits in the derived vendor dir; nothing may tail
	// it until the root is enabled. Munge mirrors claudecode.TranscriptDir,
	// over the canonical root (reconcile resolves symlinks before StartTail).
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	vendorDir := filepath.Join(home, ".claude", "projects", strings.ReplaceAll(canonRoot, "/", "-"))
	if err := os.MkdirAll(vendorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	session := "3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55"
	line := `{"type":"assistant","cwd":"` + canonRoot + `","requestId":"req_x","sessionId":"` + session + `","message":{"id":"msg_x","model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":9,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}` + "\n"
	if err := os.WriteFile(filepath.Join(vendorDir, session+".jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	// `mark1 enable <root>` while the daemon runs: the CLI's file format
	// (go/mark1/internal/cli.Workspaces), byte-compatible on purpose.
	ws := `{"version":1,"workspaces":[{"path":"` + canonRoot + `","enabled_at":"2026-08-29T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(stateDir, "workspaces.json"), []byte(ws), 0o600); err != nil {
		t.Fatal(err)
	}

	// Live discovery: the tailer persists its cursor after the emitted Usage
	// flush (04 §2.1) — a cursor file appearing WITHOUT any restart is the
	// proof. Deadline covers the reconcile tick (2 s) + quiesce debounce (2 s)
	// + sweep cadence with CI headroom.
	cursorDir := filepath.Join(stateDir, "cursors")
	deadline := time.Now().Add(15 * time.Second)
	for {
		if ents, err := os.ReadDir(cursorDir); err == nil && len(ents) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tailer never discovered the enabled workspace while running")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want clean exit", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit on SIGTERM")
	}

	// The spool, reopened cold, holds the transcript's Usage event.
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("spool holds %d records, want the tailed Usage exactly once", len(recs))
	}
	var ev m1pv1.Event
	if err := proto.Unmarshal(recs[0].Payload, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.GetUsage().GetOutputTokens() != 9 {
		t.Fatalf("spooled event %v, want the transcript's Usage (output_tokens 9)", &ev)
	}
}

// TestOffSkipsUploadHalfOfDrain pins the off→upload window fix: after
// `mark1 off` cancels the session, the teardown runs the spool-fsync half of
// the 07 §6 drain but NOT the upload half — an OFF daemon uploads nothing
// (08 §7.6), so zero HTTP requests land after the marker does. SIGTERM (the
// daemon stopping, not the user turning capture off) keeps the full Flush.
func TestOffSkipsUploadHalfOfDrain(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(dir, "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Pre-load one billing event so the uplink has something to attempt.
	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := uuid.NewV7()
	session := uuid.MustParse("3f9c2e71-58d4-4b6a-9e2f-7a1c0d8b4e55")
	payload, err := proto.Marshal(&m1pv1.Event{
		EventId: id[:], SessionId: session[:], Seq: 1, SessionEpoch: 1,
		Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Append(context.Background(), [16]byte(id), spool.ClassBilling, payload); err != nil {
		t.Fatal(err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}

	// Ingest answers 429 + Retry-After 3600 always: the uplink makes exactly
	// ONE request per drain attempt, then sleeps out the test's lifetime —
	// the request COUNT is the deterministic observable.
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"M1E-9001","message":"slow down"}}`))
	}))
	defer srv.Close()

	done := make(chan error, 1)
	go func() {
		done <- run(slog.New(slog.NewTextHandler(os.Stderr, nil)), config{
			stateDir:    stateDir,
			spoolDir:    spoolDir,
			socket:      socket,
			ingestURL:   srv.URL + "/m1p/v1/ingest",
			deviceToken: "tok-test",
			offPoll:     10 * time.Millisecond,
		})
	}()

	waitFor(t, "first uplink attempt", func() bool { return requests.Load() == 1 })

	// `mark1 off`: session drains; the upload half must NOT run.
	marker := filepath.Join(stateDir, "OFF")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "fabric socket removed after off", func() bool {
		_, err := os.Stat(socket)
		return os.IsNotExist(err)
	})
	// Teardown is complete (socket gone). Give a straggling Flush ample time
	// to be observed if the gate were missing.
	time.Sleep(300 * time.Millisecond)
	if got := requests.Load(); got != 1 {
		t.Fatalf("HTTP requests after off = %d, want 0 (total 1): an OFF daemon uploads nothing (08 §7.6)", got-1)
	}

	// `mark1 on`: the retained spool re-attempts (request 2)...
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "uplink attempt after re-enable", func() bool { return requests.Load() == 2 })

	// ...and SIGTERM (not off) keeps the full drain: Flush's single best-effort
	// attempt is request 3.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want clean exit", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not exit on SIGTERM")
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests after SIGTERM drain = %d, want 3 (signal keeps the upload half)", got)
	}
}
