package main

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"os"
	"path/filepath"
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
