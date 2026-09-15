//go:build unix

// Every test in this package drives the assembled daemon through run(), which
// binds the M1PL fabric — and fabric.Listen has no Windows implementation (07
// §5's named pipe is unlanded, listener_windows.go refuses by design). So these
// are unix-tagged for the same reason the code they exercise is: not a coverage
// choice, a statement about which platforms the daemon currently starts on.
// They re-arm for Windows the moment the named-pipe row does.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spill"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// TestMain is the anchor-sandbox helper stage, exactly as main() runs it: the
// sandbox re-execs os.Executable(), which under `go test` is THIS binary. With
// no MaybeRunHelper here every sandboxed anchor run would re-enter the test
// suite instead of the tool, so the daemon's anchor plane is untestable.
func TestMain(m *testing.M) {
	anchors.MaybeRunHelper()
	os.Exit(m.Run())
}

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

// runDaemon starts the real daemon and returns a stopper that cancels only
// THIS daemon's context. main() owns the signal set for exactly this reason: a
// test that stopped its daemon with syscall.Kill(os.Getpid(), SIGTERM) killed
// the whole `go test` process, which is survivable only while no test in the
// package calls t.Parallel(). Cancellation reaches the same teardown path —
// the Flush gate reads the OFF marker, never how the context died.
func runDaemon(t *testing.T, cfg config) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, slog.New(slog.NewTextHandler(os.Stderr, nil)), cfg) }()
	return func() {
		t.Helper()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("run returned %v, want clean exit", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("daemon did not exit on cancellation")
		}
	}
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
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stateDir, "OFF")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	stop := runDaemon(t, config{
		stateDir: stateDir,
		spoolDir: spoolDir,
		socket:   socket,
		offPoll:  10 * time.Millisecond,
	})

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

	stop()
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
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	stop := runDaemon(t, config{
		stateDir: stateDir,
		spoolDir: spoolDir,
		socket:   socket,
		offPoll:  10 * time.Millisecond,
	})

	pubPath := filepath.Join(stateDir, "spill", "spill.pub")
	waitFor(t, "spill.pub materialized on first boot", func() bool {
		b, err := os.ReadFile(pubPath)
		return err == nil && len(b) == 32
	})

	// spill.pub is materialized BEFORE the listener binds, so it is not a
	// proxy for "the daemon is up" — and "socket absent" below is satisfied
	// by "socket not created yet". Without this wait the whole off/on cycle
	// could land inside that window: the marker went up and came back down
	// before the first 10 ms off-poll observed it, the session never
	// cancelled, and the ring sat undrained until the 30 s tick — 1 run in
	// ~10, and the test blamed the drain. Wait for the socket to EXIST, so
	// the negation that follows means what it says.
	waitFor(t, "fabric socket bound (daemon fully up)", func() bool {
		_, err := os.Stat(socket)
		return err == nil
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
	// M1PL(FabricFrame{event}) — what m1p_wire::encode_frame spills. Both
	// layers, because a bare Event decodes as a frame without complaint.
	payload, err := proto.Marshal(&m1pv1.FabricFrame{
		Kind: &m1pv1.FabricFrame_Event{Event: ev},
	})
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

	stop()

	// The spool, reopened cold, holds the spilled event exactly once.
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
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	home := filepath.Join(dir, "home")
	root := filepath.Join(dir, "ws")
	for _, d := range []string{stateDir, home, root} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The zero-value adapter resolves ~/.claude via $HOME (08 §5.1).
	t.Setenv("HOME", home)
	// The subject is the allow-list wiring, not version policy — but the
	// tailer refuses to run against an unpinned or absent `claude`, and this
	// test spent two weeks red on every runner (installed=false) and on every
	// laptop whose npm had moved past the pin. Present the pinned one.
	fakeClaudeOnPath(t, pinnedAgentVersion(t))

	stop := runDaemon(t, config{
		stateDir: stateDir,
		spoolDir: spoolDir,
		socket:   socket,
		saltHex:  "aa", // arms the tail subsystem (idem-key derivation)
		offPoll:  10 * time.Millisecond,
	})
	waitFor(t, "fabric socket (daemon up, no workspaces yet)", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// A transcript already sits in the derived vendor dir; nothing may tail
	// it until the root is enabled. Derived by the PRODUCTION function over
	// the canonical root (reconcile resolves symlinks before StartTail): a
	// test-side copy of the munge was separator-only and disagreed with the
	// daemon on macOS, whose temp paths carry an underscore — red on the
	// macos-14 leg, green here, for exactly the reason the munge was fixed.
	canonRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	vendorDir, err := (&claudecode.Adapter{StateDir: stateDir}).TranscriptDir(canonRoot)
	if err != nil {
		t.Fatal(err)
	}
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

	stop()

	// The spool, reopened cold, holds the transcript's Usage event.
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
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
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

	stop := runDaemon(t, config{
		stateDir:    stateDir,
		spoolDir:    spoolDir,
		socket:      socket,
		ingestURL:   srv.URL + "/m1p/v1/ingest",
		deviceToken: "tok-test",
		offPoll:     10 * time.Millisecond,
	})

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

	// ...and a stop with the marker CLEAR (the daemon stopping, not the user
	// turning capture off) keeps the full drain: Flush's single best-effort
	// attempt is request 3.
	stop()
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests after the shutdown drain = %d, want 3 (a stop that is not `mark1 off` keeps the upload half)", got)
	}
}

// TestUnsessionedHelloIsRefusedEntry is D-AT against the assembled daemon.
//
// It used to be TestUnsessionedConnectionsDoNotShareAVerdict, and the property
// it asserted — two session-less connections must not be answered on each
// other's evidence — is now enforced a layer earlier and is unreachable from
// here. D-AL closed the all-zero session at every CONSUMER; the handshake was
// still replying `accepted: true` and then silently discarding everything the
// connection sent. D-AT closes the producer axis, so there is no accepted
// session-less connection left to share anything.
//
// The assertion moves with the enforcement rather than being deleted: what a
// caller can still observe end to end is that entry is refused, and refused
// *audibly* — the failure mode D-AT exists to remove is a daemon that accepts
// and then drops.
func TestUnsessionedHelloIsRefusedEntry(t *testing.T) {
	m := proofMatrices(false)
	socket, stop := startProofDaemon(t, &m)
	defer stop()

	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	f := &fabricConn{t: t, c: c}
	f.send(&m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{Hello: &m1pv1.Hello{
		Component: "tests", Pid: uint32(os.Getpid()), Version: version, // #nosec G115 -- pid fits
	}}})

	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := c.Read(buf[:]); err == nil {
		t.Fatalf("the daemon answered a session-less Hello instead of closing (D-AT); first byte %#x", buf[0])
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("the daemon neither answered nor closed a session-less Hello — it must refuse audibly, not hang")
	}
}

// TestCoverageJournalDrainsAtBootAndAtShutdown is the daemon-level half of
// sites 3 and 4 (`mark1 enable`, `mark1 off`). internal/coverage proves the
// drain works; this proves mark1d RUNS it, at both of the two moments the CLI
// can be observed at all:
//
//   - at entry, because 08 §7.6 lets `mark1 enable`/`off` run with the daemon
//     down, so the journal is routinely older than the process reading it;
//   - on cancellation, because `mark1 off` writes its line and then the
//     off-watcher cancels this very context — the shutdown path is the
//     likeliest place to strand a disable window, and a 5-second tick would
//     never fire in it.
//
// Both windows are unreceipted if this wiring is absent, and an unreceipted
// off window reads downstream as full coverage: the assumed-100% billing
// failure C13 exists to end.
func TestCoverageJournalDrainsAtBootAndAtShutdown(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	journal := coverage.JournalPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(journal), 0o700); err != nil {
		t.Fatal(err)
	}
	// The CLI's exact bytes (go/mark1/internal/cli.AppendCoverageTransition).
	appendLine := func(line string) {
		t.Helper()
		f, err := os.OpenFile(journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	appendLine(`{"kind":"enable","reason":"user_enable","ts":"2026-08-31T10:00:00Z","workspace":"/home/dev/project"}`)

	stop := runDaemon(t, config{
		stateDir: stateDir,
		spoolDir: spoolDir,
		socket:   socket,
		offPoll:  10 * time.Millisecond,
	})
	waitFor(t, "fabric socket bound (daemon fully up)", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// Deliberately shorter than coverageDrainEvery: a daemon that only drained
	// on its ticker would pass a 5-second wait, so this window is the whole
	// assertion about the drain AT ENTRY.
	cursor := filepath.Join(stateDir, "coverage", "drain.cursor") // coverage.cursorPath
	deadline := time.Now().Add(coverageDrainEvery / 2)
	for {
		if b, err := os.ReadFile(cursor); err == nil && len(b) > 0 && string(b) != "0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon-down enable window was still unreceipted %v after boot; "+
				"it waits for a tick instead of draining at entry", coverageDrainEvery/2)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// `mark1 off` mid-run: write the line, then cancel — exactly the order the
	// off-watcher produces.
	appendLine(`{"kind":"disable","reason":"mark1_off","scope":"all","ts":"2026-08-31T11:30:00Z"}`)
	stop()

	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	got := spooledCoverage(t, sp)
	if len(got) != 2 {
		t.Fatalf("spool holds %d coverage transitions, want 2 (the boot-time enable and the shutdown disable)", len(got))
	}
	if got[0].GetReasonCode() != coverage.ReasonUserEnable || got[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_ENABLE {
		t.Errorf("first transition = %v/%q, want ENABLE/%s", got[0].GetKind(), got[0].GetReasonCode(), coverage.ReasonUserEnable)
	}
	if got[1].GetReasonCode() != coverage.ReasonMark1Off || got[1].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_DISABLE {
		t.Errorf("second transition = %v/%q, want DISABLE/%s — the off window died with the daemon",
			got[1].GetKind(), got[1].GetReasonCode(), coverage.ReasonMark1Off)
	}
	// The enable named a workspace and the off did not: they must not carry the
	// same digest, or the band cannot tell a machine-wide off from one root's.
	if bytes.Equal(got[0].GetWorkspaceId(), got[1].GetWorkspaceId()) {
		t.Error("a per-workspace enable and a device-wide off landed on the same workspace_id")
	}
}

// TestDiskHardStopReceiptsTheBypassWindow is site 2 of 04 §2.7 at the daemon
// level: the 95 % hard stop (07 §6 / NFR-FOOTPRINT-002) stops capture writing,
// which is a BYPASS window, and a window nobody receipts is billed as full
// coverage.
//
// It also pins the honest ceiling. A coverage record is DIAGNOSTIC class (07 §6
// closes the billing-grade set at {usage, verdict_event, receipt_checkpoint}),
// so the transition announcing the hard stop is shed BY the hard stop: only the
// close survives, carrying the window length. That is a real hole — named here
// executably rather than in a comment — and it is not closable from the edge,
// because intelligence.proto explicitly refuses to promote coverage to
// billing-grade ("a backpressure contract 07 never authorized").
func TestDiskHardStopReceiptsTheBypassWindow(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var usedPct atomic.Uint64
	usedPct.Store(50)

	stop := runDaemon(t, config{
		stateDir:  stateDir,
		spoolDir:  spoolDir,
		socket:    socket,
		offPoll:   10 * time.Millisecond,
		diskUsage: func(string) (float64, error) { return float64(usedPct.Load()) / 100, nil },
	})
	waitFor(t, "fabric socket bound (daemon fully up)", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	// The sampler runs on the spool's 250 ms fsync cadence, so each edge needs
	// one cadence to be observed. Both waits are several cadences.
	usedPct.Store(99)
	time.Sleep(time.Second)
	usedPct.Store(50)
	time.Sleep(time.Second)
	stop()

	sp, err := spool.Open(spool.Config{Dir: spoolDir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	got := spooledCoverage(t, sp)
	if len(got) != 1 {
		t.Fatalf("spool holds %d coverage transitions, want exactly 1 — the close of the hard-stop window "+
			"(the open is shed by the stop it reports; more than one means the shed hazard changed)", len(got))
	}
	if got[0].GetReasonCode() != coverage.ReasonDiskHardStop {
		t.Errorf("reason_code = %q, want %q", got[0].GetReasonCode(), coverage.ReasonDiskHardStop)
	}
	if got[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_BYPASS {
		t.Errorf("kind = %v, want BYPASS", got[0].GetKind())
	}
	// Nonzero is the whole point of the close: sidefx.coverageKind files a
	// zero-duration BYPASS as a bypass_START, so a close that lost its window
	// would re-open the bypass instead of ending it.
	if got[0].GetDurationMs() == 0 {
		t.Error("duration_ms = 0, so the server files this close as a second bypass_start and the window never ends")
	}
}
