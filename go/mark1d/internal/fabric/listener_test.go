//go:build unix

package fabric

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
)

// TestSocketPathResolution pins 07 §5's two-step resolution.
func TestSocketPathResolution(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	p, err := SocketPath()
	if err != nil || p != "/run/user/1000/omium-mark1/m1p.sock" {
		t.Fatalf("got %q, %v", p, err)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	home, _ := os.UserHomeDir()
	p, err = SocketPath()
	if err != nil || p != filepath.Join(home, ".omium", "mark1", "m1p.sock") {
		t.Fatalf("fallback got %q, %v", p, err)
	}
}

// TestListenRejectsBadPerms pins the 07 §5 boundary: a parent dir with any
// group/world grant is refused, never chmod'd into compliance.
func TestListenRejectsBadPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(dir, "m1p.sock")); err == nil {
		t.Fatal("0755 socket dir accepted — 07 §5 requires refusal")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(filepath.Join(dir, "m1p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	fi, err := os.Lstat(filepath.Join(dir, "m1p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o, want 0600", fi.Mode().Perm())
	}
}

// fabric_symlink_refusal (04 §10). Listen removes a stale socket so a dead daemon cannot
// wedge the next boot, and that remove is the whole reason the check above it has to be
// Lstat: under Stat a symlink reports its TARGET's type, so one planted at the socket path
// and pointed at a live socket elsewhere would read as "stale, ours to clear". The refusal
// is what keeps the daemon from operating on a path it does not own.
//
// The assertion is therefore two-part. Refusing is half; the other half is that the planted
// object is still there afterwards, because "we refused" and "we deleted the attacker's
// symlink and then refused" are the same error string and very different behaviours.
func TestListenRefusesSymlinkAtSocketPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sock")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "m1p.sock")

	// The target is a REAL listening socket, not a regular file, and that is the only version
	// of this test that can fail: against a regular file Stat and Lstat both report "not a
	// socket" and refuse identically, so the test would pass under the bug it exists to catch.
	// Pointed at a live socket, Stat reports ModeSocket and the stale-socket branch claims it.
	target := filepath.Join(t.TempDir(), "elsewhere")
	victim, err := net.Listen("unix", target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = victim.Close() }()
	if err := os.Symlink(target, sock); err != nil {
		t.Fatal(err)
	}

	l, err := Listen(sock)
	if err == nil {
		_ = l.Close()
		t.Fatal("Listen accepted a symlink at the socket path; 04 §10 fabric_symlink_refusal requires refusal")
	}

	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatalf("Listen refused but removed the symlink it refused: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("path is now mode %v, want the planted symlink untouched", fi.Mode())
	}
	if _, terr := os.Stat(target); terr != nil {
		t.Fatalf("symlink target was followed and destroyed: %v", terr)
	}
}

func startDaemon(t *testing.T, dir string) (path string, sp *spool.Spool, adm *capture.Admitter, srv *Server) {
	t.Helper()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	adm, err = capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "run", "m1p.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	srv = NewServer(adm.AdmitBytes, func(err error) bool {
		return errors.Is(err, capture.ErrShed) || errors.Is(err, capture.ErrQuarantined)
	})
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })
	return path, sp, adm, srv
}

// TestHandshakeDeadlineReclaimsSilentPeers pins both halves of the bound: a
// peer that connects and never sends its 08 §4.3 Hello is reclaimed, and a
// peer that completed the handshake is not — mark1d outlives every agent
// session, so a deadline that kept running would sever the long-lived writers
// the fabric exists to carry.
func TestHandshakeDeadlineReclaimsSilentPeers(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp.Close() }()
	adm, err := capture.New(sp, capture.Config{
		EpochPath: filepath.Join(dir, "epoch"),
		Redact:    func(*m1pv1.Event) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(filepath.Join(dir, "run", "m1p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(adm.AdmitBytes, nil)
	srv.HandshakeTimeout = 150 * time.Millisecond // set before Serve: read per connection
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })

	silent, err := net.Dial("unix", filepath.Join(dir, "run", "m1p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	readClosed(t, silent) // says nothing, ever

	live, err := net.Dial("unix", filepath.Join(dir, "run", "m1p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Close() }()
	hello(t, live)
	time.Sleep(3 * srv.HandshakeTimeout)
	if err := live.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = live.Read(make([]byte, 1))
	if errors.Is(err, io.EOF) {
		t.Fatal("handshake deadline severed an established session")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("established session: want an idle read timeout, got %v", err)
	}
}

// TestServeFramesAndReject is the listener e2e: accepted frames land in the
// spool through admission; a framing violation closes the connection (07 §5)
// with everything before it kept — reject-then-close, never resync.
func TestServeFramesAndReject(t *testing.T) {
	dir := t.TempDir()
	path, sp, _, _ := startDaemon(t, dir)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	hello(t, c)
	writeEvent(t, c, 1, 210)
	writeEvent(t, c, 1, 1042)
	// The reject case: bad magic desynchronizes the stream ⇒ close.
	if _, err := c.Write([]byte{'M', '1', 'P', 'X', 0x01, 4, 0, 0, 0, 1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	readClosed(t, c) // the hangup is also the barrier: both good frames were admitted first

	if err := sp.Sync(); err != nil {
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("spool holds %d records, want the 2 pre-reject frames", len(recs))
	}
	var ev m1pv1.Event
	if err := proto.Unmarshal(recs[1].Payload, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.GetUsage().GetOutputTokens() != 1042 || ev.GetSeq() != 2 || ev.GetSessionEpoch() != 1 {
		t.Fatalf("admitted event lost its stamp: %+v", &ev)
	}

	// A malformed EVENT inside an intact FabricFrame is per-event:
	// quarantined, accounted, and the connection stays open.
	c2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	hello(t, c2)
	garbageEvent := append([]byte{0x0a, 0x04}, 0xff, 0xff, 0xff, 0xff) // field 1 (event), 4 garbage bytes
	if err := WriteFrame(c2, garbageEvent); err != nil {
		t.Fatal(err)
	}
	writeEvent(t, c2, 2, 7)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := sp.Sync(); err != nil {
			t.Fatalf("spool sync: %v", err)
		}
		recs, _, _ = sp.Records(ack)
		if len(recs) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("frame after a quarantined event never admitted (%d records) — connection wrongly closed?", len(recs))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEndToEndRecoveryScan: frames in via UDS → spool → daemon gone → the
// 07 §6 recovery scan on reopen still serves them, at-least-once by design.
func TestEndToEndRecoveryScan(t *testing.T) {
	dir := t.TempDir()
	path, sp, _, srv := startDaemon(t, dir)

	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hello(t, c)
	writeEvent(t, c, 3, 640)
	writeEvent(t, c, 3, 88)
	// Bad-magic reject as the processing barrier, then shut the daemon down.
	if _, err := c.Write([]byte("XXXXXXXXX")); err != nil {
		t.Fatalf("writing the bad-magic barrier: %v", err)
	}
	readClosed(t, c)
	_ = c.Close()
	srv.Close()
	if err := sp.Close(); err != nil { // shutdown drain: forced fsync (07 §6)
		t.Fatal(err)
	}

	sp2, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")}) // runs recovery steps 1–6
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sp2.Close() }()
	ack, _ := sp2.Cursors()
	recs, _, err := sp2.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("recovery scan sees %d records, want 2", len(recs))
	}
	var ev m1pv1.Event
	if err := proto.Unmarshal(recs[0].Payload, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.GetUsage().GetOutputTokens() != 640 {
		t.Fatalf("recovered record diverges: %+v", &ev)
	}
	if recs[0].ID.Class() != spool.ClassBilling {
		t.Fatal("usage record lost its billing class byte across recovery")
	}
}
