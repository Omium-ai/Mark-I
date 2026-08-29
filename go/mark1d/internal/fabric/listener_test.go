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
	defer l.Close()
	fi, err := os.Lstat(filepath.Join(dir, "m1p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o, want 0600", fi.Mode().Perm())
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
	go srv.Serve(context.Background(), l)
	t.Cleanup(func() { l.Close(); srv.Close() })
	return path, sp, adm, srv
}

func frameEvent(t *testing.T, w io.Writer, session byte, out uint64) {
	t.Helper()
	sid := make([]byte, 16)
	sid[0] = session
	b, err := proto.Marshal(&m1pv1.Event{
		SessionId: sid,
		Body:      &m1pv1.Event_Usage{Usage: &m1pv1.Usage{IdemKey: make([]byte, 32), OutputTokens: out}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(w, b); err != nil {
		t.Fatal(err)
	}
}

func readEOF(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection not closed, read err = %v", err)
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
	defer c.Close()
	frameEvent(t, c, 1, 210)
	frameEvent(t, c, 1, 1042)
	// The reject case: bad magic desynchronizes the stream ⇒ close.
	if _, err := c.Write([]byte{'M', '1', 'P', 'X', 0x01, 4, 0, 0, 0, 1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	readEOF(t, c) // EOF is also the barrier: both good frames were admitted first

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

	// A malformed EVENT on intact framing is per-event: quarantined,
	// accounted, and the connection stays open.
	c2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := WriteFrame(c2, []byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	frameEvent(t, c2, 2, 7)
	deadline := time.Now().Add(5 * time.Second)
	for {
		sp.Sync()
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
	frameEvent(t, c, 3, 640)
	frameEvent(t, c, 3, 88)
	// Bad-magic reject as the processing barrier, then shut the daemon down.
	c.Write([]byte("XXXXXXXXX"))
	readEOF(t, c)
	c.Close()
	srv.Close()
	if err := sp.Close(); err != nil { // shutdown drain: forced fsync (07 §6)
		t.Fatal(err)
	}

	sp2, err := spool.Open(spool.Config{Dir: filepath.Join(dir, "spool")}) // runs recovery steps 1–6
	if err != nil {
		t.Fatal(err)
	}
	defer sp2.Close()
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
