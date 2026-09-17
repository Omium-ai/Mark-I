package fabric

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"
)

// testPipe is SocketPath() plus a random suffix so parallel tests (and a live daemon) never share an instance.
func testPipe(t *testing.T) string {
	t.Helper()
	p, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return p + "-test-" + hex.EncodeToString(b[:])
}

// TestSocketPathIsThePerUserPipe pins 07 §5's Windows endpoint: prefix + this user's string SID, nothing else.
func TestSocketPathIsThePerUserPipe(t *testing.T) {
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sid, "S-1-") || strings.Count(sid, "-") < 3 {
		t.Fatalf("userSID %q is not a string SID", sid)
	}
	p, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if p != `\\.\pipe\omium-mark1-`+sid {
		t.Fatalf("SocketPath %q, want \\\\.\\pipe\\omium-mark1-%s", p, sid)
	}
}

// TestListenPipeRoundTrip drives the production accept loop over the pipe: DialPipe, Hello/HelloAck, one Event, the inner bytes at the handle.
func TestListenPipeRoundTrip(t *testing.T) {
	path := testPipe(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got [][]byte
	srv := NewServer(func(_ context.Context, p []byte) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, append([]byte(nil), p...))
		return nil
	}, nil)
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })

	c, err := winio.DialPipe(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	hello(t, c)
	writeEvent(t, c, 7, 42)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("handle saw %d payloads, want 1", len(got))
	}
	ev := &m1pv1.Event{}
	if err := proto.Unmarshal(got[0], ev); err != nil {
		t.Fatalf("handle payload is not an Event: %v", err)
	}
	if ev.GetSessionId()[0] != 7 || ev.GetUsage().GetOutputTokens() != 42 {
		t.Fatalf("event round-trip mismatch: %v", ev)
	}
}

// TestListenPipeDACLIsOwnerOnly reads the DACL back off the live pipe: exactly one ACE, allow, this user's SID.
func TestListenPipeDACLIsOwnerOnly(t *testing.T) {
	path := testPipe(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	// go-winio only has a connectable instance while an Accept is pending.
	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.Close()
		}
	}()
	c, err := winio.DialPipe(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	h := windows.Handle(c.(interface{ Fd() uintptr }).Fd())
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if dacl == nil {
		t.Fatal("pipe has a NULL DACL — that grants everyone")
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL has %d ACEs, want exactly 1 (owner SID): %s", dacl.AceCount, sd.String())
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("ACE type %d, want ACCESS_ALLOWED: %s", ace.Header.AceType, sd.String())
	}
	sid, err := userSID()
	if err != nil {
		t.Fatal(err)
	}
	if got := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String(); got != sid {
		t.Fatalf("ACE grants %s, want this user %s", got, sid)
	}
}

// TestListenPipeRefusesASecondInstance is the single-writer discipline: a name already served is a refusal.
func TestListenPipeRefusesASecondInstance(t *testing.T) {
	path := testPipe(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if l2, err := Listen(path); err == nil {
		_ = l2.Close()
		t.Fatal("second Listen on a held pipe name succeeded")
	}
}
