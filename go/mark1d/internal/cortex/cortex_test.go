package cortex

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"lukechampine.com/blake3"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
)

// The re-exec seam supervise_test uses: this test binary IS the fake cortexd.
// "record" writes its argv to $CORTEX_TEST_OUT/<pid> and stays up until
// signalled, which is all a supervised child has to do to be counted.
const (
	childEnvVar = "CORTEX_TEST_CHILD"
	childOutVar = "CORTEX_TEST_OUT"
)

func TestMain(m *testing.M) {
	switch os.Getenv(childEnvVar) {
	case "":
		os.Exit(m.Run())
	case "record":
		out := filepath.Join(os.Getenv(childOutVar), strconv.Itoa(os.Getpid()))
		if err := os.WriteFile(out, []byte(strings.Join(os.Args[1:], "\n")), 0o600); err != nil {
			os.Exit(2)
		}
		time.Sleep(time.Hour)
		os.Exit(0)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// workspace makes an enabled root and the vendor transcript dir a session in
// it would be filed under (08 §5.1), returning both.
func workspace(t *testing.T, home, name string) (root, transcripts string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	d, err := (&claudecode.Adapter{Home: home}).TranscriptDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return root, d
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func event(sid [16]byte, body any) *m1pv1.Event {
	ev := &m1pv1.Event{SessionId: sid[:]}
	switch b := body.(type) {
	case *m1pv1.SessionStart:
		ev.Body = &m1pv1.Event_SessionStart{SessionStart: b}
	case *m1pv1.SessionEnd:
		ev.Body = &m1pv1.Event_SessionEnd{SessionEnd: b}
	case *m1pv1.ToolUse:
		ev.Body = &m1pv1.Event_ToolUse{ToolUse: b}
	case *m1pv1.CortexInjection:
		ev.Body = &m1pv1.Event_CortexInjection{CortexInjection: b}
	}
	return ev
}

func readSessionFile(t *testing.T, path string) (sessionFile, os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("session file: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sf sessionFile
	if err := json.Unmarshal(b, &sf); err != nil {
		t.Fatalf("session file %q: %v", b, err)
	}
	return sf, fi.Mode().Perm()
}

// TestCortexChildIsSupervisedPerWorkspace: 04 §1.2's per-workspace spawn.
// Two enabled roots ⇒ two children, each told its own root, store, session
// file and the bundle budget; cancelling the session reaps both.
func TestCortexChildIsSupervisedPerWorkspace(t *testing.T) {
	state := t.TempDir()
	out := t.TempDir()
	rootA, _ := workspace(t, t.TempDir(), "a")
	rootB, _ := workspace(t, t.TempDir(), "b")
	t.Setenv(childEnvVar, "record")
	t.Setenv(childOutVar, out)
	p, err := New(Config{StateDir: state, Roots: []string{rootA, rootB}, Budget: 4096, Binary: os.Args[0], Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		p.Supervise(ctx)
		close(done)
	}()
	var argvs []string
	for deadline := time.Now().Add(30 * time.Second); len(argvs) < 2; {
		if time.Now().After(deadline) {
			t.Fatalf("only %d child(ren) reported in: %v", len(argvs), argvs)
		}
		time.Sleep(10 * time.Millisecond)
		entries, _ := os.ReadDir(out)
		argvs = argvs[:0]
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(out, e.Name()))
			argvs = append(argvs, string(b))
		}
	}
	cancel()
	<-done

	for _, root := range []string{rootA, rootB} {
		want := strings.Join([]string{
			"--root", root,
			"--store", filepath.Join(state, "cortex", WorkspaceID(root)),
			"--budget", "4096",
			"--session-file", SessionFile(state, root),
		}, "\n")
		found := false
		for _, a := range argvs {
			found = found || a == want
		}
		if !found {
			t.Errorf("no child was started for %s with\n%s\ngot:\n%s", root, want, strings.Join(argvs, "\n---\n"))
		}
	}
	// Reaped, not orphaned: every recorded pid is gone.
	if runtime.GOOS != "windows" {
		entries, _ := os.ReadDir(out)
		for _, e := range entries {
			pid, _ := strconv.Atoi(e.Name())
			if proc, err := os.FindProcess(pid); err == nil && proc.Signal(nil) == nil {
				// Signal(nil) on unix is a liveness probe. A zombie also answers
				// it, so give the reaper a moment before calling it a leak.
				time.Sleep(200 * time.Millisecond)
				if proc.Signal(nil) == nil {
					t.Errorf("child %d outlived the supervisor", pid)
				}
			}
		}
	}
}

// TestSessionFileTracksSessionStartAndEnd: the daemon publishes a workspace's
// live session for its cortexd only once the vendor has filed the session's
// transcript under that workspace, and unpublishes it on SessionEnd. A session
// in no enabled root never gets a file — no attribution by guess.
func TestSessionFileTracksSessionStartAndEnd(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	root, transcripts := workspace(t, home, "repo")
	p, err := New(Config{StateDir: state, Roots: []string{root}, Home: home, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	file := SessionFile(state, root)
	sid := uuid.New()

	// SessionStart fires before the transcript exists (it appears with the
	// first prompt): nothing to attribute yet, so nothing is published.
	p.Observe(event(sid, &m1pv1.SessionStart{Agent: "claudecode"}))
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("published before the vendor filed the session anywhere: %v", err)
	}
	// A session filed under some OTHER cwd is not this workspace's.
	stranger := uuid.New()
	touch(t, filepath.Join(transcripts, "..", "-somewhere-else", stranger.String()+".jsonl"))
	p.Observe(event(stranger, &m1pv1.ToolUse{}))
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("a session outside every enabled root was attributed to one: %v", err)
	}

	touch(t, filepath.Join(transcripts, sid.String()+".jsonl"))
	p.Observe(event(sid, &m1pv1.ToolUse{}))
	sf, mode := readSessionFile(t, file)
	if sf.SessionIDHex != hex.EncodeToString(sid[:]) {
		t.Fatalf("session_id_hex %q, want %x", sf.SessionIDHex, sid[:])
	}
	if _, err := time.Parse(time.RFC3339, sf.StartedAt); err != nil {
		t.Fatalf("started_at %q: %v", sf.StartedAt, err)
	}
	if runtime.GOOS != "windows" && mode != 0o600 {
		t.Fatalf("session file mode %o, want 0600", mode)
	}

	// A second session in the same workspace takes over the file; the first
	// ending then leaves the second's identity in place, and the second
	// ending removes it.
	sid2 := uuid.New()
	touch(t, filepath.Join(transcripts, sid2.String()+".jsonl"))
	p.Observe(event(sid2, &m1pv1.SessionStart{}))
	if sf, _ := readSessionFile(t, file); sf.SessionIDHex != hex.EncodeToString(sid2[:]) {
		t.Fatalf("newest live session not published: %q", sf.SessionIDHex)
	}
	p.Observe(event(sid, &m1pv1.SessionEnd{}))
	if sf, _ := readSessionFile(t, file); sf.SessionIDHex != hex.EncodeToString(sid2[:]) {
		t.Fatalf("an older session's end unpublished the live one: %q", sf.SessionIDHex)
	}
	p.Observe(event(sid2, &m1pv1.SessionEnd{}))
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("session file survived SessionEnd: %v", err)
	}
	// Boot hygiene: a file this daemon did not write is not evidence.
	touch(t, file)
	if _, err := New(Config{StateDir: state, Roots: []string{root}, Home: home, Log: quiet()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("a stale session file survived New: %v", err)
	}
}

// --- the fake cortexd: a Go M1PL client doing exactly what fabric/mod.rs does ---

func writeFrame(t *testing.T, w io.Writer, f *m1pv1.FabricFrame) {
	t.Helper()
	b, err := proto.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := fabric.WriteFrame(w, b); err != nil {
		t.Fatal(err)
	}
}

func readFrame(t *testing.T, c net.Conn) *m1pv1.FabricFrame {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dec := &fabric.Decoder{}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("reading the daemon's reply: %v", err)
		}
		dec.Push(buf[:n])
		payload, _, derr := dec.Next()
		if derr != nil {
			t.Fatal(derr)
		}
		if payload == nil {
			continue
		}
		f := &m1pv1.FabricFrame{}
		if err := proto.Unmarshal(payload, f); err != nil {
			t.Fatal(err)
		}
		return f
	}
}

// fakeSandbox is anchors' test double, restated: RunOne must see a run to
// emit the vote whose integrity envelope this test reads.
type fakeSandbox struct{}

func (fakeSandbox) Run(_ context.Context, spec anchors.RunSpec) (anchors.RunResult, error) {
	var env []string
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	return anchors.RunResult{ExitCode: 0, EffectiveEnv: env}, nil
}
func (fakeSandbox) FSConfined() bool { return false }

type recordingEmitter struct {
	mu  sync.Mutex
	evs []*m1pv1.Event
}

func (r *recordingEmitter) Admit(_ context.Context, ev *m1pv1.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recordingEmitter) roots() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out [][]byte
	for _, ev := range r.evs {
		out = append(out, ev.GetAnchorVote().GetIntegrity().GetWorktreeMerkleRoot())
	}
	return out
}

// consentedRuff builds an Enabled-shaped entry by hand, hash-bound to a fake
// binary so RunOne's consent gate at the execution point passes.
func consentedRuff(t *testing.T) anchors.CatalogEntry {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ruff")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	sum := blake3.Sum256(b)
	return anchors.CatalogEntry{
		ID: "ruff@cat-1", Kind: anchors.KindRuff, Tool: "ruff",
		Argv:  []string{bin, "check", "--output-format", "concise", "."},
		Class: anchors.ClassFast, SideEffect: anchors.SideEffectStatic,
		BinaryPath: bin, BinaryHash: sum[:], ToolVersion: "0.0", ConsentedAt: time.Now(),
	}
}

// TestCortexInjectionRootReachesTheAnchorRunner is the whole seam, end to
// end, with the daemon's own parts: the fabric server admits a fake cortexd
// that Hellos with the session the daemon PUBLISHED (read back from the file,
// not invented), its CortexInjection reaches Observe on the handler path
// cmd/main.go runs, and the next anchor vote carries that root as
// worktree_merkle_root (TestRunOneL0RootSeam is the callee-side model).
func TestCortexInjectionRootReachesTheAnchorRunner(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	root, transcripts := workspace(t, home, "repo")
	p, err := New(Config{StateDir: state, Roots: []string{root}, Home: home, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	em := &recordingEmitter{}
	runner := anchors.NewRunner(fakeSandbox{}, em, nil, false)
	p.OnRoot(root, runner.SetL0Root)

	// The daemon's fabric handler, as cmd/main.go assembles it: decode, then
	// Observe. Admission itself is stubbed — the spool is not under test.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := fabric.NewServer(func(_ context.Context, payload []byte) error {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(payload, ev); err != nil {
			return err
		}
		p.Observe(ev)
		return nil
	}, nil)
	go func() { _ = srv.Serve(context.Background(), l) }()
	t.Cleanup(func() { _ = l.Close(); srv.Close() })

	// The agent's session becomes attributable, and the daemon publishes it.
	sid := uuid.New()
	touch(t, filepath.Join(transcripts, sid.String()+".jsonl"))
	p.Observe(event(sid, &m1pv1.SessionStart{Agent: "claudecode"}))
	sf, _ := readSessionFile(t, SessionFile(state, root))
	published, err := hex.DecodeString(sf.SessionIDHex)
	if err != nil || len(published) != 16 {
		t.Fatalf("published session %q", sf.SessionIDHex)
	}

	// Fake cortexd: Hello WITH the published session, push a root.
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	writeFrame(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Hello{
		Hello: &m1pv1.Hello{Component: "cortexd", Pid: 1, Version: "0.1.0", SessionId: published},
	}})
	if ack := readFrame(t, c).GetHelloAck(); ack == nil || !ack.GetAccepted() {
		t.Fatalf("the daemon refused the session it published itself: %+v", ack)
	}
	want := bytes.Repeat([]byte{0x5A}, 32)
	writeFrame(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Event{Event: &m1pv1.Event{
		SessionId: published,
		Body:      &m1pv1.Event_CortexInjection{CortexInjection: &m1pv1.CortexInjection{RootHash: want, IndexClock: 1}},
	}}})
	writeFrame(t, c, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_Flush{Flush: &m1pv1.Flush{}}})
	if d := readFrame(t, c).GetFlushAck().GetDrained(); d != 1 {
		t.Fatalf("drained %d, want the root push", d)
	}

	// The next vote carries it.
	e := consentedRuff(t)
	if err := runner.RunOne(context.Background(), e, sid, [16]byte{1}, root); err != nil {
		t.Fatal(err)
	}
	if roots := em.roots(); len(roots) != 1 || !bytes.Equal(roots[0], want) {
		t.Fatalf("worktree_merkle_root %x, want cortexd's pushed root %x", roots, want)
	}

	// A push under a session that has ENDED is admitted (capture's business)
	// but stamps nothing: cortexd's own event is not evidence its session is
	// live, and the root it carries would be attributed to nobody.
	p.Observe(event(sid, &m1pv1.SessionEnd{}))
	p.Observe(event(sid, &m1pv1.CortexInjection{RootHash: bytes.Repeat([]byte{0xEE}, 32), IndexClock: 2}))
	if err := runner.RunOne(context.Background(), e, sid, [16]byte{1}, root); err != nil {
		t.Fatal(err)
	}
	if roots := em.roots(); len(roots) != 2 || !bytes.Equal(roots[1], want) {
		t.Fatalf("a push under an ended session moved the root: %x", roots)
	}
}

func TestBudgetFromBundle(t *testing.T) {
	for _, tc := range []struct {
		sec  policy.CortexSection
		want uint32
	}{
		{policy.CortexSection{}, DefaultBudget},
		{policy.CortexSection{MapBudgetTokensMin: 1000, MapBudgetTokensMax: 6000}, 6000},
		{policy.CortexSection{MapBudgetTokensMax: 1 << 40}, DefaultBudget},
	} {
		if got := BudgetFrom(tc.sec); got != tc.want {
			t.Errorf("BudgetFrom(%+v) = %d, want %d", tc.sec, got, tc.want)
		}
	}
	// A missing binary is a logged refusal, never a crash loop — and never a
	// reason New fails, since Observe/OnRoot still serve a hand-run cortexd.
	p, err := New(Config{StateDir: t.TempDir(), Roots: []string{t.TempDir()}, Binary: filepath.Join(t.TempDir(), "nope"), Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { p.Supervise(t.Context()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Supervise did not return on a missing binary")
	}
}
