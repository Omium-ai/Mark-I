package tailers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
)

// TestIgnoreSubsetMatches pins the documented gitignore subset in BOTH
// directions. Every excluded row is paired with an allowed row over the same
// rule, so a matcher that simply says "ignored" to everything fails here — a
// control that rejects the whole workspace only looks strict.
func TestIgnoreSubsetMatches(t *testing.T) {
	for _, tc := range []struct {
		name    string
		file    string
		rel     string
		isDir   bool
		ignored bool
	}{
		{"comments and blanks ignore nothing", "# secrets/\n\n", "secrets/prod.env", false, false},
		{"dir-only excludes the dir", "secrets/\n", "secrets", true, true},
		{"dir-only takes the whole subtree", "secrets/\n", "secrets/deep/prod.env", false, true},
		{"dir-only spares a same-named FILE", "build/\n", "build", false, false},
		{"anchored at root", "/dist\n", "dist", true, true},
		{"anchored does not match at depth", "/dist\n", "pkg/dist", true, false},
		{"embedded slash is anchored too", "src/gen\n", "src/gen", true, true},
		{"embedded slash not matched at depth", "src/gen\n", "a/src/gen", true, false},
		{"unanchored matches basename at any depth", "vendor\n", "a/b/vendor", true, true},
		{"unanchored basename glob", "*.pem\n", "certs/key.pem", false, true},
		{"unanchored glob spares a non-match", "*.pem\n", "certs/key.pub", false, false},
		{"? is exactly one char", "tmp?\n", "tmp1", false, true},
		{"? does not match zero chars", "tmp?\n", "tmp", false, false},
		{"** crosses segments", "**/vendor\n", "a/b/vendor", true, true},
		{"** matches zero segments", "a/**/c\n", "a/c", false, true},
		{"** matches many segments", "a/**/c\n", "a/x/y/c", false, true},
		{"** does not escape its anchor", "a/**/c\n", "z/a/x/c", false, false},
		{"* alone is the whole-repo opt-out", "*\n", "app/main.go", false, true},
		{"* alone excludes the root itself", "*\n", ".", true, true},
		{"** alone is the whole-repo opt-out", "**\n", "app/main.go", false, true},
		{"an unrelated rule leaves the root readable", "secrets/\n", ".", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ig, err := parseIgnore(tc.file)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.file, err)
			}
			if got := ig.match(tc.rel, tc.isDir); got != tc.ignored {
				t.Fatalf("%q vs %q (isDir=%v): ignored=%v, want %v", tc.file, tc.rel, tc.isDir, got, tc.ignored)
			}
		})
	}
}

// TestIgnoreRefusesUnsupportedConstructs: the subset's boundary is an explicit
// refusal, never a silent no-match. A customer who writes `[Pp]rivate/` must
// not end up with a tailer that read it anyway — so the whole file fails to
// parse and the whole workspace goes dark (fail-closed, 02 CON-007).
func TestIgnoreRefusesUnsupportedConstructs(t *testing.T) {
	refused := []string{
		"secrets/\n!secrets/ok.md\n", // negation
		"[Pp]rivate/\n",              // character class
		"\\#literal\n",               // backslash escape
	}
	for _, text := range refused {
		if _, err := parseIgnore(text); err == nil {
			t.Fatalf("parseIgnore(%q) accepted an unsupported construct", text)
		}
	}
	// Positive control on the same axis: '!' is only special LEADING, and a
	// supported file must still parse — otherwise "refuses everything" would
	// pass the assertions above for free.
	for _, text := range []string{"secrets/\n", "we!rd-name\n", "# just a comment\n"} {
		if _, err := parseIgnore(text); err != nil {
			t.Fatalf("parseIgnore(%q) refused a supported file: %v", text, err)
		}
	}

	// End to end through the oracle: the refused file excludes everything.
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "app"))
	set, err := NewWorkspaceSet(root)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Allowed(filepath.Join(root, "app")) {
		t.Fatal("anti-vacuity: the root must be allowed BEFORE .mark1ignore exists")
	}
	mustWrite(t, filepath.Join(root, IgnoreFileName), "[Pp]rivate/\n")
	if set.Allowed(filepath.Join(root, "app")) {
		t.Fatal("an unparseable .mark1ignore degraded to 'ignore nothing' — the silent widening CON-012 forbids")
	}
	if set.Allowed(root) {
		t.Fatal("the root itself stayed readable under an unparseable .mark1ignore")
	}
}

// TestIgnoreUnreadableFailsClosed: a .mark1ignore that exists but cannot be
// read is not "no exclusions". The consent record is unreadable, so nothing
// under the root may be read (02 CON-007 fail-closed for legality/secrets).
func TestIgnoreUnreadableFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs unix permission bits and a non-root euid")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "app"))
	set, err := NewWorkspaceSet(root)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Allowed(filepath.Join(root, "app")) {
		t.Fatal("anti-vacuity: the root must be allowed before the unreadable file exists")
	}
	path := filepath.Join(root, IgnoreFileName)
	mustWrite(t, path, "secrets/\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if set.Allowed(filepath.Join(root, "app")) {
		t.Fatal("an unreadable .mark1ignore failed OPEN")
	}
	// And it recovers: readable again ⇒ the exclusions apply as written, not
	// a latched deny.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if !set.Allowed(filepath.Join(root, "app")) {
		t.Fatal("a repaired .mark1ignore stayed latched closed")
	}
	if set.Allowed(filepath.Join(root, "secrets")) {
		t.Fatal("the repaired file's own exclusion was not applied")
	}
}

// TestIgnoreDoesNotWidenViaSymlink: the ignore check runs on the RESOLVED
// path, so a symlink whose name is innocuous cannot launder an excluded
// subtree past the oracle.
func TestIgnoreDoesNotWidenViaSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on windows")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "secrets"))
	mustWrite(t, filepath.Join(root, IgnoreFileName), "secrets/\n")
	link := filepath.Join(root, "app")
	if err := os.Symlink(filepath.Join(root, "secrets"), link); err != nil {
		t.Fatal(err)
	}
	set, err := NewWorkspaceSet(root)
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: an ordinary directory of the same name IS allowed, so the
	// refusal below is about the link target, not about the name "app".
	mustMkdir(t, filepath.Join(root, "app2"))
	if !set.Allowed(filepath.Join(root, "app2")) {
		t.Fatal("a plain sibling directory was refused; the assertion below proves nothing")
	}
	if set.Allowed(link) {
		t.Fatal("a symlink laundered an excluded subtree into an allowed name")
	}
}

// TestMark1IgnoredStreamNeverEmits is the CON-012 acceptance criterion at the
// tailers plane: a transcript whose cwd sits under a .mark1ignore'd subtree
// contributes to NO event. Run twice over the identical fixture — once with
// no .mark1ignore, once with one — so the zero is provably caused by the
// exclusion and not by a fixture the manager never parsed.
func TestMark1IgnoredStreamNeverEmits(t *testing.T) {
	root, vendor := t.TempDir(), t.TempDir()
	mustMkdir(t, filepath.Join(root, "app"))
	mustMkdir(t, filepath.Join(root, "secrets"))
	appSession := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	secSession := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	mustWrite(t, filepath.Join(vendor, appSession.String()+".jsonl"),
		cwdUsageLine(filepath.Join(root, "app"), appSession, "msg_app", "req_app", 10))
	mustWrite(t, filepath.Join(vendor, secSession.String()+".jsonl"),
		cwdUsageLine(filepath.Join(root, "secrets"), secSession, "msg_secret", "req_secret", 20))

	// Positive control: with no exclusion file, BOTH streams emit. This is
	// what makes the negative assertion below non-vacuous.
	if ids := runManagerOnce(t, root, vendor); len(ids) != 2 || !ids["msg_app"] || !ids["msg_secret"] {
		t.Fatalf("control run emitted %v; both streams must emit before the exclusion exists", ids)
	}

	mustWrite(t, filepath.Join(root, IgnoreFileName), "# tailers must not read this tree\nsecrets/\n")
	ids := runManagerOnce(t, root, vendor)
	if ids["msg_secret"] {
		t.Fatal("a .mark1ignore'd stream still produced a Usage event (CON-012)")
	}
	if !ids["msg_app"] {
		t.Fatal("the permitted stream stopped emitting — the exclusion over-matched")
	}
	if len(ids) != 1 {
		t.Fatalf("emitted %v, want only the permitted stream", ids)
	}
}

// TestMark1IgnoreWrittenMidSessionStopsStream: admission is not a one-time
// grant. A .mark1ignore written while a stream is already open closes it, and
// the Usage still buffered in that stream is dropped rather than flushed on
// the way out (04 §2.1's "consulted on every DISCOVERY, not just once").
func TestMark1IgnoreWrittenMidSessionStopsStream(t *testing.T) {
	run := func(writeIgnore bool) map[string]bool {
		t.Helper()
		root, vendor := t.TempDir(), t.TempDir()
		mustMkdir(t, filepath.Join(root, "app"))
		session := uuid.MustParse("33333333-3333-4333-8333-333333333333")
		mustWrite(t, filepath.Join(vendor, session.String()+".jsonl"),
			cwdUsageLine(filepath.Join(root, "app"), session, "msg_mid", "req_mid", 30))
		set, err := NewWorkspaceSet(root)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		mgr, err := NewManager(Config{
			Dir: vendor, StateDir: t.TempDir(), Allowed: set.Allowed, UsageIdemKey: testIdemKey,
			Emit: func(_ context.Context, ev *m1pv1.Event) error {
				got[ev.GetUsage().GetMessageId()] = true
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		mgr.Sweep(ctx) // opens the stream; msg_mid is pending, not yet emitted
		if writeIgnore {
			mustWrite(t, filepath.Join(root, IgnoreFileName), "app/\n")
		}
		mgr.Sweep(ctx)
		if err := mgr.CloseFlush(ctx); err != nil {
			t.Fatal(err)
		}
		return got
	}
	// Positive control first: without the mid-session write the pending Usage
	// really does flush, so the empty map below is caused by the exclusion.
	if got := run(false); !got["msg_mid"] {
		t.Fatalf("control run emitted %v; the pending Usage must flush when nothing excludes it", got)
	}
	if got := run(true); len(got) != 0 {
		t.Fatalf("a stream excluded mid-session still emitted %v", got)
	}
}

// --- helpers ---------------------------------------------------------------

// cwdUsageLine is usageLine plus the `cwd` field the containment gate reads
// off the stream head (04 §2.1).
func cwdUsageLine(cwd string, session uuid.UUID, msg, req string, out uint64) string {
	return fmt.Sprintf(`{"type":"assistant","cwd":%q,"isSidechain":false,"requestId":%q,"sessionId":%q,"message":{"id":%q,"model":"claude-fable-5","usage":{"input_tokens":1,"output_tokens":%d,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"service_tier":"standard"}}}`+"\n",
		cwd, req, session.String(), msg, out)
}

// runManagerOnce sweeps and drains one vendor dir under one enabled root,
// returning the message ids that reached Emit.
func runManagerOnce(t *testing.T, root, vendor string) map[string]bool {
	t.Helper()
	set, err := NewWorkspaceSet(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	mgr, err := NewManager(Config{
		Dir: vendor, StateDir: t.TempDir(), Allowed: set.Allowed, UsageIdemKey: testIdemKey,
		Emit: func(_ context.Context, ev *m1pv1.Event) error {
			got[ev.GetUsage().GetMessageId()] = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mgr.Sweep(ctx)
	if err := mgr.CloseFlush(ctx); err != nil {
		t.Fatal(err)
	}
	return got
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
