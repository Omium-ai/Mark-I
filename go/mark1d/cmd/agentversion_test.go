package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Omium-ai/omium-mark1/go/mark1d/adapters/claudecode"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/capture"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/coverage"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/redact"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/route"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/taskseg"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/proto"
)

// fakeClaudeOnPath puts a `claude` on PATH that reports version. The version
// sniff execs the real binary, so a version fixture has to be an executable,
// not a stub type. Every daemon-level test that expects the tailer to RUN
// needs this: a runner has no `claude` at all, and a developer's is whatever
// npm installed this week, neither of which is the pinned version.
func fakeClaudeOnPath(t *testing.T, version string) {
	t.Helper()
	bin := t.TempDir()
	name, script := "claude", "#!/bin/sh\necho '"+version+" (Claude Code)'\n"
	if runtime.GOOS == "windows" {
		// What npm puts on a Windows PATH is claude.cmd, and LookPath("claude")
		// resolves it through PATHEXT — the same route Detect takes there.
		name, script = "claude.cmd", "@echo "+version+" (Claude Code)\r\n"
	}
	if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil { //nolint:gosec // G306: it must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	// Detect reads ANTHROPIC_API_KEY to classify the regime. Unset it so the
	// test does not depend on the developer's environment.
	t.Setenv("ANTHROPIC_API_KEY", "")
	// The structural probe (D-EE) reads ~/.claude/projects; never the developer's.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

// unpinnedTranscript lays one transcript line from an unpinned `claude` under
// the test HOME — the evidence the structural probe admits or refuses on.
func unpinnedTranscript(t *testing.T, line string) {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".claude", "projects", "-home-devuser-workspace-acme-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aa000000-0000-4000-8000-000000000201.jsonl"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

const unpinnedUsageLine = `{"isSidechain":false,"message":{"model":"claude-x","id":"msg_01A","role":"assistant","usage":{"input_tokens":2,"cache_creation_input_tokens":6425,"cache_read_input_tokens":10143,"output_tokens":4,"service_tier":"standard"}},"requestId":"req_01A","type":"assistant","cwd":"/home/devuser/workspace/acme-app","sessionId":"aa000000-0000-4000-8000-000000000201","version":"9.9.9"}`

// pinnedAgentVersion is any version the conformance corpus pins — the one
// input under which capture must run.
func pinnedAgentVersion(t *testing.T) string {
	t.Helper()
	for v := range claudecode.SupportedVersions {
		return v
	}
	t.Fatal("SupportedVersions is empty; capture is disabled for every version")
	return ""
}

// fakeClaude is fakeClaudeOnPath plus the state dir, spool and admitter
// tailWorkspaces runs against.
func fakeClaude(t *testing.T, version string) (state string, adm *capture.Admitter, sp *spool.Spool) {
	t.Helper()
	fakeClaudeOnPath(t, version)

	state = t.TempDir()
	var err error
	sp, err = spool.Open(spool.Config{Dir: filepath.Join(state, "spool")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	sc, err := redact.NewScanner(nil)
	if err != nil {
		t.Fatal(err)
	}
	adm, err = capture.New(sp, capture.Config{
		EpochPath: filepath.Join(state, "session_epoch"),
		Redact:    sc.RedactEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state, adm, sp
}

// runTail runs tailWorkspaces and reports whether it returned on its own
// before the deadline. A refusal returns immediately; an accepted version runs
// until its context ends, which is what distinguishes the two paths without
// needing a transcript fixture to produce events from.
func runTail(t *testing.T, state string, adm *capture.Admitter, cov *coverage.Emitter) (returnedEarly bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- tailWorkspaces(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)),
			config{stateDir: state}, []byte("idem-key-for-the-test"), adm, cov, &route.Emitter{Next: adm.Admit}, taskseg.New(make([]byte, 32)))
	}()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		return false
	}
}

// TestUnsupportedAgentVersionDropsTheTranscriptSurface is 12 §7's
// `adapter_version_sniff_drop` and FR-AGENT-002's acceptance criterion:
// an unsupported version yields Dropped{UNSUPPORTED_AGENT_VERSION} and zero
// parsed events from that surface.
//
// The failure this guards is not a crash. internal/tailers.txLine names every
// token field as a compiled struct tag, so a release that renames one still
// decodes — encoding/json leaves the field zero and a well-formed Usage
// carrying wrong numbers reaches the ledger with nothing marking it. Refusing
// the surface is the only outcome an operator can see.
func TestUnsupportedAgentVersionDropsTheTranscriptSurface(t *testing.T) {
	state, adm, _ := fakeClaude(t, "99.0.0")

	if !runTail(t, state, adm, nil) {
		t.Fatal("tailWorkspaces kept tailing an unpinned version — it parsed blind")
	}

	drops := adm.DrainDropped()
	if len(drops) != 1 {
		t.Fatalf("drop rows = %d (%v), want exactly one", len(drops), drops)
	}
	if drops[0].Reason != dropUnsupportedAgentVersion {
		t.Errorf("reason = %d, want %d (DROP_REASON_UNSUPPORTED_AGENT_VERSION)",
			drops[0].Reason, dropUnsupportedAgentVersion)
	}
	// Billing-grade, not diagnostic: what the refusal loses is Usage, and the
	// loss ledger has to say a billable class went unread.
	if drops[0].Class != spool.ClassBilling {
		t.Errorf("class = %v, want billing — the refused surface is the Usage source", drops[0].Class)
	}
}

// TestAnUnsniffableAgentIsAlsoDropped covers the shape that is easy to read as
// benign: `claude` absent from the daemon's PATH. Detect reports Installed
// false and version "", and a daemon that cannot see the binary cannot know
// the format — a service-managed daemon with a trimmed PATH is a live install
// whose transcripts we would otherwise parse against a guessed version.
func TestAnUnsniffableAgentIsAlsoDropped(t *testing.T) {
	state, adm, _ := fakeClaude(t, "2.1.251")
	t.Setenv("PATH", t.TempDir()) // same fixture, binary now out of reach

	if !runTail(t, state, adm, nil) {
		t.Fatal("tailWorkspaces kept tailing an agent it could not version-sniff")
	}
	drops := adm.DrainDropped()
	if len(drops) != 1 || drops[0].Reason != dropUnsupportedAgentVersion {
		t.Fatalf("drops = %v, want one UNSUPPORTED_AGENT_VERSION row", drops)
	}
}

// TestSupportedAgentVersionKeepsTailing is the positive control, and it is the
// half that makes the two tests above mean anything: without it "zero events"
// and "returned early" are satisfied by a tailWorkspaces that refuses
// everything. The pinned version must reach the tailer fleet and raise no drop
// row at all.
func TestSupportedAgentVersionKeepsTailing(t *testing.T) {
	pinned := pinnedAgentVersion(t)
	state, adm, _ := fakeClaude(t, pinned)

	if runTail(t, state, adm, coverage.New(adm.Admit, nil)) {
		t.Fatalf("tailWorkspaces refused %s, which conformance/hooks/claudecode pins", pinned)
	}
	if drops := adm.DrainDropped(); len(drops) != 0 {
		t.Fatalf("a supported version raised drop rows: %v", drops)
	}
}

// spooledCoverage reads back every CoverageTransition the spool holds. It
// decodes rather than counts: "a record exists" is satisfied by any bytes.
func spooledCoverage(t *testing.T, sp *spool.Spool) []*m1pv1.CoverageTransition {
	t.Helper()
	if err := sp.Sync(); err != nil { // Records reads the durable region only
		t.Fatal(err)
	}
	ack, _ := sp.Cursors()
	recs, _, err := sp.Records(ack)
	if err != nil {
		t.Fatal(err)
	}
	var out []*m1pv1.CoverageTransition
	for _, r := range recs {
		ev := &m1pv1.Event{}
		if err := proto.Unmarshal(r.Payload, ev); err != nil {
			t.Fatalf("a spooled record did not decode as an Event: %v", err)
		}
		if b, ok := ev.GetBody().(*m1pv1.Event_CoverageTransition); ok {
			out = append(out, b.CoverageTransition)
		}
	}
	return out
}

// TestUnsupportedAgentVersionReceiptsTheBypassWindow is the coverage half of
// FR-AGENT-002's refusal, and the reason the Dropped row alone was never
// enough. That row says one SURFACE was refused; it cannot say how many events
// were lost, because refusing is what stops us counting them. The bypass
// window is the honest number — and without it the band is computed as if
// capture had been armed the whole time, which is the assumed-100%-coverage
// billing failure C13 exists to end.
func TestUnsupportedAgentVersionReceiptsTheBypassWindow(t *testing.T) {
	state, adm, sp := fakeClaude(t, "99.0.0")

	if !runTail(t, state, adm, coverage.New(adm.Admit, nil)) {
		t.Fatal("tailWorkspaces kept tailing an unpinned version — it parsed blind")
	}

	got := spooledCoverage(t, sp)
	if len(got) != 1 {
		t.Fatalf("coverage transitions = %d, want exactly 1 — the refusal opened an unreceipted window", len(got))
	}
	if got[0].GetReasonCode() != coverage.ReasonUnsupportedAgentVersion {
		t.Errorf("reason_code = %q, want %q", got[0].GetReasonCode(), coverage.ReasonUnsupportedAgentVersion)
	}
	if got[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_BYPASS {
		t.Errorf("kind = %v, want BYPASS — an unarmed capture surface is a bypass window, not a disable", got[0].GetKind())
	}
	// Zero duration files it as bypass_start server-side: capture never arms
	// for this daemon's life, so the window has no in-process close.
	if got[0].GetDurationMs() != 0 {
		t.Errorf("duration_ms = %d, want 0 (bypass_start)", got[0].GetDurationMs())
	}
	if len(got[0].GetWorkspaceId()) != coverage.WorkspaceIDLen {
		t.Errorf("workspace_id is %d bytes; m1_043 CHECKs exactly %d inside the checkpoint transaction",
			len(got[0].GetWorkspaceId()), coverage.WorkspaceIDLen)
	}
	// Both halves, from one refusal: the loss ledger AND the coverage window.
	if drops := adm.DrainDropped(); len(drops) != 1 || drops[0].Reason != dropUnsupportedAgentVersion {
		t.Fatalf("drops = %v, want one UNSUPPORTED_AGENT_VERSION row alongside the bypass", drops)
	}
}

// TestSupportedAgentVersionReceiptsNoBypass is the positive control for the
// test above: without it, "a bypass was emitted" is equally satisfied by a
// tailWorkspaces that declares a bypass on every boot, which would drag every
// tenant's band down for no reason.
func TestSupportedAgentVersionReceiptsNoBypass(t *testing.T) {
	pinned := pinnedAgentVersion(t)
	state, adm, sp := fakeClaude(t, pinned)
	if runTail(t, state, adm, coverage.New(adm.Admit, nil)) {
		t.Fatalf("tailWorkspaces refused %s, which conformance/hooks/claudecode pins", pinned)
	}
	if got := spooledCoverage(t, sp); len(got) != 0 {
		t.Fatalf("a supported version declared %d coverage bypass windows: %v", len(got), got)
	}
}

// TestCompatibleUnpinnedVersionCapturesAndReceipts is D-EE's middle verdict:
// an unpinned version whose transcript shape passes the structural probe is
// TAILED (no drop row), and the unverified window is receipted as the same
// unsupported_agent_version bypass the refusal uses.
func TestCompatibleUnpinnedVersionCapturesAndReceipts(t *testing.T) {
	state, adm, sp := fakeClaude(t, "9.9.9")
	unpinnedTranscript(t, unpinnedUsageLine)

	if runTail(t, state, adm, coverage.New(adm.Admit, nil)) {
		t.Fatal("tailWorkspaces refused a structurally compatible unpinned version")
	}
	if drops := adm.DrainDropped(); len(drops) != 0 {
		t.Fatalf("compatible_unpinned raised drop rows: %v", drops)
	}
	got := spooledCoverage(t, sp)
	if len(got) != 1 || got[0].GetReasonCode() != coverage.ReasonUnsupportedAgentVersion ||
		got[0].GetKind() != m1pv1.CoverageKind_COVERAGE_KIND_BYPASS || got[0].GetDurationMs() != 0 {
		t.Fatalf("coverage = %v, want exactly one unsupported_agent_version bypass_start marking the window unverified", got)
	}
}

// TestIncompatibleUnpinnedShapeRefuses: the probe fails (a token field the
// corpus relies on is gone) ⇒ today's refusal, drop row and bypass included.
func TestIncompatibleUnpinnedShapeRefuses(t *testing.T) {
	state, adm, sp := fakeClaude(t, "9.9.9")
	unpinnedTranscript(t, strings.Replace(unpinnedUsageLine, `"cache_read_input_tokens":10143,`, "", 1))

	if !runTail(t, state, adm, coverage.New(adm.Admit, nil)) {
		t.Fatal("tailWorkspaces tailed an unpinned version whose shape failed the probe — it parsed blind")
	}
	if drops := adm.DrainDropped(); len(drops) != 1 || drops[0].Reason != dropUnsupportedAgentVersion {
		t.Fatalf("drops = %v, want one UNSUPPORTED_AGENT_VERSION row", drops)
	}
	if got := spooledCoverage(t, sp); len(got) != 1 {
		t.Fatalf("coverage transitions = %d, want 1", len(got))
	}
}
