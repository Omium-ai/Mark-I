//go:build unix

// Unix-tagged with the rest of this package: run() binds the fabric, and
// fabric.Listen refuses on Windows until 07 §5's named pipe lands (main_test.go).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/anchors"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric/fabrictest"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/policy"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/spool"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/verdict"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// kneeAttempt is the attempt the second knee row makes economical to stop at:
// attempts 1..kneeAttempt-1 fall on row 1 (0.9 · 10 = 9.0 > 0.5, keep paying),
// attempt kneeAttempt falls on row 2 (0.1 · 10 = 1.0 ≤ 5.0, stop).
const kneeAttempt = 3

// kneeBundle is the tenant policy the retry loop is arrested by: one verifier
// (the id the LOCAL catalog derives for ruff — a bundle enables by id and can
// never name a command) and a two-row knee table whose rows carry p_lcb. It is
// rendered through the shipping verdict.FromBundle, so the D-Z pointer mapping
// that makes a bundle-sourced knee evaluable at all is on the path under test.
func kneeBundle(t *testing.T) *verdict.BundleMatrices {
	t.Helper()
	below, stop := 0.9, 0.1
	m, err := verdict.FromBundle(&policy.Bundle{
		Seq: 7,
		Verify: policy.VerifySection{
			Priors: policy.Posterior4(verdict.DefaultPriors),
			Verifiers: []policy.VerifierModel{{
				VerifierID: "ruff@cat-1",
				Confusion: [4]policy.Signal3{
					{0.96, 0.02, 0.02}, // satisfied: accept, reject, abstain
					{0.04, 0.95, 0.01}, // violated
					{0.40, 0.30, 0.30}, // refused
					{0.35, 0.25, 0.40}, // error
				},
			}},
		},
		Route: policy.RouteSection{Knee: policy.KneeTable{
			CostBasis: policy.CostBasisUsd,
			VDefault:  10.0,
			Rows: []policy.KneeRow{
				{N: 1, CN: 0.5, PLCB: &below},
				{N: kneeAttempt, CN: 5.0, PLCB: &stop},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Stale {
		t.Fatal("bundle rendered stale: a stale bundle can never stop, so the knee would be untestable")
	}
	return m
}

// defectWorkspace writes a real repo that really configures ruff and really
// fails it: F401, an unused import. Nothing here is a fixture of a verdict —
// the verdict is whatever ruff says about these bytes.
func defectWorkspace(t *testing.T) string {
	t.Helper()
	ws := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"pyproject.toml": "[tool.ruff]\n",
		"defect.py":      "import os\n",
	} {
		if err := os.WriteFile(filepath.Join(ws, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ws
}

// consentTo is the user's half — `mark1 doctor --approve` — done against the
// SAME derivation the daemon will perform. It approves what was derived; it
// cannot name a command, and a machine without ruff on PATH derives nothing and
// consents to nothing, which is the fail-open posture, not a test failure.
func consentTo(t *testing.T, stateDir, worktree string) []anchors.CatalogEntry {
	t.Helper()
	derived, err := anchors.Derive(anchors.NewSandbox(t.TempDir()), worktree)
	if err != nil {
		t.Fatal(err)
	}
	var ruff []anchors.CatalogEntry
	for _, e := range derived {
		if e.Kind == anchors.KindRuff {
			ruff = append(ruff, e)
		}
	}
	if len(ruff) == 0 {
		// Skipping here is right on a developer laptop and catastrophic in CI, where this is the
		// Phase 2 MILESTONE: it exits 0 either way, so the gate it backs reads green while proving
		// nothing (D-CG). Same gate as the store-backed suites, and for the same reason — that
		// variable already covers a non-store binary (receipts/integration_test.go gates `cargo`
		// on it), so requiring an anchor binary needs no second concept.
		if os.Getenv("M1_REQUIRE_STORES") == "1" {
			t.Fatal("ruff is not on PATH but M1_REQUIRE_STORES=1: the Phase 2 milestone must fail loudly rather than skip, since a skip is indistinguishable from a pass in the gate that cites it")
		}
		t.Skip("ruff is not on PATH: the Phase 2 artifact needs a real consented anchor to run, and refuses to fake one")
	}
	if err := anchors.Approve(anchors.ConsentPath(stateDir), time.Now(), ruff...); err != nil {
		t.Fatal(err)
	}
	return ruff
}

type voteSink struct{ vote *m1pv1.AnchorVote }

func (s *voteSink) Admit(_ context.Context, ev *m1pv1.Event) error {
	s.vote = ev.GetAnchorVote()
	return nil
}

// requireRealJudgementOrSkip runs the consented anchor once through the real
// runner and the real sandbox BEFORE the daemon boots. A VERDICT_ERROR means the
// tool never reached the point of judging the code, so every assertion below
// would be measuring the sandbox rather than the knee — and a milestone artifact
// that cannot tell those apart is worse than no artifact. It declines to run and
// says exactly what stopped it.
//
// It used to skip on every many-core host: the anchor memory cap was RLIMIT_AS,
// and ruff's per-core rayon stacks plus mimalloc's arenas exhausted 512 MiB of
// ADDRESS SPACE before parsing a byte, so every run voted VERDICT_ERROR
// ("killed"). The cap is RLIMIT_DATA now (D-AN(b), internal/anchors/sandbox.go)
// and the milestone runs. This is a live guard again, not a known-defect notice.
func requireRealJudgementOrSkip(t *testing.T, stateDir, ws string) {
	t.Helper()
	// Doctor is the call main.go makes, so the entry under test is consented the
	// way the daemon consents it, not the way a test could hand-build it.
	rep, err := anchors.Doctor(anchors.NewSandbox(t.TempDir()), ws, anchors.ConsentPath(stateDir))
	if err != nil || len(rep.Enabled) == 0 {
		t.Fatalf("consented catalog is empty after Approve: %v", err)
	}
	sink := &voteSink{}
	r := anchors.NewRunner(anchors.NewSandbox(t.TempDir()), sink, nil, false)
	if err := r.RunOne(context.Background(), rep.Enabled[0], [16]byte{1}, [16]byte{2}, ws); err != nil {
		t.Fatal(err)
	}
	if sink.vote.GetVote() == m1pv1.Verdict_VERDICT_VIOLATED {
		return
	}
	t.Skipf("PHASE 2 ARTIFACT DID NOT RUN — the consented anchor voted %v (%q) instead of judging the code, "+
		"so everything below would measure the sandbox rather than the knee.",
		sink.vote.GetVote(), sink.vote.GetEvidence().GetDiagnosticCode())
}

// toolUse is the PostToolUse event a real agent emits after every edit — the
// scheduler's trigger, and the only thing this test writes to drive an anchor.
func (f *fabricConn) toolUse(session [16]byte, n int) {
	f.t.Helper()
	f.event(session, &m1pv1.Event{Body: &m1pv1.Event_ToolUse{ToolUse: &m1pv1.ToolUse{
		ToolName:  "Edit",
		ToolUseId: fmt.Sprintf("toolu_01Phase2RetryAttempt%02d", n),
		Status:    m1pv1.ToolStatus_TOOL_STATUS_OK,
	}}})
}

// TestPhase2RetryLoopArrestedAtTheKnee IS the Phase 2 milestone: "retry loops
// demonstrably arrested at the knee on live sessions", with nothing seeded.
//
// What is real: the assembled daemon through run(); the UDS socket, the 08 §4.3
// handshake and every frame; a workspace on disk with a real ruff defect; the
// locally derived, user-consented catalog; the anchor executed by the real
// Landlock/userns sandbox; the AnchorVote it emits; the segmenter's task id;
// fusion; the knee table, decoded from a bundle through verdict.FromBundle.
//
// What this test writes: one human Turn and one ToolUse per attempt. It never
// writes an AnchorVote — every vote here was produced by ruff.
func TestPhase2RetryLoopArrestedAtTheKnee(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	spoolDir := filepath.Join(dir, "spool")
	socket := filepath.Join(fabrictest.SocketDir(t), "sock", "m1p.sock")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(dir, "home")) // keep the tailer off the real ~/.claude

	ws := defectWorkspace(t)
	consentTo(t, stateDir, ws)
	requireRealJudgementOrSkip(t, stateDir, ws)

	stop := runDaemon(t, config{
		stateDir:  stateDir,
		spoolDir:  spoolDir,
		socket:    socket,
		workspace: ws,
		saltHex:   "a1b2c3d4",
		offPoll:   10 * time.Millisecond,
		matrices:  kneeBundle(t),
	})
	waitFor(t, "fabric socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})

	session := uuid.New()
	c := dialFabric(t, socket, session)
	c.prompt(session) // the human turn that opens the task (ADR-0002 R1)

	// The retry loop: each attempt is a tool call on the same task, which the
	// scheduler debounces into one anchor run, whose vote is the attempt's
	// evidence. Below the knee the Stop gate must BLOCK — the agent is forced to
	// keep going, which is the whole mechanism.
	var last *m1pv1.GateVerdict
	for n := 1; n < kneeAttempt; n++ {
		c.toolUse(session, n)
		want := fmt.Sprintf("attempt %d", n)
		waitFor(t, "the stop gate to BLOCK at "+want, func() bool {
			last = c.gate()
			// The reason must name THIS attempt: a BLOCK left over from attempt
			// n-1 would otherwise satisfy the decision check on its own.
			return last.GetDecision() == m1pv1.GateDecision_GATE_DECISION_BLOCK &&
				strings.Contains(last.GetReason(), want)
		})
		if last.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED {
			t.Fatalf("%s BLOCK carries verdict %v, want VIOLATED from ruff", want, last.GetVerdict())
		}
	}

	// The knee: same defect, same anchor, same fused verdict — only the attempt
	// index moved onto the second row, and another attempt stops being worth
	// paying for. The loop is arrested.
	c.toolUse(session, kneeAttempt)
	waitFor(t, "the knee governor to arrest the retry loop", func() bool {
		last = c.gate()
		return strings.Contains(last.GetReason(), "knee governor")
	})
	if last.GetDecision() != m1pv1.GateDecision_GATE_DECISION_ALLOW {
		t.Fatalf("decision %v at the knee, want ALLOW: %s", last.GetDecision(), last.GetReason())
	}
	if last.GetVerdict() != m1pv1.Verdict_VERDICT_VIOLATED {
		t.Fatalf("the knee allow carries verdict %v: the defect did not stop existing, the retry stopped paying", last.GetVerdict())
	}
	if !strings.Contains(last.GetReason(), fmt.Sprintf("attempt %d", kneeAttempt)) {
		t.Fatalf("knee allow %q is not the attempt-%d evaluation", last.GetReason(), kneeAttempt)
	}

	stop()

	// The spool, read cold, is the receipt that the evidence was ruff's own: no
	// path in this test can produce an F401 except running the tool.
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
	votes := 0
	for _, r := range recs {
		var ev m1pv1.Event
		if err := proto.Unmarshal(r.Payload, &ev); err != nil {
			continue
		}
		av := ev.GetAnchorVote()
		if av == nil {
			continue
		}
		votes++
		if av.GetAnchorId() != "ruff@cat-1" || av.GetVote() != m1pv1.Verdict_VERDICT_VIOLATED {
			t.Fatalf("spooled vote %s = %v, want a VIOLATED ruff@cat-1 vote", av.GetAnchorId(), av.GetVote())
		}
		if got := av.GetEvidence().GetDiagnosticCode(); got != "F401" {
			t.Fatalf("spooled vote carries diagnostic_code %q, want ruff's own F401", got)
		}
		if len(av.GetIntegrity().GetEnvScrubAttestation()) == 0 {
			t.Fatal("spooled vote carries no env-scrub attestation: it did not come out of the sandbox")
		}
	}
	if votes < kneeAttempt {
		t.Fatalf("spool holds %d anchor votes, want one per attempt (%d)", votes, kneeAttempt)
	}
}
