package memory

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

func cem888() hostprofile.Profile {
	return hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SchemaVersion: "1"}
}

// TestProposeModeIsADeclaredHostThatOwnsMemory pins FR-SPINE-047's selector:
// Default (Mark 1 owns memory) and a declared host with owns_memory false
// inject; only a declared host that owns memory proposes.
func TestProposeModeIsADeclaredHostThatOwnsMemory(t *testing.T) {
	if ProposeMode(hostprofile.Default) {
		t.Fatal("Default must inject, not propose")
	}
	p := cem888()
	if !ProposeMode(p) {
		t.Fatal("a declared host that owns memory must propose")
	}
	p.OwnsMemory = false
	if ProposeMode(p) {
		t.Fatal("a declared host that does not own memory must inject")
	}
}

// TestProposeInjectsNothingAndRecordsNothing is FR-SPINE-048/049: for a
// cem888 session the hook-context pack and the reactive pitfall return no
// text, record no MemoryInjection and no ArtifactOutcome, never call the
// server's fuzz match, and hand one MemoryProposal per candidate to the sink
// with the candidate text and its evidence. The same cache, asked by a
// Default session, injects as before (FR-SPINE-047).
func TestProposeInjectsNothingAndRecordsNothing(t *testing.T) {
	rs := newRetrievalServer(t, plantedSet())
	rs.match = []Artifact{{ID: pitfallID, Kind: "pitfall", Guidance: "run the retry test with --attempts 3"}}
	sk := &sink{}
	c := newCache(t, rs, sk, m1pv1.Verdict_VERDICT_SATISFIED)
	reg := hostprofile.NewRegistry()
	c.cfg.Profiles = reg
	reg.Set(session, cem888())
	var proposals []*m1pv1.MemoryProposal
	c.SetOnPropose(func(s, tk [16]byte, p *m1pv1.MemoryProposal) {
		if s != session || tk != task {
			t.Errorf("proposal scoped to %x/%x", s, tk)
		}
		proposals = append(proposals, p)
	})
	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session); got != "" {
		t.Fatalf("PROPOSE pack injected text: %q", got)
	}
	// The pack's candidates in LCB order within MInject: fix_pattern, invariant,
	// fix_pattern — pitfalls and non-injectable kinds excluded, exactly what
	// STORE_AND_INJECT would have packed.
	wantCat := []m1pv1.ProposalCategory{
		m1pv1.ProposalCategory_PROPOSAL_CATEGORY_TOOL_GUIDANCE, m1pv1.ProposalCategory_PROPOSAL_CATEGORY_CONVENTION,
		m1pv1.ProposalCategory_PROPOSAL_CATEGORY_TOOL_GUIDANCE,
	}
	if len(proposals) != len(wantCat) {
		t.Fatalf("pack proposed %d, want %d: %v", len(proposals), len(wantCat), proposals)
	}
	for i, p := range proposals {
		if p.GetCategory() != wantCat[i] || p.GetEvidence() != "pack" || p.GetChannel() != m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT {
			t.Fatalf("proposal %d = %v", i, p)
		}
	}
	if !bytes.Equal(proposals[0].GetArtifactId(), idOf(fixID)) || proposals[0].GetCandidateGuidance() != "use exponential backoff" || proposals[0].GetCandidateTrigger() != "flaky retries" {
		t.Fatalf("first proposal lost the candidate: %v", proposals[0])
	}
	if got := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), session); got != "" || len(proposals) != MInject {
		t.Fatalf("second pack must propose nothing again: %q, %d", got, len(proposals))
	}

	// Reactive: an exact digest proposes the pitfall with the digest as
	// evidence; a near miss proposes nothing and NEVER asks the server.
	if got := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, planted), session); got != "" {
		t.Fatalf("PROPOSE pitfall injected text: %q", got)
	}
	if len(proposals) != MInject+1 || proposals[MInject].GetCategory() != m1pv1.ProposalCategory_PROPOSAL_CATEGORY_PITFALL ||
		proposals[MInject].GetEvidence() != SignatureDigest(NormalizeSignature(planted)) || !strings.Contains(proposals[MInject].GetCandidateGuidance(), "--attempts 3") {
		t.Fatalf("pitfall proposal: %v", proposals)
	}
	if got := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, near), session); got != "" || len(proposals) != MInject+1 {
		t.Fatalf("near miss: %q, %d proposals", got, len(proposals))
	}
	if rs.matches != 0 {
		t.Fatalf("PROPOSE made %d /memory/match call(s); the rule is none for the session", rs.matches)
	}
	c.OnClose(task)
	time.Sleep(50 * time.Millisecond)
	if inj, out := sk.injections(), sk.outcomes(); len(inj) != 0 || len(out) != 0 {
		t.Fatalf("PROPOSE recorded %d injection(s) and %d outcome(s); want none", len(inj), len(out))
	}

	// FR-SPINE-047: the same cache, a session with no declared profile,
	// injects as before.
	solo := [16]byte{0x50, 1}
	c.cfg.TaskFor = func(s, _ [16]byte) ([16]byte, bool) { return task, s == solo || s == session }
	proposalsBefore := len(proposals)
	text := c.Context(context.Background(), query(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, ""), solo)
	if !strings.Contains(text, "use exponential backoff") {
		t.Fatalf("Default session did not inject: %q", text)
	}
	if len(proposals) != proposalsBefore {
		t.Fatal("Default session produced a proposal")
	}
}
