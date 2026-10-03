package memory

import (
	"context"
	"strings"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/fabric"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// ADR-0016 PROPOSE mode. Detection is the same as STORE_AND_INJECT's; what
// differs is the sink: nothing is injected, no MemoryInjection or
// ArtifactOutcome is recorded, the server's fuzz hop is never made for the
// session, and each candidate becomes one MemoryProposal to the host.

// ProposeMode reports whether a profile puts memory in PROPOSE mode: a
// DECLARED host (host_id set) that owns memory. hostprofile.Default's
// OwnsMemory reads "the owner — Mark 1 — owns it" and never proposes, the
// same declared-host reading as ADR-0014 §4.
func ProposeMode(p hostprofile.Profile) bool { return p.HostID != "" && p.OwnsMemory }

// SetOnPropose installs the daemon's proposal sink (cmd/propose.go). nil
// drops proposals, which only tests do.
func (c *Cache) SetOnPropose(fn func(session, task [16]byte, p *m1pv1.MemoryProposal)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onPropose = fn
}

// category maps an artifact kind (08 §3.7's vocabulary) to the proposal's.
func category(kind string) m1pv1.ProposalCategory {
	switch kind {
	case "pitfall":
		return m1pv1.ProposalCategory_PROPOSAL_CATEGORY_PITFALL
	case "invariant":
		return m1pv1.ProposalCategory_PROPOSAL_CATEGORY_CONVENTION
	case "fix_pattern":
		return m1pv1.ProposalCategory_PROPOSAL_CATEGORY_TOOL_GUIDANCE
	}
	return m1pv1.ProposalCategory_PROPOSAL_CATEGORY_UNSPECIFIED
}

// propose is PROPOSE mode's Context: the candidates STORE_AND_INJECT would
// have packed (hook context) or the exact-digest pitfall it would have
// delivered (reactive), each handed to the sink as a MemoryProposal. Returns
// "" always — the host injects, or does not, by its own means. The fuzz
// server hop (c.fuzz) is deliberately absent: 08 §3.7's rule for the session.
func (c *Cache) propose(_ context.Context, q fabric.ContextQuery, session, task [16]byte) string {
	c.mu.Lock()
	sink := c.onPropose
	c.mu.Unlock()
	if sink == nil {
		return ""
	}
	st := c.state(session, task)
	room, seen := c.budget(st)
	if room <= 0 {
		return ""
	}
	emit := func(a Artifact, ch m1pv1.InjectionChannel, evidence string) {
		id, _ := idBytes(a)
		c.mu.Lock()
		st.seen[a.ID] = true // one proposal per artifact per task, as one injection would be
		c.mu.Unlock()
		sink(session, task, &m1pv1.MemoryProposal{
			ArtifactId: id, Category: category(a.Kind),
			CandidateTrigger: strings.TrimSpace(a.Trigger), CandidateGuidance: strings.TrimSpace(a.Guidance),
			Evidence: evidence, Channel: ch, SessionId: session[:], TaskId: task[:],
		})
	}
	switch q.Channel {
	case uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT):
		c.mu.Lock()
		packed := st.packed
		st.packed = true
		c.mu.Unlock()
		if packed {
			return ""
		}
		n := 0
		for _, a := range c.artifacts() {
			if n >= room {
				break
			}
			if a.Kind == "pitfall" || !injectable[a.Kind] || seen[a.ID] {
				continue
			}
			emit(a, m1pv1.InjectionChannel_INJECTION_CHANNEL_HOOK_CONTEXT, "pack")
			n++
		}
	case uint32(m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL):
		if q.IsInterrupt {
			return ""
		}
		norm := NormalizeSignature(q.Error)
		if norm == "" {
			return ""
		}
		digest := SignatureDigest(norm)
		for _, a := range c.artifacts() {
			if a.Kind == "pitfall" && a.SigDigest == digest && !seen[a.ID] {
				emit(a, m1pv1.InjectionChannel_INJECTION_CHANNEL_REACTIVE_PITFALL, digest)
				break
			}
		}
	}
	return ""
}
