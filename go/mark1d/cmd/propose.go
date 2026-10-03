package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"path/filepath"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProposalsDir is where file-tail hosts read memory's candidates (08 §3.7):
// <state>/run/proposals/<session-hex>.jsonl, one protojson Event per line.
func ProposalsDir(stateDir string) string { return filepath.Join(stateDir, "run", "proposals") }

// proposeSink is ADR-0016's fan-out for memory.Cache.SetOnPropose, the same
// three paths as recommendSink: the bound ext: fabric connection
// (FabricFrame{memory_proposal}), the proposals file, and the ledger — which
// is also what reaches the control API's SSE stream (family "proposal") and
// the verify ring. No MemoryInjection and no ArtifactOutcome are recorded:
// a PROPOSE session contributes nothing to ADMIT-LCB (06 §9.5).
func proposeSink(stateDir string, admit func(context.Context, *m1pv1.Event) error, push func([16]byte, *m1pv1.FabricFrame) int, log *slog.Logger) func(session, task [16]byte, p *m1pv1.MemoryProposal) {
	return func(session, task [16]byte, p *m1pv1.MemoryProposal) {
		ev := &m1pv1.Event{
			SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.Now(),
			Body: &m1pv1.Event_MemoryProposal{MemoryProposal: p},
		}
		if push != nil {
			push(session, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_MemoryProposal{MemoryProposal: p}})
		}
		if err := appendSessionLine(ProposalsDir(stateDir), session, ev); err != nil {
			log.Warn("propose: file append failed", "session", hex.EncodeToString(session[:]), "err", err)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := admit(ctx, ev); err != nil && !perEventLoss(err) {
				log.Warn("propose: proposal not recorded", "category", p.GetCategory().String(), "err", err)
			}
		}()
	}
}
