package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RecommendationsDir is where file-tail hosts read the gate's judgements
// (08 §4.7): <state>/run/recommendations/<session-hex>.jsonl, one protojson
// Event per line, appended as they happen.
func RecommendationsDir(stateDir string) string {
	return filepath.Join(stateDir, "run", "recommendations")
}

// recommendSink is ADR-0015's fan-out for fabric.Gate.OnRecommend: the
// judgement the gate would have enforced for an ACT session, delivered to a
// RECOMMEND host on every path it may be listening on — and recorded. Four
// paths, one function, so a path cannot be silently lost:
//
//  1. the ledger: the ArrestRecommendation Event is admitted (capture's door),
//     which is also what reaches the control API's SSE stream and verify ring
//     through the hub's tap;
//  2. the bound ext: fabric connection: FabricFrame{arrest_recommendation},
//     the one unsolicited daemon→writer frame;
//  3. the recommendations file for file-tail hosts, which have no connection;
//  4. (the GateVerdict reply itself is the gate's, set before this fires.)
//
// No GuardDecision is recorded: that is how the savings guarantee stays an
// ACT-only count (ADR-0015 §4).
func recommendSink(stateDir string, admit func(context.Context, *m1pv1.Event) error, push func([16]byte, *m1pv1.FabricFrame) int, log *slog.Logger) func(session, task [16]byte, rec *m1pv1.ArrestRecommendation) {
	return func(session, task [16]byte, rec *m1pv1.ArrestRecommendation) {
		ev := &m1pv1.Event{
			SessionId: session[:], TaskId: task[:], OccurredAt: timestamppb.Now(),
			Body: &m1pv1.Event_ArrestRecommendation{ArrestRecommendation: rec},
		}
		// Fabric push first: it is the lowest-latency path and the host's
		// loop may be deciding right now.
		if push != nil {
			push(session, &m1pv1.FabricFrame{Kind: &m1pv1.FabricFrame_ArrestRecommendation{ArrestRecommendation: rec}})
		}
		if err := appendRecommendation(stateDir, session, ev); err != nil {
			log.Warn("recommend: file append failed", "session", hex.EncodeToString(session[:]), "err", err)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := admit(ctx, ev); err != nil && !perEventLoss(err) {
				log.Warn("recommend: recommendation not recorded", "kind", rec.GetKind(), "err", err)
			}
		}()
	}
}

// appendRecommendation writes one protojson line to the session's file.
func appendRecommendation(stateDir string, session [16]byte, ev *m1pv1.Event) error {
	return appendSessionLine(RecommendationsDir(stateDir), session, ev)
}

// appendSessionLine appends one protojson Event line to <dir>/<session-hex>.jsonl,
// creating the directory 0700 and the file 0600 on first use. Shared by the
// recommendations (ADR-0015) and proposals (ADR-0016) files.
func appendSessionLine(dir string, session [16]byte, ev *m1pv1.Event) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	line, err := protojson.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, hex.EncodeToString(session[:])+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
