package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestProposeSinkFansOutOnEveryPath is FR-SPINE-048's daemon half: one
// proposal from memory becomes the fabric push to the bound session, one
// protojson line in <state>/run/proposals/<session>.jsonl and one
// MemoryProposal Event in the ledger — never a MemoryInjection.
func TestProposeSinkFansOutOnEveryPath(t *testing.T) {
	state := t.TempDir()
	var mu sync.Mutex
	var admitted []*m1pv1.Event
	admit := func(_ context.Context, ev *m1pv1.Event) error {
		mu.Lock()
		defer mu.Unlock()
		admitted = append(admitted, ev)
		return nil
	}
	var pushedTo [16]byte
	var pushed *m1pv1.FabricFrame
	push := func(sid [16]byte, f *m1pv1.FabricFrame) int { pushedTo, pushed = sid, f; return 1 }
	var log bytes.Buffer
	sink := proposeSink(state, admit, push, slog.New(slog.NewTextHandler(&log, nil)))

	session, task := [16]byte{0xaa, 1}, [16]byte{0xbb, 2}
	p := &m1pv1.MemoryProposal{Category: m1pv1.ProposalCategory_PROPOSAL_CATEGORY_PITFALL, CandidateTrigger: "flaky", CandidateGuidance: "retry", Evidence: "abcd", SessionId: session[:], TaskId: task[:]}
	sink(session, task, p)

	if pushedTo != session || pushed.GetMemoryProposal() != p {
		t.Fatalf("fabric push: session %x frame %v", pushedTo, pushed)
	}
	line, err := os.ReadFile(filepath.Join(ProposalsDir(state), hex.EncodeToString(session[:])+".jsonl"))
	if err != nil {
		t.Fatalf("proposals file: %v", err)
	}
	if strings.Count(string(line), "\n") != 1 {
		t.Fatalf("want exactly one line, got:\n%s", line)
	}
	fromFile := &m1pv1.Event{}
	if err := protojson.Unmarshal(bytes.TrimSpace(line), fromFile); err != nil {
		t.Fatalf("file line is not a protojson Event: %v", err)
	}
	if fromFile.GetMemoryProposal().GetCandidateGuidance() != "retry" || !bytes.Equal(fromFile.GetTaskId(), task[:]) {
		t.Fatalf("file line = %v", fromFile)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(admitted)
		mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(admitted) != 1 || admitted[0].GetMemoryProposal() == nil || admitted[0].GetMemoryInjection() != nil {
		t.Fatalf("ledger: admitted %v, want one MemoryProposal", admitted)
	}
	if log.Len() != 0 {
		t.Fatalf("sink logged on the happy path: %s", log.String())
	}
}
