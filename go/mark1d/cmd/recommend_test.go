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

// TestRecommendSinkFansOutOnEveryPath is FR-SPINE-044's daemon half: one
// recommendation from the gate becomes the fabric push to the bound session,
// one protojson line in <state>/run/recommendations/<session>.jsonl, and one
// ArrestRecommendation Event admitted to the ledger — and never a
// GuardDecision (FR-SPINE-046: the savings count stays ACT-only).
func TestRecommendSinkFansOutOnEveryPath(t *testing.T) {
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
	sink := recommendSink(state, admit, push, slog.New(slog.NewTextHandler(&log, nil)))

	session, task := [16]byte{0xaa, 1}, [16]byte{0xbb, 2}
	rec := &m1pv1.ArrestRecommendation{Kind: "stop_gate_block", Reason: "below the knee", KStarEstimate: 2, ProjectedCost: 777, SessionId: session[:], TaskId: task[:]}
	sink(session, task, rec)

	if pushedTo != session || pushed.GetArrestRecommendation() != rec {
		t.Fatalf("fabric push: session %x frame %v", pushedTo, pushed)
	}
	line, err := os.ReadFile(filepath.Join(RecommendationsDir(state), hex.EncodeToString(session[:])+".jsonl"))
	if err != nil {
		t.Fatalf("recommendations file: %v", err)
	}
	if strings.Count(string(line), "\n") != 1 {
		t.Fatalf("want exactly one line, got:\n%s", line)
	}
	fromFile := &m1pv1.Event{}
	if err := protojson.Unmarshal(bytes.TrimSpace(line), fromFile); err != nil {
		t.Fatalf("file line is not a protojson Event: %v", err)
	}
	if fromFile.GetArrestRecommendation().GetProjectedCost() != 777 || !bytes.Equal(fromFile.GetSessionId(), session[:]) {
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
	if len(admitted) != 1 || admitted[0].GetArrestRecommendation() == nil {
		t.Fatalf("ledger: admitted %v, want one ArrestRecommendation", admitted)
	}
	for _, ev := range admitted {
		if ev.GetGuardDecision() != nil {
			t.Fatal("a recommendation recorded a GuardDecision; the savings guarantee would count it")
		}
	}
	if !bytes.Equal(admitted[0].GetTaskId(), task[:]) {
		t.Fatalf("ledger event lost the task: %v", admitted[0])
	}
	if log.Len() != 0 {
		t.Fatalf("sink logged on the happy path: %s", log.String())
	}

	// A second recommendation appends, never truncates.
	sink(session, task, rec)
	line, _ = os.ReadFile(filepath.Join(RecommendationsDir(state), hex.EncodeToString(session[:])+".jsonl"))
	if strings.Count(string(line), "\n") != 2 {
		t.Fatalf("second recommendation did not append:\n%s", line)
	}
}
