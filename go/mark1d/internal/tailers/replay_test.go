// The conf_hooks_claudecode_2.1.251_replay suite, tailer half (12 §3.2):
// every committed transcript stream through the dedupe core and the manager,
// with transcripts/expectations.json as the oracle — exactly one Usage per
// (message.id, requestId), sidechain lines never emit from the parent, last
// line's numbers win, and the naive per-line sum stays the ≥2× overcount the
// corpus exists to prove (NFR-CORRECTNESS-001).
package tailers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
)

const fixtureRoot = "../../../../conformance/hooks/claudecode/v2.1.251"

// testIdemKey is an injected stand-in for the tenant usage-idem key: the real
// root arrives with enrollment (04 §2.9) and is HKDF-derived; the recipe under
// test is key-agnostic.
var testIdemKey = []byte("m1p-usage-idem-TEST-KEY-32bytes!")

type expectations struct {
	WorkspaceRoot  string `json:"workspace_root"`
	OutOfWorkspace []struct {
		File               string `json:"file"`
		Cwd                string `json:"cwd"`
		NeverEmitMessageID string `json:"never_emit_message_id"`
	} `json:"out_of_workspace_streams"`
	Streams []struct {
		File        string          `json:"file"`
		Role        string          `json:"role"`
		UsageEvents []expectedUsage `json:"usage_events"`
		NeverEmit   []struct {
			MessageID string `json:"message_id"`
			RequestID string `json:"request_id"`
		} `json:"never_emit"`
	} `json:"streams"`
	OvercountCase struct {
		MessageID           string  `json:"message_id"`
		RequestID           string  `json:"request_id"`
		StreamedLines       int     `json:"streamed_lines"`
		NaiveSum            uint64  `json:"naive_per_line_output_token_sum"`
		CorrectOutputTokens uint64  `json:"correct_output_tokens"`
		MinOvercountRatio   float64 `json:"min_overcount_ratio_asserted"`
	} `json:"overcount_case"`
}

type expectedUsage struct {
	IdemInputs struct {
		SessionID string `json:"session_id"`
		MessageID string `json:"message_id"`
		RequestID string `json:"request_id"`
	} `json:"idem_key_inputs"`
	Usage struct {
		InputTokens              uint64 `json:"input_tokens"`
		OutputTokens             uint64 `json:"output_tokens"`
		CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
		ServiceTier              string `json:"service_tier"`
	} `json:"usage"`
	Model string `json:"model"`
}

func loadExpectations(t *testing.T) expectations {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot, "transcripts", "expectations.json"))
	if err != nil {
		t.Fatalf("fixture missing (08 §5 rule 3: no fixture, no adapter): %v", err)
	}
	var e expectations
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func fixtureLines(t *testing.T, rel string) [][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join(fixtureRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// TestReplayStreams drives each committed stream through the dedupe core and
// asserts the exact per-stream emission sequence expectations.json fixes.
func TestReplayStreams(t *testing.T) {
	exp := loadExpectations(t)
	for _, st := range exp.Streams {
		t.Run(st.Role+"/"+filepath.Base(st.File), func(t *testing.T) {
			session := uuid.MustParse(st.UsageEvents[0].IdemInputs.SessionID)
			role := RoleParent
			if st.Role == "subagent" {
				role = RoleSubagent
			}
			s := stream{role: role, session: session, idemKey: testIdemKey}
			now := time.Now()
			var got []*m1pv1.Event
			for _, line := range fixtureLines(t, st.File) {
				got = append(got, s.consume(line, now)...)
			}
			got = append(got, s.flush()...)

			if len(got) != len(st.UsageEvents) {
				t.Fatalf("emitted %d Usage events, expectations fix %d", len(got), len(st.UsageEvents))
			}
			seen := map[string]bool{}
			for i, want := range st.UsageEvents {
				u := got[i].GetUsage()
				if u == nil {
					t.Fatalf("event %d has no Usage body", i)
				}
				if u.GetMessageId() != want.IdemInputs.MessageID || u.GetRequestId() != want.IdemInputs.RequestID {
					t.Fatalf("event %d key = (%s,%s), want (%s,%s) — first-seen-key order is the contract",
						i, u.GetMessageId(), u.GetRequestId(), want.IdemInputs.MessageID, want.IdemInputs.RequestID)
				}
				if u.GetInputTokens() != want.Usage.InputTokens ||
					u.GetOutputTokens() != want.Usage.OutputTokens ||
					u.GetCacheCreationInputTokens() != want.Usage.CacheCreationInputTokens ||
					u.GetCacheReadInputTokens() != want.Usage.CacheReadInputTokens ||
					u.GetServiceTier() != want.Usage.ServiceTier {
					t.Fatalf("event %d (%s): token numbers diverge from the last line: got %+v", i, want.IdemInputs.MessageID, u)
				}
				if u.GetModel() != want.Model {
					t.Fatalf("event %d model = %q, want %q", i, u.GetModel(), want.Model)
				}
				wantKey := IdemKey(testIdemKey, session, want.IdemInputs.MessageID, want.IdemInputs.RequestID)
				if !bytes.Equal(u.GetIdemKey(), wantKey) {
					t.Fatalf("event %d idem_key diverges from the events.proto recipe", i)
				}
				if seen[string(u.GetIdemKey())] {
					t.Fatalf("duplicate idem_key for %s — the one duplicate class this layer exists to kill", want.IdemInputs.MessageID)
				}
				seen[string(u.GetIdemKey())] = true
				if !bytes.Equal(got[i].GetSessionId(), session[:]) {
					t.Fatalf("event %d session_id is not the PARENT session (04 §2.1)", i)
				}
			}
			for _, never := range st.NeverEmit {
				for _, ev := range got {
					u := ev.GetUsage()
					if u.GetMessageId() == never.MessageID && u.GetRequestId() == never.RequestID {
						t.Fatalf("sidechain key (%s,%s) emitted from this stream — PROTOCOL INVARIANT violated (07 §7 layer 1)", never.MessageID, never.RequestID)
					}
				}
			}
		})
	}
}

// TestReplayOvercount re-derives the ~2.5× arithmetic from the corpus: the
// naive per-line sum must still overcount the emitted (last-line) number by
// at least the fixture's asserted ratio.
func TestReplayOvercount(t *testing.T) {
	exp := loadExpectations(t)
	oc := exp.OvercountCase
	var naive uint64
	var lines int
	for _, line := range fixtureLines(t, exp.Streams[0].File) {
		var l txLine
		if json.Unmarshal(line, &l) != nil || l.Message == nil || l.Message.Usage == nil {
			continue
		}
		if l.Message.ID == oc.MessageID && l.RequestID == oc.RequestID {
			naive += l.Message.Usage.OutputTokens
			lines++
		}
	}
	if lines != oc.StreamedLines || naive != oc.NaiveSum {
		t.Fatalf("corpus drifted: %d lines summing %d, fixture says %d/%d", lines, naive, oc.StreamedLines, oc.NaiveSum)
	}
	if ratio := float64(naive) / float64(oc.CorrectOutputTokens); ratio < oc.MinOvercountRatio {
		t.Fatalf("corpus no longer overcounts: ratio %.2f < %.2f", ratio, oc.MinOvercountRatio)
	}
}

// TestReplayManager runs the full file-follower over the committed layout:
// discovery must find the parent stream and the subagent stream — and refuse
// the munge-colliding foreign stream that shares the vendor dir (invariant 3)
// — and the union of emissions must contain every expected key exactly once,
// zero duplicate idem_keys across streams even though the sidechain key
// exists in two files.
func TestReplayManager(t *testing.T) {
	exp := loadExpectations(t)
	// The oracle is the enabled root from the corpus; the foreign fixture's
	// cwd munges to the same directory but resolves outside it.
	set, err := NewWorkspaceSet(exp.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	var got []*m1pv1.Event
	mgr, err := NewManager(Config{
		Dir:          filepath.Join(fixtureRoot, "transcripts", "-home-devuser-workspace-acme-app"),
		StateDir:     t.TempDir(),
		Allowed:      set.Allowed,
		UsageIdemKey: testIdemKey,
		Emit: func(_ context.Context, ev *m1pv1.Event) error {
			got = append(got, ev)
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

	var wantTotal int
	for _, st := range exp.Streams {
		wantTotal += len(st.UsageEvents)
	}
	if len(got) != wantTotal {
		t.Fatalf("manager emitted %d Usage events, expectations fix %d", len(got), wantTotal)
	}
	byKey := map[string]*m1pv1.Usage{}
	for _, ev := range got {
		u := ev.GetUsage()
		k := string(u.GetIdemKey())
		if byKey[k] != nil {
			t.Fatalf("duplicate idem_key for (%s,%s) across streams", u.GetMessageId(), u.GetRequestId())
		}
		byKey[k] = u
	}
	for _, st := range exp.Streams {
		session := uuid.MustParse(st.UsageEvents[0].IdemInputs.SessionID)
		for _, want := range st.UsageEvents {
			u := byKey[string(IdemKey(testIdemKey, session, want.IdemInputs.MessageID, want.IdemInputs.RequestID))]
			if u == nil {
				t.Fatalf("expected key (%s,%s) never emitted", want.IdemInputs.MessageID, want.IdemInputs.RequestID)
			}
			if u.GetOutputTokens() != want.Usage.OutputTokens {
				t.Fatalf("(%s): output_tokens %d, want last-line %d", want.IdemInputs.MessageID, u.GetOutputTokens(), want.Usage.OutputTokens)
			}
		}
	}
	// The sidechain origin (subagent numbers) must be what won for the
	// replayed key — the parent's replay carries the same numbers by
	// construction, so the count==1 assertion above plus per-stream
	// TestReplayStreams provenance closes the invariant.
	oc := exp.OvercountCase
	session := uuid.MustParse(exp.Streams[0].UsageEvents[0].IdemInputs.SessionID)
	if u := byKey[string(IdemKey(testIdemKey, session, oc.MessageID, oc.RequestID))]; u == nil || u.GetOutputTokens() != oc.CorrectOutputTokens {
		t.Fatalf("overcount key emitted %v, want exactly one event with the last line's %d", u, oc.CorrectOutputTokens)
	}

	// Invariant 3 (04 §0.3): the munge-colliding foreign stream shares this
	// vendor dir on disk — assert the trap exists, then that nothing from it
	// ever emitted. The wantTotal check above already excludes its count.
	if len(exp.OutOfWorkspace) == 0 {
		t.Fatal("corpus lost its out-of-workspace fixture — the containment gate is untested")
	}
	for _, foreign := range exp.OutOfWorkspace {
		if _, err := os.Stat(filepath.Join(fixtureRoot, foreign.File)); err != nil {
			t.Fatalf("foreign fixture missing (a vacuous pass proves nothing): %v", err)
		}
		for _, ev := range got {
			if ev.GetUsage().GetMessageId() == foreign.NeverEmitMessageID {
				t.Fatalf("foreign workspace key %s emitted — a non-enabled workspace was captured (invariant 3)", foreign.NeverEmitMessageID)
			}
		}
	}
}

// TestQuiesceDebounce pins 04 §2.1's third emission trigger: a pending entry
// with no newer line for 2 s emits without a Stop hook.
func TestQuiesceDebounce(t *testing.T) {
	exp := loadExpectations(t)
	session := uuid.MustParse(exp.Streams[0].UsageEvents[0].IdemInputs.SessionID)
	s := stream{role: RoleParent, session: session, idemKey: testIdemKey}
	now := time.Now()
	var usageLine []byte
	for _, line := range fixtureLines(t, exp.Streams[0].File) {
		var l txLine
		if json.Unmarshal(line, &l) == nil && l.Message != nil && l.Message.Usage != nil && !l.IsSidechain {
			usageLine = line
			break
		}
	}
	if evs := s.consume(usageLine, now); len(evs) != 0 {
		t.Fatal("first key must pend, not emit")
	}
	if evs := s.quiet(now.Add(quiesce - time.Millisecond)); len(evs) != 0 {
		t.Fatal("quiesce fired early")
	}
	if evs := s.quiet(now.Add(quiesce)); len(evs) != 1 {
		t.Fatalf("quiesce at 2 s must emit the pending entry, got %d", len(evs))
	}
}
