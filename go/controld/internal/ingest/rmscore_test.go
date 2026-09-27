package ingest

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func rmScoreEvent(t *testing.T, priv ed25519.PrivateKey, mut func(*m1pv1.RmScore)) *m1pv1.Event {
	t.Helper()
	rs := &m1pv1.RmScore{
		ModelId: "rm:m1-qwen3-0-6b@1", Score: 0.73, CalibrationVersion: "temp-v1",
		ExecutionHash: make([]byte, 32), Locus: m1pv1.JudgeLocus_JUDGE_LOCUS_CLIENT_SIDE,
	}
	if priv != nil {
		canon, err := proto.MarshalOptions{Deterministic: true}.Marshal(rs)
		if err != nil {
			t.Fatal(err)
		}
		rs.Signature = ed25519.Sign(priv, canon)
	}
	if mut != nil {
		mut(rs)
	}
	eventID, session := mustV7(t), mustV7(t)
	return &m1pv1.Event{
		EventId: eventID[:], Seq: 1, SessionId: session[:],
		OccurredAt: timestamppb.New(time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)),
		Body:       &m1pv1.Event_RmScore{RmScore: rs},
	}
}

func TestRmScoreSignedGoodAccepted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &fakeDeviceKeys{pub: pub}
	h := newHarnessFull(t, nil, dk)
	dk.device = h.device
	b, id := testBatch(t, rmScoreEvent(t, priv, nil))
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatalf("a well-formed signed RmScore must land: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRmScoreUnsignedClientSideRefused(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dk := &fakeDeviceKeys{pub: pub}
	h := newHarnessFull(t, nil, dk)
	dk.device = h.device
	ev := rmScoreEvent(t, nil, nil)
	b, id := testBatch(t, ev)
	rec := h.post(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" || !strings.Contains(rec.Body.String(), `"rm_score_unsigned"`) ||
		!strings.Contains(rec.Body.String(), uuid.Must(uuid.FromBytes(ev.EventId)).String()) {
		t.Fatalf("a device's unsigned CLIENT_SIDE RmScore: want 422 M1E-2006 rm_score_unsigned naming the event, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("an unsigned device RmScore landed")
	}
}

func TestRmScoreMalformedRefused(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, kind string
		priv       ed25519.PrivateKey
		mut        func(*m1pv1.RmScore)
	}{
		{"judge id", "rm_score_model_id", nil, func(r *m1pv1.RmScore) { r.ModelId = "judge:x@1" }},
		{"no version", "rm_score_model_id", nil, func(r *m1pv1.RmScore) { r.ModelId = "rm:m1-qwen" }},
		{"upper case", "rm_score_model_id", nil, func(r *m1pv1.RmScore) { r.ModelId = "rm:Qwen@1" }},
		{"version zero", "rm_score_model_id", nil, func(r *m1pv1.RmScore) { r.ModelId = "rm:m1@0" }},
		{"NaN", "rm_score_range", nil, func(r *m1pv1.RmScore) { r.Score = math.NaN() }},
		{"above one", "rm_score_range", nil, func(r *m1pv1.RmScore) { r.Score = 1.0001 }},
		{"negative", "rm_score_range", nil, func(r *m1pv1.RmScore) { r.Score = -0.1 }},
		{"+Inf", "rm_score_range", nil, func(r *m1pv1.RmScore) { r.Score = math.Inf(1) }},
		{"tampered after signing", "rm_score_signature", priv, func(r *m1pv1.RmScore) { r.Score = 0.99 }},
		{"garbage signature", "rm_score_signature", nil, func(r *m1pv1.RmScore) { r.Signature = []byte("not a signature") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dk := &fakeDeviceKeys{pub: pub}
			h := newHarnessFull(t, nil, dk)
			dk.device = h.device
			ev := rmScoreEvent(t, c.priv, c.mut)
			b, id := testBatch(t, ev)
			rec := h.post(t, id, encodeBatch(t, b), nil)
			if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" {
				t.Fatalf("want 422 M1E-2006, got %d %s", rec.Code, rec.Body.String())
			}
			evID := uuid.Must(uuid.FromBytes(ev.EventId)).String()
			if body := rec.Body.String(); !strings.Contains(body, evID) || !strings.Contains(body, `"`+c.kind+`"`) {
				t.Fatalf("422 must name event %s and kind %s: %s", evID, c.kind, body)
			}
			if len(h.store.keys()) != 0 {
				t.Fatal("a refused RmScore batch must not land")
			}
		})
	}
}

func TestConsentsCarryTheRewardModelChoice(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{`{"e1":true,"cloud_judge":false,"training":true,"local_rm":"yes"}`, `{"e1":true,"cloud_judge":false,"training":true,"cloud_rm":1}`} {
		if rec := h.putConsents(t, h.token, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	rec := h.putConsents(t, h.token, `{"e1":false,"cloud_judge":false,"training":false,"local_rm":true,"cloud_rm":false}`)
	if rec.Code != http.StatusOK || h.tomb.calls != 1 {
		t.Fatalf("local_rm body: %d %s (store calls %d)", rec.Code, rec.Body.String(), h.tomb.calls)
	}
}

func TestRmScoreCloudLocusIsTheServicePrincipalsAlone(t *testing.T) {
	cloud := func(r *m1pv1.RmScore) { r.Locus = m1pv1.JudgeLocus_JUDGE_LOCUS_CLOUD; r.ExecutionHash = nil }
	h := newHarness(t)
	ev := rmScoreEvent(t, nil, cloud)
	b, id := testBatch(t, ev)
	b.AdvisoryTenantId = h.tenant[:]
	if rec := h.postService(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatalf("the adjudicator's unsigned CLOUD RmScore must land via service ingest: %d %s", rec.Code, rec.Body.String())
	}
	for name, c := range map[string]struct {
		mut     func(*m1pv1.RmScore)
		service bool
		kind    string
	}{
		"device claims CLOUD":        {cloud, false, "rm_score_locus"},
		"service claims CLIENT_SIDE": {nil, true, "rm_score_locus"},
		"service score out of range": {func(r *m1pv1.RmScore) { cloud(r); r.Score = 2.3 }, true, "rm_score_range"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			ev := rmScoreEvent(t, nil, c.mut)
			b, id := testBatch(t, ev)
			post := h.post
			if c.service {
				b.AdvisoryTenantId = h.tenant[:]
				post = h.postService
			}
			if rec := post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" || !strings.Contains(rec.Body.String(), `"`+c.kind+`"`) {
				t.Fatalf("want 422 M1E-2006 %s, got %d %s", c.kind, rec.Code, rec.Body.String())
			}
		})
	}
}

// ADR-0013: a GuardDecision's knee_basis and cost_basis are closed words, "" from an edge that predates them; anything else is refused by name.
func TestGuardDecisionBasesAreClosedWords(t *testing.T) {
	decision := func(knee, cost string) *m1pv1.Event {
		eventID, session, task := mustV7(t), mustV7(t), mustV7(t)
		return &m1pv1.Event{
			EventId: eventID[:], Seq: 1, SessionId: session[:], TaskId: task[:],
			OccurredAt: timestamppb.New(time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)),
			Body: &m1pv1.Event_GuardDecision{GuardDecision: &m1pv1.GuardDecision{
				Outcome: m1pv1.GuardOutcome_GUARD_OUTCOME_ARRESTED, SampleRate: 1, ReasonCode: "knee_arrest", KneeBasis: knee, CostBasis: cost,
			}},
		}
	}
	for _, ok := range [][2]string{{"", ""}, {"prior", "quota"}, {"unknown", "usd"}, {"certified", ""}, {"anchor_grounded", "quota"}} {
		h := newHarness(t)
		b, id := testBatch(t, decision(ok[0], ok[1]))
		if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
			t.Fatalf("%v must land: %d %s", ok, rec.Code, rec.Body.String())
		}
	}
	for _, bad := range [][2]string{{"fitted", "usd"}, {"prior", "tokens"}, {"Prior", ""}, {"", "unknown"}} {
		h := newHarness(t)
		ev := decision(bad[0], bad[1])
		b, id := testBatch(t, ev)
		rec := h.post(t, id, encodeBatch(t, b), nil)
		if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" || !strings.Contains(rec.Body.String(), `"guard_basis"`) || !strings.Contains(rec.Body.String(), uuid.Must(uuid.FromBytes(ev.EventId)).String()) {
			t.Fatalf("%v: want 422 M1E-2006 guard_basis naming the event, got %d %s", bad, rec.Code, rec.Body.String())
		}
	}
}
