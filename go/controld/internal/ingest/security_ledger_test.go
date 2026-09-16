package ingest

// The two security rows' road to the ledger, at the two places it was
// unproven: overflow (FR-SPINE-011 — Enqueue used to drop the row with only
// chproj's "recovered by replay" counter, which is false for a row whose
// batch never landed) and the ruleset bump (FR-SPINE-012 — a batch that
// landed clean under an older stage-7 edition is re-acked as Duplicate above
// the recorder on every re-POST, so only Rescan can raise its alert).

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/chproj"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/scanner"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// withModule rebinds the harness mux to a module built over the harness's
// store/pools with the PRODUCTION recorder (Security nil ⇒ projectorSecurity)
// and the given projector + scanner edition.
func (h *harness) withModule(t *testing.T, proj *chproj.Projector, rs *scanner.Ruleset) *Module {
	t.Helper()
	mux := http.NewServeMux()
	m := New(Deps{
		Verifier: h.verifier,
		ObsCfg:   obs.Config{ServiceName: "controld-test"},
		PG:       fakeReady{}, Store: h.store, Proj: proj, Sidefx: h.sfx, DB: h.tomb,
		Scanner:  rs,
		PoolSize: 4,
	})
	m.RegisterRoutes(mux)
	h.mux = mux
	return m
}

func droppedCount(code string) float64 {
	return testutil.ToFloat64(securityEventsDropped.WithLabelValues(code))
}

// A projector with no workers and no queue overflows on every Enqueue. The
// security row is not diagnostics that replay recovers: the M1E-8003 batch
// never landed, and the quarantine prefix is never auto-replayed. So the drop
// must be priced under its own name (11 §10.1) — and NOT priced when the row
// was in fact queued, or the counter pages on nothing.
func TestSecurityRowDropOnProjectorOverflowIsCounted(t *testing.T) {
	other := uuid.New()
	post8003 := func(h *harness) {
		t.Helper()
		b, id := testBatch(t)
		b.AdvisoryTenantId = other[:]
		if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusForbidden {
			t.Fatalf("want 403, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	h := newHarness(t)
	full := chproj.New(&fakeInserter{}, 0, 0)
	t.Cleanup(full.Close)
	h.withModule(t, full, nil)

	before := droppedCount("M1E-8003")
	post8003(h)
	if got := droppedCount("M1E-8003") - before; got != 1 {
		t.Fatalf("M1E-8003 row dropped on a full projector queue and the drop went unpriced: counter delta %v, want 1", got)
	}

	// The quarantine alert rides the same recorder and the same fate.
	before = droppedCount("M1E-7002")
	b, id := leakyBatch(t)
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := droppedCount("M1E-7002") - before; got != 1 {
		t.Fatalf("M1E-7002 row dropped and unpriced: counter delta %v, want 1", got)
	}

	// Positive control: a one-slot queue with no worker takes exactly one
	// row. The first 403 queues it (no drop counted); the second overflows.
	h2 := newHarness(t)
	oneSlot := chproj.New(&fakeInserter{}, 0, 1)
	t.Cleanup(oneSlot.Close)
	h2.withModule(t, oneSlot, nil)
	before = droppedCount("M1E-8003")
	post8003(h2)
	if got := droppedCount("M1E-8003") - before; got != 0 {
		t.Fatalf("a row that was QUEUED was counted as dropped: delta %v", got)
	}
	post8003(h2)
	if got := droppedCount("M1E-8003") - before; got != 1 {
		t.Fatalf("second row on a one-slot queue must overflow and be counted: delta %v", got)
	}
}

// Land clean under edition A (no github_token rule), re-POST under edition B
// and watch the live path re-ack it as Duplicate with NO alert — the hole,
// reproduced, so the rest of the test cannot pass vacuously. Then Rescan under
// B: the tenant alert row (recorder in the path), the quarantine twin as the
// marker, Replay honouring the marker, and a second Rescan changing nothing.
func TestRescanUnderNewerRulesetAlertsAndQuarantines(t *testing.T) {
	ctx := context.Background()
	editionA, err := scanner.Compile("A", map[string]string{
		plantedAWSClass: `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`,
	})
	if err != nil {
		t.Fatal(err)
	}
	editionB := scanner.Default
	if hits := editionA.Scan(&m1pv1.Batch{Events: []*m1pv1.Event{{Body: &m1pv1.Event_Usage{Usage: &m1pv1.Usage{RequestId: plantedGHToken}}}}}); len(hits) != 0 {
		t.Fatalf("edition A must not know github tokens or the flip below is not a flip: %+v", hits)
	}

	h := newHarness(t)
	h.withModule(t, h.proj, editionA)
	session := mustV7(t)
	gh := usageEvent(t, session, 1)
	gh.GetUsage().RequestId = plantedGHToken
	b, id := testBatch(t, gh)
	body := encodeBatch(t, b)

	if rec := h.post(t, id, body, nil); rec.Code != http.StatusOK {
		t.Fatalf("clean under edition A: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	ingestKey := s3land.IngestKey(h.tenant, id)
	if keys := h.store.keys(); len(keys) != 1 || keys[0] != ingestKey {
		t.Fatalf("want exactly the ingest landing, got %v", keys)
	}

	// The ruleset bump: the same module shape, edition B. The re-POST is a
	// Duplicate above the recorder (pipeline.go, pinned by
	// TestFlaggedRePostOfCleanLandedBatchIsDuplicateNotQuarantine): 200, no
	// alert. This is the hole, not a regression — and it is what makes the
	// "exactly 1 alert row" count below non-vacuous: had the live path
	// alerted here, the rescan would make it 2.
	mB := h.withModule(t, h.proj, editionB)
	if rec := h.post(t, id, body, nil); rec.Code != http.StatusOK {
		t.Fatalf("re-POST under edition B: want 200 duplicate, got %d: %s", rec.Code, rec.Body.String())
	}

	tenant, err := querychoke.FromClaims(auth.Claims{TenantID: h.tenant})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	flagged, err := mB.Rescan(ctx, tenant, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if flagged != 1 {
		t.Fatalf("rescan under edition B flagged %d, want 1", flagged)
	}
	h.proj.Close() // drain

	rows := guardDecisions(h.ins)
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 tenant alert row (rescan only; the duplicate re-POST must not alert), got %d", len(rows))
	}
	row := rows[0]
	if got := projCol(t, row, "tenant_id"); got != h.tenant {
		t.Fatalf("alert filed under the wrong tenant: %v", got)
	}
	if got := projCol(t, row, "device_id"); got != h.device {
		t.Fatalf("alert lost the device stamp (rides the landing object's metadata): %v", got)
	}
	var payload struct {
		ReasonCode string `json:"reason_code"`
		ErrorCode  string `json:"error_code"`
		BatchID    string `json:"batch_id"`
		Detail     string `json:"detail"`
	}
	raw, _ := projCol(t, row, "payload").(string)
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("payload not JSON: %s", raw)
	}
	if payload.ErrorCode != "M1E-7002" || payload.ReasonCode != "pre_egress_quarantine" || payload.BatchID != id.String() || payload.Detail != plantedGHClass {
		t.Fatalf("alert must be the 08 §9 M1E-7002 row naming the batch and the fired class only: %+v", payload)
	}
	if leaks := rowLeaks(row, plantedGHToken); len(leaks) != 0 {
		t.Fatalf("the rescan alert leaks the secret it found: %v", leaks)
	}

	// The quarantine marker: the twin under the quarantine prefix, next to
	// the (immutable) ingest object.
	quarantineKey := s3land.QuarantineKey(h.tenant, id)
	keys := h.store.keys()
	if len(keys) != 2 || !contains(keys, ingestKey) || !contains(keys, quarantineKey) {
		t.Fatalf("want ingest object + quarantine twin, got %v", keys)
	}
	if q, err := h.store.Probe(ctx, quarantineKey, body); err != nil || q != s3land.Duplicate {
		t.Fatalf("quarantine twin must hold the landed bytes: %v %v", q, err)
	}

	// Replay honours the marker: the batch is not re-projected (05 §2.3).
	replayIns := &fakeInserter{}
	replayed, err := Replay(ctx, h.tomb, h.store, replayIns, nil, tenant, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if replayed != 0 || replayIns.count() != 0 {
		t.Fatalf("replay re-projected a batch quarantined after landing: replayed=%d rows=%d", replayed, replayIns.count())
	}

	// A second rescan (a fresh projector — the harness one is drained)
	// re-derives the same event_id and re-Duplicates the twin: nothing
	// multiplies.
	proj2 := chproj.New(h.ins, 1, 8)
	if flagged, err := h.withModule(t, proj2, editionB).Rescan(ctx, tenant, now, now); err != nil || flagged != 1 {
		t.Fatalf("second rescan: flagged=%d err=%v", flagged, err)
	}
	proj2.Close()
	again := guardDecisions(h.ins)
	if len(again) != 2 || projCol(t, again[0], "event_id") != projCol(t, again[1], "event_id") {
		t.Fatalf("second rescan must re-derive the same event_id (ReplacingMergeTree collapses it): %d rows", len(again))
	}
	if keys := h.store.keys(); len(keys) != 2 {
		t.Fatalf("second rescan changed the landing set: %v", keys)
	}
}

func guardDecisions(ins *fakeInserter) [][]any {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	var out [][]any
	for _, r := range ins.rows {
		for i, c := range chproj.Columns {
			if c == "event_type" && r[i] == "GuardDecision" {
				out = append(out, r)
			}
		}
	}
	return out
}

func contains(keys []string, k string) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}
