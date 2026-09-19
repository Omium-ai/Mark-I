package ingest

// The service ingest route (06 §1.2's owed adjudicator→ingest seam): the
// receipts append.go auth shape in front of the SAME pipeline a device batch
// runs, under the ServiceDevice stamp and with no stage-11 side effects.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/sidefx"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

// revisedEvent is what adjudicator-svc authors: stage REVISED, the D-T
// certification axis, the cert it stamped, the task it re-adjudicated.
func revisedEvent(t *testing.T, session uuid.UUID, stage m1pv1.VerdictStage) *m1pv1.Event {
	t.Helper()
	ev := verdictEvent(t, session, 1)
	task := mustV7(t)
	ev.TaskId = task[:]
	ev.SessionEpoch = 0xFFFFFFFF
	ev.Body = &m1pv1.Event_VerdictEvent{VerdictEvent: &m1pv1.VerdictEvent{
		Stage:         stage,
		Verdict:       m1pv1.Verdict_VERDICT_VIOLATED,
		Posterior:     []float64{0.12, 0.83, 0.03, 0.02},
		NoiseCertId:   uuid.NewString(),
		BundleSeq:     1757894400,
		VoteCount:     3,
		Certification: m1pv1.CertificationStatus_CERTIFICATION_STATUS_BOOTSTRAPPING,
	}}
	return ev
}

func (h *harness) postService(t *testing.T, batchID uuid.UUID, body []byte, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/ingest/service", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+testServiceToken)
	req.Header.Set(TenantHeader, h.tenant.String())
	req.Header.Set("Content-Type", "application/x-m1p-protobuf")
	req.Header.Set("Content-Encoding", "zstd")
	req.Header.Set("M1P-Schema", "m1p.v1")
	req.Header.Set("M1P-Batch-Id", batchID.String())
	req.ContentLength = int64(len(body))
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func TestServiceIngestLandsUnderTheServiceDeviceStamp(t *testing.T) {
	h := newHarness(t)
	ev := revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED)
	b, id := testBatch(t, ev)
	b.AdvisoryTenantId = h.tenant[:]
	rec := h.postService(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || ack.Accepted != 1 {
		t.Fatalf("bad ack: %s", rec.Body.String())
	}
	keys := h.store.keys()
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "t/"+h.tenant.String()+"/ingest/v1/") {
		t.Fatalf("service batch must land under the tenant's ingest prefix, got %v", keys)
	}
	if _, dev, _ := h.store.Get(context.Background(), keys[0]); dev != ServiceDevice {
		t.Fatalf("landing object device stamp %s, want ServiceDevice %s", dev, ServiceDevice)
	}
	h.drain()
	if h.ins.count() != 1 {
		t.Fatalf("want 1 projected row, got %d", h.ins.count())
	}
	row := h.ins.rows[0]
	if got := projCol(t, row, "tenant_id"); got != h.tenant {
		t.Fatalf("tenant_id %v, want the header tenant %s", got, h.tenant)
	}
	if got := projCol(t, row, "device_id"); got != ServiceDevice {
		t.Fatalf("device_id %v, want ServiceDevice", got)
	}
	if got := projCol(t, row, "verdict_stage"); got != "revised" {
		t.Fatalf("verdict_stage %v, want revised", got)
	}
	if got := projCol(t, row, "session_epoch"); got != uint32(0xFFFFFFFF) {
		t.Fatalf("session_epoch %v, want the batch's own", got)
	}
	for c, want := range map[string]float32{"p_satisfied": 0.12, "p_violated": 0.83, "p_refused": 0.03, "p_error": 0.02} {
		if got := projCol(t, row, c); got != want {
			t.Fatalf("%s: want %v got %v", c, want, got)
		}
	}
	if h.db.calls != 0 {
		t.Fatalf("a service batch ran stage 11 (%d sidefx calls): the sentinel has no device row and no chain", h.db.calls)
	}
}

func TestServiceIngestReplayIsADuplicateNotASecondLanding(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED))
	body := encodeBatch(t, b)
	if rec := h.postService(t, id, body, nil); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	rec := h.postService(t, id, body, nil)
	var ack struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || rec.Code != http.StatusOK || ack.Duplicates != 1 || ack.Accepted != 0 {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
	h.drain()
	if h.ins.count() != 1 || len(h.store.keys()) != 1 {
		t.Fatalf("replay doubled: rows=%d keys=%d", h.ins.count(), len(h.store.keys()))
	}
}

func TestServiceIngestRefusesWithoutTheServiceCredential(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"missing": func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testServiceToken+"x") },
		"device_token": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+newHarness(t).token)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED))
			rec := h.postService(t, id, encodeBatch(t, b), mutate)
			if rec.Code != http.StatusForbidden || errCode(t, rec) != "M1E-1001" {
				t.Fatalf("want 403 M1E-1001, got %d %s", rec.Code, rec.Body.String())
			}
			if len(h.store.keys()) != 0 {
				t.Fatal("refused service batch landed")
			}
		})
	}
	// An unconfigured token is an absent surface, never an open one.
	h := newHarnessWithRegistry(t, nil)
	mux := http.NewServeMux()
	New(Deps{Verifier: h.verifier, PG: fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, Security: h.sec}).RegisterRoutes(mux)
	h.mux = mux
	b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED))
	if rec := h.postService(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("empty configured token must verify nothing: got %d", rec.Code)
	}
}

func TestServiceIngestRequiresATenantHeader(t *testing.T) {
	for name, val := range map[string]string{"missing": "", "garbage": "not-a-uuid", "nil": uuid.Nil.String()} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED))
			rec := h.postService(t, id, encodeBatch(t, b), func(r *http.Request) { r.Header.Set(TenantHeader, val) })
			if rec.Code != http.StatusBadRequest || errCode(t, rec) != "M1E-2001" {
				t.Fatalf("want 400 M1E-2001, got %d %s", rec.Code, rec.Body.String())
			}
			if len(h.store.keys()) != 0 {
				t.Fatal("tenant-less service batch landed")
			}
		})
	}
}

// The origin rule, both directions. A device token authors PROVISIONAL and
// (slow anchors, 04 §2 / D-AS) REVISED but never CERTIFIED; the service
// authors CERTIFIED and REVISED but never PROVISIONAL.
func TestVerdictStageOriginIsEnforcedPerPrincipal(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL))
	rec := h.postService(t, id, encodeBatch(t, b), nil)
	if rec.Code != http.StatusUnprocessableEntity || errCode(t, rec) != "M1E-2006" || !strings.Contains(rec.Body.String(), `"verdict_stage_origin"`) {
		t.Fatalf("service PROVISIONAL: want 422 M1E-2006 verdict_stage_origin, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 0 {
		t.Fatal("refused verdict landed")
	}
	for _, st := range []m1pv1.VerdictStage{m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED, m1pv1.VerdictStage_VERDICT_STAGE_REVISED} {
		b, id := testBatch(t, revisedEvent(t, mustV7(t), st))
		if rec := h.postService(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
			t.Fatalf("service %v: want 200, got %d %s", st, rec.Code, rec.Body.String())
		}
	}

	ev := verdictEvent(t, mustV7(t), 1)
	ev.GetVerdictEvent().Stage = m1pv1.VerdictStage_VERDICT_STAGE_CERTIFIED
	assertVerdictRefused(t, newHarness(t), ev, "verdict_stage_origin")
	for _, st := range []m1pv1.VerdictStage{m1pv1.VerdictStage_VERDICT_STAGE_PROVISIONAL, m1pv1.VerdictStage_VERDICT_STAGE_REVISED} {
		h := newHarness(t)
		ev := verdictEvent(t, mustV7(t), 1)
		ev.GetVerdictEvent().Stage = st
		b, id := testBatch(t, ev)
		if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
			t.Fatalf("device %v: want 200, got %d %s", st, rec.Code, rec.Body.String())
		}
	}
}

func TestServiceIngestIdentityDisagreementIsRecordedAgainstTheSentinel(t *testing.T) {
	other := uuid.New()
	for name, mutate := range map[string]func(*m1pv1.Batch){
		"advisory_tenant": func(b *m1pv1.Batch) { b.AdvisoryTenantId = other[:] },
		"advisory_device": func(b *m1pv1.Batch) { b.AdvisoryDeviceId = other[:] },
		"band_device":     func(b *m1pv1.Batch) { b.Events[0].DeviceId = ServiceDevice[:] },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED))
			mutate(b)
			rec := h.postService(t, id, encodeBatch(t, b), nil)
			if rec.Code != http.StatusForbidden || errCode(t, rec) != "M1E-8003" {
				t.Fatalf("want 403 M1E-8003, got %d %s", rec.Code, rec.Body.String())
			}
			if h.sec.count() != 1 || len(h.store.keys()) != 0 {
				t.Fatalf("security=%d keys=%v", h.sec.count(), h.store.keys())
			}
		})
	}
	// Positive control: the advisory slots agreeing with the stamp are legal.
	h := newHarness(t)
	b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED))
	b.AdvisoryTenantId, b.AdvisoryDeviceId = h.tenant[:], ServiceDevice[:]
	if rec := h.postService(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK || h.sec.count() != 0 {
		t.Fatalf("agreeing advisory identity refused: %d %s (security=%d)", rec.Code, rec.Body.String(), h.sec.count())
	}
}

func TestReplayOfAServiceBatchSkipsStageEleven(t *testing.T) {
	h := newHarness(t)
	b, id := testBatch(t, revisedEvent(t, mustV7(t), m1pv1.VerdictStage_VERDICT_STAGE_REVISED))
	if rec := h.postService(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	h.drain()
	tenant, err := querychoke.FromServiceJob(mustCred(t), h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	sfx := sidefx.New(h.db, nil, nil, 1, 100)
	sfx.SetLeafStore(sidefx.NewMemoryLeafStore())
	now := time.Now().UTC()
	n, err := Replay(context.Background(), h.tomb, h.store, h.ins, sfx, tenant, now.AddDate(0, 0, -1), now.AddDate(0, 0, 1))
	sfx.Close()
	if err != nil || n != 1 {
		t.Fatalf("replay: n=%d err=%v", n, err)
	}
	if h.ins.count() != 2 || h.ins.rows[1][3] != h.ins.rows[0][3] {
		t.Fatalf("replay must re-project the same event_id: rows=%d", h.ins.count())
	}
	if got := sfx.PendingLeafCount(tenant, ServiceDevice); got != 0 || h.db.calls != 0 {
		t.Fatalf("replay ran stage 11 for the sentinel: leaves=%d db=%d", got, h.db.calls)
	}
}

func mustCred(t *testing.T) querychoke.ServiceCred {
	t.Helper()
	cred, err := querychoke.VerifyServiceCredential(testServiceToken, testServiceToken)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}
