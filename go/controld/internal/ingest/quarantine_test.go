package ingest

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/ingest/s3land"
)

// Run sweeps once at entry and then once per tick, never on its own clock: two fake "days" drive exactly three passes (the boot line's tenant lookup is the one extra source call, at entry only).
func TestQuarantineSweepRunsAtEntryAndOnEveryTick(t *testing.T) {
	tick := make(chan time.Time)
	passes := make(chan struct{}, 8)
	j := NewQuarantineSweep(nil, nil, nil, func(context.Context) ([]uuid.UUID, error) { passes <- struct{}{}; return nil, nil })
	j.Clock(func() time.Time { return time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC) }, tick)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { j.Run(ctx); close(done) }()

	await := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			select {
			case <-passes:
			case <-time.After(2 * time.Second):
				t.Fatalf("pass %d never ran", i+1)
			}
		}
		select {
		case <-passes:
			t.Fatal("an extra sweep pass ran without a tick")
		case <-time.After(20 * time.Millisecond):
		}
	}
	await(2)
	tick <- time.Time{}
	await(1)
	tick <- time.Time{}
	await(1)
	cancel()
	<-done
}

// A tenant source that fails is the tick failing, logged, and the next tick tries again; nothing panics on nil stores.
func TestQuarantineSweepRunOnceSurfacesTenantSourceErrors(t *testing.T) {
	j := NewQuarantineSweep(nil, nil, nil, func(context.Context) ([]uuid.UUID, error) { return nil, errors.New("no list") })
	if err := j.RunOnce(context.Background()); err == nil || err.Error() != "no list" {
		t.Fatalf("RunOnce = %v, want the tenant source's error", err)
	}
}

// Deps.DB nil must fail CLOSED on the flagged path (503, tombstone counter) and leave nothing landed: a flagged batch
// with no never-replay marker is not durably held. Clean batches are unaffected.
func TestFlaggedBatchWithoutTombstoneStoreIs503AndLandsNothing(t *testing.T) {
	h := newHarness(t)
	h.tomb = nil
	mux := http.NewServeMux()
	m := New(Deps{Verifier: h.verifier, PG: fakeReady{}, Store: h.store, Proj: h.proj, Sidefx: h.sfx, Security: h.sec, PoolSize: 4})
	m.RegisterRoutes(mux)
	h.mux = mux

	b, id := leakyBatch(t)
	if rec := h.post(t, id, encodeBatch(t, b), nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("flagged batch without a tombstone store: want 503, got %d %s", rec.Code, rec.Body.String())
	}
	if len(h.store.keys()) != 0 || h.sec.quarantineCount() != 0 {
		t.Fatalf("a refused quarantine landed or alerted: keys=%v alerts=%d", h.store.keys(), h.sec.quarantineCount())
	}
	cb, cid := testBatch(t)
	if rec := h.post(t, cid, encodeBatch(t, cb), nil); rec.Code != http.StatusOK {
		t.Fatalf("clean batch must still land without the tombstone store: %d %s", rec.Code, rec.Body.String())
	}
}

type refusingDeleteStore struct{ deletes int }

func (s *refusingDeleteStore) Land(context.Context, string, []byte, uuid.UUID, uuid.UUID) (s3land.Outcome, error) {
	return s3land.Landed, nil
}
func (s *refusingDeleteStore) Probe(context.Context, string, []byte) (s3land.Outcome, error) {
	return s3land.Duplicate, nil
}
func (s *refusingDeleteStore) Ready(context.Context) error                    { return nil }
func (s *refusingDeleteStore) List(context.Context, string) ([]string, error) { return nil, nil }
func (s *refusingDeleteStore) Get(context.Context, string) ([]byte, uuid.UUID, error) {
	return nil, uuid.Nil, nil
}
func (s *refusingDeleteStore) Delete(context.Context, string) error {
	s.deletes++
	return errors.New("AccessDenied: object lock")
}

// A delete the store refuses is not a deletion: no reason may come back for the receipt (the lead's re-mutation
// that receipted retention_30d over a failed Delete survived the lane's suite).
func TestQuarantineSweepNeverReceiptsAFailedDelete(t *testing.T) {
	st := &refusingDeleteStore{}
	j := NewQuarantineSweep(nil, st, nil, nil)
	reason, err := j.deleteObject(context.Background(), "t/x/quarantine/v1/dt=2026-08-01/b.m1p.zst")
	if err == nil || reason != "" {
		t.Fatalf("deleteObject = (%q, %v), want no reason and the store's error", reason, err)
	}
	if st.deletes != 1 {
		t.Fatalf("Delete called %d times, want 1", st.deletes)
	}
}
