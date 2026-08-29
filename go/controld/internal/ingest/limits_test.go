package ingest

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLimiterDebitAndRefill(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	tenant, device := uuid.New(), uuid.New()

	if _, ok := l.Debit(tenant, device, map[string]int{"usage": 6000}); !ok {
		t.Fatal("first 6000 within the 10000/60 bucket must pass")
	}
	wait, ok := l.Debit(tenant, device, map[string]int{"usage": 6000})
	if ok {
		t.Fatal("12000 in one window must refuse")
	}
	if wait <= 0 {
		t.Fatalf("refusal must name the wait (Retry-After floor): %v", wait)
	}
	// Refill: 10000/60s ≈ 166.7/s; after 15 s ≈ 2500 tokens back on top of
	// the 4000 remaining ⇒ 6000 affordable again.
	now = now.Add(15 * time.Second)
	if _, ok := l.Debit(tenant, device, map[string]int{"usage": 6000}); !ok {
		t.Fatal("refill did not restore capacity")
	}
}

// The tenant bucket (20×) binds when many devices share a tenant (05 §2.4).
func TestTenantBucketBinds(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	tenant := uuid.New()
	// 21 devices × 10000 usage exceeds the tenant cap of 200000.
	for i := 0; i < 20; i++ {
		if _, ok := l.Debit(tenant, uuid.New(), map[string]int{"usage": 10000}); !ok {
			t.Fatalf("device %d within both buckets must pass", i)
		}
	}
	if _, ok := l.Debit(tenant, uuid.New(), map[string]int{"usage": 10000}); ok {
		t.Fatal("tenant bucket did not bind at 20× device limits")
	}
}

// All-or-nothing: a refused batch debits NOTHING (a batch lands whole or not
// at all, so its rate debit must too).
func TestRefusedDebitLeavesBucketsUntouched(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	tenant, device := uuid.New(), uuid.New()
	if _, ok := l.Debit(tenant, device, map[string]int{"diagnostic": 3000}); ok {
		t.Fatal("3000 diagnostic exceeds the 2000/60 bucket")
	}
	if _, ok := l.Debit(tenant, device, map[string]int{"diagnostic": 2000}); !ok {
		t.Fatal("the refused debit above leaked tokens")
	}
}

func TestCategoryCounts(t *testing.T) {
	got := categoryCounts([]string{"Usage", "Usage", "VerdictEvent", "RouteDecision", "ToolUse", "ReceiptCheckpoint"})
	want := map[string]int{"usage": 2, "verdict": 1, "route": 1, "diagnostic": 1}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("category %s: want %d got %d (%v)", k, v, got[k], got)
		}
	}
	if _, ok := got["receipt"]; ok {
		t.Fatal("ReceiptCheckpoint is never rate-limited (05 §8.4)")
	}
}
