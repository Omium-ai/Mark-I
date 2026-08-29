package ingest

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Per-device, per-category token buckets with tenant buckets at 20× (05 §2.4,
// 08 §2.6). A 429 is backpressure, not loss: billing-grade classes are never
// shed server-side — the edge spool blocks-on-full for them, so the data
// waits at the edge and the server's only lever is the 429.
//
// ReceiptCheckpoint has no bucket on purpose (05 §8.4: receipt-checkpoint is
// in the never-shed class; its volume is bounded by the checkpoint cadence,
// not by the developer's activity).

type catLimit struct {
	limit  float64 // tokens per window
	window float64 // seconds
}

// The 05 §2.4 defaults, per device.
var deviceLimits = map[string]catLimit{
	"usage":      {10000, 60},
	"verdict":    {5000, 60},
	"route":      {5000, 60},
	"diagnostic": {2000, 60},
}

const tenantMultiplier = 20 // 05 §2.4: tenant buckets at 20× the device bucket

// RateLimitsHeader is the M1P-Rate-Limits grammar (08 §2.6, Sentry grammar:
// <category>:<limit>:<window>;…), fixed at the defaults.
const RateLimitsHeader = "usage:10000:60;verdict:5000:60;route:5000:60;diagnostic:2000:60"

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter holds all buckets under one lock.
// ponytail: per-pod in-process buckets, LRU-free size cap — 05 §8.2 itself
// marks the shared-store upgrade as trigger-gated; the cap eviction below
// resets everyone to full buckets, which briefly fails open, never closed.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

const maxBucketKeys = 100_000 // 05 §8.2

func NewLimiter() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket), now: time.Now}
}

// Debit atomically debits every category's device AND tenant bucket for this
// batch, all-or-nothing: a batch is landed whole or not at all (05 §2.2), so
// its rate debit must be too. On refusal it returns the wait until the
// tightest bucket can afford the batch — the Retry-After floor (08 §2.4).
func (l *Limiter) Debit(tenant, device uuid.UUID, counts map[string]int) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	type debit struct {
		b *bucket
		n float64
		r float64 // refill rate/s
	}
	var debits []debit
	var wait time.Duration
	for cat, n := range counts {
		lim, known := deviceLimits[cat]
		if !known || n == 0 {
			continue
		}
		for _, scope := range []struct {
			key string
			cap float64
		}{
			{fmt.Sprintf("d/%s/%s", device, cat), lim.limit},
			{fmt.Sprintf("t/%s/%s", tenant, cat), lim.limit * tenantMultiplier},
		} {
			b := l.bucket(scope.key, scope.cap, now)
			rate := scope.cap / lim.window
			if b.tokens < float64(n) {
				if w := time.Duration((float64(n) - b.tokens) / rate * float64(time.Second)); w > wait {
					wait = w
				}
			}
			debits = append(debits, debit{b: b, n: float64(n), r: rate})
		}
	}
	if wait > 0 {
		return wait, false
	}
	for _, d := range debits {
		d.b.tokens -= d.n
	}
	return 0, true
}

func (l *Limiter) bucket(key string, capacity float64, now time.Time) *bucket {
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBucketKeys {
			l.buckets = make(map[string]*bucket) // the ponytail eviction above
		}
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
		return b
	}
	rate := capacity / windowFor(key)
	b.tokens = math.Min(capacity, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	return b
}

func windowFor(key string) float64 {
	// key suffix is the category; all categories share the 60 s window today,
	// but read it from the table so a future per-category window change
	// cannot silently skew refill math.
	for cat, lim := range deviceLimits {
		if len(key) > len(cat) && key[len(key)-len(cat):] == cat {
			return lim.window
		}
	}
	return 60
}

// categoryCounts maps a decoded batch onto the 05 §2.4 categories.
func categoryCounts(eventTypes []string) map[string]int {
	counts := make(map[string]int, 4)
	for _, t := range eventTypes {
		switch t {
		case "Usage":
			counts["usage"]++
		case "VerdictEvent":
			counts["verdict"]++
		case "RouteDecision":
			counts["route"]++
		case "ReceiptCheckpoint":
			// never shed (05 §8.4) — no bucket
		default:
			counts["diagnostic"]++
		}
	}
	return counts
}
