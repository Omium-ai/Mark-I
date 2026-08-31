// Per-device token buckets for the two policy routes (05 §8.2: "Bundle poll |
// 4 / min / device", "Bundle ACK | 10 / min / device").
//
// Not ingest.Limiter: that one debits N tokens across a category map because
// an ingest batch carries N events of mixed classes. These two routes debit
// one token per request, and bending the category machinery around that would
// be more code than the twenty lines below.

package policydist

import (
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
)

// maxBucketKeys is 05 §8.2's in-process bound.
// ponytail: on overflow the whole map is dropped, which resets every device to
// a full bucket — a brief fail-OPEN, never fail-closed. Same trade ingest
// already makes, and 05 §8.2 marks the shared-store upgrade as trigger-gated.
const maxBucketKeys = 100_000

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time
}

func newLimiter() *limiter {
	return &limiter{buckets: make(map[string]*tokenBucket), now: time.Now}
}

// allow debits one token from (route, device), refilling at perMinute/60 per
// second. Capacity is perMinute, so a device that has been quiet may burst its
// whole minute at once and then waits — which is what an edge waking up from
// sleep and polling once actually does.
func (l *limiter) allow(route string, device uuid.UUID, perMinute float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := route + "/" + device.String()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBucketKeys {
			l.buckets = make(map[string]*tokenBucket)
		}
		b = &tokenBucket{tokens: perMinute, last: now}
		l.buckets[key] = b
	} else {
		b.tokens = math.Min(perMinute, b.tokens+now.Sub(b.last).Seconds()*perMinute/60)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
