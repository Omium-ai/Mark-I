package enroll

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ponytail: all three stores below are in-memory and per-pod. The nonce store
// is correct anyway (a nonce fetched from pod A and spent on pod B just fails
// and the daemon re-fetches — refresh retries are the edge's normal path);
// the two limiters under-count across replicas by the replica factor. Move to
// Postgres/Redis when controld scales past the pilot's single active replica.

// nonceStore issues the single-use 60 s PoP nonces (05 §3.3). The nonce is
// bound to (tenant, device) at issue time so the token endpoint needs no
// tenant in its body (08 §3.1's exact shape) — the nonce record carries the
// routing the RLS GUC discipline needs.
type nonceStore struct {
	mu sync.Mutex
	m  map[string]nonceRec
	// byDevice tracks each device's live nonces in issue order so a flood
	// naming one device_id evicts only ITS OWN oldest nonce, never another
	// device's (05 §3.5 abuse-case posture: /nonce is unauthenticated, so a
	// per-key bound must contain the damage to the key being hammered).
	byDevice map[uuid.UUID][]string
	ttl      time.Duration
	now      func() time.Time
}

type nonceRec struct {
	tenant  uuid.UUID
	device  uuid.UUID
	expires time.Time
}

// perDeviceNonceCap: a genuine daemon holds at most one live nonce (fetch,
// sign, spend inside the 60 s TTL); 8 leaves retry headroom while making a
// flood on one device_id self-limiting.
const perDeviceNonceCap = 8

func newNonceStore(now func() time.Time) *nonceStore {
	return &nonceStore{
		m: make(map[string]nonceRec), byDevice: make(map[uuid.UUID][]string),
		ttl: 60 * time.Second, now: now,
	}
}

// Issue returns ok=false when the store is at its hard cap even after
// sweeping — refusal beats unbounded memory under a nonce-flood. Per-device,
// the oldest live nonce is evicted first (the cap is per-key damage control;
// the global cap stays as the memory backstop).
func (s *nonceStore) Issue(tenant, device uuid.UUID) (string, bool) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	n := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if live := s.byDevice[device]; len(live) >= perDeviceNonceCap {
		delete(s.m, live[0])
		s.byDevice[device] = live[1:]
	}
	if len(s.m) >= 65536 {
		return "", false
	}
	s.m[n] = nonceRec{tenant: tenant, device: device, expires: s.now().Add(s.ttl)}
	s.byDevice[device] = append(s.byDevice[device], n)
	return n, true
}

// Take consumes the nonce — single-use is the replay defense (05 §3.5 abuse
// case 4: "the nonce is single-use and 60 s TTL; replay yields nothing"), so
// it is removed BEFORE any signature check; a failed attempt burns it.
func (s *nonceStore) Take(nonce string) (nonceRec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[nonce]
	if !ok {
		return nonceRec{}, false
	}
	delete(s.m, nonce)
	s.dropFromDeviceLocked(rec.device, nonce)
	if s.now().After(rec.expires) {
		return nonceRec{}, false
	}
	return rec, true
}

// dropFromDeviceLocked removes one nonce from its device's live list (≤ 8
// entries, so the linear scan is free) and drops the empty key so the index
// cannot outgrow the nonce map it mirrors.
func (s *nonceStore) dropFromDeviceLocked(device uuid.UUID, nonce string) {
	live := s.byDevice[device]
	for i, n := range live {
		if n == nonce {
			live = append(live[:i], live[i+1:]...)
			break
		}
	}
	if len(live) == 0 {
		delete(s.byDevice, device)
		return
	}
	s.byDevice[device] = live
}

func (s *nonceStore) sweepLocked() {
	if len(s.m) < 4096 { // amortize: only sweep once the map is worth it
		return
	}
	now := s.now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
			s.dropFromDeviceLocked(v.device, k)
		}
	}
}

// pacer enforces a minimum interval per key: the per-device_code poll cadence
// (429 M1E-9001 when polled faster than `interval`, 08 §3.1) and the per-IP
// /start rate limit (05 §3.5 abuse case 2) both reduce to it.
type pacer struct {
	mu  sync.Mutex
	m   map[string]time.Time
	min time.Duration
	now func() time.Time
}

func newPacer(min time.Duration, now func() time.Time) *pacer {
	return &pacer{m: make(map[string]time.Time), min: min, now: now}
}

func (p *pacer) Allow(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if len(p.m) >= 65536 { // bound memory before booking the new key
		for k, at := range p.m {
			if now.Sub(at) > p.min {
				delete(p.m, k)
			}
		}
	}
	if last, ok := p.m[key]; ok && now.Sub(last) < p.min {
		return false
	}
	p.m[key] = now
	return true
}

// bucketLimiter is the §8.2 token bucket (in-process per pod, lazily created,
// crude-evicted near 100k keys — §8.2's own "ponytail: per-pod buckets"
// records the shared-store upgrade trigger). Used for /start per IP (10/hour)
// and token refresh per device (12/day).
type bucketLimiter struct {
	mu       sync.Mutex
	m        map[string]bucket
	capacity float64
	perSec   float64
	now      func() time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newBucketLimiter(capacity float64, per time.Duration, now func() time.Time) *bucketLimiter {
	return &bucketLimiter{
		m: make(map[string]bucket), capacity: capacity,
		perSec: capacity / per.Seconds(), now: now,
	}
}

func (l *bucketLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.m[key]
	if !ok {
		b = bucket{tokens: l.capacity, at: now}
	}
	b.tokens = min(l.capacity, b.tokens+now.Sub(b.at).Seconds()*l.perSec)
	b.at = now
	if b.tokens < 1 {
		l.m[key] = b
		return false
	}
	b.tokens--
	if len(l.m) >= 100_000 {
		for k, v := range l.m {
			if v.tokens >= l.capacity-0.5 { // full buckets carry no state worth keeping
				delete(l.m, k)
			}
		}
	}
	l.m[key] = b
	return true
}
