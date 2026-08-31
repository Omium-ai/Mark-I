package enroll

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeviceCodeRoundtrip(t *testing.T) {
	tenant := uuid.New()
	hmac := make([]byte, 32)
	hmac[0], hmac[31] = 0xab, 0xcd
	code := encodeDeviceCode(tenant, "linux-x86_64", hmac, "idp-code-xyz")
	gotTenant, platform, gotHMAC, idpCode, err := decodeDeviceCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if gotTenant != tenant || platform != "linux-x86_64" || idpCode != "idp-code-xyz" {
		t.Fatalf("roundtrip mismatch: %v %q %q", gotTenant, platform, idpCode)
	}
	if gotHMAC[0] != 0xab || gotHMAC[31] != 0xcd {
		t.Fatal("hostname hmac corrupted")
	}
}

// Tampering with any part of the composed code changes its SHA-256 — the
// stored device_code_hash no longer matches, so embedding routing facts adds
// zero trust surface (see codec.go's WHY).
func TestDeviceCodeTamperChangesHash(t *testing.T) {
	code := encodeDeviceCode(uuid.New(), "linux", make([]byte, 32), "idp-code")
	other := encodeDeviceCode(uuid.New(), "linux", make([]byte, 32), "idp-code")
	if string(hashCode(code)) == string(hashCode(other)) {
		t.Fatal("different tenants must hash differently")
	}
	for _, bad := range []string{"", "no-dot", "!!!.idp-code"} {
		if _, _, _, _, err := decodeDeviceCode(bad); err == nil {
			t.Fatalf("decoded garbage %q", bad)
		}
	}
}

func TestPubkeyAndHostnameParsing(t *testing.T) {
	if _, err := parseDevicePubkey("ed25519:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err != nil {
		t.Fatalf("valid pubkey rejected: %v", err)
	}
	for _, bad := range []string{"", "AAAA", "rsa:AAAA", "ed25519:short"} {
		if _, err := parseDevicePubkey(bad); err == nil {
			t.Fatalf("accepted bad pubkey %q", bad)
		}
	}
	// 32 bytes as hex and as base64 both satisfy ck_m1_devices_hostname_len.
	hexHash := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if _, err := parseHostnameHash(hexHash); err != nil {
		t.Fatal(err)
	}
	if _, err := parseHostnameHash("hmac-sha256:" + hexHash); err != nil {
		t.Fatal(err)
	}
	if _, err := parseHostnameHash("tooshort"); err == nil {
		t.Fatal("accepted short hostname hash")
	}
}

func TestNonceSingleUseAndTTL(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := newNonceStore(clock)
	tenant, device := uuid.New(), uuid.New()
	n, ok := s.Issue(tenant, device)
	if !ok {
		t.Fatal("issue refused")
	}
	rec, ok := s.Take(n)
	if !ok || rec.tenant != tenant || rec.device != device {
		t.Fatalf("take: %v %+v", ok, rec)
	}
	// Single-use: replay yields nothing (05 §3.5 abuse case 4).
	if _, ok := s.Take(n); ok {
		t.Fatal("nonce replay accepted")
	}
	// TTL: 60 s hard.
	n2, _ := s.Issue(tenant, device)
	now = now.Add(61 * time.Second)
	if _, ok := s.Take(n2); ok {
		t.Fatal("expired nonce accepted")
	}
}

// The nonce-flood containment (05 §3.5 posture): /nonce is unauthenticated,
// so a flood naming ONE device_id must evict only that device's own oldest
// nonce — never another device's live nonce — while the 65536 global cap
// stays as the memory backstop.
func TestNonceFloodEvictsOnlyItsOwnDevice(t *testing.T) {
	now := time.Now()
	s := newNonceStore(func() time.Time { return now })
	tenant := uuid.New()
	victim, attacker := uuid.New(), uuid.New()

	victimNonce, ok := s.Issue(tenant, victim)
	if !ok {
		t.Fatal("victim issue refused")
	}
	// Flood far past the per-device cap on the attacker's device_id.
	var attackerFirst string
	for i := 0; i < perDeviceNonceCap*10; i++ {
		n, ok := s.Issue(tenant, attacker)
		if !ok {
			t.Fatalf("flood issue %d refused before the global cap", i)
		}
		if i == 0 {
			attackerFirst = n
		}
	}
	// The attacker's own oldest nonce was evicted (cap holds)…
	if _, ok := s.Take(attackerFirst); ok {
		t.Fatal("per-device cap did not evict the flooding device's oldest nonce")
	}
	if live := len(s.byDevice[attacker]); live > perDeviceNonceCap {
		t.Fatalf("flooding device holds %d live nonces, cap is %d", live, perDeviceNonceCap)
	}
	// …and the victim's live nonce survived the whole flood.
	rec, ok := s.Take(victimNonce)
	if !ok || rec.device != victim {
		t.Fatalf("flood evicted another device's live nonce: %v %+v", ok, rec)
	}
}

func TestPacerEnforcesInterval(t *testing.T) {
	now := time.Now()
	p := newPacer(5*time.Second, func() time.Time { return now })
	if !p.Allow("k") {
		t.Fatal("first poll refused")
	}
	if p.Allow("k") {
		t.Fatal("immediate re-poll allowed (M1E-9001 contract)")
	}
	now = now.Add(5 * time.Second)
	if !p.Allow("k") {
		t.Fatal("poll at interval refused")
	}
}

func TestBucketLimiter(t *testing.T) {
	now := time.Now()
	l := newBucketLimiter(2, time.Hour, func() time.Time { return now })
	if !l.Allow("ip") {
		t.Fatal("first burst token refused")
	}
	if !l.Allow("ip") {
		t.Fatal("second burst token refused")
	}
	if l.Allow("ip") {
		t.Fatal("over-capacity allowed")
	}
	now = now.Add(30 * time.Minute) // refills 1 of 2
	if !l.Allow("ip") {
		t.Fatal("refilled token refused")
	}
	if l.Allow("ip") {
		t.Fatal("second token appeared early")
	}
}

// The §3.4 staleness ladder: fresh entries served, refresh failures served
// only within maxStale, past it (or with no entry) unknown state is an error
// — which auth.Verify turns into fail-closed 401.
func TestRevocationCacheFailClosedPastCeiling(t *testing.T) {
	now := time.Now()
	c := NewRevocationCache(nil, 60*time.Second)
	c.now = func() time.Time { return now }
	healthy := true
	c.fetchFn = func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
		if healthy {
			return false, nil
		}
		return false, errors.New("pg down")
	}
	tenant, device := uuid.New(), uuid.New()
	ctx := context.Background()

	if rev, err := c.IsRevoked(ctx, tenant, device); err != nil || rev {
		t.Fatalf("healthy fetch: %v %v", rev, err)
	}
	healthy = false
	// Within refresh window: cached answer, no fetch needed.
	now = now.Add(29 * time.Second)
	if _, err := c.IsRevoked(ctx, tenant, device); err != nil {
		t.Fatalf("fresh cache must serve: %v", err)
	}
	// Past refresh, within maxStale: fetch fails, stale answer still legal.
	now = now.Add(25 * time.Second) // 54s old
	if _, err := c.IsRevoked(ctx, tenant, device); err != nil {
		t.Fatalf("≤60s stale must serve: %v", err)
	}
	// Past the ceiling: unknown state = error = fail closed.
	now = now.Add(10 * time.Second) // 64s old
	if _, err := c.IsRevoked(ctx, tenant, device); err == nil {
		t.Fatal("served revocation state older than the 60s ceiling")
	}
	// Recovery: a successful fetch resumes service.
	healthy = true
	if _, err := c.IsRevoked(ctx, tenant, device); err != nil {
		t.Fatalf("recovered fetch: %v", err)
	}
}

// Invalidate drops the local entry so the next check hits the authority.
func TestRevocationCacheInvalidate(t *testing.T) {
	c := NewRevocationCache(nil, 60*time.Second)
	answer := false
	c.fetchFn = func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return answer, nil }
	tenant, device := uuid.New(), uuid.New()
	if rev, _ := c.IsRevoked(context.Background(), tenant, device); rev {
		t.Fatal("not yet revoked")
	}
	answer = true
	c.Invalidate(device)
	if rev, _ := c.IsRevoked(context.Background(), tenant, device); !rev {
		t.Fatal("invalidate did not force a re-fetch")
	}
}
