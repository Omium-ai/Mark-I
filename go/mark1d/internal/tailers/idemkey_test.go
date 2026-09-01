// FR-SPINE-003's third clause, "HMAC keyed per tenant". The replay suite
// proves the dedupe arithmetic under an injected stand-in key, which is
// key-AGNOSTIC by construction; this file proves the key is not. 07 §7 has the
// server upsert Usage on idem_key alone, so two tenants deriving the same key
// for one (session, message.id, request_id) triple would fuse two
// organisations' ledgers — a privacy break, not a billing rounding error.
package tailers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
	"github.com/google/uuid"
)

// The golden vector below freezes the derivation the whole ledger is keyed on.
// Roots are opaque bytes in production (enrollment custody, 04 §2.9); these two
// only need to differ.
const (
	tenantRootA = "tenant-a-hmac-root"
	tenantRootB = "tenant-b-hmac-root"

	// goldenTenantRoot ⇒ goldenUsageIdemKey pins HKDF-SHA256 under the
	// events.proto label "m1p.usage.idem" (07 §7). This vector is WIRE, not an
	// implementation detail: every idem_key already uploaded was computed under
	// this label, so changing it silently re-namespaces the server's dedupe and
	// resurrects the ~2.5× streaming overcount FR-SPINE-003 exists to defeat —
	// while every behavioural test in this package stays green. Move it only
	// with a protocol version bump and a re-key plan.
	goldenTenantRoot   = "m1p-conformance-tenant-root"
	goldenUsageIdemKey = "52f1ca9019a31a87645edc8c0a833f4f3c91ad5c04869fd21a1aedd839112e13"
)

// assertDerived rejects the vacuous pass: an empty or zeroed key would satisfy
// "the two differ" checks below just as well as a real derivation.
func assertDerived(t *testing.T, who string, k []byte) {
	t.Helper()
	if len(k) != sha256.Size {
		t.Fatalf("%s: derived key is %d bytes, want %d — nothing was derived", who, len(k), sha256.Size)
	}
	if bytes.Equal(k, make([]byte, sha256.Size)) {
		t.Fatalf("%s: derived key is all zero — a comparison against it proves nothing", who)
	}
}

// TestDeriveUsageIdemKeyPerTenant exercises the real derivation (the suites
// elsewhere inject testIdemKey): distinct tenant roots must not share a
// usage-idem key, and one root must yield the same key forever — dedupe across
// restarts is exactly that determinism.
func TestDeriveUsageIdemKeyPerTenant(t *testing.T) {
	a, err := DeriveUsageIdemKey([]byte(tenantRootA))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveUsageIdemKey([]byte(tenantRootB))
	if err != nil {
		t.Fatal(err)
	}
	assertDerived(t, "tenant A", a)
	assertDerived(t, "tenant B", b)
	if bytes.Equal(a, b) {
		t.Fatal("two tenant roots derived the SAME usage-idem key — the derivation is not keyed by the root, so every tenant shares one idem_key namespace (07 §7)")
	}
	again, err := DeriveUsageIdemKey([]byte(tenantRootA))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, again) {
		t.Fatal("one root derived two different keys — a restart would re-key the ledger and every already-emitted Usage would dedupe against nothing")
	}
}

// TestUsageIdemKeyIsolatesTenants is the same property through the production
// path: the committed corpus replayed under two tenant roots. Same
// (session_id, message.id, request_id) triples, two roots ⇒ every emitted
// idem_key must differ; the same root twice ⇒ every one identical.
func TestUsageIdemKeyIsolatesTenants(t *testing.T) {
	exp := loadExpectations(t)
	st := exp.Streams[0]
	session := uuid.MustParse(st.UsageEvents[0].IdemInputs.SessionID)
	lines := fixtureLines(t, st.File)

	replay := func(tenantRoot string) map[pendingKey][]byte {
		t.Helper()
		key, err := DeriveUsageIdemKey([]byte(tenantRoot))
		if err != nil {
			t.Fatal(err)
		}
		s := stream{role: RoleParent, session: session, idemKey: key}
		now := time.Now()
		var evs []*m1pv1.Event
		for _, line := range lines {
			evs = append(evs, s.consume(line, now)...)
		}
		evs = append(evs, s.flush()...)
		out := map[pendingKey][]byte{}
		for _, ev := range evs {
			u := ev.GetUsage()
			out[pendingKey{u.GetMessageId(), u.GetRequestId()}] = u.GetIdemKey()
		}
		return out
	}

	a, b, aAgain := replay(tenantRootA), replay(tenantRootB), replay(tenantRootA)
	if len(a) == 0 {
		t.Fatal("corpus emitted no Usage — the tenant-isolation assertions below would be vacuous")
	}
	if len(a) != len(b) {
		t.Fatalf("tenant A emitted %d keys, tenant B %d — the tenant root must key the idem_key, never the dedupe", len(a), len(b))
	}
	for k, ka := range a {
		assertDerived(t, "tenant A "+k.MessageID, ka)
		kb, ok := b[k]
		if !ok {
			t.Fatalf("(%s,%s) emitted under tenant A but not tenant B", k.MessageID, k.RequestID)
		}
		assertDerived(t, "tenant B "+k.MessageID, kb)
		if bytes.Equal(ka, kb) {
			t.Fatalf("(%s,%s) yields the SAME idem_key under two tenant roots — usage from separate organisations would collide on the server's idem_key upsert (07 §7)", k.MessageID, k.RequestID)
		}
		if !bytes.Equal(ka, aAgain[k]) {
			t.Fatalf("(%s,%s) yields two different idem_keys under ONE tenant root — dedupe is impossible", k.MessageID, k.RequestID)
		}
	}
}

// TestDeriveUsageIdemKeyGoldenVector pins the HKDF label. Behavioural tests
// cannot see a label change: keys stay 32 bytes, stay per-tenant, stay
// deterministic, and every already-uploaded idem_key stops matching.
func TestDeriveUsageIdemKeyGoldenVector(t *testing.T) {
	got, err := DeriveUsageIdemKey([]byte(goldenTenantRoot))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != goldenUsageIdemKey {
		t.Fatalf("usage-idem derivation moved:\n got  %s\n want %s\nHKDF label %q and the derivation shape are protocol (events.proto Usage.idem_key). This is a wire break — server-side dedupe re-namespaces and the ~2.5× overcount returns — not a refactor.",
			hex.EncodeToString(got), goldenUsageIdemKey, "m1p.usage.idem")
	}
}
