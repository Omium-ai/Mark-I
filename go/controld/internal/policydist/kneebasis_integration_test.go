//go:build integration

package policydist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// poll is one device's GET /api/v1/policy/bundle on stable: features is its X-Mark1-Bundle-Features ("" = an edge that predates ADR-0013). It returns the served route.knee.basis and seq.
func (h *itHarness) poll(t *testing.T, token, features string) (string, uint64) {
	t.Helper()
	hdr := map[string]string{"X-Mark1-Edge-Version": "0.2.0"}
	if features != "" {
		hdr["X-Mark1-Bundle-Features"] = features
	}
	resp := h.req(http.MethodGet, "/api/v1/policy/bundle?channel=stable", token, nil, hdr)
	defer itClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("poll: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("served bundle does not decode: %v", err)
	}
	return b.Sections.Route.Knee.Basis, b.Seq
}

func (h *itHarness) basisDraft(basis string) Draft {
	s := validSections()
	s.Route.Knee.Basis = basis
	return Draft{Channel: BootstrapChannel, MaxAge: BootstrapMaxAge, SectionsCBOR: mustEncode(h.t, s)}
}

// chained is the catalog's own chain check over a channel: every seq's prev_hash is its predecessor's body_sha256.
func (h *itHarness) chained(t *testing.T, tenant uuid.UUID, channel string) int {
	t.Helper()
	rows, err := h.admin.Query(context.Background(), `SELECT seq, body_sha256, prev_hash FROM policy_bundles WHERE tenant_id = $1 AND channel = $2 ORDER BY seq`, tenant, channel)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	prev := make([]byte, 32)
	n := 0
	for rows.Next() {
		var seq int64
		var body, prevHash []byte
		if err := rows.Scan(&seq, &body, &prevHash); err != nil {
			t.Fatal(err)
		}
		if seq != int64(n+1) || !bytes.Equal(prevHash, prev) {
			t.Fatalf("%s seq %d: prev_hash %x does not chain to %x", channel, seq, prevHash, prev)
		}
		prev, n = body, n+1
	}
	return n
}

// ADR-0013 §8, mixed fleet: one device that decodes route.knee.basis and one that predates it. The key is withheld from the signed bytes (both devices are served a bundle they decode) while the producer's word is kept; when the old device upgrades, its next poll republishes the head with the key.
func TestIntegrationKneeBasisWithheldUntilEveryDeviceDecodesIt(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	h.poll0(t)
	if _, err := h.mod.Publish(ctx, h.tenantA, h.basisDraft("certified")); err != nil {
		t.Fatal(err)
	}
	if basis, seq := h.poll(t, h.tokenA1, BundleFeatureKneeBasis); basis != "" || seq != 1 {
		t.Fatalf("mixed fleet: A1 served basis %q at seq %d, want the key withheld at seq 1", basis, seq)
	}
	if basis, _ := h.poll(t, h.tokenA2, ""); basis != "" {
		t.Fatalf("the old device was served a key it cannot decode: %q", basis)
	}
	var intended, published *string
	if err := h.admin.QueryRow(ctx, `SELECT knee_basis_intended, knee_basis FROM policy_bundles WHERE tenant_id = $1 AND channel = 'stable' AND seq = 1`, h.tenantAID).Scan(&intended, &published); err != nil {
		t.Fatal(err)
	}
	if intended == nil || *intended != "certified" || published != nil {
		t.Fatalf("catalog row: intended %v published %v, want certified withheld", intended, published)
	}
	// A2 upgrades: its next poll says so, the head is republished with the key at seq 2, and both devices now read it.
	if basis, seq := h.poll(t, h.tokenA2, BundleFeatureKneeBasis); basis != "certified" || seq != 2 {
		t.Fatalf("after the upgrade: basis %q seq %d, want certified at seq 2", basis, seq)
	}
	if basis, seq := h.poll(t, h.tokenA1, BundleFeatureKneeBasis); basis != "certified" || seq != 2 {
		t.Fatalf("A1 after the upgrade: %q seq %d", basis, seq)
	}
	if n := h.chained(t, h.tenantAID, BootstrapChannel); n != 2 {
		t.Fatalf("chain length %d, want 2", n)
	}
	if h.adminCount("tlog_leaves") != 2 || h.adminCount("m1_receipts WHERE record_type = 'bundle_publication'") != 2 {
		t.Fatal("the republication is a normal publication: one leaf and one receipt each")
	}
	// Idempotent: nothing left to change.
	if n, err := h.mod.ReconcileKneeBasis(ctx, h.tenantA); err != nil || n != 0 {
		t.Fatalf("second resync published %d (%v), want 0", n, err)
	}
	// A device that downgrades (or an old device joining) is never handed the key: its poll withholds it first.
	if basis, seq := h.poll(t, h.tokenA1, ""); basis != "" || seq != 3 {
		t.Fatalf("downgraded device served %q at seq %d, want the key withheld at seq 3", basis, seq)
	}
	if n := h.chained(t, h.tenantAID, BootstrapChannel); n != 3 {
		t.Fatalf("chain length %d, want 3", n)
	}
}

// poll0 records both of tenant A's devices as pre-ADR-0013 edges (no features): the state of every device enrolled before this release.
func (h *itHarness) poll0(t *testing.T) {
	t.Helper()
	for _, d := range []uuid.UUID{h.deviceA1, h.deviceA2} {
		if _, err := h.mod.store.StampBundleFeatures(context.Background(), h.tenantA, d, nil); err != nil {
			t.Fatal(err)
		}
	}
}

// ADR-0013 §8, all-new fleet: every device advertised knee_basis, so the publication carries the key; a revoked device does not count.
func TestIntegrationKneeBasisPublishedToAnAllNewFleet(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	for _, d := range []uuid.UUID{h.deviceA1, h.deviceA2} {
		if _, err := h.mod.store.StampBundleFeatures(ctx, h.tenantA, d, []string{BundleFeatureKneeBasis}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.admin.Exec(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac, revoked_at, revoked_by, bundle_features) VALUES ($1, 'linux', decode(repeat('cd', 32), 'hex'), now(), 'it', '{}')`, h.tenantAID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mod.Publish(ctx, h.tenantA, h.basisDraft("certified")); err != nil {
		t.Fatal(err)
	}
	if basis, seq := h.poll(t, h.tokenA1, BundleFeatureKneeBasis); basis != "certified" || seq != 1 {
		t.Fatalf("all-new fleet: basis %q seq %d, want certified at seq 1", basis, seq)
	}
	// Tenant B's one device has not polled since it enrolled: nothing is known against it, so the key may go out and its first poll re-checks. Once it polls without the word it is known old.
	if ok, err := h.mod.store.KneeBasisCapable(ctx, h.tenantB); err != nil || !ok {
		t.Fatalf("tenant B before any poll: capable=%v err=%v, want true", ok, err)
	}
	if _, err := h.mod.store.StampBundleFeatures(ctx, h.tenantB, h.deviceB, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := h.mod.store.KneeBasisCapable(ctx, h.tenantB); err != nil || ok {
		t.Fatalf("tenant B after an old poll: capable=%v err=%v, want false", ok, err)
	}
}

// ADR-0013 §9: a tenant still on its pre-ADR-0013 bootstrap (stable seq 1, producer basis never recorded) is re-issued once as the current bootstrap at seq 2 — normal publication, chained, logged, receipted; seq 1 is never rewritten and a second run changes nothing.
func TestIntegrationReissueBootstrapStillOnSeqOne(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	old := validSections()
	old.Route.Knee.Basis = ""
	if _, err := h.mod.store.Publish(ctx, h.tenantA, Draft{Channel: BootstrapChannel, MaxAge: BootstrapMaxAge, SectionsCBOR: mustEncode(t, old), FirstOnly: true}); err != nil {
		t.Fatal(err)
	}
	var seq1Before []byte
	if err := h.admin.QueryRow(ctx, `SELECT body_cbor FROM policy_bundles WHERE tenant_id = $1 AND channel = 'stable' AND seq = 1`, h.tenantAID).Scan(&seq1Before); err != nil {
		t.Fatal(err)
	}
	for _, d := range []uuid.UUID{h.deviceA1, h.deviceA2} {
		if _, err := h.mod.store.StampBundleFeatures(ctx, h.tenantA, d, []string{BundleFeatureKneeBasis}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := h.mod.ReconcileKneeBasis(ctx, h.tenantA)
	if err != nil || n != 1 {
		t.Fatalf("re-issue published %d (%v), want 1", n, err)
	}
	if n, err := h.mod.ReconcileKneeBasis(ctx, h.tenantA); err != nil || n != 0 {
		t.Fatalf("second run published %d (%v), want 0", n, err)
	}
	served, err := h.mod.store.Latest(ctx, h.tenantA, BootstrapChannel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Unmarshal(served.Body)
	if err != nil {
		t.Fatal(err)
	}
	want, err := BootstrapSections(bootstrapRegime{CostBasis: "quota", VDefault: 1})
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonEnc.Marshal(b.Sections)
	if err != nil {
		t.Fatal(err)
	}
	if served.Seq != 2 || !bytes.Equal(got, want) || b.Sections.Route.Knee.Basis != "prior" {
		t.Fatalf("seq %d basis %q: want the current bootstrap (tests their own clique, basis prior) at seq 2", served.Seq, b.Sections.Route.Knee.Basis)
	}
	groups := map[string]bool{}
	for _, g := range b.Sections.Verify.CorrelationGroups {
		groups[g.GroupID] = true
	}
	if !groups["tests"] || !groups["syntactic"] {
		t.Fatalf("the re-issue carries the tests-as-own-clique fix: %+v", b.Sections.Verify.CorrelationGroups)
	}
	var seq1After []byte
	if err := h.admin.QueryRow(ctx, `SELECT body_cbor FROM policy_bundles WHERE tenant_id = $1 AND channel = 'stable' AND seq = 1`, h.tenantAID).Scan(&seq1After); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seq1Before, seq1After) || sha256.Sum256(seq1Before) != sha256.Sum256(seq1After) {
		t.Fatal("seq 1 was rewritten")
	}
	if n := h.chained(t, h.tenantAID, BootstrapChannel); n != 2 {
		t.Fatalf("chain length %d, want 2", n)
	}
	if h.adminCount("tlog_leaves") != 2 || h.adminCount("m1_receipts WHERE record_type = 'bundle_publication'") != 2 {
		t.Fatal("one log leaf and one receipt per publication")
	}
}

// A mixed fleet re-issue still goes out — with the key withheld — so the tests fix reaches an old fleet too.
func TestIntegrationReissueBootstrapToAMixedFleetWithholdsTheKey(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	h.poll0(t)
	old := validSections()
	if _, err := h.mod.store.Publish(ctx, h.tenantA, Draft{Channel: BootstrapChannel, MaxAge: BootstrapMaxAge, SectionsCBOR: mustEncode(t, old), FirstOnly: true}); err != nil {
		t.Fatal(err)
	}
	if n, err := h.mod.ReconcileKneeBasis(ctx, h.tenantA); err != nil || n != 1 {
		t.Fatalf("re-issue published %d (%v), want 1", n, err)
	}
	if basis, seq := h.poll(t, h.tokenA2, ""); basis != "" || seq != 2 {
		t.Fatalf("old device served %q at seq %d, want the re-issue without the key", basis, seq)
	}
	var intended *string
	if err := h.admin.QueryRow(ctx, `SELECT knee_basis_intended FROM policy_bundles WHERE tenant_id = $1 AND channel = 'stable' AND seq = 2`, h.tenantAID).Scan(&intended); err != nil {
		t.Fatal(err)
	}
	if intended == nil || *intended != "prior" {
		t.Fatalf("the producer's word is kept for the day the fleet upgrades: %v", intended)
	}
}

// A device alternating X-Mark1-Bundle-Features every poll cannot make the tenant republish every poll: withholding stays immediate (it is never served a key it refused), adding the key back happens at most once per kneeAddEvery per tenant, and the sweep adds it once the window has passed.
func TestIntegrationKneeBasisFlappingDeviceIsRateLimited(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	for _, d := range []uuid.UUID{h.deviceA1, h.deviceA2} {
		if _, err := h.mod.store.StampBundleFeatures(ctx, h.tenantA, d, []string{BundleFeatureKneeBasis}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.mod.Publish(ctx, h.tenantA, h.basisDraft("certified")); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		features, basis string
		seq             uint64
	}{
		{"", "", 2},                              // withheld at once
		{BundleFeatureKneeBasis, "certified", 3}, // the first add of the window
		{"", "", 4},                              // withheld at once
		{BundleFeatureKneeBasis, "", 4},          // add held: the window is spent
		{"", "", 4},
		{BundleFeatureKneeBasis, "", 4},
		{"", "", 4},
		{BundleFeatureKneeBasis, "", 4},
	}
	for i, w := range want {
		h.mod.limiter.mu.Lock()
		h.mod.limiter.buckets = map[string]*tokenBucket{}
		h.mod.limiter.mu.Unlock()
		if basis, seq := h.poll(t, h.tokenA1, w.features); basis != w.basis || seq != w.seq {
			t.Fatalf("poll %d (%q): basis %q seq %d, want %q at %d", i, w.features, basis, seq, w.basis, w.seq)
		}
	}
	if n := h.chained(t, h.tenantAID, BootstrapChannel); n != 4 {
		t.Fatalf("eight flapping polls published %d bundles, want 4", n)
	}
	if basis, _ := h.poll(t, h.tokenA2, BundleFeatureKneeBasis); basis != "" {
		t.Fatalf("the steady device is served the held head: %q", basis)
	}
	h.mod.kneeAdded.Store(h.tenantA.UUID(), time.Now().Add(-2*kneeAddEvery))
	if n, err := h.mod.ReconcileKneeBasis(ctx, h.tenantA); err != nil || n != 1 {
		t.Fatalf("the sweep after the window published %d (%v), want the key added once", n, err)
	}
	if basis, seq := h.poll(t, h.tokenA2, BundleFeatureKneeBasis); basis != "certified" || seq != 5 {
		t.Fatalf("after the window: %q seq %d", basis, seq)
	}
}
