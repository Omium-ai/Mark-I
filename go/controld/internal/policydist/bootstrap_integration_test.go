//go:build integration

package policydist

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
)

type keysDoc struct {
	Schema            string        `json:"schema"`
	BundleSectionKeys []ManifestKey `json:"bundle_section_keys"`
	Tlog              struct {
		Head *struct {
			Size  int64  `json:"size"`
			Root  string `json:"root"`
			KeyID string `json:"key_id"`
			Sig   string `json:"sig"`
		} `json:"head"`
	} `json:"tlog"`
}

func (h *itHarness) wellKnown(token, query string) keysDoc {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.api.URL+"/.well-known/mark1-keys"+query, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer itClose(resp)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("well-known: HTTP %d", resp.StatusCode)
	}
	var d keysDoc
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		h.t.Fatal(err)
	}
	return d
}

// TestIntegrationBootstrapIsSeqOneOnceAndServable: the first call mints stable seq 1 (log leaf, receipt, catalog row), the second is a no-op, the served bytes decode to the bootstrap content, and the head at the proof's tree_size is what the key surface answers under the device token.
func TestIntegrationBootstrapIsSeqOneOnceAndServable(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()

	p, published, err := h.mod.Bootstrap(ctx, h.tenantA)
	if err != nil || !published {
		t.Fatalf("first bootstrap: published=%v err=%v", published, err)
	}
	if p.Channel != BootstrapChannel || p.Seq != 1 || p.TreeSize != 1 {
		t.Fatalf("bootstrap landed at %+v, want stable seq 1 as tlog leaf 0", p)
	}
	if _, again, err := h.mod.Bootstrap(ctx, h.tenantA); err != nil || again {
		t.Fatalf("second bootstrap must be a no-op: published=%v err=%v", again, err)
	}
	if got := h.headSeq(BootstrapChannel); got != 1 {
		t.Fatalf("head_seq %d after a repeated bootstrap, want 1 (never re-publish seq 1)", got)
	}
	if h.adminCount("m1_receipts WHERE record_type = 'bundle_publication'") != 1 || h.adminCount("tlog_leaves") != 1 {
		t.Fatal("one publication receipt and one log leaf, exactly")
	}
	// An existing head (tenant B publishes something else first) is untouched.
	if _, err := h.mod.Publish(ctx, h.tenantB, h.draft(BootstrapChannel)); err != nil {
		t.Fatal(err)
	}
	if _, published, err := h.mod.Bootstrap(ctx, h.tenantB); err != nil || published {
		t.Fatalf("tenant with a bundle: published=%v err=%v", published, err)
	}
	if _, err := h.mod.store.Publish(ctx, h.tenantB, Draft{Channel: BootstrapChannel, MaxAge: BootstrapMaxAge, SectionsCBOR: h.draft(BootstrapChannel).SectionsCBOR, FirstOnly: true}); !errors.Is(err, ErrChannelHasHead) {
		t.Fatalf("FirstOnly on a live channel: %v, want ErrChannelHasHead", err)
	}

	served, err := h.mod.store.Latest(ctx, h.tenantA, BootstrapChannel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Unmarshal(served.Body)
	if err != nil {
		t.Fatalf("served bootstrap does not decode: %v", err)
	}
	if len(b.Sections.Verify.Verifiers) != len(bootstrapAnchors) || !b.Sections.Gates.StopGateEnabled || b.MaxAge != uint64(BootstrapMaxAge.Seconds()) {
		t.Fatalf("served content is not the bootstrap: %+v", b.Sections.Verify)
	}
	if len(b.Inclusion.AuditPath) != 0 || b.Inclusion.AuditPath == nil {
		t.Fatalf("leaf 0 of a one-leaf tree carries an EMPTY path, never null: %#v", b.Inclusion.AuditPath)
	}
	if b.Sections.Route.Knee.CostBasis != "quota" {
		t.Fatalf("no regime row ⇒ quota, got %s", b.Sections.Route.Knee.CostBasis)
	}

	// Grow the log past the bundle (a key manifest leaf), then ask for the head the proof targets.
	if _, err := h.mod.store.PublishKeyManifest(ctx, h.tenantA, mustManifest(t, h.ring)); err != nil {
		t.Fatal(err)
	}
	anon := h.wellKnown("", "")
	if anon.Schema != KeyManifestSchema || len(anon.BundleSectionKeys) != len(SectionNames) || anon.Tlog.Head != nil {
		t.Fatalf("anonymous key surface: %+v — keys for everyone, a head for nobody", anon)
	}
	newest := h.wellKnown(h.tokenA1, "")
	if newest.Tlog.Head == nil || newest.Tlog.Head.Size != 2 {
		t.Fatalf("device token, no size: %+v, want the newest head (size 2)", newest.Tlog)
	}
	at := h.wellKnown(h.tokenA1, "?tree_size="+itoa(b.Inclusion.TreeSize))
	if at.Tlog.Head == nil || at.Tlog.Head.Size != 1 || at.Tlog.Head.Root != hex.EncodeToString(b.Inclusion.RootHash) {
		t.Fatalf("head at the proof's tree_size: %+v, want size 1 root %x", at.Tlog, b.Inclusion.RootHash)
	}
	if got := h.wellKnown(h.tokenB, "?tree_size=1"); got.Tlog.Head != nil && got.Tlog.Head.Root == at.Tlog.Head.Root {
		t.Fatal("tenant B was served tenant A's head")
	}
	if got := h.wellKnown("not-a-token", "?tree_size=1"); got.Tlog.Head != nil {
		t.Fatal("a bad token must not unlock a head")
	}
}

// TestIntegrationBootstrapFollowsTheTenantRegime: a usd regime row picks the basis and V(task).
func TestIntegrationBootstrapFollowsTheTenantRegime(t *testing.T) {
	h := itSetup(t)
	ctx := context.Background()
	if _, err := h.admin.Exec(ctx, `INSERT INTO m1_tenant_regimes (tenant_id, cost_basis, price_model_id, v_default, set_by) VALUES ($1, 'usd', 'claude-sonnet-4-5', 25, 'it')`, h.tenantAID); err != nil {
		t.Fatal(err)
	}
	if _, published, err := h.mod.Bootstrap(ctx, h.tenantA); err != nil || !published {
		t.Fatalf("published=%v err=%v", published, err)
	}
	served, err := h.mod.store.Latest(ctx, h.tenantA, BootstrapChannel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Unmarshal(served.Body)
	if err != nil {
		t.Fatal(err)
	}
	k := b.Sections.Route.Knee
	if k.CostBasis != "usd" || k.VDefault != 25 || k.Rows[0].CN != kneeRho*kneeP1*25 {
		t.Fatalf("usd regime, V=25: knee %+v", k)
	}
	var seq int64
	if err := h.admin.QueryRow(ctx, `SELECT head_seq FROM bundle_channel_heads WHERE tenant_id = $1 AND channel = 'stable'`, h.tenantBID).Scan(&seq); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant A's bootstrap leaked a head to tenant B: seq=%d err=%v", seq, err)
	}
}

func mustManifest(t *testing.T, ring *Keyring) *KeyManifest {
	t.Helper()
	update, err := DeriveKeyring(append([]byte{1}, itSectionSeed[1:]...))
	if err != nil {
		t.Fatal(err)
	}
	m, err := BuildKeyManifest(ring, nil, update.byName["verify"], nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }
