//go:build integration

package receipts_test

// 15-teams: a team member's GET /api/v1/receipts lists only the rows their devices signed, while chain_head stays the tenant's (the sealer builds on it) and the export stays whole (a filtered chain cannot verify).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Omium-ai/omium-mark1/go/controld/internal/auth"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/obs"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/querychoke"
	"github.com/Omium-ai/omium-mark1/go/controld/internal/receipts"
)

type staticViewers struct{ v querychoke.Viewer }

func (s staticViewers) Viewer(context.Context, querychoke.TenantID, auth.Claims) (querychoke.Viewer, error) {
	return s.v, nil
}

func TestIntegrationTeamMemberListsOnlyTheirReceipts(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

	var mate uuid.UUID
	if err := h.admin.QueryRow(ctx, `INSERT INTO m1_devices (tenant_id, platform, hostname_hmac) VALUES ($1, 'linux', $2) RETURNING id`, h.tenantA.UUID(), bytes.Repeat([]byte{1}, 32)).Scan(&mate); err != nil {
		t.Fatal(err)
	}
	mateKey, err := receipts.NewSigner(bytes.Repeat([]byte{0x12}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.admin.Exec(ctx, `INSERT INTO m1_device_keys (tenant_id, device_id, key_id, public_key) VALUES ($1, $2, $3, $4)`, h.tenantA.UUID(), mate, mateKey.KeyID(), []byte(mateKey.Public())); err != nil {
		t.Fatal(err)
	}
	for i, d := range []struct {
		device uuid.UUID
		key    *receipts.Signer
	}{{h.deviceA, h.deviceKey}, {mate, mateKey}, {h.deviceA, h.deviceKey}} {
		ev := h.sealCheckpoint(t, h.tenantA, d.device, d.key, leavesOf(v7(t), v7(t)), at.Add(time.Duration(i)*time.Minute))
		if _, err := h.store.AppendCheckpoint(ctx, h.tenantA, ev, nil); err != nil {
			t.Fatal(err)
		}
	}

	list := func(v querychoke.Viewer, path string) (seqs []int64, keys []string, headSeq int64, raw []byte) {
		t.Helper()
		mux := http.NewServeMux()
		receipts.NewModule(receipts.ModuleDeps{DB: h.db, PG: h.db, Verifier: auth.NewHMACVerifier([]byte("team-key"), auth.StaticRevocations{}),
			ObsCfg: obs.Config{ServiceName: "receipts-team-it"}, Viewers: staticViewers{v}}).RegisterRoutes(mux)
		srv := httptest.NewServer(mux)
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+auth.Mint([]byte("team-key"), h.tenantA.UUID(), h.deviceA, time.Hour))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ = io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, raw)
		}
		if path != "/api/v1/receipts" {
			return nil, nil, 0, raw
		}
		var out struct {
			Receipts []struct {
				ReceiptSeq int64  `json:"receipt_seq"`
				KeyID      string `json:"key_id"`
			} `json:"receipts"`
			ChainHead struct {
				Seq int64 `json:"seq"`
			} `json:"chain_head"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		for _, r := range out.Receipts {
			seqs, keys = append(seqs, r.ReceiptSeq), append(keys, r.KeyID)
		}
		return seqs, keys, out.ChainHead.Seq, raw
	}

	seqs, _, head, _ := list(querychoke.Viewer{Subject: "omium:owner", Devices: []uuid.UUID{h.deviceA}}, "/api/v1/receipts")
	if len(seqs) != 3 || head != 3 {
		t.Fatalf("a solo tenant lists the whole chain: %v head %d", seqs, head)
	}
	seqs, keys, head, _ := list(querychoke.Viewer{Subject: "omium:me", Team: true, Devices: []uuid.UUID{h.deviceA}}, "/api/v1/receipts")
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 3 || keys[0] != h.deviceKey.KeyID() || keys[1] != h.deviceKey.KeyID() || head != 3 {
		t.Fatalf("a member lists only their device's rows under the tenant head: %v %v head %d", seqs, keys, head)
	}
	seqs, _, head, _ = list(querychoke.Viewer{Subject: "omium:new", Team: true, Devices: []uuid.UUID{}}, "/api/v1/receipts")
	if len(seqs) != 0 || head != 3 {
		t.Fatalf("an empty device list lists nothing, head still the tenant's: %v head %d", seqs, head)
	}
	_, _, _, export := list(querychoke.Viewer{Subject: "omium:me", Team: true, Devices: []uuid.UUID{h.deviceA}}, "/api/v1/receipts/export")
	if n := bytes.Count(export, []byte("\n")); n != 3 {
		t.Fatalf("the export is verifier food and stays whole: %d lines", n)
	}
}
