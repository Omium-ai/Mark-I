package receipts

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConfVectorsHostchainControld* drive conformance/vectors/hostchain/
// manifest.json from the countersigning side (ADR-0017): the reconstruction
// controld verifies an origin signature over — Checkpoint.Payload with the
// event's hosts and counters — must reproduce every frozen v1 and v2 row
// byte for byte, and the chain and its negatives verify as the vectors say.

const hostchainVectorsDir = "../../../../conformance/vectors/hostchain"

type hcTask struct {
	TaskID       string `json:"task_id"`
	IdentityHash string `json:"identity_hash"`
}

type hcHost struct {
	SessionID         string   `json:"session_id"`
	Transport         string   `json:"transport"`
	HostID            string   `json:"host_id"`
	HostVersion       string   `json:"host_version"`
	ProfileHash       string   `json:"profile_hash"`
	HostCorrelationID string   `json:"host_correlation_id"`
	Tasks             []hcTask `json:"tasks"`
}

type hcPayload struct {
	V                  int      `json:"v"`
	TenantID           string   `json:"tenant_id"`
	Seq                int64    `json:"seq"`
	PrevReceiptHash    string   `json:"prev_receipt_hash"`
	DeviceID           string   `json:"device_id"`
	IssuedAt           string   `json:"issued_at"`
	CheckpointSeq      int64    `json:"checkpoint_seq"`
	MerkleRoot         string   `json:"merkle_root"`
	LeafCount          int      `json:"leaf_count"`
	Hosts              []hcHost `json:"hosts"`
	ArrestsActed       uint32   `json:"arrests_acted"`
	ArrestsRecommended uint32   `json:"arrests_recommended"`
}

type hcManifest struct {
	Keys struct {
		Device vectorKey `json:"device"`
		Server vectorKey `json:"server"`
	} `json:"keys"`
	Chain     []chainEntry `json:"chain"`
	Negatives []struct {
		Name         string     `json:"name"`
		Receipt      chainEntry `json:"receipt"`
		ExpectDefect string     `json:"expect_defect"`
	} `json:"negatives"`
}

func loadHostchain(t *testing.T) *hcManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(hostchainVectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m hcManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	if len(m.Chain) == 0 || len(m.Negatives) == 0 {
		t.Fatalf("manifest families empty: chain=%d negatives=%d", len(m.Chain), len(m.Negatives))
	}
	return &m
}

func hostchainKeySet(t *testing.T, m *hcManifest) KeySet {
	t.Helper()
	ks := KeySet{}
	ks.Add(ed25519.PublicKey(unhex(t, m.Keys.Device.PublicHex)), RoleDeviceOrigin)
	ks.Add(ed25519.PublicKey(unhex(t, m.Keys.Server.PublicHex)), RoleServerChain)
	return ks
}

func hostsFromVector(t *testing.T, hs []hcHost) []HostBinding {
	t.Helper()
	out := make([]HostBinding, 0, len(hs))
	for _, h := range hs {
		hb := HostBinding{Transport: h.Transport, HostID: h.HostID, HostVersion: h.HostVersion, HostCorrelationID: h.HostCorrelationID, ProfileHash: unhex32(t, h.ProfileHash)}
		copy(hb.SessionID[:], unhex(t, h.SessionID))
		for _, tk := range h.Tasks {
			tb := TaskBinding{}
			copy(tb.TaskID[:], unhex(t, tk.TaskID))
			if tk.IdentityHash != "" {
				tb.IdentityHash = unhex(t, tk.IdentityHash)
			}
			hb.Tasks = append(hb.Tasks, tb)
		}
		out = append(out, hb)
	}
	return out
}

// TestConfVectorsHostchainControldChain: controld's reconstruction of a v2
// checkpoint (the bytes it countersigns) equals the frozen text, hash and
// origin signature; v1 rows reconstruct as before; the chain verifies.
func TestConfVectorsHostchainControldChain(t *testing.T) {
	m := loadHostchain(t)
	deviceKey, err := NewSigner(unhex(t, m.Keys.Device.SeedHex))
	if err != nil {
		t.Fatal(err)
	}
	recs := make([]Receipt, 0, len(m.Chain))
	sawV2 := false
	for i := range m.Chain {
		e := &m.Chain[i]
		var p hcPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("seq %d: %v", e.Seq, err)
		}
		// The store's reconstruction: v1 fields from the head and the event,
		// then — iff payload_version == 2 — the event's hosts and counters.
		cp := Checkpoint{
			TenantID: p.TenantID, DeviceID: p.DeviceID, Seq: p.Seq,
			PrevReceiptHash: unhex32(t, p.PrevReceiptHash), IssuedAt: p.IssuedAt,
			CheckpointSeq: p.CheckpointSeq, MerkleRoot: unhex32(t, p.MerkleRoot), LeafCount: p.LeafCount,
		}
		if p.V == 2 {
			sawV2 = true
			cp.Hosts = hostsFromVector(t, p.Hosts)
			if cp.Hosts == nil {
				cp.Hosts = []HostBinding{}
			}
			cp.ArrestsActed, cp.ArrestsRecommended = p.ArrestsActed, p.ArrestsRecommended
		}
		signed, err := OriginSign(deviceKey, cp.Payload(deviceKey.KeyID()))
		if err != nil {
			t.Fatalf("seq %d: OriginSign: %v", e.Seq, err)
		}
		if signed.PayloadText != e.CanonicalJSON {
			t.Errorf("seq %d: reconstruction:\n got %s\nwant %s", e.Seq, signed.PayloadText, e.CanonicalJSON)
		}
		if signed.ReceiptHash != unhex32(t, e.ReceiptHashHex) {
			t.Errorf("seq %d: hash %x, manifest %s", e.Seq, signed.ReceiptHash, e.ReceiptHashHex)
		}
		if hex.EncodeToString(signed.DeviceSig) != e.DeviceSignatureHex {
			t.Errorf("seq %d: origin signature diverges from manifest", e.Seq)
		}
		if got := hostBindingsColumn(cp); (p.V == 2) != (got != nil) {
			t.Errorf("seq %d: host_bindings column = %v for v%d", e.Seq, got, p.V)
		}
		recs = append(recs, manifestReceipt(t, e, e.CanonicalJSON))
	}
	if !sawV2 {
		t.Fatal("manifest has no v2 row")
	}
	rep := VerifyChain(recs, hostchainKeySet(t, m), 1)
	if !rep.Valid || len(rep.Defects) != 0 {
		t.Fatalf("hostchain must verify clean, got defects %+v", rep.Defects)
	}
}

// TestConfVectorsHostchainControldNegatives: the host block and the
// counters are inside the signed bytes — rewriting them is payload_mismatch,
// a signature over a different block is bad_signature.
func TestConfVectorsHostchainControldNegatives(t *testing.T) {
	m := loadHostchain(t)
	keys := hostchainKeySet(t, m)
	for _, n := range m.Negatives {
		e := n.Receipt
		fields, err := DecodePayload(e.Payload)
		if err != nil {
			t.Fatalf("%s: decoding payload: %v", n.Name, err)
		}
		text, err := CanonicalJSON(fields)
		if err != nil {
			t.Fatalf("%s: CanonicalJSON: %v", n.Name, err)
		}
		rep := VerifyChain([]Receipt{manifestReceipt(t, &e, text)}, keys, e.Seq)
		if rep.Valid {
			t.Errorf("%s: verified clean, want %s", n.Name, n.ExpectDefect)
			continue
		}
		found := false
		for _, d := range rep.Defects {
			if string(d.Defect) == n.ExpectDefect {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want defect %s, got %+v", n.Name, n.ExpectDefect, rep.Defects)
		}
	}
}
