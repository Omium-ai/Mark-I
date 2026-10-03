package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// TestConfVectorsHostchain* drive conformance/vectors/hostchain/manifest.json
// — ADR-0017's frozen v2 checkpoint payload: the host block inside the signed
// bytes, the profile hash, the per-task identity hash, a v1→v2→v2 chain and
// three negatives. The sealer's builder (Checkpoint.Payload) must reproduce
// every byte, hash and signature; the mirror in controld and the Rust and
// Python builders drive the same file.

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

type hcEntry struct {
	Seq                int64           `json:"seq"`
	Payload            json.RawMessage `json:"payload"`
	CanonicalJSON      string          `json:"canonical_json"`
	ReceiptHashHex     string          `json:"receipt_hash_hex"`
	DeviceKeyID        string          `json:"device_key_id"`
	DeviceSignatureHex string          `json:"device_signature_hex"`
	ServerKeyID        string          `json:"server_key_id"`
	ServerSignatureHex string          `json:"server_signature_hex"`
}

type hcProfile struct {
	Canonical string `json:"canonical"`
	HashHex   string `json:"hash_hex"`
}

type hcManifest struct {
	Keys struct {
		Device vectorKey `json:"device"`
		Server vectorKey `json:"server"`
	} `json:"keys"`
	Profiles          map[string]hcProfile `json:"profiles"`
	IdentityDomainHex string               `json:"identity_domain_hex"`
	Chain             []hcEntry            `json:"chain"`
	Negatives         []struct {
		Name         string  `json:"name"`
		Receipt      hcEntry `json:"receipt"`
		ExpectDefect string  `json:"expect_defect"`
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
	if len(m.Chain) == 0 || len(m.Negatives) == 0 || len(m.Profiles) == 0 {
		t.Fatalf("manifest families empty: chain=%d negatives=%d profiles=%d", len(m.Chain), len(m.Negatives), len(m.Profiles))
	}
	return &m
}

func hostchainKeySet(t *testing.T, m *hcManifest) KeySet {
	t.Helper()
	return KeySet{
		m.Keys.Device.KeyID: {Pub: ed25519.PublicKey(unhex(t, m.Keys.Device.PublicHex)), Role: RoleDeviceOrigin},
		m.Keys.Server.KeyID: {Pub: ed25519.PublicKey(unhex(t, m.Keys.Server.PublicHex)), Role: RoleServerChain},
	}
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

func hostchainProfiles() map[string]hostprofile.Profile {
	return map[string]hostprofile.Profile{
		"cem888":   {HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"},
		"tailhost": {HostID: "tailhost", HostVersion: "0.9", OwnsExecution: true, OwnsConfigSurface: false, OwnsMemory: false, ArrestMode: hostprofile.Act, SuppliesIdentity: false, SchemaVersion: "m1p.v1"},
		"default":  hostprofile.Default,
	}
}

// TestConfVectorsHostchainProfiles: profile_hash is sha256 over the ADR-0013
// canonical profile — the bytes mark1d logs at the Hello — for a declared
// host, a file-tail host and Default alike.
func TestConfVectorsHostchainProfiles(t *testing.T) {
	m := loadHostchain(t)
	for name, p := range hostchainProfiles() {
		v, ok := m.Profiles[name]
		if !ok {
			t.Fatalf("manifest has no profile %q", name)
		}
		if got := string(hostprofile.Canonical(p)); got != v.Canonical {
			t.Errorf("%s: canonical profile\n got %s\nwant %s", name, got, v.Canonical)
		}
		if got := hex.EncodeToString(func() []byte { h := ProfileHash(p); return h[:] }()); got != v.HashHex {
			t.Errorf("%s: profile_hash %s, manifest %s", name, got, v.HashHex)
		}
	}
	if hex.EncodeToString([]byte(identityDomain)) != m.IdentityDomainHex {
		t.Errorf("identity domain %x, manifest %s", identityDomain, m.IdentityDomainHex)
	}
}

// TestConfVectorsHostchainChain: the builder reproduces every frozen row —
// v1 (Hosts nil) and v2 (hosts, counters) — byte for byte, and the chain
// verifies from genesis; every identity_hash is IdentityHash's.
func TestConfVectorsHostchainChain(t *testing.T) {
	m := loadHostchain(t)
	deviceKey := deviceKeyFromSeed(unhex(t, m.Keys.Device.SeedHex))
	recs := make([]Receipt, 0, len(m.Chain))
	sawV2 := false
	for _, e := range m.Chain {
		var p hcPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatalf("seq %d: %v", e.Seq, err)
		}
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
			for _, h := range p.Hosts {
				for _, tk := range h.Tasks {
					var task [16]byte
					copy(task[:], unhex(t, tk.TaskID))
					if tk.IdentityHash == "" {
						continue
					}
					if got := hex.EncodeToString(IdentityHash(h.HostID, h.HostCorrelationID, task)); got != tk.IdentityHash {
						t.Errorf("seq %d %s/%s: identity_hash %s, manifest %s", e.Seq, h.HostID, tk.TaskID, got, tk.IdentityHash)
					}
				}
			}
		}
		signed, err := OriginSign(deviceKey, cp.Payload(deviceKey.KeyID()))
		if err != nil {
			t.Fatalf("seq %d: OriginSign: %v", e.Seq, err)
		}
		if signed.PayloadText != e.CanonicalJSON {
			t.Errorf("seq %d: builder payload:\n got %s\nwant %s", e.Seq, signed.PayloadText, e.CanonicalJSON)
		}
		if signed.ReceiptHash != unhex32(t, e.ReceiptHashHex) {
			t.Errorf("seq %d: origin hash = %x, manifest %s", e.Seq, signed.ReceiptHash, e.ReceiptHashHex)
		}
		if hex.EncodeToString(signed.DeviceSig) != e.DeviceSignatureHex {
			t.Errorf("seq %d: origin signature diverges from manifest", e.Seq)
		}
		recs = append(recs, manifestReceipt(t, &chainEntry{
			Seq: e.Seq, ReceiptHashHex: e.ReceiptHashHex, DeviceKeyID: e.DeviceKeyID, DeviceSignatureHex: e.DeviceSignatureHex,
			ServerKeyID: e.ServerKeyID, ServerSignatureHex: e.ServerSignatureHex,
		}, e.CanonicalJSON))
	}
	if !sawV2 {
		t.Fatal("manifest has no v2 row; the family would not be testing ADR-0017")
	}
	rep := VerifyChain(recs, hostchainKeySet(t, m), 1)
	if !rep.Valid || len(rep.Defects) != 0 {
		t.Fatalf("hostchain must verify clean, got defects %+v", rep.Defects)
	}
}

// TestConfVectorsHostchainNegatives: a rewritten host block or counter is
// payload_mismatch; a signature over a different host block is bad_signature.
func TestConfVectorsHostchainNegatives(t *testing.T) {
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
		if text == e.CanonicalJSON {
			text = e.CanonicalJSON
		}
		rec := manifestReceipt(t, &chainEntry{
			Seq: e.Seq, ReceiptHashHex: e.ReceiptHashHex, DeviceKeyID: e.DeviceKeyID, DeviceSignatureHex: e.DeviceSignatureHex,
			ServerKeyID: e.ServerKeyID, ServerSignatureHex: e.ServerSignatureHex,
		}, text)
		rep := VerifyChain([]Receipt{rec}, keys, e.Seq)
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
