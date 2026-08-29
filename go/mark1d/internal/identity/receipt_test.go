// Chain-walk behaviors the frozen vectors cannot express: the vacuous-walk
// verdict and tenant binding of device keys. The role split itself is locked
// by the server_key_as_device_origin vector. TEST-ONLY seeds per the vectors'
// README — worthless by definition.

package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

const testTenant = "11111111-1111-1111-1111-111111111111"

func testRow(t *testing.T) Receipt {
	t.Helper()
	device := deviceKeyFromSeed(bytes.Repeat([]byte{0x11}, seedLen))
	server := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, seedLen))
	root, err := MerkleRoot([][]byte{bytes.Repeat([]byte{0x01}, 16)})
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	cp := Checkpoint{
		TenantID:        testTenant,
		DeviceID:        "device-unit",
		Seq:             1,
		PrevReceiptHash: GenesisHash,
		IssuedAt:        "2026-08-29T00:00:00Z",
		CheckpointSeq:   1,
		MerkleRoot:      root,
		LeafCount:       1,
	}
	signed, err := OriginSign(device, cp.Payload(device.KeyID()))
	if err != nil {
		t.Fatalf("OriginSign: %v", err)
	}
	signingInput := append([]byte(DomainPrefix), signed.PayloadText...)
	return Receipt{
		Seq:         1,
		PayloadText: signed.PayloadText,
		ReceiptHash: sha256.Sum256(signingInput),
		DeviceSig:   signed.DeviceSig,
		ServerKeyID: DeriveKeyID(server.Public().(ed25519.PublicKey)),
		ServerSig:   ed25519.Sign(server, signingInput),
	}
}

func testKeySet(deviceTenant string) KeySet {
	device := deviceKeyFromSeed(bytes.Repeat([]byte{0x11}, seedLen))
	server := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, seedLen))
	ks := KeySet{}
	id := ks.Add(device.Public(), RoleDeviceOrigin)
	if deviceTenant != "" {
		entry := ks[id]
		entry.TenantID = deviceTenant
		ks[id] = entry
	}
	ks.Add(server.Public().(ed25519.PublicKey), RoleServerChain)
	return ks
}

func TestEmptyWalkIsNotValid(t *testing.T) {
	// Zero rows walked is a vacuous walk: no defects, but never the verdict a
	// verified history earns — a truncated-to-nothing export must not pass.
	rep := VerifyChain(nil, testKeySet(""), 1)
	if rep.Valid {
		t.Fatal("empty chain reported Valid")
	}
	if len(rep.Defects) != 0 || rep.Checked != 0 {
		t.Fatalf("empty chain: %+v", rep)
	}
}

func TestTenantScopedDeviceKeyAnswersOnlyItsTenant(t *testing.T) {
	row := testRow(t)
	if rep := VerifyChain([]Receipt{row}, testKeySet(testTenant), 1); !rep.Valid {
		t.Fatalf("matching tenant must verify: %+v", rep.Defects)
	}
	rep := VerifyChain([]Receipt{row}, testKeySet("99999999-9999-9999-9999-999999999999"), 1)
	if rep.Valid {
		t.Fatal("another tenant's device key answered this chain")
	}
	found := false
	for _, d := range rep.Defects {
		if d.Defect == DefectUnknownKey {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unknown_key, got %+v", rep.Defects)
	}
}
