package ingest

// FR-VERIFY-004: drives the PRODUCTION verifier (verifyAnchorVoteSignature,
// pipeline.go) against the frozen signed-good/tampered pair in
// conformance/anchorvote/manifest.json -- see that directory's README for why
// this lives outside the closed conformance/vectors/ cross-language families
// (this check is Go-only, producer and verifier both).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	m1pv1 "github.com/Omium-ai/omium-mark1/proto/gen/go/m1p/v1"
)

func TestAnchorVoteConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "conformance", "anchorvote", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		DevicePubkeyHex string `json:"device_pubkey_hex"`
		Vectors         []struct {
			Name            string `json:"name"`
			AnchorVotePbHex string `json:"anchor_vote_pb_hex"`
			Expect          string `json:"expect"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	pubBytes, err := hex.DecodeString(manifest.DevicePubkeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		t.Fatalf("bad device_pubkey_hex: %v (len %d)", err, len(pubBytes))
	}
	pub := ed25519.PublicKey(pubBytes)

	if len(manifest.Vectors) != 2 {
		t.Fatalf("want 2 frozen vectors (signed_good, tampered), got %d", len(manifest.Vectors))
	}
	for _, v := range manifest.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pbBytes, err := hex.DecodeString(v.AnchorVotePbHex)
			if err != nil {
				t.Fatal(err)
			}
			var av m1pv1.AnchorVote
			if err := proto.Unmarshal(pbBytes, &av); err != nil {
				t.Fatal(err)
			}
			sig := av.GetSignature()
			if len(sig) == 0 {
				t.Fatal("vector carries no signature to verify")
			}
			got := verifyAnchorVoteSignature(pub, &av, sig)
			want := v.Expect == "verify_ok"
			if got != want {
				t.Fatalf("%s: verifyAnchorVoteSignature = %v, want %v (expect=%q)", v.Name, got, want, v.Expect)
			}
		})
	}
}
