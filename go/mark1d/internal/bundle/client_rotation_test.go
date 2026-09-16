// The edge leg of the bundle rotation vectors (ADR-0004): a bundle signed by
// the verify successor is unknown_key until the manifest's cross-signed
// rotation is admitted -- and only the accept manifest admits it; every
// refused manifest leaves keys.json byte-identical and last-known-good in
// force. `ConfVectorsBundle` is the crosslang script's family token: these
// drive frozen vectors, unlike the wiring tests beside them.
package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type rotationFamily struct {
	Successor struct {
		PublicHex string `json:"public_hex"`
		KeyID     string `json:"key_id"`
	} `json:"successor"`
	Bundle struct {
		File     string  `json:"file"`
		TlogHead vecHead `json:"tlog_head"`
	} `json:"bundle"`
	Vectors []struct {
		Name   string `json:"name"`
		File   string `json:"file"`
		Expect string `json:"expect"`
		Kind   string `json:"kind"`
	} `json:"vectors"`
}

func loadRotation(t *testing.T) *rotationFamily {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Rotation rotationFamily `json:"rotation"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if len(top.Rotation.Vectors) == 0 {
		t.Fatal("rotation family empty")
	}
	return &top.Rotation
}

func TestConfVectorsBundleRotationAtEdge(t *testing.T) {
	rot := loadRotation(t)
	rotated, err := os.ReadFile(filepath.Join(vectorsDir, rot.Bundle.File))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rot.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			h := newHarness(t)
			c := h.client()
			h.applyChain(c)
			keysPath := filepath.Join(h.state, "policy", keysFile)
			before, _ := os.ReadFile(keysPath)
			doc, err := os.ReadFile(filepath.Join(vectorsDir, v.File))
			if err != nil {
				t.Fatal(err)
			}
			head := rot.Bundle.TlogHead
			h.cp.set(func(s *cp) { s.body, s.etag, s.seq, s.head, s.keysDoc = rotated, `"t7-stable-000003"`, "3", &head, doc })
			if !c.tick(context.Background()) {
				t.Fatal("tick reported a retryable failure")
			}
			acks, _ := h.cp.snapshot()
			last := acks[len(acks)-1]
			after, _ := os.ReadFile(keysPath)
			switch v.Expect {
			case "accept":
				if c.lkg.b.Seq != 3 || last.Result != "applied" || last.Seq != "3" {
					t.Fatalf("rotated bundle not applied: lkg seq %d, ack %+v", c.lkg.b.Seq, last)
				}
				if !strings.Contains(string(after), rot.Successor.PublicHex) || !strings.Contains(string(after), `"cross_sig"`) {
					t.Fatalf("admitted key not persisted with its provenance:\n%s", after)
				}
				// Boot re-verifies LKG under the persisted ring: the admitted
				// key must survive a restart or the rotated bundle is lost.
				again := h.client()
				if again.lkg == nil || again.lkg.b.Seq != 3 {
					t.Fatal("rotated bundle does not reload from custody")
				}
			case "reject":
				if c.lkg.b.Seq != 2 {
					t.Fatalf("%s: last-known-good lost (seq %d)", v.Kind, c.lkg.b.Seq)
				}
				if last.Result != "rejected" || last.RejectCode != "M1E-3001" {
					t.Fatalf("%s: ack %+v", v.Kind, last)
				}
				if !bytes.Equal(before, after) {
					t.Fatalf("%s: a refused manifest changed keys.json", v.Kind)
				}
			}
		})
	}
}
