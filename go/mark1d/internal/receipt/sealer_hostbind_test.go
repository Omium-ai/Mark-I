package receipt

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/identity"
)

// TestSealBindsHostsAsControldWould is FR-SPINE-051/053 at the sealer: with a
// session lookup and a bound session in the batch, the seal is a v2 payload —
// ReceiptCheckpoint carries payload_version 2, the hosts and the counters —
// and controld's reconstruction from exactly those wire fields verifies the
// origin signature. A batch of native sessions under the same sealer stays
// v1 (FR-SPINE-050).
func TestSealBindsHostsAsControldWould(t *testing.T) {
	h := newHarness(t, nil)
	cem := hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	sCem, sNative := [16]byte{0xaa}, [16]byte{0x0b}
	cfg := h.cfg
	cfg.Session = func(sid [16]byte) identity.SessionBinding {
		if sid == sCem {
			return identity.SessionBinding{Transport: "fabric", HostID: cem.HostID, HostVersion: cem.HostVersion, HostCorrelationID: "run-7", ProfileHash: identity.ProfileHash(cem), SuppliesIdentity: true, Bound: true}
		}
		return identity.SessionBinding{ProfileHash: identity.ProfileHash(hostprofile.Default)}
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// --- a native-only batch: v1, byte for byte the old posture ---
	var solo identity.BatchFacts
	solo.Note(sNative, [16]byte{3})
	s.Seal(context.Background(), [][]byte{leaf(1)}, solo)
	cps := h.checkpoints(t)
	if len(cps) != 1 || cps[0].GetReceiptCheckpoint().GetPayloadVersion() != 0 || len(cps[0].GetReceiptCheckpoint().GetHosts()) != 0 {
		t.Fatalf("native-only batch must seal v1: %v", cps)
	}

	// --- a batch with a bound session: v2 ---
	var facts identity.BatchFacts
	facts.Note(sCem, [16]byte{2})
	facts.Note(sCem, [16]byte{1})
	facts.Note(sNative, [16]byte{3})
	facts.ArrestsActed, facts.ArrestsRecommended = 1, 2
	leaves := [][]byte{leaf(2), leaf(3)}
	s.Seal(context.Background(), leaves, facts)
	cps = h.checkpoints(t)
	if len(cps) != 2 {
		t.Fatalf("sealed %d checkpoints, want 2", len(cps))
	}
	ev := cps[1]
	cp := ev.GetReceiptCheckpoint()
	if cp.GetPayloadVersion() != 2 || cp.GetArrestsActed() != 1 || cp.GetArrestsRecommended() != 2 {
		t.Fatalf("wire: version=%d acted=%d recommended=%d", cp.GetPayloadVersion(), cp.GetArrestsActed(), cp.GetArrestsRecommended())
	}
	hosts := cp.GetHosts()
	if len(hosts) != 2 || !bytes.Equal(hosts[0].GetSessionId(), sNative[:]) || hosts[0].GetTransport() != "native" ||
		!bytes.Equal(hosts[1].GetSessionId(), sCem[:]) || hosts[1].GetHostId() != "cem888" || hosts[1].GetHostCorrelationId() != "run-7" {
		t.Fatalf("wire hosts: %v", hosts)
	}
	if len(hosts[1].GetTasks()) != 2 || len(hosts[1].GetTasks()[0].GetIdentityHash()) != 32 || len(hosts[0].GetTasks()[0].GetIdentityHash()) != 0 {
		t.Fatalf("wire tasks: %v / %v", hosts[1].GetTasks(), hosts[0].GetTasks())
	}

	// --- controld's reconstruction (store.go): v1 fields from the head and
	// the envelope, then the event's hosts and counters because
	// payload_version == 2 — exactly sidefx's mapping, field for field. ---
	headHash, err := hex.DecodeString(headHashHex)
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := identity.ReceiptHash(rebuild(cps[0], headSeq+1, [32]byte(headHash)).Payload(cps[0].GetReceiptCheckpoint().GetKeyId()))
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := rebuild(ev, headSeq+2, firstHash)
	rebuilt.Hosts = []identity.HostBinding{}
	for _, wh := range hosts {
		hb := identity.HostBinding{Transport: wh.GetTransport(), HostID: wh.GetHostId(), HostVersion: wh.GetHostVersion(), HostCorrelationID: wh.GetHostCorrelationId()}
		copy(hb.SessionID[:], wh.GetSessionId())
		copy(hb.ProfileHash[:], wh.GetProfileHash())
		for _, wt := range wh.GetTasks() {
			tb := identity.TaskBinding{}
			copy(tb.TaskID[:], wt.GetTaskId())
			if len(wt.GetIdentityHash()) > 0 {
				tb.IdentityHash = append([]byte(nil), wt.GetIdentityHash()...)
			}
			hb.Tasks = append(hb.Tasks, tb)
		}
		rebuilt.Hosts = append(rebuilt.Hosts, hb)
	}
	rebuilt.ArrestsActed, rebuilt.ArrestsRecommended = cp.GetArrestsActed(), cp.GetArrestsRecommended()
	text, err := identity.CanonicalJSON(rebuilt.Payload(cp.GetKeyId()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(text), []byte(`"v":2`)) || !bytes.Contains([]byte(text), []byte(`"host_id":"cem888"`)) {
		t.Fatalf("reconstruction is not the v2 payload: %s", text)
	}
	signingInput := append([]byte(identity.DomainPrefix), text...)
	if !identity.Verify(h.pub, cp.GetOriginSignature(), signingInput) {
		t.Fatalf("origin signature does not verify over the v2 reconstruction — controld would refuse bad_signature.\nreconstructed: %s", text)
	}
}
