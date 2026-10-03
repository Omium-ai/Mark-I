package identity

import (
	"bytes"
	"testing"

	"github.com/Omium-ai/omium-mark1/go/mark1d/internal/hostprofile"
)

// TestBatchFactsBindKeepsV1ForSoloDevelopers is FR-SPINE-050: with no lookup,
// or when no session in the batch is bound, Bind is nil and Payload is the
// v1 map — the solo developer's receipts do not change shape.
func TestBatchFactsBindKeepsV1ForSoloDevelopers(t *testing.T) {
	var f BatchFacts
	f.Note([16]byte{1}, [16]byte{9})
	if f.Bind(nil) != nil {
		t.Fatal("no lookup must bind nothing")
	}
	native := func([16]byte) SessionBinding { return SessionBinding{ProfileHash: ProfileHash(hostprofile.Default)} }
	if f.Bind(native) != nil {
		t.Fatal("a batch of native sessions must bind nothing")
	}
	cp := Checkpoint{TenantID: "t", DeviceID: "d", Seq: 1, IssuedAt: "2026-10-03T00:00:00Z", CheckpointSeq: 1, LeafCount: 1}
	cp.Hosts = f.Bind(native)
	p := cp.Payload("k")
	if p["v"] != 1 || p["hosts"] != nil || len(p) != 11 {
		t.Fatalf("v1 payload changed shape: %v", p)
	}
}

// TestBatchFactsBindIsSortedAndIdentityIsPerTask is FR-SPINE-051: a bound
// session makes the batch v2; hosts sort by session id, tasks by task id,
// native sessions ride along as "native", and identity_hash exists only
// under a host that supplies identity.
func TestBatchFactsBindIsSortedAndIdentityIsPerTask(t *testing.T) {
	cem := hostprofile.Profile{HostID: "cem888", HostVersion: "2.0.1", OwnsExecution: true, OwnsConfigSurface: true, OwnsMemory: true, ArrestMode: hostprofile.Recommend, SuppliesIdentity: true, SchemaVersion: "m1p.v1"}
	sCem, sNative := [16]byte{0xaa}, [16]byte{0x0b}
	lookup := func(sid [16]byte) SessionBinding {
		if sid == sCem {
			return SessionBinding{Transport: "fabric", HostID: cem.HostID, HostVersion: cem.HostVersion, HostCorrelationID: "run-7", ProfileHash: ProfileHash(cem), SuppliesIdentity: true, Bound: true}
		}
		return SessionBinding{ProfileHash: ProfileHash(hostprofile.Default)}
	}
	var f BatchFacts
	f.Note(sCem, [16]byte{2})
	f.Note(sCem, [16]byte{1})
	f.Note(sNative, [16]byte{3})
	f.Note(sNative, [16]byte{}) // a session-scoped leaf adds no task
	hosts := f.Bind(lookup)
	if len(hosts) != 2 || hosts[0].SessionID != sNative || hosts[1].SessionID != sCem {
		t.Fatalf("hosts order/count: %+v", hosts)
	}
	if hosts[0].Transport != "native" || hosts[0].HostID != "" || len(hosts[0].Tasks) != 1 || hosts[0].Tasks[0].IdentityHash != nil {
		t.Fatalf("native entry: %+v", hosts[0])
	}
	c := hosts[1]
	if c.Transport != "fabric" || c.HostID != "cem888" || c.HostCorrelationID != "run-7" || len(c.Tasks) != 2 || c.Tasks[0].TaskID != ([16]byte{1}) {
		t.Fatalf("cem888 entry: %+v", c)
	}
	if !bytes.Equal(c.Tasks[0].IdentityHash, IdentityHash("cem888", "run-7", [16]byte{1})) || bytes.Equal(c.Tasks[0].IdentityHash, c.Tasks[1].IdentityHash) {
		t.Fatal("identity hash must be per task under a host that supplies identity")
	}
	cp := Checkpoint{Hosts: hosts, ArrestsActed: 1, ArrestsRecommended: 2}
	p := cp.Payload("k")
	if p["v"] != 2 || p["arrests_acted"] != 1 || p["arrests_recommended"] != 2 || len(p["hosts"].([]any)) != 2 {
		t.Fatalf("v2 payload: %v", p)
	}
}

// TestBatchFactsMergeCarriesPendingLeaves: facts of leaves carried into the
// next seal join it — sessions, tasks and both counters.
func TestBatchFactsMergeCarriesPendingLeaves(t *testing.T) {
	var a, b BatchFacts
	a.Note([16]byte{1}, [16]byte{1})
	a.ArrestsActed = 1
	b.Note([16]byte{1}, [16]byte{2})
	b.Note([16]byte{2}, [16]byte{})
	b.ArrestsRecommended = 3
	m := a.Merge(b)
	if len(m.Tasks) != 2 || len(m.Tasks[[16]byte{1}]) != 2 || len(m.Tasks[[16]byte{2}]) != 0 || m.ArrestsActed != 1 || m.ArrestsRecommended != 3 {
		t.Fatalf("merge = %+v", m)
	}
	if len(a.Tasks[[16]byte{1}]) != 1 {
		t.Fatal("merge mutated its receiver")
	}
}
